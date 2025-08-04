import asyncio
import httpx
import os
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from bson import ObjectId
import base64

# Import your app modules
from . import crud, database, email_service, detector

logger = logging.getLogger(__name__)

async def poll_user_repos():
    """
    30-SECOND POLLING with 15-MINUTE FREEZE LOGIC:
    - Detects new repositories within 30 seconds
    - Scans existing repos on FIRST commit, then freezes for 15 minutes
    - After 15 minutes, scans ONCE if there were commits during freeze
    - No endless loops - only scans when needed
    """
    try:
        logger.info("🚀 Starting 30-second polling with 15-min freeze logic...")
        
        db = await database.get_database()
        
        # Get all users who have GitHub tokens stored
        users = await db.users.find({
            "github_access_token": {"$exists": True, "$ne": None}
        }).to_list(None)
        
        if not users:
            logger.info("📭 No users with GitHub tokens found")
            return
        
        logger.info(f"👥 Found {len(users)} users with GitHub tokens")
        new_repos_found = 0
        repos_scanned = 0
        repos_frozen = 0
        
        for user in users:
            try:
                user_email = user.get("email")
                github_token = user.get("github_access_token")
                
                if not github_token:
                    logger.warning(f"⚠️ No GitHub token for user {user_email}")
                    continue
                
                logger.info(f"🔍 Checking repos for user: {user_email}")
                
                # Fetch user's repositories from GitHub API
                headers = {
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "SecretGuardian/1.0"
                }
                
                # Get user's repositories sorted by update time
                url = "https://api.github.com/user/repos?per_page=100&sort=updated&direction=desc"
                
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(url, headers=headers)
                
                # Check for rate limiting
                rate_limit_remaining = response.headers.get("X-RateLimit-Remaining")
                if rate_limit_remaining:
                    logger.info(f"📊 GitHub API rate limit remaining: {rate_limit_remaining}")
                
                if response.status_code == 401:
                    logger.error(f"🔑 Invalid GitHub token for user {user_email}")
                    continue
                elif response.status_code == 403:
                    logger.warning(f"⚠️ Rate limited for user {user_email}")
                    continue
                elif response.status_code != 200:
                    logger.error(f"❌ Failed to fetch repos for {user_email}: {response.status_code}")
                    continue
                
                repos = response.json()
                logger.info(f"📊 Checking {len(repos)} repositories for user {user_email}")
                
                # Process each repository with freeze logic
                for repo_data in repos:
                    try:
                        full_name = repo_data["full_name"]
                        html_url = repo_data["html_url"]
                        is_private = repo_data.get("private", False)
                        updated_at = repo_data.get("updated_at")
                        pushed_at = repo_data.get("pushed_at")
                        
                        # Skip if no pushed_at (empty repo)
                        if not pushed_at:
                            continue
                        
                        # Parse GitHub's pushed_at timestamp
                        github_pushed_time = datetime.fromisoformat(pushed_at.replace('Z', '+00:00'))
                        
                        # Check if this repository exists in our database
                        existing_repo = await db.repositories.find_one({
                            "user_email": user_email,
                            "repository_name": full_name
                        })
                        
                        if not existing_repo:
                            # 🆕 NEW REPOSITORY DETECTED - Always scan immediately
                            logger.info(f"🆕 NEW REPOSITORY: {full_name} for {user_email}")
                            
                            # Add repository to database
                            repo_doc = {
                                "user_email": user_email,
                                "repository_name": full_name,
                                "repository_url": html_url,
                                "is_monitored": True,
                                "added_at": datetime.utcnow(),
                                "last_scan": None,
                                "findings_count": 0,
                                "scan_status": "pending",
                                "is_private": is_private,
                                "auto_detected": True,
                                "github_updated_at": datetime.fromisoformat(updated_at.replace('Z', '+00:00')),
                                "github_pushed_at": github_pushed_time,
                                "last_known_push": pushed_at,
                                "scan_frozen_until": None,  # New repos are not frozen
                                "commits_during_freeze": 0
                            }
                            
                            result = await db.repositories.insert_one(repo_doc)
                            repo_id = str(result.inserted_id)
                            
                            logger.info(f"✅ Added new repository: {full_name} (ID: {repo_id})")
                            new_repos_found += 1
                            
                            # 🚀 SCAN NEW REPOSITORY IMMEDIATELY
                            success = await scan_repository_with_notifications(
                                repo_id, user_email, github_token, full_name, "new_repository"
                            )
                            
                            if success:
                                # Set 15-minute freeze after first scan
                                freeze_until = datetime.utcnow() + timedelta(minutes=15)
                                await db.repositories.update_one(
                                    {"_id": ObjectId(repo_id)},
                                    {"$set": {"scan_frozen_until": freeze_until}}
                                )
                                logger.info(f"✅ New repo scan completed, frozen until: {freeze_until}")
                                repos_scanned += 1
                            else:
                                logger.error(f"❌ New repo scan failed: {full_name}")
                        
                        else:
                            # 🔄 EXISTING REPOSITORY - Apply 15-minute freeze logic
                            repo_id = str(existing_repo["_id"])
                            last_known_push = existing_repo.get("last_known_push")
                            scan_frozen_until = existing_repo.get("scan_frozen_until")
                            commits_during_freeze = existing_repo.get("commits_during_freeze", 0)
                            
                            # Check if there's a new commit
                            if pushed_at != last_known_push:
                                logger.info(f"🔄 NEW COMMIT detected in {full_name}")
                                logger.info(f"   Previous push: {last_known_push}")
                                logger.info(f"   Latest push: {pushed_at}")
                                
                                now = datetime.utcnow()
                                
                                # Parse freeze time if it exists
                                freeze_time = None
                                if scan_frozen_until:
                                    if isinstance(scan_frozen_until, str):
                                        freeze_time = datetime.fromisoformat(scan_frozen_until.replace('Z', '+00:00'))
                                    else:
                                        freeze_time = scan_frozen_until
                                
                                if freeze_time is None or now >= freeze_time:
                                    # ✅ NOT FROZEN - Can scan now
                                    logger.info(f"🚀 Scanning {full_name} - not frozen")
                                    
                                    # Update repository with new push info
                                    await db.repositories.update_one(
                                        {"_id": existing_repo["_id"]},
                                        {
                                            "$set": {
                                                "last_known_push": pushed_at,
                                                "github_pushed_at": github_pushed_time,
                                                "scan_status": "pending",
                                                "commits_during_freeze": 0
                                            }
                                        }
                                    )
                                    
                                    # 🚀 TRIGGER SCAN
                                    success = await scan_repository_with_notifications(
                                        repo_id, user_email, github_token, full_name, "new_commits"
                                    )
                                    
                                    if success:
                                        # Set new 15-minute freeze
                                        new_freeze_until = now + timedelta(minutes=15)
                                        await db.repositories.update_one(
                                            {"_id": existing_repo["_id"]},
                                            {"$set": {"scan_frozen_until": new_freeze_until}}
                                        )
                                        logger.info(f"✅ Commit scan completed, frozen until: {new_freeze_until}")
                                        repos_scanned += 1
                                    else:
                                        logger.error(f"❌ Commit scan failed: {full_name}")
                                
                                else:
                                    # ❄️ FROZEN - Just track the commit for later
                                    logger.info(f"❄️ {full_name} is frozen until {freeze_time}")
                                    logger.info(f"   Tracking commit for post-freeze scan")
                                    
                                    # Update commit info but don't scan
                                    await db.repositories.update_one(
                                        {"_id": existing_repo["_id"]},
                                        {
                                            "$set": {
                                                "last_known_push": pushed_at,
                                                "github_pushed_at": github_pushed_time,
                                                "commits_during_freeze": commits_during_freeze + 1
                                            }
                                        }
                                    )
                                    repos_frozen += 1
                            
                            else:
                                # No new commits - check if freeze expired with pending commits
                                now = datetime.utcnow()
                                freeze_time = None
                                if scan_frozen_until:
                                    if isinstance(scan_frozen_until, str):
                                        freeze_time = datetime.fromisoformat(scan_frozen_until.replace('Z', '+00:00'))
                                    else:
                                        freeze_time = scan_frozen_until
                                
                                # If freeze just expired and we had commits during freeze
                                if (freeze_time and now >= freeze_time and 
                                    commits_during_freeze > 0):
                                    
                                    logger.info(f"🔓 Freeze expired for {full_name} with {commits_during_freeze} pending commits")
                                    
                                    # 🚀 TRIGGER POST-FREEZE SCAN
                                    success = await scan_repository_with_notifications(
                                        repo_id, user_email, github_token, full_name, "post_freeze_commits"
                                    )
                                    
                                    if success:
                                        # Clear freeze and reset counters
                                        await db.repositories.update_one(
                                            {"_id": existing_repo["_id"]},
                                            {
                                                "$set": {
                                                    "scan_frozen_until": None,  # Clear freeze
                                                    "commits_during_freeze": 0
                                                }
                                            }
                                        )
                                        logger.info(f"✅ Post-freeze scan completed for {full_name}")
                                        repos_scanned += 1
                                    else:
                                        logger.error(f"❌ Post-freeze scan failed: {full_name}")
                        
                    except Exception as repo_error:
                        logger.error(f"❌ Error processing repository {repo_data.get('full_name', 'unknown')}: {repo_error}")
                        continue
                
            except Exception as user_error:
                logger.error(f"❌ Error polling repos for user {user.get('email', 'unknown')}: {user_error}")
                continue
        
        # Summary log
        if new_repos_found > 0 or repos_scanned > 0 or repos_frozen > 0:
            logger.info(f"🎯 30-second polling with freeze logic completed:")
            logger.info(f"   🆕 New repositories: {new_repos_found}")
            logger.info(f"   🚀 Repositories scanned: {repos_scanned}")
            logger.info(f"   ❄️ Repositories frozen: {repos_frozen}")
        else:
            logger.info("🔄 30-second polling completed - no changes detected")
        
    except Exception as e:
        logger.error(f"💥 Critical error in 30-second polling: {e}")

async def scan_repository_with_notifications(repo_id: str, user_email: str, access_token: str, repo_name: str, scan_reason: str) -> bool:
    """
    Enhanced repository scanning with different email messages
    scan_reason: "new_repository", "new_commits", or "post_freeze_commits"
    """
    try:
        db = await database.get_database()
        
        # Update scan status to scanning
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {
                "scan_status": "scanning", 
                "last_scan_started": datetime.utcnow(),
                "scan_reason": scan_reason
            }}
        )
        
        if scan_reason == "new_repository":
            logger.info(f"🆕 Scanning NEW repository: {repo_name}")
        elif scan_reason == "new_commits":
            logger.info(f"🔄 Scanning repository with NEW COMMITS: {repo_name}")
        else:  # post_freeze_commits
            logger.info(f"🔓 Scanning repository after FREEZE PERIOD: {repo_name}")
        
        # Extract owner and repo name from full name
        if "/" not in repo_name:
            logger.error(f"❌ Invalid repository name format: {repo_name}")
            await update_scan_status(repo_id, "failed", "Invalid repository name format")
            return False
            
        owner, repo_short_name = repo_name.split("/", 1)
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecretGuardian/1.0"
        }
        
        # Get repository information
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo_short_name}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(repo_info_url, headers=headers)
            
            if response.status_code == 404:
                error_msg = f"Repository not found or access denied: {owner}/{repo_short_name}"
                logger.error(f"❌ {error_msg}")
                await update_scan_status(repo_id, "failed", error_msg)
                return False
            elif response.status_code == 403:
                error_msg = f"Access forbidden - rate limited or insufficient permissions"
                logger.error(f"❌ {error_msg}")
                await update_scan_status(repo_id, "failed", error_msg)
                return False
            elif response.status_code != 200:
                error_msg = f"Failed to get repository info: {response.status_code}"
                logger.error(f"❌ {error_msg}")
                await update_scan_status(repo_id, "failed", error_msg)
                return False
        
        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")
        
        logger.info(f"📂 Repository: {owner}/{repo_short_name}, branch: {default_branch}")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/git/trees/{default_branch}?recursive=1"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(tree_url, headers=headers)
            
            if response.status_code == 409:
                # Empty repository
                logger.info(f"📭 Empty repository: {repo_name}")
                all_findings = []
                scanned_files_count = 0
            elif response.status_code != 200:
                error_msg = f"Failed to get repository tree: {response.status_code}"
                logger.error(f"❌ {error_msg}")
                await update_scan_status(repo_id, "failed", error_msg)
                return False
            else:
                tree_data = response.json()
                
                def is_text_file(file_path: str) -> bool:
                    text_extensions = ['.py', '.js', '.java', '.c', '.cpp', '.cs', '.php',
                                     '.rb', '.go', '.swift', '.kt', '.ts', '.html', '.css',
                                     '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg',
                                     '.md', '.txt', '.env', '.sh', '.bat', '.ps1', '.sql',
                                     '.xml', '.csv', '.log', '.conf', '.config', '.dockerfile']
                    return any(file_path.lower().endswith(ext) for ext in text_extensions)
                
                # Scan all files
                all_findings = []
                scanned_files_count = 0
                
                for item in tree_data.get("tree", []):
                    if item["type"] == "blob" and item.get("size", 0) > 0:
                        file_path = item["path"]
                        
                        if not is_text_file(file_path):
                            continue
                        
                        # Skip large files (> 1MB)
                        if item.get("size", 0) > 1024 * 1024:
                            logger.warning(f"⚠️ Skipping large file: {file_path}")
                            continue
                            
                        file_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/contents/{file_path}?ref={default_branch}"
                        
                        try:
                            async with httpx.AsyncClient(timeout=30.0) as client:
                                response = await client.get(file_url, headers=headers)
                                
                                if response.status_code != 200:
                                    continue
                            
                            file_data = response.json()
                            
                            if "content" not in file_data:
                                continue
                            
                            # Decode file content
                            try:
                                content = base64.b64decode(file_data["content"]).decode("utf-8")
                            except UnicodeDecodeError:
                                continue
                            except Exception:
                                continue
                            
                            # Scan for secrets
                            findings = detector.scan_text(content)
                            
                            for finding in findings:
                                finding["location"] = f"File: {file_path}"
                                finding["repository"] = repo_name
                                all_findings.append(finding)
                            
                            scanned_files_count += 1
                        
                        except Exception as file_error:
                            logger.error(f"❌ Error processing file {file_path}: {file_error}")
                            continue
        
        # Create report
        if scan_reason == "new_repository":
            scan_type = "automatic_new_repo"
        elif scan_reason == "post_freeze_commits":
            scan_type = "automatic_post_freeze"
        else:
            scan_type = "automatic_commit"
        
        report = await crud.create_report(
            user_email=user_email,
            repository_name=repo_name,
            findings=all_findings,
            scan_type=scan_type
        )
        
        logger.info(f"📊 Scan completed: {repo_name} - {len(all_findings)} findings, {scanned_files_count} files")
        
        # 📧 SEND DIFFERENT EMAIL MESSAGES BASED ON SCAN REASON
        try:
            if scan_reason == "new_repository":
                # Email for NEW repository
                if all_findings:
                    subject = f"🆕 NEW REPO ALERT: {repo_name} - {len(all_findings)} secrets found!"
                    await email_service.send_security_alert(user_email, subject, all_findings, str(report["_id"]))
                    logger.info(f"📧 NEW REPO security alert sent to {user_email}")
                else:
                    await email_service.send_no_findings_alert(user_email, repo_name, str(report["_id"]))
                    logger.info(f"📧 NEW REPO no-findings alert sent to {user_email}")
            
            elif scan_reason == "post_freeze_commits":
                # Email for POST-FREEZE commits (multiple commits batched)
                if all_findings:
                    subject = f"🔓 BATCH COMMIT ALERT: {repo_name} - {len(all_findings)} secrets found!"
                    await email_service.send_security_alert(user_email, subject, all_findings, str(report["_id"]))
                    logger.info(f"📧 POST-FREEZE security alert sent to {user_email}")
                else:
                    await email_service.send_commit_clean_alert(user_email, repo_name, str(report["_id"]))
                    logger.info(f"📧 POST-FREEZE clean alert sent to {user_email}")
            
            else:  # new_commits
                # Email for regular commit
                if all_findings:
                    subject = f"🔄 COMMIT ALERT: {repo_name} - {len(all_findings)} secrets in latest changes!"
                    await email_service.send_security_alert(user_email, subject, all_findings, str(report["_id"]))
                    logger.info(f"📧 COMMIT security alert sent to {user_email}")
                else:
                    await email_service.send_commit_clean_alert(user_email, repo_name, str(report["_id"]))
                    logger.info(f"📧 COMMIT clean alert sent to {user_email}")
        
        except Exception as email_error:
            logger.error(f"📧 Failed to send email: {email_error}")
        
        # Update repository with scan results
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {
                "last_scan": datetime.utcnow(),
                "findings_count": len(all_findings),
                "scan_status": "completed",
                "scanned_files_count": scanned_files_count,
                "last_scan_successful": True
            }}
        )
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Scan error for {repo_name}: {e}")
        await update_scan_status(repo_id, "failed", str(e))
        return False

async def update_scan_status(repo_id: str, status: str, error_message: str = None):
    """Update repository scan status with error message"""
    try:
        db = await database.get_database()
        update_data = {
            "scan_status": status,
            "last_scan_completed": datetime.utcnow()
        }
        if error_message:
            update_data["error_message"] = error_message
            update_data["last_scan_failed"] = datetime.utcnow()
            
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)}, 
            {"$set": update_data}
        )
        logger.info(f"📝 Updated scan status to '{status}' for repo {repo_id}")
    except Exception as e:
        logger.error(f"💥 Failed to update scan status: {e}")

async def cleanup_old_scans():
    """Clean up old scan results and reset failed scans"""
    try:
        logger.info("🧹 Cleaning up old scans...")
        
        db = await database.get_database()
        
        # Reset failed scans older than 5 minutes for retry
        five_min_ago = datetime.utcnow() - timedelta(minutes=5)
        
        result = await db.repositories.update_many(
            {
                "scan_status": "failed",
                "last_scan_failed": {"$lt": five_min_ago}
            },
            {
                "$set": {"scan_status": "pending"},
                "$unset": {"error_message": "", "last_scan_failed": ""}
            }
        )
        
        if result.modified_count > 0:
            logger.info(f"🔄 Reset {result.modified_count} failed scans")
        
        # Clean up expired freezes (optional cleanup)
        now = datetime.utcnow()
        expired_freezes = await db.repositories.update_many(
            {
                "scan_frozen_until": {"$lt": now},
                "commits_during_freeze": 0
            },
            {
                "$unset": {"scan_frozen_until": ""}
            }
        )
        
        if expired_freezes.modified_count > 0:
            logger.info(f"🔓 Cleaned up {expired_freezes.modified_count} expired freezes")
        
        # Clean up old reports (older than 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        old_reports = await db.reports.delete_many({
            "created_at": {"$lt": thirty_days_ago}
        })
        
        if old_reports.deleted_count > 0:
            logger.info(f"🗑️ Cleaned up {old_reports.deleted_count} old reports")
            
    except Exception as e:
        logger.error(f"💥 Cleanup error: {e}")

def start_background_scheduler():
    """Start background scheduler - 30 SECOND polling with 15-minute freeze logic"""
    scheduler = AsyncIOScheduler()
    
    # 🚀 Poll every 30 SECONDS with freeze logic
    scheduler.add_job(
        poll_user_repos,
        "interval",
        seconds=30,  # 30 SECOND POLLING
        id="poll_user_repos_with_freeze",
        max_instances=1,
        replace_existing=True
    )
    
    # Clean up every 15 minutes
    scheduler.add_job(
        cleanup_old_scans,
        "interval",
        minutes=15,
        id="cleanup_old_scans",
        max_instances=1,
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("🚀 Background scheduler started - 30 SECOND polling with 15-MINUTE FREEZE logic!")
    
    return scheduler

def stop_background_scheduler(scheduler):
    """Stop the background scheduler"""
    if scheduler:
        scheduler.shutdown()
        logger.info("⏰ Background scheduler stopped")
