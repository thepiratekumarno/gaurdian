# COMPLETE app/scheduler.py - 1 minute polling with commit detection
# REPLACE your entire app/scheduler.py file with this code

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
    COMPLETE: Check for new repositories AND new commits every 1 minute
    - Detects new repositories within 1 minute
    - Detects new commits in existing repositories
    - Automatically scans and sends emails
    """
    try:
        logger.info("🚀 Starting 1-minute polling for repos and commits...")
        
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
        commits_detected = 0
        
        for user in users:
            try:
                user_email = user.get("email")
                github_token = user.get("github_access_token")
                
                if not github_token:
                    logger.warning(f"⚠️ No GitHub token for user {user_email}")
                    continue
                
                logger.info(f"🔍 Checking repos + commits for user: {user_email}")
                
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
                
                # Process each repository
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
                        
                        # Check if this repository exists in our database
                        existing_repo = await db.repositories.find_one({
                            "user_email": user_email,
                            "repository_name": full_name
                        })
                        
                        if not existing_repo:
                            # 🆕 NEW REPOSITORY DETECTED!
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
                                "github_pushed_at": datetime.fromisoformat(pushed_at.replace('Z', '+00:00')),
                                "last_known_push": pushed_at
                            }
                            
                            result = await db.repositories.insert_one(repo_doc)
                            repo_id = str(result.inserted_id)
                            
                            logger.info(f"✅ Added new repository: {full_name} (ID: {repo_id})")
                            new_repos_found += 1
                            
                            # 🚀 TRIGGER SCAN FOR NEW REPOSITORY
                            success = await scan_repository_with_notifications(
                                repo_id, user_email, github_token, full_name, "new_repository"
                            )
                            
                            if success:
                                logger.info(f"✅ New repo scan completed: {full_name}")
                            else:
                                logger.error(f"❌ New repo scan failed: {full_name}")
                        
                        else:
                            # 🔄 EXISTING REPOSITORY - CHECK FOR NEW COMMITS
                            last_known_push = existing_repo.get("last_known_push")
                            
                            if pushed_at and pushed_at != last_known_push:
                                logger.info(f"🔄 NEW COMMITS DETECTED in {full_name}")
                                logger.info(f"   Previous push: {last_known_push}")
                                logger.info(f"   Latest push: {pushed_at}")
                                
                                # Update the last known push time
                                await db.repositories.update_one(
                                    {"_id": existing_repo["_id"]},
                                    {
                                        "$set": {
                                            "last_known_push": pushed_at,
                                            "github_pushed_at": datetime.fromisoformat(pushed_at.replace('Z', '+00:00')),
                                            "scan_status": "pending",
                                            "updated_at": datetime.utcnow()
                                        }
                                    }
                                )
                                
                                commits_detected += 1
                                
                                # 🚀 TRIGGER SCAN FOR UPDATED REPOSITORY
                                success = await scan_repository_with_notifications(
                                    str(existing_repo["_id"]), user_email, github_token, full_name, "new_commits"
                                )
                                
                                if success:
                                    logger.info(f"✅ Commit scan completed: {full_name}")
                                else:
                                    logger.error(f"❌ Commit scan failed: {full_name}")
                        
                    except Exception as repo_error:
                        logger.error(f"❌ Error processing repository {repo_data.get('full_name', 'unknown')}: {repo_error}")
                        continue
                
            except Exception as user_error:
                logger.error(f"❌ Error polling repos for user {user.get('email', 'unknown')}: {user_error}")
                continue
        
        if new_repos_found > 0 or commits_detected > 0:
            logger.info(f"🎯 1-minute polling completed:")
            logger.info(f"   🆕 New repositories: {new_repos_found}")
            logger.info(f"   🔄 Repositories with new commits: {commits_detected}")
        else:
            logger.info("🔄 1-minute polling completed - no changes detected")
        
    except Exception as e:                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             

        logger.error(f"💥 Critical error in 1-minute polling: {e}")

async def scan_repository_with_notifications(repo_id: str, user_email: str, access_token: str, repo_name: str, scan_reason: str) -> bool:
    """
    COMPLETE: Enhanced repository scanning with different email messages
    scan_reason: "new_repository" or "new_commits"
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
        else:
            logger.info(f"🔄 Scanning repository with NEW COMMITS: {repo_name}")
        
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
        scan_type = "automatic_new_repo" if scan_reason == "new_repository" else "automatic_commit"
        
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
            
            else:  # new_commits
                # Email for UPDATED repository
                if all_findings:
                    subject = f"🔄 COMMIT ALERT: {repo_name} - {len(all_findings)} secrets in latest changes!"
                    await email_service.send_security_alert(user_email, subject, all_findings, str(report["_id"]))
                    logger.info(f"📧 COMMIT security alert sent to {user_email}")
                else:
                    # Send clean commit notification
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
    """Start background scheduler - 1 minute polling"""
    scheduler = AsyncIOScheduler()
    
    # 🚀 Poll every 1 MINUTE
    scheduler.add_job(
        poll_user_repos,
        "interval",
        minutes=1,  # 1 MINUTE POLLING
        id="poll_user_repos_1min",
        max_instances=1,
        replace_existing=True
    )
    
    # Clean up every 30 minutes
    scheduler.add_job(
        cleanup_old_scans,
        "interval",
        minutes=30,
        id="cleanup_old_scans",
        max_instances=1,
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("🚀 Background scheduler started - 1 MINUTE polling!")
    
    return scheduler

def stop_background_scheduler(scheduler):
    """Stop the background scheduler"""
    if scheduler:
        scheduler.shutdown()
        logger.info("⏰ Background scheduler stopped")
