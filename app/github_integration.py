# app/github_integration.py - COMPLETE FIXED VERSION

import hashlib
import hmac
import json
import os
from fastapi import Request, HTTPException
from typing import Dict, Any, List
from bson import ObjectId
from datetime import datetime
from dotenv import load_dotenv
import httpx
import base64
import logging
import asyncio
from . import detector, crud, email_service, database

load_dotenv()

logger = logging.getLogger(__name__)

## UPDATE your existing handle_webhook function to include user repo handling

async def handle_webhook(request: Request) -> Dict[str, Any]:
    """Enhanced webhook handling for both organization and user events"""
    try:
        # Verify webhook signature
        signature = request.headers.get("X-Hub-Signature-256", "")
        webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        
        if webhook_secret:
            body = await request.body()
            digest = hmac.new(
                webhook_secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, f"sha256={digest}"):
                raise HTTPException(status_code=403, detail="Invalid signature")
        
        # Get event type
        event_type = request.headers.get("X-GitHub-Event")
        payload = await request.json()
        
        logger.info(f"Received webhook event: {event_type}")
        
        # Handle repository creation - BOTH org and user repos
        if event_type == "repository" and payload.get("action") in ["created", "publicized"]:
            # Check if this is an organization event or user event
            repository = payload.get("repository", {})
            owner = repository.get("owner", {})
            owner_type = owner.get("type", "").lower()
            
            if owner_type == "organization":
                return await handle_repo_created(payload)  # Your existing org handler
            else:
                return await handle_user_repo_created(payload)  # New user handler
        
        # Handle push events to existing repositories
        elif event_type == "push":
            return await handle_push_event(payload)
        
        # Handle repository deletion
        elif event_type == "repository" and payload.get("action") == "deleted":
            return await handle_repo_deleted(payload)
        
        return {"message": f"Event type '{event_type}' processed"}
        
    except Exception as e:
        logger.error(f"Webhook error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Webhook processing failed")

async def handle_repo_created(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle repository creation event - ENHANCED VERSION"""
    try:
        repository = payload.get("repository", {})
        sender = payload.get("sender", {})
        
        repo_name = repository.get("full_name", "unknown")
        repo_url = repository.get("html_url", "")
        owner = repository.get("owner", {})
        owner_login = owner.get("login", "unknown")
        
        # Get user email - try multiple sources
        user_email = sender.get("email")
        if not user_email:
            # If no email in sender, use a fallback
            user_email = f"{owner_login}@users.noreply.github.com"
        
        logger.info(f"Processing repository creation: {repo_name} by {owner_login}")
        
        # Check if repository is private or public
        is_private = repository.get("private", False)
        
        # Add repository to database
        db = await database.get_database()
        
        # Check if repository already exists
        existing_repo = await db.repositories.find_one({
            "repository_name": repo_name,
            "user_email": user_email
        })
        
        if existing_repo:
            logger.info(f"Repository {repo_name} already exists in database")
            return {"status": "repository already exists", "repo_id": str(existing_repo["_id"])}
        
        repo_data = {
            "user_email": user_email,
            "repository_name": repo_name,
            "repository_url": repo_url,
            "is_monitored": True,  # Auto-enable monitoring for new repos
            "added_at": datetime.utcnow(),
            "last_scan": None,
            "findings_count": 0,
            "scan_status": "pending",
            "is_private": is_private,
            "owner_login": owner_login,
            "webhook_auto_created": True
        }
        
        result = await db.repositories.insert_one(repo_data)
        repo_id = str(result.inserted_id)
        
        logger.info(f"Repository {repo_name} added to database with ID: {repo_id}")
        
        # Get access token for scanning
        access_token = os.getenv("GITHUB_ACCESS_TOKEN")
        if not access_token:
            logger.error("GitHub access token not configured")
            return {"status": "error", "error": "GitHub access token missing"}
        
        # Trigger automatic scan immediately in background
        asyncio.create_task(scan_and_notify(repo_id, user_email, access_token, repo_name))
        
        return {
            "status": "repository added and scan started", 
            "repo_id": repo_id,
            "repository": repo_name,
            "user_email": user_email
        }
        
    except Exception as e:
        logger.error(f"Error handling repository creation: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}

async def handle_repo_deleted(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle repository deletion event"""
    try:
        repository = payload.get("repository", {})
        repo_name = repository.get("full_name", "unknown")
        
        db = await database.get_database()
        
        # Delete repository from database
        result = await db.repositories.delete_many({
            "repository_name": repo_name
        })
        
        # Also delete associated reports
        reports_deleted = await db.reports.delete_many({
            "repository_name": repo_name
        })
        
        logger.info(f"Repository {repo_name} deleted from database. Repositories: {result.deleted_count}, Reports: {reports_deleted.deleted_count}")
        
        return {
            "status": "repository removed", 
            "repository": repo_name,
            "repositories_deleted": result.deleted_count,
            "reports_deleted": reports_deleted.deleted_count
        }
        
    except Exception as e:
        logger.error(f"Error deleting repository: {e}")
        return {"status": "error", "error": str(e)}

async def handle_push_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle push events to trigger scans on existing repositories"""
    try:
        repository = payload.get("repository", {})
        sender = payload.get("sender", {})
        pusher = payload.get("pusher", {})
        
        repo_name = repository.get("full_name", "unknown")
        owner = repository.get("owner", {}).get("login", "unknown")
        
        # Try to get user email from various sources
        user_email = None
        if pusher and pusher.get("email"):
            user_email = pusher.get("email")
        elif sender and sender.get("email"):
            user_email = sender.get("email")
        else:
            user_email = f"{owner}@users.noreply.github.com"
        
        logger.info(f"Processing push event for repository: {repo_name}")
        
        # Find repository in database
        db = await database.get_database()
        repo = await db.repositories.find_one({
            "repository_name": repo_name,
            "is_monitored": True
        })
        
        if not repo:
            logger.info(f"Repository {repo_name} not found or not monitored")
            return {"message": "Repository not monitored"}
        
        # Update user email if it was a fallback before
        if repo.get("user_email", "").endswith("@users.noreply.github.com") and not user_email.endswith("@users.noreply.github.com"):
            await db.repositories.update_one(
                {"_id": repo["_id"]},
                {"$set": {"user_email": user_email}}
            )
            repo["user_email"] = user_email
        
        # Trigger scan
        access_token = os.getenv("GITHUB_ACCESS_TOKEN")
        if not access_token:
            logger.error("GitHub access token not configured")
            return {"message": "GitHub access token missing"}
        
        asyncio.create_task(scan_and_notify(str(repo["_id"]), repo["user_email"], access_token, repo_name))
        
        return {"message": "Scan triggered for repository push"}
        
    except Exception as e:
        logger.error(f"Error handling push event: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}

async def scan_and_notify(repo_id: str, user_email: str, access_token: str, repo_name: str):
    """Enhanced scanning and notification function"""
    db = await database.get_database()
    
    try:
        logger.info(f"Starting scan for repository: {repo_name}")
        
        # Update status to scanning
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"scan_status": "scanning", "last_scan_started": datetime.utcnow()}}
        )
        
        # Perform the scan
        scan_success, findings_count = await scan_repository_enhanced(repo_id, user_email, access_token)
        
        # Update status and send notification
        if scan_success:
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {"$set": {
                    "scan_status": "completed",
                    "findings_count": findings_count,
                    "last_scan_completed": datetime.utcnow()
                }}
            )
            
            logger.info(f"Scan completed successfully for {repo_name}. Findings: {findings_count}")
            
        else:
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {"$set": {
                    "scan_status": "failed",
                    "last_scan_completed": datetime.utcnow()
                }}
            )
            
            logger.error(f"Scan failed for {repo_name}")
            
    except Exception as e:
        logger.error(f"Scan and notify error for {repo_name}: {e}", exc_info=True)
        
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {
                "scan_status": "failed",
                "error_message": str(e),
                "last_scan_completed": datetime.utcnow()
            }}
        )

async def scan_repository_enhanced(repo_id: str, user_email: str, access_token: str) -> tuple[bool, int]:
    """Enhanced repository scanning with better error handling and email notifications"""
    
    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        
        if not repo:
            logger.error(f"Repository with ID {repo_id} not found")
            return False, 0
        
        repo_url = repo["repository_url"]
        repo_name = repo["repository_name"]
        
        if "github.com" not in repo_url:
            logger.error(f"Not a GitHub repository: {repo_url}")
            return False, 0
        
        # Extract owner and repo name from URL or repository_name
        if "/" in repo_name:
            owner, repo_short_name = repo_name.split("/", 1)
        else:
            # Fallback: extract from URL
            parts = repo_url.split("github.com/")[1].split("/")
            if len(parts) < 2:
                logger.error(f"Cannot parse repository URL: {repo_url}")
                return False, 0
            owner = parts[0]
            repo_short_name = parts[1].replace(".git", "")
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # Get repository information
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo_short_name}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(repo_info_url, headers=headers)
            
            if response.status_code == 404:
                logger.error(f"Repository not found or access denied: {owner}/{repo_short_name}")
                return False, 0
            elif response.status_code != 200:
                logger.error(f"Failed to get repository info: {response.status_code} - {response.text}")
                return False, 0
        
        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")
        
        logger.info(f"Scanning repository: {owner}/{repo_short_name}, branch: {default_branch}")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/git/trees/{default_branch}?recursive=1"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(tree_url, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get repository tree: {response.status_code} - {response.text}")
                return False, 0
        
        tree_data = response.json()
        
        # Filter for text files only
        def is_text_file(file_path: str) -> bool:
            text_extensions = [
                '.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go', 
                '.swift', '.kt', '.ts', '.html', '.css', '.json', '.yml', '.yaml', 
                '.toml', '.ini', '.cfg', '.md', '.txt', '.env', '.sh', '.bat', 
                '.ps1', '.sql', '.xml', '.csv', '.log', '.conf', '.config', '.dockerfile'
            ]
            return any(file_path.lower().endswith(ext) for ext in text_extensions)
        
        # Scan all text files
        all_findings = []
        scanned_files_count = 0
        
        for item in tree_data.get("tree", []):
            if item["type"] == "blob" and item.get("size", 0) > 0:
                file_path = item["path"]
                
                if not is_text_file(file_path):
                    continue
                
                # Skip large files (> 1MB)
                if item.get("size", 0) > 1024 * 1024:
                    logger.info(f"Skipping large file: {file_path}")
                    continue
                
                file_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/contents/{file_path}?ref={default_branch}"
                
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(file_url, headers=headers)
                        
                        if response.status_code != 200:
                            logger.warning(f"Failed to get file content: {file_path} - {response.status_code}")
                            continue
                    
                    file_data = response.json()
                    
                    if "content" not in file_data:
                        continue
                    
                    # Decode file content
                    try:
                        content = base64.b64decode(file_data["content"]).decode("utf-8")
                    except UnicodeDecodeError:
                        logger.warning(f"Cannot decode file as UTF-8: {file_path}")
                        continue
                    
                    # Scan for secrets
                    findings = detector.scan_text(content)
                    
                    for finding in findings:
                        finding["location"] = f"File: {file_path}"
                        finding["repository"] = repo_name
                        all_findings.append(finding)
                    
                    scanned_files_count += 1
                    
                    if findings:
                        logger.info(f"Found {len(findings)} potential secrets in {file_path}")
                
                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {e}")
                    continue
        
        logger.info(f"Scanned {scanned_files_count} files, found {len(all_findings)} potential secrets")
        
        # Create report
        report = await crud.create_report(
            user_email=user_email,
            repository_name=repo_name,
            findings=all_findings,
            scan_type="automatic"
        )
        
        # Update repository with scan results
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {
                "last_scan": datetime.utcnow(),
                "findings_count": len(all_findings),
                "scanned_files_count": scanned_files_count
            }}
        )
        
        # Send email notification
        try:
            if all_findings:
                await email_service.send_security_alert(
                    user_email,
                    f"🚨 Security Alert: {repo_name} - {len(all_findings)} secrets found",
                    all_findings,
                    str(report["_id"])
                )
                logger.info(f"Security alert sent to {user_email} for {len(all_findings)} findings in {repo_name}")
            else:
                await email_service.send_no_findings_alert(
                    user_email,
                    repo_name,
                    str(report["_id"])
                )
                logger.info(f"Clean scan notification sent to {user_email} for {repo_name}")
                
        except Exception as email_error:
            logger.error(f"Failed to send email notification: {email_error}")
            # Don't fail the scan if email fails
        
        return True, len(all_findings)
        
    except Exception as e:
        logger.error(f"Repository scan error: {e}", exc_info=True)
        return False, 0

# Helper functions for GitHub API integration

async def create_organization_webhook(org_name: str, webhook_url: str, webhook_secret: str, access_token: str) -> Dict[str, Any]:
    """Create an organization-level webhook to catch all repository events"""
    
    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        webhook_data = {
            "name": "web",
            "active": True,
            "events": [
                "repository",  # Repository created, deleted, etc.
                "push",        # Push events
                "pull_request" # Optional: PR events
            ],
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "secret": webhook_secret,
                "insecure_ssl": "0"
            }
        }
        
        url = f"https://api.github.com/orgs/{org_name}/hooks"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=webhook_data)
            
            if response.status_code == 201:
                webhook_info = response.json()
                logger.info(f"Organization webhook created successfully for {org_name}")
                return {"status": "success", "webhook_id": webhook_info["id"]}
            else:
                logger.error(f"Failed to create organization webhook: {response.status_code} - {response.text}")
                return {"status": "error", "error": response.text}
                
    except Exception as e:
        logger.error(f"Error creating organization webhook: {e}")
        return {"status": "error", "error": str(e)}

async def setup_organization_webhook(org_name: str) -> Dict[str, Any]:
    """Setup organization webhook for automatic repository detection"""
    
    access_token = os.getenv("GITHUB_ACCESS_TOKEN")
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    if not all([access_token, webhook_secret, base_url]):
        return {"status": "error", "error": "Missing required configuration"}
    
    webhook_url = f"{base_url}/github-webhook"
    
    return await create_organization_webhook(org_name, webhook_url, webhook_secret, access_token)

# Background task management
scan_queue = asyncio.Queue()

async def scan_worker():
    """Background worker to process scan queue"""
    while True:
        try:
            task = await scan_queue.get()
            repo_id = task["repo_id"]
            user_email = task["user_email"]
            access_token = task["access_token"]
            repo_name = task["repo_name"]
            
            await scan_and_notify(repo_id, user_email, access_token, repo_name)
            
        except Exception as e:
            logger.error(f"Scan worker error: {e}")
        finally:
            scan_queue.task_done()
            
## ADD this function to your existing github_integration.py

async def handle_user_repo_created(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle repository creation for individual users (not just organizations)"""
    try:
        repository = payload.get("repository", {})
        sender = payload.get("sender", {})
        
        repo_name = repository.get("full_name", "unknown")
        repo_url = repository.get("html_url", "")
        owner = repository.get("owner", {})
        owner_login = owner.get("login", "unknown")
        
        # For personal repos, we need to find the user by GitHub username
        user_email = sender.get("email")
        if not user_email:
            user_email = f"{owner_login}@users.noreply.github.com"
        
        logger.info(f"Processing personal repository creation: {repo_name} by {owner_login}")
        
        # Find user in database by GitHub username or email
        db = await database.get_database()
        
        # Try to find user by username first, then by email
        user = await db.users.find_one({
            "$or": [
                {"username": owner_login},
                {"email": user_email},
                {"provider_id": str(sender.get("id", ""))}
            ]
        })
        
        if not user:
            logger.warning(f"User not found for repository {repo_name}, owner: {owner_login}")
            return {"status": "user not found", "repo": repo_name}
        
        user_email = user["email"]
        
        # Check if repository already exists
        existing_repo = await db.repositories.find_one({
            "repository_name": repo_name,
            "user_email": user_email
        })
        
        if existing_repo:
            logger.info(f"Repository {repo_name} already exists in database")
            return {"status": "repository already exists", "repo_id": str(existing_repo["_id"])}
        
        # Add repository to database
        repo_data = {
            "user_email": user_email,
            "repository_name": repo_name,
            "repository_url": repo_url,
            "is_monitored": True,  # Auto-enable monitoring for new repos
            "added_at": datetime.utcnow(),
            "last_scan": None,
            "findings_count": 0,
            "scan_status": "pending",
            "is_private": repository.get("private", False),
            "owner_login": owner_login,
            "webhook_auto_created": True
        }
        
        result = await db.repositories.insert_one(repo_data)
        repo_id = str(result.inserted_id)
        
        logger.info(f"Repository {repo_name} added to database with ID: {repo_id}")
        
        # Get user's GitHub token for scanning
        github_token = user.get("github_access_token")
        if not github_token:
            logger.error(f"No GitHub token found for user {user_email}")
            return {"status": "error", "error": "GitHub token missing for user"}
        
        # Trigger automatic scan immediately in background
        asyncio.create_task(scan_and_notify(repo_id, user_email, github_token, repo_name))
        
        return {
            "status": "repository added and scan started", 
            "repo_id": repo_id,
            "repository": repo_name,
            "user_email": user_email
        }
        
    except Exception as e:
        logger.error(f"Error handling user repository creation: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}

async def start_scan_worker():
    """Start the background scan worker"""
    asyncio.create_task(scan_worker())
    logger.info("Scan worker started")
