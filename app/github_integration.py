import hashlib
import hmac
import json
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

async def handle_webhook(request: Request) -> Dict[str, Any]:
    """Simplified and reliable webhook handling"""
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

        # Handle repository creation
        if event_type == "repository" and payload.get("action") in ["created", "publicized"]:
            return await handle_repo_created(payload)

        # Handle push events
        elif event_type == "push":
            return await handle_push_event(payload)

        return {"message": f"Event type '{event_type}' not handled"}

    except Exception as e:
        logger.error(f"Webhook error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Webhook processing failed")
    # Add case for repository deletion
    if event_type == "repository" and action == "deleted":
        return await handle_repo_deleted(payload)
    
async def handle_repo_deleted(payload: Dict[str, Any]):
    """Handle repository deletion event"""
    try:
        repository = payload.get("repository", {})
        repo_name = repository.get("full_name", "unknown")
        
        db = await database.get_database()
        result = await db.repositories.delete_one(
            {"repository_name": repo_name}
        )
        
        # Automatically stop any scheduled scans
        # (Implementation depends on your scheduler)
        
        return {"status": "repository removed", "deleted_count": result.deleted_count}
    except Exception as e:
        logger.error(f"Error deleting repository: {e}")
        return {"status": "error", "error": str(e)}

async def handle_repo_created(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Direct repository scanning without queues"""
    try:
        repository = payload.get("repository", {})
        sender = payload.get("sender", {})
        
        repo_name = repository.get("full_name", "unknown")
        repo_url = repository.get("html_url", "")
        owner = sender.get("login", "unknown")
        user_email = sender.get("email", f"{owner}@users.noreply.github.com")
        
        # Add repository to database
        db = await database.get_database()
        repo_data = {
            "user_email": user_email,
            "repository_name": repo_name,
            "repository_url": repo_url,
            "is_monitored": True,
            "added_at": datetime.utcnow(),
            "last_scan": None,
            "findings_count": 0,
            "scan_status": "scanning"
        }
        
        result = await db.repositories.insert_one(repo_data)
        repo_id = str(result.inserted_id)
        
        # Perform scan immediately
        access_token = os.getenv("GITHUB_ACCESS_TOKEN")
        if not access_token:
            logger.error("GitHub access token not configured")
            return {"status": "error", "error": "GitHub access token missing"}
        
        asyncio.create_task(scan_and_notify(repo_id, user_email, access_token, repo_name))
        
        return {"status": "repository added and scan started", "repo_id": repo_id}
    except Exception as e:
        logger.error(f"Error adding repository: {e}")
        return {"status": "error", "error": str(e)}
    
async def scan_worker():
    """Background worker to process scan queue"""
    while True:
        try:
            task = await scan_queue.get()
            repo_id = task["repo_id"]
            user_email = task["user_email"]
            installation_id = task["installation_id"]
            
            # Get installation token
            access_token = await get_installation_token(installation_id)
            if not access_token:
                access_token = os.getenv("GITHUB_ACCESS_TOKEN")
            
            # Perform scan
            await scan_repository(repo_id, user_email, access_token)
            
        except Exception as e:
            logger.error(f"Scan worker error: {e}")
        finally:
            scan_queue.task_done()   
    
async def get_installation_token(installation_id: int) -> str:
    """Get installation access token for better permissions"""
    if not installation_id:
        return None
        
    try:
        jwt_token = generate_jwt_token()
        if not jwt_token:
            return None
            
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers)
            if response.status_code == 201:
                token_data = response.json()
                return token_data.get("token")
            else:
                logger.error(f"Failed to get installation token: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error getting installation token: {e}")
    return None


def generate_jwt_token() -> str:
    """Generate JWT token for GitHub App authentication"""
    try:
        # Load GitHub App credentials
        app_id = os.getenv("GITHUB_APP_ID")
        private_key = os.getenv("GITHUB_APP_PRIVATE_KEY")
        
        if not app_id or not private_key:
            logger.error("GitHub App credentials not configured")
            return None
            
        # Generate JWT token
        from jwt import encode
        from time import time
        
        payload = {
            "iat": int(time()),
            "exp": int(time()) + 600,  # 10 minutes expiration
            "iss": app_id
        }
        
        return encode(payload, private_key, algorithm="RS256")
        
    except Exception as e:
        logger.error(f"Error generating JWT token: {e}")
        return None


# Start scan worker on application startup
async def start_scan_worker():
    asyncio.create_task(scan_worker())

async def scan_and_notify(repo_id: str, user_email: str, access_token: str, repo_name: str):
    """Unified scanning and notification function"""
    db = await database.get_database()
    try:
        # Update status to scanning
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"scan_status": "scanning"}}
        )
        
        # Perform the scan
        scan_success, findings_count = await scan_repository(repo_id, user_email, access_token)
        
        # Update status and send notification
        if scan_success:
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {"$set": {
                    "scan_status": "completed",
                    "findings_count": findings_count
                }}
            )
            # Send notification email
            await email_service.send_scan_notification(
                user_email,
                repo_name,
                True,
                findings_count
            )
        else:
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {"$set": {"scan_status": "failed"}}
            )
            # Send failure email
            await email_service.send_scan_notification(
                user_email,
                repo_name,
                False,
                0
            )
            
    except Exception as e:
        logger.error(f"Scan and notify error: {e}")
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"scan_status": "failed"}}
        )


async def scan_repository(repo_id: str, user_email: str, access_token: str) -> (bool, int):
    """Simplified scanning function returns success and findings count"""
    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        if not repo:
            return False, 0
            
        repo_url = repo["repository_url"]
        if "github.com" not in repo_url:
            return False, 0
            
        parts = repo_url.split("github.com/")[1].split("/")
        if len(parts) < 2:
            return False, 0
            
        owner = parts[0]
        repo_name = parts[1]
        
        # Get default branch
        headers = {"Authorization": f"Bearer {access_token}"}
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo_name}"
        async with httpx.AsyncClient() as client:
            response = await client.get(repo_info_url, headers=headers)
            if response.status_code != 200:
                return False, 0
            repo_info = response.json()
            default_branch = repo_info.get("default_branch", "main")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{default_branch}?recursive=1"
        async with httpx.AsyncClient() as client:
            response = await client.get(tree_url, headers=headers)
            if response.status_code != 200:
                return False, 0
            tree_data = response.json()
        
        # Scan all files
        all_findings = []
        for item in tree_data.get("tree", []):
            if item["type"] != "blob" or item["size"] <= 0:
                continue
                
            file_path = item["path"]
            if any(file_path.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bin', '.zip']):
                continue
                
            file_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/{file_path}?ref={default_branch}"
            async with httpx.AsyncClient() as client:
                response = await client.get(file_url, headers=headers)
                if response.status_code != 200:
                    continue
                
                file_data = response.json()
                if "content" not in file_data:
                    continue
                
                try:
                    content = base64.b64decode(file_data["content"]).decode("utf-8")
                    findings = detector.scan_text(content)
                    for finding in findings:
                        finding["location"] = f"File: {file_path}"
                        all_findings.append(finding)
                except Exception:
                    continue
        
        # Create report
        report = await crud.create_report(
            user_email=user_email,
            repository_name=repo["repository_name"],
            findings=all_findings,
            scan_type="automatic"
        )
        
        # Update last scan time
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"last_scan": datetime.utcnow()}}
        )
        
        # Send security alert
        if all_findings:
            await email_service.send_security_alert(
                user_email,
                f"Security Alert for {repo['repository_name']}",
                all_findings,
                str(report["_id"])
                
            )
        else:
            await email_service.send_no_findings_alert(
                user_email,
                repo["repository_name"],
                str(report["_id"])
                
            )
        
        return True, len(all_findings)
        
    except Exception as e:
        logger.error(f"Repository scan error: {e}")
        return False, 0


async def handle_push_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Trigger scan on push events"""
    repository = payload.get("repository", {})
    sender = payload.get("sender", {})
    
    repo_name = repository.get("full_name", "unknown")
    owner = repository.get("owner", {}).get("login", "unknown")
    user_email = sender.get("email", f"{owner}@users.noreply.github.com")
    
    # Find repository in database
    db = await database.get_database()
    repo = await db.repositories.find_one({
        "repository_name": repo_name,
        "user_email": user_email,
        "is_monitored": True
    })
    
    if not repo:
        return {"message": "Repository not monitored"}
    
    # Trigger scan
    access_token = os.getenv("GITHUB_ACCESS_TOKEN")
    if not access_token:
        return {"message": "GitHub access token missing"}
    
    asyncio.create_task(scan_and_notify(str(repo["_id"]), user_email, access_token, repo_name))
    
    return {"message": "Scan triggered for repository"}

async def scan_commit(commit: Dict[str, Any], repo_name: str, owner: str) -> list:
    """Scan a single commit for secrets"""
    findings = []
    
    # Get commit details
    commit_id = commit.get("id", "")
    commit_message = commit.get("message", "")
    added_files = commit.get("added", [])
    modified_files = commit.get("modified", [])
    removed_files = commit.get("removed", [])
    
    # Scan commit message
    message_findings = detector.scan_text(commit_message)
    for finding in message_findings:
        finding["location"] = f"Commit message: {commit_id[:8]}"
        findings.append(finding)
    
    # Scan files using GitHub API
    access_token = os.getenv("GITHUB_ACCESS_TOKEN", os.getenv("GITHUB_CLIENT_SECRET"))
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    all_files = added_files + modified_files
    for file_path in all_files:
        try:
            # Skip binary files
            if any(ext in file_path for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bin']):
                continue
                
            # Fetch file content
            file_url = f"https://api.github.com/repos/{repo_name}/contents/{file_path}?ref={commit_id}"
            async with httpx.AsyncClient() as client:
                response = await client.get(file_url, headers=headers)
                if response.status_code != 200:
                    continue
                    
                file_data = response.json()
                if "content" not in file_data:
                    continue
                    
                # Decode content
                content = base64.b64decode(file_data["content"]).decode("utf-8")
                
                # Scan content
                content_findings = detector.scan_text(content)
                for finding in content_findings:
                    finding["location"] = f"File: {file_path}"
                    findings.append(finding)
        except Exception as e:
            print(f"Error scanning file {file_path}: {str(e)}")
    
    return findings
