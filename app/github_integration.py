# Enhanced GitHub Integration with Event-Based Scanning
# Place this file as: app/github_integration.py

import asyncio
import logging
import httpx
import hmac
import hashlib
import json
import os
from fastapi import Request, HTTPException
from datetime import datetime
from . import database
from .scheduler import handle_repository_event

logger = logging.getLogger(__name__)

async def handle_webhook(request: Request):
    """
    Handle GitHub webhook events for repository creation and pushes
    This replaces the polling mechanism with event-driven scanning
    """
    try:
        # Get webhook payload
        payload = await request.body()
        
        # Verify webhook signature (security)
        webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        if webhook_secret:
            signature = request.headers.get("X-Hub-Signature-256", "")
            if not verify_webhook_signature(payload, signature, webhook_secret):
                logger.warning("Invalid webhook signature")
                raise HTTPException(status_code=403, detail="Invalid signature")
        
        # Parse event data
        event_type = request.headers.get("X-GitHub-Event")
        payload_data = json.loads(payload.decode("utf-8"))
        
        logger.info(f"🎯 Received GitHub webhook: {event_type}")
        
        # Handle different event types
        if event_type == "repository":
            await handle_repository_webhook(payload_data)
        elif event_type == "push":
            await handle_push_webhook(payload_data)
        elif event_type == "ping":
            logger.info("📡 Webhook ping received - connection successful")
        else:
            logger.info(f"ℹ️ Unhandled webhook event: {event_type}")
        
        return {"status": "success", "event": event_type}
        
    except Exception as e:
        logger.error(f"Webhook handling error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

async def handle_repository_webhook(payload_data: dict):
    """Handle repository creation/deletion events"""
    try:
        action = payload_data.get("action")
        repository = payload_data.get("repository", {})
        sender = payload_data.get("sender", {})
        
        if action == "created":
            # New repository created
            logger.info(f"🆕 New repository created: {repository.get('full_name')}")
            
            # Find user by GitHub ID
            github_id = str(sender.get("id"))
            user_email = await get_user_email_by_github_id(github_id)
            
            if user_email:
                # Trigger event-based scan
                await handle_repository_event("repository_created", repository, user_email)
            else:
                logger.warning(f"User not found for GitHub ID: {github_id}")
                
        elif action == "deleted":
            logger.info(f"🗑️ Repository deleted: {repository.get('full_name')}")
            # Handle repository deletion if needed
            
    except Exception as e:
        logger.error(f"Repository webhook error: {e}")

async def handle_push_webhook(payload_data: dict):
    """Handle push events (commits)"""
    try:
        repository = payload_data.get("repository", {})
        pusher = payload_data.get("pusher", {})
        commits = payload_data.get("commits", [])
        
        repo_name = repository.get("full_name")
        logger.info(f"🔄 Push event received for repo: {repo_name}, commits: {len(commits)}")
        
        # Skip if no commits (e.g., branch deletion)
        if not commits:
            logger.info("No commits in push event, skipping scan")
            return
        
        # Find user by repository
        user_email = await get_user_email_by_repository(repo_name)
        
        if user_email:
            # Trigger event-based scan with freeze logic
            await handle_repository_event("push", repository, user_email)
        else:
            logger.warning(f"User not found for repository: {repo_name}")
            
    except Exception as e:
        logger.error(f"Push webhook error: {e}")

async def get_user_email_by_github_id(github_id: str) -> str:
    """Get user email by GitHub ID"""
    try:
        db = await database.get_database()
        user = await db.users.find_one({"provider_id": github_id, "provider": "github"})
        return user["email"] if user else None
    except Exception as e:
        logger.error(f"Error getting user by GitHub ID: {e}")
        return None

async def get_user_email_by_repository(repo_name: str) -> str:
    """Get user email by repository name"""
    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"repository_name": repo_name})
        return repo["user_email"] if repo else None
    except Exception as e:
        logger.error(f"Error getting user by repository: {e}")
        return None

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature for security"""
    try:
        if not signature.startswith("sha256="):
            return False
        
        expected_signature = "sha256=" + hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False

async def setup_organization_webhook(org_name: str, webhook_url: str = None):
    """Setup webhook for GitHub organization (optional helper function)"""
    try:
        if not webhook_url:
            base_url = os.getenv("BASE_URL", "https://your-domain.com")
            webhook_url = f"{base_url}/github-webhook"
        
        github_token = os.getenv("GITHUB_ACCESS_TOKEN")
        if not github_token:
            return {"status": "error", "error": "GitHub access token not configured"}
        
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        webhook_config = {
            "name": "web",
            "active": True,
            "events": ["repository", "push"],
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "secret": os.getenv("GITHUB_WEBHOOK_SECRET", "")
            }
        }
        
        url = f"https://api.github.com/orgs/{org_name}/hooks"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=webhook_config)
            
            if response.status_code == 201:
                webhook_data = response.json()
                logger.info(f"✅ Webhook created for organization: {org_name}")
                return {
                    "status": "success",
                    "webhook_id": webhook_data["id"],
                    "webhook_url": webhook_url
                }
            else:
                logger.error(f"Failed to create webhook: {response.status_code} - {response.text}")
                return {
                    "status": "error",
                    "error": f"GitHub API error: {response.status_code}"
                }
                
    except Exception as e:
        logger.error(f"Webhook setup error: {e}")
        return {"status": "error", "error": str(e)}

# Legacy function for backward compatibility - now does nothing
async def start_scan_worker():
    """Legacy function - no longer needed with event-based scanning"""
    logger.info("🚀 Event-based scanning enabled - no background worker needed")
    pass

# Legacy function for backward compatibility - now does nothing  
async def scan_and_notify(repo_id: str, user_email: str):
    """Legacy function - scanning now handled by webhook events"""
    logger.info("ℹ️ scan_and_notify called - use event-based scanning instead")
    pass

# Manual scan function (for testing or manual triggers)
async def manual_scan_repository(repo_id: str, user_email: str):
    """Manually trigger a repository scan (bypass freeze logic)"""
    try:
        from .scheduler import event_scanner
        
        # Get repository data
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        
        if not repo:
            logger.error(f"Repository not found: {repo_id}")
            return False
        
        # Create fake repo data for manual scan
        repo_data = {
            "full_name": repo["repository_name"],
            "name": repo["repository_name"],
            "html_url": repo["repository_url"]
        }
        
        # Perform scan without freeze check
        await event_scanner._perform_scan_and_notify(
            repo_id, 
            repo["repository_name"], 
            user_email, 
            "manual"
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Manual scan error: {e}")
        return False
