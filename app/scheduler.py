
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Set
from . import database, email_service, detector
from bson import ObjectId
import httpx
import base64

logger = logging.getLogger(__name__)

class EventBasedRepoScanner:
    """Event-based repository scanner that only scans on new commits/repos"""
    
    def __init__(self):
        self.frozen_repos: Dict[str, datetime] = {}  # repo_id -> freeze_until_time
        self.scanning_locks: Set[str] = set()  # prevent duplicate scans
        self.freeze_duration = timedelta(minutes=15)  # 15 minute freeze
        self.email_delay = 10  # 10 seconds delay for email
        
    async def handle_repo_event(self, event_type: str, repo_data: dict, user_email: str):
        """
        Handle repository events (new repo created or commit pushed)
        
        Args:
            event_type: 'repository_created' or 'push'
            repo_data: GitHub repository data
            user_email: User email who owns the repo
        """
        try:
            repo_name = repo_data.get('full_name') or repo_data.get('name', 'Unknown Repo')
            repo_url = repo_data.get('html_url', '')
            
            logger.info(f"🎯 Received {event_type} event for repo: {repo_name}")
            
            if event_type == 'repository_created':
                # New repo created - always scan immediately
                await self._scan_new_repository(repo_data, user_email)
                
            elif event_type == 'push':
                # Push event to existing repo - check freeze status
                await self._handle_push_event(repo_data, user_email)
                
        except Exception as e:
            logger.error(f"Error handling repo event: {e}")
    
    async def _scan_new_repository(self, repo_data: dict, user_email: str):
        """Scan newly created repository immediately"""
        try:
            repo_name = repo_data.get('full_name') or repo_data.get('name')
            repo_url = repo_data.get('html_url', '')
            
            logger.info(f"🆕 Scanning NEW repository: {repo_name}")
            
            # Add to database if not exists
            db = await database.get_database()
            existing_repo = await db.repositories.find_one({
                "user_email": user_email,
                "repository_name": repo_name
            })
            
            if not existing_repo:
                repo_doc = {
                    "user_email": user_email,
                    "repository_name": repo_name,
                    "repository_url": repo_url,
                    "is_monitored": True,
                    "added_at": datetime.utcnow(),
                    "last_scan": None,
                    "findings_count": 0,
                    "scan_status": "pending"
                }
                result = await db.repositories.insert_one(repo_doc)
                repo_id = str(result.inserted_id)
            else:
                repo_id = str(existing_repo["_id"])
            
            # Scan immediately (no freeze check for new repos)
            await self._perform_scan_and_notify(repo_id, repo_name, user_email, "new_repository")
            
        except Exception as e:
            logger.error(f"Error scanning new repository: {e}")
    
    async def _handle_push_event(self, repo_data: dict, user_email: str):
        """Handle push event to existing repository with freeze logic"""
        try:
            repo_name = repo_data.get('full_name') or repo_data.get('name')
            
            # Find repo in database
            db = await database.get_database()
            repo = await db.repositories.find_one({
                "user_email": user_email,
                "repository_name": repo_name
            })
            
            if not repo:
                logger.warning(f"Repository {repo_name} not found in database, treating as new repo")
                await self._scan_new_repository(repo_data, user_email)
                return
            
            repo_id = str(repo["_id"])
            
            # Check if repo is frozen
            if self._is_repo_frozen(repo_id):
                remaining_time = self._get_freeze_remaining_time(repo_id)
                logger.info(f"❄️ Repository {repo_name} is FROZEN for {remaining_time.total_seconds():.0f} more seconds")
                return
            
            logger.info(f"🔄 Processing PUSH event for repository: {repo_name}")
            
            # Scan and freeze
            await self._perform_scan_and_notify(repo_id, repo_name, user_email, "push")
            self._freeze_repository(repo_id)
            
        except Exception as e:
            logger.error(f"Error handling push event: {e}")
    
    async def _perform_scan_and_notify(self, repo_id: str, repo_name: str, user_email: str, scan_type: str):
        """Perform actual scanning and email notification"""
        try:
            # Prevent duplicate scans
            if repo_id in self.scanning_locks:
                logger.info(f"⏳ Scan already in progress for {repo_name}")
                return
            
            self.scanning_locks.add(repo_id)
            
            try:
                # Update scan status
                db = await database.get_database()
                await db.repositories.update_one(
                    {"_id": ObjectId(repo_id)},
                    {"$set": {"scan_status": "scanning", "last_scan_started": datetime.utcnow()}}
                )
                
                # Get GitHub access token
                user = await db.users.find_one({"email": user_email})
                access_token = None
                if user and "github_access_token" in user:
                    access_token = user["github_access_token"]
                else:
                    # Try to get from environment as fallback
                    import os
                    access_token = os.getenv("GITHUB_ACCESS_TOKEN")
                
                if not access_token:
                    logger.error(f"No GitHub access token found for user {user_email}")
                    return
                
                # Perform the actual scan
                findings = await self._scan_repository_content(repo_name, access_token, user_email)
                
                # Create report
                from . import crud
                report = await crud.create_report(
                    user_email=user_email,
                    repository_name=repo_name,
                    findings=findings,
                    scan_type=scan_type
                )
                
                # Update repository with scan results
                await db.repositories.update_one(
                    {"_id": ObjectId(repo_id)},
                    {"$set": {
                        "last_scan": datetime.utcnow(),
                        "findings_count": len(findings),
                        "scan_status": "completed"
                    }}
                )
                
                logger.info(f"✅ Scan completed for {repo_name}: {len(findings)} findings detected")
                
                # Wait 10 seconds then send email notification
                logger.info(f"⏰ Waiting {self.email_delay} seconds before sending email notification...")
                await asyncio.sleep(self.email_delay)
                
                # Send email notification
                try:
                    if findings:
                        await email_service.send_security_alert(
                            user_email,
                            f"🚨 Security Alert: {repo_name} - {len(findings)} secrets found",
                            findings,
                            str(report["_id"])
                        )
                        logger.info(f"📧 Security alert email sent to {user_email}")
                    else:
                        await email_service.send_no_findings_alert(
                            user_email,
                            repo_name,
                            str(report["_id"])
                        )
                        logger.info(f"📧 No-findings email sent to {user_email}")
                        
                except Exception as email_error:
                    logger.error(f"Failed to send email notification: {email_error}")
                
            finally:
                self.scanning_locks.discard(repo_id)
                
        except Exception as e:
            logger.error(f"Error in scan and notify: {e}")
            # Remove from scanning locks on error
            self.scanning_locks.discard(repo_id)
    
    async def _scan_repository_content(self, repo_name: str, access_token: str, user_email: str):
        """Scan repository content for secrets"""
        try:
            # Parse owner/repo from full name
            if "/" in repo_name:
                owner, repo_short_name = repo_name.split("/", 1)
            else:
                # Fallback - assume current user is owner
                owner = user_email.split("@")[0]
                repo_short_name = repo_name
            
            headers = {"Authorization": f"Bearer {access_token}"}
            
            # Get repository information
            repo_info_url = f"https://api.github.com/repos/{owner}/{repo_short_name}"
            async with httpx.AsyncClient() as client:
                response = await client.get(repo_info_url, headers=headers)
                if response.status_code != 200:
                    logger.error(f"Failed to get repo info: {response.status_code}")
                    return []
            
            repo_info = response.json()
            default_branch = repo_info.get("default_branch", "main")
            
            # Get repository tree
            tree_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/git/trees/{default_branch}?recursive=1"
            async with httpx.AsyncClient() as client:
                response = await client.get(tree_url, headers=headers)
                if response.status_code != 200:
                    logger.error(f"Failed to get repo tree: {response.status_code}")
                    return []
            
            tree_data = response.json()
            
            # Scan files
            all_findings = []
            text_extensions = ['.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', 
                              '.rb', '.go', '.swift', '.kt', '.ts', '.html', '.css',
                              '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg',
                              '.md', '.txt', '.env', '.sh', '.bat', '.ps1', '.sql']
            
            for item in tree_data.get("tree", []):
                if item["type"] == "blob" and item.get("size", 0) > 0:
                    file_path = item["path"]
                    
                    # Check if it's a text file
                    if not any(file_path.lower().endswith(ext) for ext in text_extensions):
                        continue
                    
                    # Skip large files
                    if item.get("size", 0) > 1024 * 1024:  # 1MB limit
                        continue
                    
                    # Get file content
                    file_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/contents/{file_path}?ref={default_branch}"
                    try:
                        async with httpx.AsyncClient() as client:
                            response = await client.get(file_url, headers=headers)
                            if response.status_code != 200:
                                continue
                        
                        file_data = response.json()
                        if "content" not in file_data:
                            continue
                        
                        # Decode content
                        content = base64.b64decode(file_data["content"]).decode("utf-8")
                        
                        # Scan for secrets
                        findings = await detector.scan_text(content, user_email)
                        for finding in findings:
                            finding["location"] = f"File: {file_path}"
                            finding["repository"] = repo_name
                            all_findings.append(finding)
                            
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path}: {e}")
                        continue
            
            return all_findings
            
        except Exception as e:
            logger.error(f"Error scanning repository content: {e}")
            return []
    
    def _is_repo_frozen(self, repo_id: str) -> bool:
        """Check if repository is currently frozen"""
        if repo_id not in self.frozen_repos:
            return False
        
        freeze_until = self.frozen_repos[repo_id]
        current_time = datetime.utcnow()
        
        if current_time >= freeze_until:
            # Freeze period expired, remove from frozen list
            del self.frozen_repos[repo_id]
            return False
        
        return True
    
    def _get_freeze_remaining_time(self, repo_id: str) -> timedelta:
        """Get remaining freeze time for repository"""
        if repo_id not in self.frozen_repos:
            return timedelta(0)
        
        freeze_until = self.frozen_repos[repo_id]
        current_time = datetime.utcnow()
        
        remaining = freeze_until - current_time
        return remaining if remaining.total_seconds() > 0 else timedelta(0)
    
    def _freeze_repository(self, repo_id: str):
        """Freeze repository for 15 minutes"""
        freeze_until = datetime.utcnow() + self.freeze_duration
        self.frozen_repos[repo_id] = freeze_until
        
        logger.info(f"❄️ Repository {repo_id} FROZEN until {freeze_until.strftime('%H:%M:%S')}")
    
    async def cleanup_expired_freezes(self):
        """Clean up expired freeze entries (optional maintenance)"""
        current_time = datetime.utcnow()
        expired_repos = []
        
        for repo_id, freeze_until in self.frozen_repos.items():
            if current_time >= freeze_until:
                expired_repos.append(repo_id)
        
        for repo_id in expired_repos:
            del self.frozen_repos[repo_id]
            logger.info(f"🔓 Repository {repo_id} freeze expired and removed")

# Global scanner instance
event_scanner = EventBasedRepoScanner()

async def handle_repository_event(event_type: str, repo_data: dict, user_email: str):
    """Public function to handle repository events"""
    await event_scanner.handle_repo_event(event_type, repo_data, user_email)

def start_background_scheduler():
    """Start minimal background services (NO polling)"""
    logger.info("🚀 Event-based scanner initialized - NO POLLING!")
    return None

def stop_background_scheduler(scheduler):
    """Stop background services"""
    logger.info("🔄 Event-based scanner stopped")
    return None
