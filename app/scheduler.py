# app/scheduler.py - NEW FILE TO ADD
# This file handles background polling for new repositories

import asyncio
import httpx
import os
import logging
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from . import crud, database, github_integration

logger = logging.getLogger(__name__)

async def poll_user_repos():
    """
    Background task to check for new repositories for all users
    This runs periodically to detect new repos and trigger automatic scans
    """
    try:
        logger.info("Starting user repository polling...")
        
        db = await database.get_database()
        
        # Get all users who have GitHub tokens
        users = await db.users.find({}).to_list(None)
        
        if not users:
            logger.info("No users found to poll")
            return
        
        scanned_count = 0
        new_repos_found = 0
        
        for user in users:
            try:
                user_email = user.get("email")
                logger.info(f"Polling repositories for user: {user_email}")
                
                # Try to get GitHub token from user session/database
                # Note: You'll need to store the GitHub token when user logs in
                github_token = user.get("github_access_token")
                
                if not github_token:
                    # Try to get from a separate tokens collection if you store it there
                    token_doc = await db.user_tokens.find_one({"user_email": user_email})
                    if token_doc:
                        github_token = token_doc.get("github_access_token")
                
                if not github_token:
                    logger.warning(f"No GitHub token found for user {user_email}")
                    continue
                
                # Fetch user's repositories from GitHub API
                headers = {
                    "Authorization": f"token {github_token}",
                    "Accept": "application/vnd.github+json"
                }
                
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        "https://api.github.com/user/repos?per_page=100&sort=created&direction=desc",
                        headers=headers
                    )
                
                if response.status_code != 200:
                    logger.error(f"Failed to fetch repos for {user_email}: {response.status_code}")
                    continue
                
                repos = response.json()
                logger.info(f"Found {len(repos)} repositories for user {user_email}")
                
                # Check each repository
                for repo_data in repos:
                    full_name = repo_data["full_name"]
                    html_url = repo_data["html_url"]
                    is_private = repo_data.get("private", False)
                    created_at = repo_data.get("created_at")
                    
                    # Check if this repository is already in our database
                    existing_repo = await db.repositories.find_one({
                        "user_email": user_email,
                        "repository_name": full_name
                    })
                    
                    if not existing_repo:
                        # This is a new repository!
                        logger.info(f"New repository detected: {full_name} for user {user_email}")
                        
                        # Add repository to database
                        repo_doc = await crud.add_repository(
                            user_email=user_email,
                            repo_name=full_name,
                            repo_url=html_url,
                            is_monitored=True
                        )
                        
                        new_repos_found += 1
                        
                        # Trigger automatic scan for the new repository
                        repo_id = str(repo_doc["_id"])
                        
                        # Use the user's GitHub token for scanning
                        asyncio.create_task(
                            github_integration.scan_and_notify(
                                repo_id, user_email, github_token, full_name
                            )
                        )
                        
                        logger.info(f"Triggered automatic scan for new repo: {full_name}")
                
                scanned_count += 1
                
            except Exception as e:
                logger.error(f"Error polling repos for user {user.get('email', 'unknown')}: {e}")
                continue
        
        logger.info(f"Repository polling completed. Scanned {scanned_count} users, found {new_repos_found} new repositories")
        
    except Exception as e:
        logger.error(f"Error in poll_user_repos: {e}")

async def cleanup_old_scans():
    """
    Optional: Clean up old scan results or failed scans
    """
    try:
        db = await database.get_database()
        
        # Clean up failed scans older than 24 hours
        from datetime import datetime, timedelta
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        result = await db.repositories.update_many(
            {
                "scan_status": "failed",
                "last_scan_completed": {"$lt": cutoff_time}
            },
            {
                "$set": {"scan_status": "pending"}
            }
        )
        
        if result.modified_count > 0:
            logger.info(f"Reset {result.modified_count} failed scans to pending")
            
    except Exception as e:
        logger.error(f"Error in cleanup_old_scans: {e}")

def start_background_scheduler():
    """
    Start the background scheduler for polling repositories
    """
    scheduler = AsyncIOScheduler()
    
    # Poll for new repositories every 30 minutes
    scheduler.add_job(
        poll_user_repos,
        "interval",
        minutes=30,
        id="poll_user_repos",
        max_instances=1,  # Prevent overlapping runs
        replace_existing=True
    )
    
    # Clean up old scans every 6 hours
    scheduler.add_job(
        cleanup_old_scans,
        "interval",
        hours=6,
        id="cleanup_old_scans",
        max_instances=1,
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Background scheduler started")
    
    return scheduler

def stop_background_scheduler(scheduler):
    """
    Stop the background scheduler
    """
    if scheduler:
        scheduler.shutdown()
        logger.info("Background scheduler stopped")
