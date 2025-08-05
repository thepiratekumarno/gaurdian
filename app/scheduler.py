
import asyncio
import httpx
import os
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from bson import ObjectId
import base64
import hashlib

# Import your app modules
from . import crud, database, email_service as email_service, detector

logger = logging.getLogger(__name__)

def should_skip_directory(dir_path: str) -> bool:
    """Check if directory should be skipped during scanning"""
    skip_dirs = [
        'node_modules', 'vendor', '.git', '.svn', '.hg', 'dist', 'build',
        '__pycache__', '.pytest_cache', '.cache', 'coverage', '.nyc_output',
        'logs', 'log', 'tmp', 'temp', '.tmp', '.temp', 'uploads', 'downloads',
        '.vscode', '.idea', '.vs', 'bin', 'obj', 'packages', 'bower_components',
        '.next', '.nuxt', 'out', 'public/assets', 'static/assets', 'assets/vendor',
        'venv','virtualenv', '.virtualenv', 'conda-meta',
        'site-packages', 'Lib/site-packages', '.tox', '.nox', 'htmlcov'
    ]
    
    # Check if any part of the path contains skip directories
    path_parts = dir_path.lower().split('/')
    return any(skip_dir in path_parts for skip_dir in skip_dirs)

def is_binary_file(file_path: str) -> bool:
    """Check if file is binary based on extension"""
    binary_exts = [
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.ico', '.svg',
        # Videos
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv', '.m4v',
        # Audio
        '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a',
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.z',
        # Executables
        '.exe', '.dll', '.so', '.dylib', '.app', '.deb', '.rpm', '.msi',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp',
        # Fonts
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        # Other binary
        '.bin', '.dat', '.db', '.sqlite', '.sqlite3', '.pyc', '.pyo', '.class',
        '.o', '.obj', '.lib', '.a', '.jar', '.war', '.ear'
    ]
    return any(file_path.lower().endswith(ext) for ext in binary_exts)

def is_scannable_file(file_path: str) -> bool:
    """Check if file should be scanned for secrets"""
    # Files we want to scan
    scannable_exts = [
        # Code files
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cs', '.php',
        '.rb', '.go', '.swift', '.kt', '.scala', '.rs', '.dart', '.lua', '.perl', '.pl',
        '.r', '.matlab', '.m', '.vb', '.vbs', '.ps1', '.sh', '.bash', '.zsh', '.fish',
        # Config files
        '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.config', '.xml',
        '.properties', '.env', '.environment', '.settings', '.plist',
        # Web files
        '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte',
        # Data files
        '.csv', '.tsv', '.sql', '.graphql', '.gql',
        # Documentation and text
        '.md', '.txt', '.rst', '.adoc', '.tex',
        # Other important files
        '.dockerfile', '.makefile', '.cmake', '.gradle', '.maven', '.sbt',
        '.requirements', '.pipfile', '.gemfile', '.package', '.composer'
    ]
    
    # Check extension
    has_scannable_ext = any(file_path.lower().endswith(ext) for ext in scannable_exts)
    
    # Check for important files without extensions
    filename = os.path.basename(file_path).lower()
    important_files = [
        'dockerfile', 'makefile', 'rakefile', 'gemfile', 'pipfile',
        'requirements.txt', 'package.json', 'composer.json', 'pom.xml',
        'build.gradle', 'cargo.toml', '.env', '.environment', '.config'
    ]
    has_important_name = filename in important_files
    
    return has_scannable_ext or has_important_name

def is_large_file(file_size: int) -> bool:
    """Check if file is too large to scan (over 500KB)"""
    return file_size > 500 * 1024  # 500KB limit

async def discover_user_repositories(user_email: str, github_token: str, is_new_user: bool = False):
    """
    Discover and store user repositories WITHOUT automatically scanning them
    For new users, just fetch and store repo info, don't trigger scans
    """
    try:
        db = await database.get_database()
        
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecretGuardian/1.0"
        }
        
        # Get user's repositories
        url = "https://api.github.com/user/repos?per_page=100&sort=updated&direction=desc"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"❌ Failed to fetch repos for {user_email}: {response.status_code}")
            return 0
        
        repos = response.json()
        new_repos_added = 0
        
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
                
                # Check if this repository already exists in our database
                existing_repo = await db.repositories.find_one({
                    "user_email": user_email,
                    "repository_name": full_name
                })
                
                if not existing_repo:
                    # Add new repository WITHOUT scanning it automatically
                    repo_doc = {
                        "user_email": user_email,
                        "repository_name": full_name,
                        "repository_url": html_url,
                        "is_monitored": True,
                        "added_at": datetime.utcnow(),
                        "last_scan": None,
                        "findings_count": 0,
                        "scan_status": "idle",  # Don't scan automatically
                        "is_private": is_private,
                        "auto_detected": True,
                        "github_updated_at": datetime.fromisoformat(updated_at.replace('Z', '+00:00')),
                        "github_pushed_at": github_pushed_time,
                        "last_known_push": pushed_at,
                        "scan_frozen_until": None,
                        "commits_during_freeze": 0,
                        # Email deduplication fields
                        "last_emailed_push": None,
                        "last_email_sent_at": None,
                        "email_batch_commits": [],
                        # Mark as discovered for new user (not to be auto-scanned)
                        "discovered_for_new_user": is_new_user,
                        "initial_discovery": is_new_user
                    }
                    
                    try:
                        result = await db.repositories.insert_one(repo_doc)
                        logger.info(f"📋 Discovered repository: {full_name} (not auto-scanned)")
                        new_repos_added += 1
                    except Exception as insert_error:
                        logger.error(f"❌ Failed to insert discovered repository {full_name}: {insert_error}")
                        continue
            
            except Exception as repo_error:
                logger.error(f"❌ Error processing repository discovery {repo_data.get('full_name', 'unknown')}: {repo_error}")
                continue
        
        # Send welcome email for new users
        if is_new_user and new_repos_added > 0:
            # Get username from GitHub API
            user_info_url = "https://api.github.com/user"
            async with httpx.AsyncClient(timeout=30.0) as client:
                user_response = await client.get(user_info_url, headers=headers)
            
            username = user_email.split('@')[0]  # fallback
            if user_response.status_code == 200:
                user_info = user_response.json()
                username = user_info.get('login', username)
            
            await email_service.send_welcome_email_for_new_user(
                user_email=user_email,
                username=username,
                repos_count=new_repos_added
            )
        
        logger.info(f"📋 Repository discovery completed for {user_email}: {new_repos_added} new repositories found")
        return new_repos_added
        
    except Exception as e:
        logger.error(f"❌ Error in discover_user_repositories: {e}")
        return 0

async def poll_user_repos():
    """
    FINAL VERSION: Monitor repositories for changes WITHOUT auto-scanning new user repos
    - Discovers new repositories for new users without scanning
    - Only scans when there are actual commits/changes
    - Uses secure email notifications with URLs only
    """
    try:
        logger.info("🚀 Starting repository monitoring (no auto-scan for new users)...")
        
        db = await database.get_database()
        
        # Get all users who have GitHub tokens stored
        users = await db.users.find({
            "github_access_token": {"$exists": True, "$ne": None}
        }).to_list(None)
        
        if not users:
            logger.info("📭 No users with GitHub tokens found")
            return
        
        logger.info(f"👥 Found {len(users)} users with GitHub tokens")
        new_repos_discovered = 0
        repos_scanned = 0
        repos_frozen = 0
        repos_locked = 0
        
        for user in users:
            try:
                user_email = user.get("email")
                github_token = user.get("github_access_token")
                
                if not github_token:
                    logger.warning(f"⚠️ No GitHub token for user {user_email}")
                    continue
                
                logger.info(f"🔍 Checking repos for user: {user_email}")
                
                # Check if this is a new user (no repositories in our database yet)
                existing_repos_count = await db.repositories.count_documents({
                    "user_email": user_email
                })
                
                is_new_user = existing_repos_count == 0
                
                if is_new_user:
                    # NEW USER: Just discover repositories, don't scan them
                    logger.info(f"🆕 New user detected: {user_email} - discovering repositories without scanning")
                    discovered = await discover_user_repositories(user_email, github_token, is_new_user=True)
                    new_repos_discovered += discovered
                    continue  # Skip to next user, don't process for scanning
                
                # EXISTING USER: Check for changes and scan when needed
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
                        
                        # Parse GitHub's pushed_at timestamp
                        github_pushed_time = datetime.fromisoformat(pushed_at.replace('Z', '+00:00'))
                        
                        # Check if this repository exists in our database
                        existing_repo = await db.repositories.find_one({
                            "user_email": user_email,
                            "repository_name": full_name
                        })
                        
                        if not existing_repo:
                            # 🆕 NEW REPOSITORY for existing user - Add and scan
                            logger.info(f"🆕 NEW REPOSITORY: {full_name} for existing user {user_email}")
                            
                            # Create repository document with atomic insert
                            repo_doc = {
                                "user_email": user_email,
                                "repository_name": full_name,
                                "repository_url": html_url,
                                "is_monitored": True,
                                "added_at": datetime.utcnow(),
                                "last_scan": None,
                                "findings_count": 0,
                                "scan_status": "scanning",  # Immediately lock for scanning
                                "is_private": is_private,
                                "auto_detected": True,
                                "github_updated_at": datetime.fromisoformat(updated_at.replace('Z', '+00:00')),
                                "github_pushed_at": github_pushed_time,
                                "last_known_push": pushed_at,
                                "scan_frozen_until": None,
                                "commits_during_freeze": 0,
                                # Email deduplication fields
                                "last_emailed_push": None,
                                "last_email_sent_at": None,
                                "email_batch_commits": [],
                                # Atomic locking fields
                                "scan_lock_id": generate_lock_id(),
                                "scan_lock_expires": datetime.utcnow() + timedelta(minutes=10),
                                "scan_worker_id": get_worker_id(),
                                # Not marked as initial discovery for existing users
                                "discovered_for_new_user": False,
                                "initial_discovery": False
                            }
                            
                            try:
                                result = await db.repositories.insert_one(repo_doc)
                                repo_id = str(result.inserted_id)
                                logger.info(f"✅ Added new repository for existing user: {full_name}")
                                new_repos_discovered += 1
                                
                                # 🚀 SCAN NEW REPOSITORY (for existing users only)
                                success = await scan_repository_secure(
                                    repo_id, user_email, github_token, full_name, "new_repository", pushed_at
                                )
                                
                                if success:
                                    repos_scanned += 1
                                else:
                                    logger.error(f"❌ New repo scan failed: {full_name}")
                                    
                            except Exception as insert_error:
                                logger.error(f"❌ Failed to insert new repository {full_name}: {insert_error}")
                                continue
                        
                        else:
                            # 🔄 EXISTING REPOSITORY - Check for changes
                            repo_id = str(existing_repo["_id"])
                            last_known_push = existing_repo.get("last_known_push")
                            scan_frozen_until = existing_repo.get("scan_frozen_until")
                            commits_during_freeze = existing_repo.get("commits_during_freeze", 0)
                            was_discovered_for_new_user = existing_repo.get("discovered_for_new_user", False)
                            
                            # Skip auto-scanning repositories that were discovered for new users
                            # They can only be scanned manually or when user makes new commits
                            if was_discovered_for_new_user and pushed_at == last_known_push:
                                # No new commits since discovery, skip auto-scan
                                continue
                            
                            # Check if there's a new commit
                            if pushed_at != last_known_push:
                                logger.info(f"🔄 NEW COMMIT detected in {full_name}")
                                
                                now = datetime.utcnow()
                                
                                # Parse freeze time if it exists
                                freeze_time = None
                                if scan_frozen_until:
                                    if isinstance(scan_frozen_until, str):
                                        freeze_time = datetime.fromisoformat(scan_frozen_until.replace('Z', '+00:00'))
                                    else:
                                        freeze_time = scan_frozen_until
                                
                                if freeze_time is None or now >= freeze_time:
                                    # ✅ NOT FROZEN - Try to acquire atomic lock for scanning
                                    lock_acquired = await acquire_scan_lock(db, repo_id, full_name)
                                    
                                    if lock_acquired:
                                        logger.info(f"🔒 Acquired scan lock for {full_name}")
                                        
                                        # Update repository with new push info
                                        await db.repositories.update_one(
                                            {"_id": existing_repo["_id"]},
                                            {
                                                "$set": {
                                                    "last_known_push": pushed_at,
                                                    "github_pushed_at": github_pushed_time,
                                                    "commits_during_freeze": 0,
                                                    "discovered_for_new_user": False  # Clear flag on activity
                                                }
                                            }
                                        )
                                        
                                        # 🚀 TRIGGER SECURE SCAN WITH ATOMIC LOCK
                                        success = await scan_repository_secure(
                                            repo_id, user_email, github_token, full_name, "new_commits", pushed_at
                                        )
                                        
                                        if success:
                                            repos_scanned += 1
                                        else:
                                            logger.error(f"❌ Commit scan failed: {full_name}")
                                    else:
                                        logger.info(f"🔒 Scan already in progress for {full_name}, skipping")
                                        repos_locked += 1
                                
                                else:
                                    # ❄️ FROZEN - Just track the commit for later
                                    logger.info(f"❄️ {full_name} is frozen until {freeze_time}")
                                    
                                    # Add commit to batch tracking
                                    email_batch_commits = existing_repo.get("email_batch_commits", [])
                                    email_batch_commits.append({
                                        "pushed_at": pushed_at,
                                        "detected_at": now.isoformat()
                                    })
                                    
                                    # Update commit info but don't scan
                                    await db.repositories.update_one(
                                        {"_id": existing_repo["_id"]},
                                        {
                                            "$set": {
                                                "last_known_push": pushed_at,
                                                "github_pushed_at": github_pushed_time,
                                                "commits_during_freeze": commits_during_freeze + 1,
                                                "email_batch_commits": email_batch_commits,
                                                "discovered_for_new_user": False  # Clear flag on activity
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
                                    
                                    # Try to acquire atomic lock for post-freeze scan
                                    lock_acquired = await acquire_scan_lock(db, repo_id, full_name)
                                    
                                    if lock_acquired:
                                        logger.info(f"🔓 Freeze expired for {full_name} with {commits_during_freeze} pending commits")
                                        
                                        # 🚀 TRIGGER POST-FREEZE SECURE SCAN
                                        success = await scan_repository_secure(
                                            repo_id, user_email, github_token, full_name, "post_freeze_commits", pushed_at
                                        )
                                        
                                        if success:
                                            repos_scanned += 1
                                        else:
                                            logger.error(f"❌ Post-freeze scan failed: {full_name}")
                                    else:
                                        logger.info(f"🔒 Post-freeze scan already in progress for {full_name}")
                                        repos_locked += 1
                    
                    except Exception as repo_error:
                        logger.error(f"❌ Error processing repository {repo_data.get('full_name', 'unknown')}: {repo_error}")
                        continue
            
            except Exception as user_error:
                logger.error(f"❌ Error monitoring repos for user {user.get('email', 'unknown')}: {user_error}")
                continue
        
        # Summary log
        logger.info(f"🎯 Repository monitoring completed:")
        logger.info(f"   📋 New repositories discovered: {new_repos_discovered}")
        logger.info(f"   🚀 Repositories scanned: {repos_scanned}")
        logger.info(f"   ❄️ Repositories frozen: {repos_frozen}")
        logger.info(f"   🔒 Repositories locked (skipped): {repos_locked}")
    
    except Exception as e:
        logger.error(f"💥 Critical error in repository monitoring: {e}")

async def acquire_scan_lock(db, repo_id: str, repo_name: str) -> bool:
    """ATOMIC LOCK ACQUISITION - prevents concurrent scans of same repository"""
    try:
        now = datetime.utcnow()
        lock_id = generate_lock_id()
        worker_id = get_worker_id()
        
        # Atomic update: only set lock if no active lock exists or expired lock exists
        result = await db.repositories.update_one(
            {
                "_id": ObjectId(repo_id),
                "$or": [
                    {"scan_status": {"$ne": "scanning"}},  # Not currently scanning
                    {"scan_lock_expires": {"$lt": now}},   # Or lock expired
                    {"scan_lock_expires": {"$exists": False}}  # Or no lock set
                ]
            },
            {
                "$set": {
                    "scan_status": "scanning",
                    "scan_lock_id": lock_id,
                    "scan_lock_expires": now + timedelta(minutes=10),  # 10-minute timeout
                    "scan_worker_id": worker_id,
                    "scan_started_at": now
                }
            }
        )
        
        if result.modified_count > 0:
            logger.info(f"🔒 Successfully acquired atomic lock for {repo_name}")
            return True
        else:
            logger.info(f"🔒 Failed to acquire lock for {repo_name} - already locked or scanning")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error acquiring scan lock for {repo_name}: {e}")
        return False

async def release_scan_lock(db, repo_id: str, repo_name: str, lock_id: str):
    """Release atomic scan lock after completion"""
    try:
        result = await db.repositories.update_one(
            {
                "_id": ObjectId(repo_id),
                "scan_lock_id": lock_id  # Only release if we own the lock
            },
            {
                "$set": {
                    "scan_status": "completed",
                    "last_scan": datetime.utcnow()
                },
                "$unset": {
                    "scan_lock_id": "",
                    "scan_lock_expires": "",
                    "scan_worker_id": "",
                    "scan_started_at": ""
                }
            }
        )
        
        if result.modified_count > 0:
            logger.info(f"🔓 Released atomic lock for {repo_name}")
        else:
            logger.warning(f"⚠️ Failed to release lock for {repo_name}")
            
    except Exception as e:
        logger.error(f"❌ Error releasing scan lock for {repo_name}: {e}")

async def scan_repository_secure(
    repo_id: str, user_email: str, access_token: str, repo_name: str, 
    scan_reason: str, current_push_timestamp: str
) -> bool:
    """
    SECURE VERSION: Repository scanning with smart filtering and secure email notifications
    """
    db = await database.get_database()
    lock_id = None
    
    try:
        # Get repository document to check lock and email tracking
        repo_doc = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        if not repo_doc:
            logger.error(f"❌ Repository {repo_id} not found")
            return False
        
        # Verify we own the lock
        lock_id = repo_doc.get("scan_lock_id")
        worker_id = repo_doc.get("scan_worker_id")
        current_worker = get_worker_id()
        
        if not lock_id or worker_id != current_worker:
            logger.error(f"❌ Scan lock verification failed for {repo_name}")
            return False
        
        # CHECK EMAIL DEDUPLICATION - PREVENT DUPLICATE EMAILS
        last_emailed_push = repo_doc.get("last_emailed_push")
        last_email_sent_at = repo_doc.get("last_email_sent_at")
        
        should_send_email = True
        email_skip_reason = None
        
        if last_emailed_push == current_push_timestamp:
            should_send_email = False
            email_skip_reason = f"Already emailed about push {current_push_timestamp}"
        
        # Also skip if we sent an email very recently (within 3 minutes)
        if last_email_sent_at and should_send_email:
            if isinstance(last_email_sent_at, str):
                last_email_time = datetime.fromisoformat(last_email_sent_at.replace('Z', '+00:00'))
            else:
                last_email_time = last_email_sent_at
            
            time_since_last_email = datetime.utcnow() - last_email_time
            if time_since_last_email < timedelta(minutes=3):
                should_send_email = False
                email_skip_reason = f"Recently sent email {time_since_last_email} ago"
        
        if not should_send_email:
            logger.info(f"📧 SKIPPING EMAIL - {email_skip_reason}")
        
        logger.info(f"🔍 Starting secure scan: {repo_name} ({scan_reason})")
        
        # Extract owner and repo name from full name
        if "/" not in repo_name:
            logger.error(f"❌ Invalid repository name format: {repo_name}")
            await release_scan_lock(db, repo_id, repo_name, lock_id)
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
            logger.error(f"❌ Repository not found: {owner}/{repo_short_name}")
            await release_scan_lock(db, repo_id, repo_name, lock_id)
            return False
        elif response.status_code == 403:
            logger.error(f"❌ Access forbidden - rate limited")
            await release_scan_lock(db, repo_id, repo_name, lock_id)
            return False
        elif response.status_code != 200:
            logger.error(f"❌ Failed to get repository info: {response.status_code}")
            await release_scan_lock(db, repo_id, repo_name, lock_id)
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
            skipped_files_count = 0
        elif response.status_code != 200:
            logger.error(f"❌ Failed to get repository tree: {response.status_code}")
            await release_scan_lock(db, repo_id, repo_name, lock_id)
            return False
        else:
            tree_data = response.json()
            
            # SMART FILE SCANNING with filtering
            all_findings = []
            scanned_files_count = 0
            skipped_files_count = 0
            
            for item in tree_data.get("tree", []):
                if item["type"] == "blob" and item.get("size", 0) > 0:
                    file_path = item["path"]
                    file_size = item.get("size", 0)
                    
                    # SMART FILTERING: Skip unwanted directories
                    if should_skip_directory(file_path):
                        skipped_files_count += 1
                        continue
                    
                    # SMART FILTERING: Skip binary files
                    if is_binary_file(file_path):
                        skipped_files_count += 1
                        continue
                    
                    # SMART FILTERING: Only scan relevant files
                    if not is_scannable_file(file_path):
                        skipped_files_count += 1
                        continue
                    
                    # SMART FILTERING: Skip large files
                    if is_large_file(file_size):
                        logger.warning(f"⚠️ Skipping large file ({file_size/1024:.1f}KB): {file_path}")
                        skipped_files_count += 1
                        continue
                    
                    # SCAN THE FILE
                    file_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/contents/{file_path}?ref={default_branch}"
                    
                    try:
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.get(file_url, headers=headers)
                        
                        if response.status_code != 200:
                            skipped_files_count += 1
                            continue
                        
                        file_data = response.json()
                        if "content" not in file_data:
                            skipped_files_count += 1
                            continue
                        
                        # Decode file content
                        try:
                            content = base64.b64decode(file_data["content"]).decode("utf-8")
                        except UnicodeDecodeError:
                            skipped_files_count += 1
                            continue
                        except Exception:
                            skipped_files_count += 1
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
                        skipped_files_count += 1
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
        
        logger.info(f"📊 Secure scan completed: {repo_name}")
        logger.info(f"   🔍 Files scanned: {scanned_files_count}")
        logger.info(f"   ⏭️ Files skipped: {skipped_files_count}")
        logger.info(f"   🚨 Findings: {len(all_findings)}")
        
        # 📧 SEND SECURE EMAIL WITH URL ONLY
        if should_send_email:
            # Double-check email deduplication with atomic update before sending
            now = datetime.utcnow()
            email_update_result = await db.repositories.update_one(
                {
                    "_id": ObjectId(repo_id),
                    "$or": [
                        {"last_emailed_push": {"$ne": current_push_timestamp}},
                        {"last_emailed_push": {"$exists": False}},
                        {"last_email_sent_at": {"$lt": now - timedelta(minutes=3)}}
                    ]
                },
                {
                    "$set": {
                        "last_emailed_push": current_push_timestamp,
                        "last_email_sent_at": now,
                        "email_batch_commits": []
                    }
                }
            )
            
            if email_update_result.modified_count > 0:
                # We successfully claimed the email sending right
                try:
                    # Use secure email service with URL-only notifications
                    success = await email_service.send_security_alert_with_url(
                        user_email=user_email,
                        repository_name=repo_name,
                        findings_count=len(all_findings),
                        report_id=str(report["_id"]),
                        scan_type=scan_reason
                    )
                    
                    if success:
                        logger.info(f"📧 Secure email notification sent to {user_email} for {repo_name}")
                    else:
                        logger.error(f"❌ Failed to send secure email notification")
                        # Revert email tracking on failure
                        await db.repositories.update_one(
                            {"_id": ObjectId(repo_id)},
                            {"$unset": {"last_emailed_push": "", "last_email_sent_at": ""}}
                        )
                
                except Exception as email_error:
                    logger.error(f"📧 Failed to send secure email: {email_error}")
                    # Revert email tracking on failure
                    await db.repositories.update_one(
                        {"_id": ObjectId(repo_id)},
                        {"$unset": {"last_emailed_push": "", "last_email_sent_at": ""}}
                    )
            else:
                logger.info(f"📧 Email already sent by another worker for {repo_name}")
        else:
            logger.info(f"📧 Email skipped: {email_skip_reason}")
        
        # Set freeze period for future commits
        if scan_reason in ["new_commits", "new_repository"]:
            freeze_until = datetime.utcnow() + timedelta(minutes=15)
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {"$set": {"scan_frozen_until": freeze_until}}
            )
            logger.info(f"✅ Scan completed, frozen until: {freeze_until}")
        elif scan_reason == "post_freeze_commits":
            # Clear freeze and reset counters
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {
                    "$set": {"scan_frozen_until": None, "commits_during_freeze": 0},
                    "$unset": {"email_batch_commits": ""}
                }
            )
            logger.info(f"✅ Post-freeze scan completed, freeze cleared for {repo_name}")
        
        # Update scan completion and findings count
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"findings_count": len(all_findings)}}
        )
        
        # Release the atomic lock
        await release_scan_lock(db, repo_id, repo_name, lock_id)
        
        return True
    
    except Exception as e:
        logger.error(f"💥 Critical error in secure scan: {e}")
        
        # Ensure lock is released on error
        if lock_id:
            await release_scan_lock(db, repo_id, repo_name, lock_id)
        
        return False

def generate_lock_id() -> str:
    """Generate unique lock ID"""
    import uuid
    return str(uuid.uuid4())

def get_worker_id() -> str:
    """Get unique worker/process identifier"""
    import socket
    import os
    hostname = socket.gethostname()
    pid = os.getpid()
    return f"{hostname}-{pid}"

def start_background_scheduler():
    """Start the background scheduler with secure scanning and no auto-scan for new users"""
    scheduler = AsyncIOScheduler()
    
    # Add the polling job every 45 seconds
    scheduler.add_job(
        poll_user_repos,
        'interval',
        seconds=45,
        id='poll_user_repos',
        replace_existing=True,
        max_instances=1  # Prevent overlapping scheduler runs
    )
    
    # Add cleanup job every hour to clean expired locks
    scheduler.add_job(
        cleanup_expired_locks,
        'interval',
        hours=1,
        id='cleanup_expired_locks',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("🚀 Background scheduler started - SECURE MODE (no auto-scan for new users)!")
    
    return scheduler

def stop_background_scheduler(scheduler):
    """Stop the background scheduler"""
    if scheduler:
        scheduler.shutdown()
        logger.info("🔄 Background scheduler stopped")

async def cleanup_expired_locks():
    """Clean up expired scan locks and reset frozen repositories"""
    try:
        db = await database.get_database()
        now = datetime.utcnow()
        
        # Clean up expired scan locks
        expired_locks_result = await db.repositories.update_many(
            {"scan_lock_expires": {"$lt": now}},
            {
                "$set": {"scan_status": "completed"},
                "$unset": {
                    "scan_lock_id": "",
                    "scan_lock_expires": "",
                    "scan_worker_id": "",
                    "scan_started_at": ""
                }
            }
        )
        
        if expired_locks_result.modified_count > 0:
            logger.info(f"🧹 Cleaned up {expired_locks_result.modified_count} expired scan locks")
        
        # Reset repositories that have been frozen for too long (over 2 hours)
        two_hours_ago = now - timedelta(hours=2)
        frozen_reset_result = await db.repositories.update_many(
            {"scan_frozen_until": {"$lt": two_hours_ago}},
            {
                "$unset": {
                    "scan_frozen_until": "",
                    "commits_during_freeze": "",
                    "email_batch_commits": ""
                }
            }
        )
        
        if frozen_reset_result.modified_count > 0:
            logger.info(f"🧹 Reset {frozen_reset_result.modified_count} repositories from long freeze state")
    
    except Exception as e:
        logger.error(f"Error in cleanup_expired_locks: {e}")
