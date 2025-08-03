# main.py - Fixed version with email notifications for repository scans

from fastapi import FastAPI, Request, Response, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
import os
from dotenv import load_dotenv
from . import auth, database, crud, detector, email_service, github_integration
from bson import ObjectId
import logging
import httpx
from datetime import datetime
import json
from bson import ObjectId
import base64
from fastapi import BackgroundTasks

# Import oauth_manager
from .auth import oauth_manager
import asyncio
from .github_integration import start_scan_worker
from fastapi import WebSocket, WebSocketDisconnect
from .github_integration import scan_and_notify
from .filters import init_filters

from .scheduler import start_background_scheduler, stop_background_scheduler

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecretGuardian", version="1.0.0")

background_scheduler = None

# Get secret key from environment
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=False,
    same_site="lax",
    max_age=86400,
    session_cookie="session"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="templates")
init_filters(templates.env)

# MODIFY your existing startup_event function to include scheduler
@app.on_event("startup")
async def startup_event():
    """Initialize database connection and start background services on startup"""
    global background_scheduler
    
    await database.connect_to_mongo()
    await start_scan_worker()  # Your existing scan worker
    
    # START BACKGROUND SCHEDULER FOR REPO POLLING
    background_scheduler = start_background_scheduler()
    
    logger.info("Application started successfully with background scheduler")

# MODIFY your existing shutdown_event function
@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection and stop background services on shutdown"""
    global background_scheduler
    
    await database.close_mongo_connection()
    
    # STOP BACKGROUND SCHEDULER
    if background_scheduler:
        stop_background_scheduler(background_scheduler)
    
    logger.info("Application shut down successfully")

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    """Root page - shows login if not authenticated"""
    user = auth.get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page_get(request: Request):
    """Login page"""
    user = auth.get_current_user(request)
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/token")
async def login_for_access_token(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handle traditional login"""
    try:
        if username == "admin" and password == "admin":
            user = {
                "email": "admin@example.com",
                "username": "admin",
                "full_name": "Admin User",
                "provider": "demo",
                "provider_id": "admin"
            }
            request.session["user"] = user
            logger.info(f"Demo user logged in: {username}")
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
        
        logger.warning(f"Failed login attempt for username: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

# GitHub OAuth routes
@app.get("/auth/github")
async def github_login(request: Request):
    """Initiate GitHub OAuth login"""
    try:
        logger.info("GitHub login initiated")
        return await oauth_manager.github_login(request)
    except Exception as e:
        logger.error(f"GitHub login error: {e}")
        return RedirectResponse(url="/?error=github_login_failed")

@app.get("/auth/github/callback")
async def github_callback(request: Request):
    """Handle GitHub OAuth callback"""
    try:
        logger.info("GitHub callback received")
        # oauth_manager.github_callback already handles everything and returns RedirectResponse
        return await oauth_manager.github_callback(request)
        
    except Exception as e:
        logger.error(f"GitHub callback error: {e}", exc_info=True)
        return RedirectResponse(url="/?error=github_auth_failed")


# Google OAuth routes
@app.get("/auth/google")
async def google_login(request: Request):
    """Initiate Google OAuth login"""
    try:
        logger.info("Google login initiated")
        return await oauth_manager.google_login(request)
    except Exception as e:
        logger.error(f"Google login error: {e}")
        return RedirectResponse(url="/?error=google_login_failed")

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    """Handle Google OAuth callback"""
    try:
        logger.info("Google callback received")
        user_info = await oauth_manager.google_callback(request)
        
        # Store user in session
        request.session["user"] = user_info
        
        # Create or update user in database
        await crud.create_or_get_user(
            email=user_info["email"],
            username=user_info["username"],
            full_name=user_info["name"] or user_info["username"],
            provider=user_info["provider"],
            provider_id=user_info["id"]
        )
        
        logger.info(f"Google user successfully authenticated: {user_info['email']}")
        return RedirectResponse(url="/dashboard")
        
    except HTTPException as e:
        logger.error(f"Google auth error: {e.detail}")
        return RedirectResponse(url="/?error=google_auth_failed")
    except Exception as e:
        logger.error(f"Google callback error: {e}", exc_info=True)
        return RedirectResponse(url="/?error=google_auth_failed")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Display dashboard - requires authentication"""
    user = auth.get_current_user(request)
    if not user:
        logger.warning("Unauthenticated access attempt to dashboard")
        return RedirectResponse(url="/")

    try:
        # Get dashboard statistics
        stats = await crud.get_dashboard_stats(user['email'])
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user": user,
            "stats": stats
        })
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user": user,
            "stats": {"error": "Failed to load statistics"}
        })

@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Display manual scan page - requires authentication"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")

    return templates.TemplateResponse("scan.html", {
        "request": request,
        "user": user
    })

@app.post("/scan")
async def scan_code(request: Request, code: str = Form(...)):
    """Scan code for secrets - requires authentication"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")

    try:
        findings = detector.scan_text(code)
        
        if findings:
            # Save report to database
            report = await crud.create_report(
                user_email=user['email'],
                repository_name="Manual Scan",
                findings=findings,
                scan_type="manual"
            )

            # Send email notification
            try:
                await email_service.send_security_alert(
                    user['email'],
                    "Manual Scan Security Alert",
                    findings,
                    str(report["_id"])
                )
            except Exception as email_error:
                logger.error(f"Failed to send email alert: {email_error}")

        return templates.TemplateResponse("scan_results.html", {
            "request": request,
            "user": user,
            "findings": findings,
            "code": code
        })
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return templates.TemplateResponse("scan.html", {
            "request": request,
            "user": user,
            "error": "Failed to scan code"
        })

@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    """Display reports page - requires authentication"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")

    try:
        # Get filter parameters
        repository_filter = request.query_params.get("repository")
        search_query = request.query_params.get("search")
        severity_filter = request.query_params.get("severity")
        
        # Build query
        query = {"user_email": user['email']}
        
        if repository_filter:
            query["repository_name"] = repository_filter
            
        if severity_filter:
            query["severity"] = severity_filter
            
        if search_query:
            query["$or"] = [
                {"repository_name": {"$regex": search_query, "$options": "i"}},
                {"findings.type": {"$regex": search_query, "$options": "i"}},
                {"findings.context": {"$regex": search_query, "$options": "i"}}
            ]
        
        reports = await crud.get_user_reports(user['email'], query=query)
        
        # Get all repositories for filter dropdown
        all_repositories = await crud.get_user_repositories(user['email'])
        
        return templates.TemplateResponse("reports.html", {
            "request": request,
            "user": user,
            "reports": reports,
            "all_repositories": all_repositories
        })
    except Exception as e:
        logger.error(f"Reports page error: {e}")
        return templates.TemplateResponse("reports.html", {
            "request": request,
            "user": user,
            "reports": [],
            "all_repositories": []
        })

@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str):
    """Display report detail page - requires authentication"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")

    try:
        db = await database.get_database()
        report = await db.reports.find_one({"_id": ObjectId(report_id)})
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Convert ObjectId to string
        report["_id"] = str(report["_id"])
        return templates.TemplateResponse("report_detail.html", {
            "request": request,
            "user": user,
            "report": report
        })
    except Exception as e:
        logger.error(f"Report detail error: {e}")
        return templates.TemplateResponse("404.html", {
            "request": request,
            "message": "Report not found"
        }, status_code=404)

@app.get("/repositories", response_class=HTMLResponse)
async def repositories_page(request: Request):
    """Display repositories page with scan status"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")
    
    try:
        repositories = await crud.get_user_repositories(user['email'])
        
        # Get GitHub access token if available
        github_repos = []
        access_token = request.session.get("github_access_token")
        
        if access_token and user['provider'] == "github":
            try:
                github_repos = await get_github_repositories(access_token)
            except Exception as e:
                logger.error(f"GitHub repo fetch error: {e}")
        
        scan_complete = request.query_params.get("scan_complete") == "true"
        scan_success = request.query_params.get("scan_success") == "true"
        
        # Get scan notifications from session
        scan_notification = request.session.pop("scan_notification", None)
        
        return templates.TemplateResponse("repositories.html", {
            "request": request,
            "user": user,
            "scan_complete": scan_complete,
            "scan_success": scan_success,
            "scan_notification": scan_notification,
            "repositories": repositories,
            "github_repos": github_repos
        })
    except Exception as e:
        logger.error(f"Repositories page error: {e}")
        return templates.TemplateResponse("repositories.html", {
            "request": request,
            "user": user,
            "repositories": [],
            "github_repos": []
        })

@app.post("/api/repositories")
async def add_repository(request: Request, background_tasks: BackgroundTasks):
    """Add a new repository to monitor"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    data = await request.json()
    
    try:
        db = await database.get_database()
        repo_data = {
            "user_email": user["email"],
            "repository_name": data["repository_name"],
            "repository_url": data["repository_url"],
            "is_monitored": True,
            "added_at": datetime.utcnow(),
            "last_scan": None,
            "findings_count": 0
        }
        
        result = await db.repositories.insert_one(repo_data)
        repo_id = str(result.inserted_id)
        repo_data["_id"] = repo_id
        
        # FIXED: Use enhanced scanner that doesn't rely on session
        access_token = request.session.get("github_access_token") or os.getenv("GITHUB_ACCESS_TOKEN")
        background_tasks.add_task(
            scan_repository_enhanced, 
            repo_id, 
            user["email"],
            access_token
        )
        
        repo_data["added_at"] = repo_data["added_at"].isoformat()
        
        return JSONResponse(repo_data, status_code=201)
    except Exception as e:
        logger.error(f"Add repository error: {e}")
        raise HTTPException(status_code=500, detail="Failed to add repository")

@app.patch("/api/repositories/{repo_id}/monitoring")
async def toggle_repository_monitoring(repo_id: str, request: Request, background_tasks: BackgroundTasks):
    """Toggle monitoring for a repository"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    data = await request.json()
    is_monitored = data.get("is_monitored", False)
    
    try:
        db = await database.get_database()
        result = await db.repositories.update_one(
            {"_id": ObjectId(repo_id), "user_email": user["email"]},
            {"$set": {"is_monitored": is_monitored}}
        )
        
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        # If enabling monitoring, trigger a scan with enhanced scanner
        if is_monitored:
            access_token = request.session.get("github_access_token") or os.getenv("GITHUB_ACCESS_TOKEN")
            background_tasks.add_task(
                scan_repository_enhanced, 
                repo_id, 
                user["email"],
                access_token
            )
        
        return JSONResponse({"status": "success", "is_monitored": is_monitored})
    except Exception as e:
        logger.error(f"Toggle monitoring error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update monitoring status")

@app.get("/repositories/{repo_id}/scan")
async def manual_scan_repository(repo_id: str, request: Request):
    """Manual scan with guaranteed notifications"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")
    
    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        
        if not repo or repo["user_email"] != user["email"]:
            return RedirectResponse(url="/repositories?error=not_found")
        
        # Get access token
        access_token = request.session.get("github_access_token") or os.getenv("GITHUB_ACCESS_TOKEN")
        if not access_token:
            return RedirectResponse(url="/repositories?error=no_token")
        
        # Use enhanced scanner for manual scans too
        asyncio.create_task(
            scan_repository_enhanced(
                repo_id,
                user["email"],
                access_token
            )
        )
        
        # Set session notification
        request.session["scan_notification"] = {
            "type": "info",
            "message": f"Scan started for {repo['repository_name']}"
        }
        
        return RedirectResponse(url="/repositories?scan_started=true")
        
    except Exception as e:
        logger.error(f"Manual scan error: {e}")
        return RedirectResponse(url="/repositories?error=scan_failed")

@app.delete("/api/repositories/{repo_id}")
async def delete_repository(repo_id: str, request: Request):
    """Delete a repository from monitoring"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        db = await database.get_database()
        result = await db.repositories.delete_one({
            "_id": ObjectId(repo_id),
            "user_email": user["email"]
        })
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        return JSONResponse({"status": "success", "message": "Repository deleted"})
    except Exception as e:
        logger.error(f"Delete repository error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete repository")

@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str, request: Request):
    """Delete a security report"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        db = await database.get_database()
        result = await db.reports.delete_one({
            "_id": ObjectId(report_id),
            "user_email": user["email"]
        })
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        
        return JSONResponse({"status": "success", "message": "Report deleted"})
    except Exception as e:
        logger.error(f"Delete report error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete report")

# FIXED: Enhanced repository scanner with email notifications
async def scan_repository_enhanced(repo_id: str, user_email: str, access_token: str = None):
    """Enhanced repository scanner that doesn't depend on request session and includes email notifications"""
    db = await database.get_database()
    
    try:
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        if not repo:
            logger.error(f"Repository not found: {repo_id}")
            return False
            
        # Use provided access token or fall back to environment variable
        if not access_token:
            access_token = os.getenv("GITHUB_ACCESS_TOKEN")
        
        if not access_token:
            logger.error("No GitHub access token available for scanning")
            return False
            
        # Extract owner and repo name
        repo_url = repo["repository_url"]
        if "github.com" not in repo_url:
            logger.error(f"Not a GitHub repository: {repo_url}")
            return False
            
        parts = repo_url.split("github.com/")[1].split("/")
        if len(parts) < 2:
            logger.error(f"Invalid GitHub URL format: {repo_url}")
            return False
            
        owner = parts[0]
        repo_name = parts[1]
        
        # Get default branch
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo_name}"
        async with httpx.AsyncClient() as client:
            response = await client.get(repo_info_url, headers=headers)
            if response.status_code != 200:
                logger.error(f"Failed to get repo info: {response.status_code}")
                return False
            repo_info = response.json()
            default_branch = repo_info.get("default_branch", "main")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{default_branch}?recursive=1"
        async with httpx.AsyncClient() as client:
            response = await client.get(tree_url, headers=headers)
            if response.status_code != 200:
                logger.error(f"Failed to get repo tree: {response.status_code}")
                return False
            tree_data = response.json()
            
        def is_text_file(file_path: str) -> bool:
            text_extensions = ['.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', 
                          '.rb', '.go', '.swift', '.kt', '.ts', '.html', '.css',
                          '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg',
                          '.md', '.txt', '.env', '.sh', '.bat', '.ps1', '.sql',
                          '.xml', '.csv', '.log', '.conf', '.config']
            return any(file_path.lower().endswith(ext) for ext in text_extensions)
        
        # Scan all files
        all_findings = []
        for item in tree_data.get("tree", []):
            if item["type"] == "blob" and item["size"] > 0:
                if not is_text_file(item['path']):
                    continue
                
                file_url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/{item['path']}?ref={default_branch}"
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
                            finding["location"] = f"File: {item['path']}"
                            all_findings.append(finding)
                    except UnicodeDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error processing file {item['path']}: {e}")
        
        # Create report
        report = await crud.create_report(
            user_email=user_email,
            repository_name=repo["repository_name"],
            findings=all_findings,
            scan_type="scheduled" if repo["is_monitored"] else "manual"
        )
        
        # FIXED: Add email notification logic (THIS WAS MISSING!)
        try:
            if all_findings:
                # Send security alert for findings
                await email_service.send_security_alert(
                    user_email,
                    f"Security Alert: {repo['repository_name']}",
                    all_findings,
                    str(report["_id"])
                )
                logger.info(f"Security alert sent to {user_email} for {len(all_findings)} findings in {repo['repository_name']}")
            else:
                # Send no-findings notification
                await email_service.send_no_findings_alert(
                    user_email,
                    repo["repository_name"],
                    str(report["_id"])
                )
                logger.info(f"No-findings alert sent to {user_email} for {repo['repository_name']}")
        except Exception as email_error:
            logger.error(f"Failed to send email notification: {email_error}")
            # Don't fail the scan if email fails - log and continue
        
        # Update repository with scan info
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {
                "$set": {
                    "last_scan": datetime.utcnow(),
                    "findings_count": len(all_findings),
                    "scan_status": "completed"
                }
            }
        )
        
        logger.info(f"Repository scan completed: {repo['repository_name']}, findings: {len(all_findings)}")
        return True
        
    except Exception as e:
        logger.error(f"Enhanced repository scan error: {e}")
        return False
    
    finally:
        # Always update scan status
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"scan_status": "completed"}}
        )

# Keep the old scan_repository function for backward compatibility but mark it as deprecated
async def scan_repository(request: Request, repo_id: str, user_email: str):
    """DEPRECATED: Use scan_repository_enhanced instead. Kept for backward compatibility."""
    logger.warning("Using deprecated scan_repository function. Consider using scan_repository_enhanced.")
    
    # Get access token from request session
    access_token = None
    try:
        access_token = request.session.get("github_access_token")
    except:
        access_token = os.getenv("GITHUB_ACCESS_TOKEN")
    
    # Call the enhanced version
    return await scan_repository_enhanced(repo_id, user_email, access_token)

def is_binary_file(file_path: str) -> bool:
    """Check if file is binary based on extension"""
    binary_exts = ['.png', '.jpg', '.jpeg', '.gif', '.bin', '.pyc', 
                   '.exe', '.dll', '.zip', '.pdf', '.doc', '.docx',
                   '.woff', '.ttf', '.eot', '.otf', '.ico', '.svg',
                   '.mp3', '.mp4', '.avi', '.mov', '.wav']
    return any(file_path.lower().endswith(ext) for ext in binary_exts)

@app.get("/report/{report_id}", response_class=HTMLResponse)
async def report_detail_alt(request: Request, report_id: str):
    """Alternative report detail page route"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")
    
    try:
        db = await database.get_database()
        report = await db.reports.find_one({"_id": ObjectId(report_id)})
        
        if not report or report["user_email"] != user["email"]:
            return templates.TemplateResponse("404.html", {
                "request": request,
                "message": "Report not found"
            }, status_code=404)
        
        # Convert ObjectId to string
        report["_id"] = str(report["_id"])
        return templates.TemplateResponse("report_detail.html", {
            "request": request,
            "user": user,
            "report": report
        })
    except Exception as e:
        logger.error(f"Report detail error: {e}")
        return templates.TemplateResponse("404.html", {
            "request": request,
            "message": "Report not found"
        }, status_code=404)

async def get_github_repositories(access_token: str):
    """Fetch user's GitHub repositories"""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = "https://api.github.com/user/repos?per_page=100"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

@app.post("/github-webhook")
async def github_webhook(request: Request):
    """Handle GitHub webhook events"""
    try:
        return await github_integration.handle_webhook(request)
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Webhook processing failed"}
        )

@app.get("/logout")
async def logout(request: Request):
    """Logout user"""
    user = auth.get_current_user(request)
    if user:
        logger.info(f"User logged out: {user.get('email', 'unknown')}")
    
    auth.logout_user(request)
    response = RedirectResponse(url="/")
    return response

@app.get("/api/me")
async def get_current_user_info(request: Request):
    """Get current user info - API endpoint"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "SecretGuardian"}

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return templates.TemplateResponse("404.html", {
        "request": request,
        "message": "Page not found"
    }, status_code=404)

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return templates.TemplateResponse("error.html", {
        "request": request,
        "message": "Internal server error"
    }, status_code=500)

@app.get("/test-email")
async def test_email(request: Request):
    """Test email delivery"""
    try:
        test_findings = [{
            "type": "AWS Access Key",
            "value": "AKIAEXAMPLE", 
            "line": 42,
            "confidence": 0.95,
            "context": "const awsKey = 'AKIAEXAMPLE';",
            "recommendation": "Rotate this key immediately"
        }]
        
        await email_service.send_security_alert(
            "secretguardian@zohomail.in",  # Replace with your email
            "Test Security Alert",
            test_findings,
            "test-report-123"
        )
        return {"status": "Test email sent successfully"}
    except Exception as e:
        logger.error(f"Test email failed: {e}")
        return {"status": "Test email failed", "error": str(e)}

@app.get("/test-smtp")
async def test_smtp_config(request: Request):
    """Test SMTP configuration"""
    try:
        from .email_service import test_email_configuration
        success, message = await test_email_configuration()
        return {"success": success, "message": message}
    except Exception as e:
        return {"success": False, "message": f"SMTP test failed: {e}"}

@app.post("/clear-scan-notification")
async def clear_scan_notification(request: Request):
    """Clear scan success notification from session"""
    if "scan_success" in request.session:
        del request.session["scan_success"]
    if "scanned_repo" in request.session:
        del request.session["scanned_repo"]
    return {"status": "success"}

@app.websocket("/ws/scan-status")
async def websocket_scan_status(websocket: WebSocket):
    """WebSocket for real-time scan status updates"""
    await websocket.accept()
    try:
        while True:
            # In a real implementation, we'd push updates here
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass

@app.get("/api/scan-status/{repo_id}")
async def get_scan_status(repo_id: str, request: Request):
    """Get scan status for a repository"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        return {
            "status": repo.get("scan_status", "unknown"),
            "last_scan": repo.get("last_scan", None),
            "findings_count": repo.get("findings_count", 0)
        }
    except Exception as e:
        logger.error(f"Scan status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan status")


# Add these endpoints to your existing app/main.py file
@app.post("/setup-org-webhook")
async def setup_organization_webhook_endpoint(request: Request):
    """Setup organization-level webhook for automatic repository detection"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        data = await request.json()
        org_name = data.get("organization_name")
        
        if not org_name:
            raise HTTPException(status_code=400, detail="Organization name is required")
        
        # Call the webhook setup function
        result = await github_integration.setup_organization_webhook(org_name)
        
        if result.get("status") == "success":
            return JSONResponse({
                "success": True,
                "message": f"Organization webhook created for {org_name}",
                "webhook_id": result.get("webhook_id")
            })
        else:
            return JSONResponse({
                "success": False,
                "error": result.get("error", "Unknown error")
            }, status_code=400)
            
    except Exception as e:
        logger.error(f"Setup organization webhook error: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup organization webhook")

@app.get("/webhook-status")
async def webhook_status(request: Request):
    """Check webhook status and provide setup instructions"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
        webhook_url = f"{base_url}/github-webhook"
        
        return JSONResponse({
            "webhook_url": webhook_url,
            "webhook_secret_configured": bool(os.getenv("GITHUB_WEBHOOK_SECRET")),
            "github_token_configured": bool(os.getenv("GITHUB_ACCESS_TOKEN")),
            "instructions": {
                "step1": "Go to your GitHub organization settings",
                "step2": "Navigate to Settings > Webhooks",
                "step3": "Click 'Add webhook'",
                "step4": f"Set Payload URL to: {webhook_url}",
                "step5": "Set Content type to: application/json",
                "step6": "Add your webhook secret",
                "step7": "Select events: Repository, Push, Pull request",
                "step8": "Click 'Add webhook'"
            }
        })
        
    except Exception as e:
        logger.error(f"Webhook status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get webhook status")

@app.delete("/api/repositories/{repo_id}")
async def delete_repository(repo_id: str, request: Request):
    """Delete repository from monitoring"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        success = await crud.delete_repository(repo_id)
        
        if success:
            return JSONResponse({"success": True, "message": "Repository deleted successfully"})
        else:
            raise HTTPException(status_code=404, detail="Repository not found")
            
    except Exception as e:
        logger.error(f"Delete repository error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete repository")

# Enhanced scan repository endpoint
@app.get("/repositories/{repo_id}/scan")
async def manual_scan_repository(repo_id: str, request: Request):
    """Manual scan with guaranteed notifications - ENHANCED VERSION"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")

    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        
        if not repo or repo["user_email"] != user["email"]:
            return RedirectResponse(url="/repositories?error=not_found")

        # Get access token
        access_token = os.getenv("GITHUB_ACCESS_TOKEN")
        if not access_token:
            logger.error("GitHub access token not configured")
            return RedirectResponse(url="/repositories?error=no_token")

        # Trigger enhanced scan
        success = await github_integration.scan_repository_enhanced(
            repo_id, 
            user["email"], 
            access_token
        )
        
        if success:
            # Set success notification in session
            request.session["scan_notification"] = {
                "type": "success",
                "message": f"Scan completed for {repo['repository_name']}. Check your email for results."
            }
            return RedirectResponse(url="/repositories?scan_complete=true&scan_success=true")
        else:
            # Set error notification in session
            request.session["scan_notification"] = {
                "type": "error", 
                "message": f"Scan failed for {repo['repository_name']}. Please try again or check logs."
            }
            return RedirectResponse(url="/repositories?scan_complete=true&scan_success=false")

    except Exception as e:
        logger.error(f"Manual scan error: {e}")
        request.session["scan_notification"] = {
            "type": "error",
            "message": "An error occurred during scanning. Please try again."
        }
        return RedirectResponse(url="/repositories?error=scan_failed")

@app.post("/clear-scan-notification")
async def clear_scan_notification(request: Request):
    """Clear scan notification from session"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    request.session.pop("scan_notification", None)
    return JSONResponse({"success": True})

# Enhanced repository scanning function - ADD THIS FUNCTION TO MAIN.PY
async def scan_repository_enhanced(repo_id: str, user_email: str, access_token: str) -> bool:
    """Enhanced repository scanning with better error handling and email notifications"""
    
    try:
        db = await database.get_database()
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        
        if not repo:
            logger.error(f"Repository with ID {repo_id} not found")
            return False
        
        repo_url = repo["repository_url"]
        repo_name = repo["repository_name"]
        
        if "github.com" not in repo_url:
            logger.error(f"Not a GitHub repository: {repo_url}")
            return False
        
        # Extract owner and repo name from URL or repository_name
        if "/" in repo_name:
            owner, repo_short_name = repo_name.split("/", 1)
        else:
            # Fallback: extract from URL
            parts = repo_url.split("github.com/")[1].split("/")
            if len(parts) < 2:
                logger.error(f"Cannot parse repository URL: {repo_url}")
                return False
            owner = parts[0]
            repo_short_name = parts[1].replace(".git", "")
        
        # Update scan status
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"scan_status": "scanning", "last_scan_started": datetime.utcnow()}}
        )
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # Get repository information
        repo_info_url = f"https://api.github.com/repos/{owner}/{repo_short_name}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(repo_info_url, headers=headers)
            
            if response.status_code == 404:
                logger.error(f"Repository not found or access denied: {owner}/{repo_short_name}")
                return False
            elif response.status_code != 200:
                logger.error(f"Failed to get repository info: {response.status_code} - {response.text}")
                return False
        
        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")
        
        logger.info(f"Scanning repository: {owner}/{repo_short_name}, branch: {default_branch}")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/git/trees/{default_branch}?recursive=1"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(tree_url, headers=headers)
            
            if response.status_code != 200:
                logger.error(f"Failed to get repository tree: {response.status_code} - {response.text}")
                return False
        
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
                    continue
                    
                file_url = f"https://api.github.com/repos/{owner}/{repo_short_name}/contents/{file_path}?ref={default_branch}"
                
                try:
                    async with httpx.AsyncClient() as client:
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
                    
                    # Scan for secrets
                    findings = detector.scan_text(content)
                    
                    for finding in findings:
                        finding["location"] = f"File: {file_path}"
                        finding["repository"] = repo_name
                        all_findings.append(finding)
                    
                    scanned_files_count += 1
                
                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {e}")
                    continue
        
        # Create report
        report = await crud.create_report(
            user_email=user_email,
            repository_name=repo_name,
            findings=all_findings,
            scan_type="manual"
        )
        
        # FIXED: Add email notification logic
        try:
            if all_findings:
                # Send security alert for findings
                await email_service.send_security_alert(
                    user_email,
                    f"🚨 Security Alert: {repo_name} - {len(all_findings)} secrets found",
                    all_findings,
                    str(report["_id"])
                )
                logger.info(f"Security alert sent to {user_email} for {len(all_findings)} findings in {repo_name}")
            else:
                # Send no-findings notification
                await email_service.send_no_findings_alert(
                    user_email,
                    repo_name,
                    str(report["_id"])
                )
                logger.info(f"No-findings alert sent to {user_email} for {repo_name}")
        
        except Exception as email_error:
            logger.error(f"Failed to send email notification: {email_error}")
            # Don't fail the scan if email fails
        
        # Update repository with scan info
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {
                "last_scan": datetime.utcnow(),
                "findings_count": len(all_findings),
                "scan_status": "completed",
                "scanned_files_count": scanned_files_count
            }}
        )
        
        logger.info(f"Repository scan completed: {repo_name}, findings: {len(all_findings)}")
        return True
        
    except Exception as e:
        logger.error(f"Enhanced repository scan error: {e}")
        # Update scan status to failed
        try:
            await db.repositories.update_one(
                {"_id": ObjectId(repo_id)},
                {"$set": {"scan_status": "failed", "error_message": str(e)}}
            )
        except:
            pass
        return False


# ADD this new endpoint to store user GitHub tokens persistently
@app.post("/api/store-github-token")
async def store_github_token(request: Request):
    """Store user's GitHub token for background polling"""
    user = auth.get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        # Get the GitHub access token from session
        github_token = request.session.get("github_access_token")
        
        if not github_token:
            raise HTTPException(status_code=400, detail="No GitHub token found in session")
        
        # Store the token in database for background polling
        db = await database.get_database()
        
        # Update user record with GitHub token
        await db.users.update_one(
            {"email": user["email"]},
            {
                "$set": {
                    "github_access_token": github_token,
                    "token_updated_at": datetime.utcnow()
                }
            }
        )
        
        logger.info(f"GitHub token stored for user: {user['email']}")
        
        return JSONResponse({"success": True, "message": "GitHub token stored successfully"})
        
    except Exception as e:
        logger.error(f"Error storing GitHub token: {e}")
        raise HTTPException(status_code=500, detail="Failed to store GitHub token")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port)
