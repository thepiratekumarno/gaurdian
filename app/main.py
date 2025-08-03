# main.py
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

from fastapi import BackgroundTasks  # Add this import

# Import oauth_manager
from .auth import oauth_manager
import asyncio
from .github_integration import start_scan_worker

from fastapi import WebSocket, WebSocketDisconnect

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecretGuardian", version="1.0.0")

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

@app.on_event("startup")
async def startup_event():
    """Initialize database connection on startup"""
    await database.connect_to_mongo()
    await start_scan_worker()  # Start scan worker
    logger.info("Application started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection on shutdown"""
    await database.close_mongo_connection()
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
        user_info = await oauth_manager.github_callback(request)
        
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
        
        logger.info(f"GitHub user successfully authenticated: {user_info['email']}")
        return RedirectResponse(url="/dashboard")
        
    except HTTPException as e:
        logger.error(f"GitHub auth error: {e.detail}")
        return RedirectResponse(url="/?error=github_auth_failed")
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

# Update the reports_page function
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
        
        # Trigger initial scan in background
        background_tasks.add_task(scan_repository, request, repo_id, user["email"])
        
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
        
        # If enabling monitoring, trigger a scan
        if is_monitored:
            background_tasks.add_task(scan_repository, request, repo_id, user["email"])
        
        return JSONResponse({"status": "success", "is_monitored": is_monitored})
    except Exception as e:
        logger.error(f"Toggle monitoring error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update monitoring status")

@app.get("/repositories/{repo_id}/scan")
async def manual_scan_repository(repo_id: str, request: Request, background_tasks: BackgroundTasks):
    """Trigger a manual scan of a repository"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")
    
    try:
        background_tasks.add_task(scan_repository, request, repo_id, user["email"])
        return RedirectResponse(url=f"/repositories?scan_started=true")
    except Exception as e:
        logger.error(f"Manual scan error: {e}")
        return RedirectResponse(url=f"/repositories?scan_error=true")

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
# Add this route for report details
@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str):
    """Display report detail page"""
    user = auth.get_current_user(request)
    if not user:
        return RedirectResponse(url="/")
    
    try:
        db = await database.get_database()
        report = await db.reports.find_one({"_id": ObjectId(report_id)})
        
        if not report or report["user_email"] != user["email"]:
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

async def scan_repository(request: Request, repo_id: str, user_email: str):
    """Scan a repository and generate report"""
    db = await database.get_database()
    try:
        repo = await db.repositories.find_one({"_id": ObjectId(repo_id)})
        if not repo:
            logger.error(f"Repository not found: {repo_id}")
            return
            
        # Get access token from session
        access_token = request.session.get("github_access_token")
        if not access_token:
            logger.error("GitHub access token not available for scanning")
            return
            
        # Extract owner and repo name
        repo_url = repo["repository_url"]
        if "github.com" not in repo_url:
            return
            
        parts = repo_url.split("github.com/")[1].split("/")
        if len(parts) < 2:
            return
            
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
                return
            repo_info = response.json()
            default_branch = repo_info.get("default_branch", "main")
        
        # Get repository tree
        tree_url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{default_branch}?recursive=1"
        async with httpx.AsyncClient() as client:
            response = await client.get(tree_url, headers=headers)
            if response.status_code != 200:
                return
            tree_data = response.json()
            
        # Add this helper function
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
            if item["type"] == "blob" and item["size"] > 0:  # Only scan files
                # Skip non-text files
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
                    # Decode content only for text files
                        content = base64.b64decode(file_data["content"]).decode("utf-8")
                    
                    # Scan content
                        findings = detector.scan_text(content)
                        for finding in findings:
                            finding["location"] = f"File: {item['path']}"
                            all_findings.append(finding)
                    except UnicodeDecodeError:
                    # Skip files that can't be decoded as UTF-8 text
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
        
        # Set session flag for UI notification
        request.session["scan_success"] = True
        request.session["scanned_repo"] = repo["repository_name"]
        
        return True
    
    except Exception as e:
        logger.error(f"Repository scan error: {e}")
        return False
    
    finally:
        # Always update scan status
        await db.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {"$set": {"scan_status": "completed"}}
        )
    


def is_binary_file(file_path: str) -> bool:
    """Check if file is binary based on extension"""
    binary_exts = ['.png', '.jpg', '.jpeg', '.gif', '.bin', '.pyc', 
                   '.exe', '.dll', '.zip', '.pdf', '.doc', '.docx',
                   '.woff', '.ttf', '.eot', '.otf', '.ico', '.svg',
                   '.mp3', '.mp4', '.avi', '.mov', '.wav']
    return any(file_path.lower().endswith(ext) for ext in binary_exts)

# Add this route for report details
@app.get("/report/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str):
    """Display report detail page"""
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

# Add this test route to main.py
@app.get("/test-email")
async def test_email(request: Request):
    """Test email delivery"""
    from .email_service import send_security_alert
    
    test_findings = [{
        "type": "AWS Access Key",
        "value": "AKIAEXAMPLE",
        "line": 42,
        "confidence": 0.95,
        "context": "const awsKey = 'AKIAEXAMPLE';",
        "recommendation": "Rotate this key immediately"
    }]
    
    await send_security_alert(
        "user@example.com",  # Replace with your email
        "Test Security Alert",
        test_findings,
        "test-report-123"
    )
    return {"status": "Test email sent"}

@app.post("/clear-scan-notification")
async def clear_scan_notification(request: Request):
    """Clear scan success notification from session"""
    if "scan_success" in request.session:
        del request.session["scan_success"]
    if "scanned_repo" in request.session:
        del request.session["scanned_repo"]
    return {"status": "success"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port)
    
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
