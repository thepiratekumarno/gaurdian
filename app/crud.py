from datetime import datetime
from typing import List, Dict, Any, Optional
from bson import ObjectId
from .database import get_database
import asyncio
import logging

logger = logging.getLogger(__name__)

async def create_or_get_user(email: str, username: str, full_name: str, provider: str, provider_id: str) -> Dict[str, Any]:
    """Create or get existing user"""
    db = await get_database()
    
    existing_user = await db.users.find_one({"email": email})
    if existing_user:
        return existing_user
    
    user_data = {
        "email": email,
        "username": username,
        "full_name": full_name,
        "provider": provider,
        "provider_id": provider_id,
        "created_at": datetime.utcnow(),
        "is_active": True
    }
    
    result = await db.users.insert_one(user_data)
    user_data["_id"] = str(result.inserted_id)
    return user_data

async def create_report(user_email: str, repository_name: str, findings: List[Dict], scan_type: str = "automatic") -> Dict[str, Any]:
    """Create a new security report"""
    db = await get_database()
    
    report_data = {
        "user_email": user_email,
        "repository_name": repository_name,
        "findings": findings,
        "scan_type": scan_type,
        "findings_count": len(findings),
        "severity": determine_severity(findings),
        "created_at": datetime.utcnow(),
        "status": "open"
    }
    
    result = await db.reports.insert_one(report_data)
    report_data["_id"] = str(result.inserted_id)  # Convert to string
    
    # Update repository scan status
    await db.repositories.update_one(
        {"user_email": user_email, "repository_name": repository_name},
        {
            "$set": {
                "last_scan": datetime.utcnow(),
                "findings_count": len(findings),
                "scan_status": "completed"
            }
        }
    )
    
    return report_data

async def get_user_reports(user_email: str, query: dict = {}, limit: int = 50) -> List[Dict[str, Any]]:
    """Get user's security reports with optional query"""
    db = await get_database()
    
    # Build base query
    base_query = {"user_email": user_email}
    if query:
        base_query.update(query)
    
    cursor = db.reports.find(base_query).sort("created_at", -1).limit(limit)
    reports = await cursor.to_list(length=limit)
    
    # Convert ObjectId to string
    for report in reports:
        report["_id"] = str(report["_id"])
    return reports

async def get_dashboard_stats(user_email: str) -> Dict[str, Any]:
    """Get dashboard statistics for user"""
    db = await get_database()
    
    # Count total reports
    total_reports = await db.reports.count_documents({"user_email": user_email})
    
    # Count findings by severity
    pipeline = [
        {"$match": {"user_email": user_email}},
        {"$group": {
            "_id": "$severity",
            "count": {"$sum": 1}
        }}
    ]
    severity_counts = await db.reports.aggregate(pipeline).to_list(length=None)
    
    # Initialize counts
    counts = {"high": 0, "medium": 0, "low": 0}
    for item in severity_counts:
        severity = item["_id"]
        if severity in counts:
            counts[severity] = item["count"]
    
    # Count monitored repositories
    monitored_repos = await db.repositories.count_documents({
        "user_email": user_email, 
        "is_monitored": True
    })
    
    # Get recent reports
    recent_reports = await get_user_reports(user_email, limit=5)
    
    # Convert ObjectIds to strings
    for report in recent_reports:
        report["_id"] = str(report["_id"])
    
    return {
        "total_reports": total_reports,
        "high_severity": counts["high"],
        "medium_severity": counts["medium"],
        "low_severity": counts["low"],
        "monitored_repositories": monitored_repos,
        "recent_reports": recent_reports
    }


async def get_user_repositories(user_email: str) -> List[Dict[str, Any]]:
    """Get user's repositories from database"""
    db = await get_database()
    
    cursor = db.repositories.find({"user_email": user_email}).sort("repository_name", 1)
    repositories = await cursor.to_list(length=None)
    
    # Convert ObjectId to string
    for repo in repositories:
        repo["_id"] = str(repo["_id"])
    return repositories

async def add_repository(user_email: str, repo_name: str, repo_url: str, is_monitored: bool = True) -> Dict[str, Any]:
    """Add a repository to monitoring"""
    db = await get_database()
    
    repo_data = {
        "user_email": user_email,
        "repository_name": repo_name,
        "repository_url": repo_url,
        "is_monitored": is_monitored,
        "added_at": datetime.utcnow(),
        "last_scan": None,
        "findings_count": 0
    }
    
    result = await db.repositories.insert_one(repo_data)
    repo_data["_id"] = str(result.inserted_id)
    return repo_data

def determine_severity(findings: List[Dict]) -> str:
    """Determine overall severity based on findings"""
    if not findings:
        return "low"
    
    high_risk_types = ["AWS Access Key", "AWS Secret Key", "GitHub Token", "RSA Private Key", "SSH Private Key"]
    medium_risk_types = ["JWT Token", "OAuth Client Secret", "Database URI"]
    
    for finding in findings:
        if finding.get('type') in high_risk_types:
            return "high"
        elif finding.get('type') in medium_risk_types and finding.get('confidence', 0) > 0.8:
            return "high"
    
    # Check for medium risk
    for finding in findings:
        if finding.get('confidence', 0) > 0.7:
            return "medium"
    
    return "low"

async def delete_report(report_id: str) -> bool:
    """Delete a security report"""
    db = await get_database()
    result = await db.reports.delete_one({"_id": ObjectId(report_id)})
    return result.deleted_count > 0

async def delete_repository(repo_id: str) -> bool:
    """Delete a repository and stop monitoring"""
    db = await get_database()
    result = await db.repositories.delete_one({"_id": ObjectId(repo_id)})
    
    # Automatically stop any scheduled scans
    # (Implementation depends on your scheduler)
    # Example: scheduler.remove_job(f"scan_{repo_id}")
    
    return result.deleted_count > 0

async def toggle_repository_monitoring(repo_id: str, enable: bool) -> bool:
    """Toggle monitoring for a repository"""
    db = await get_database()
    result = await db.repositories.update_one(
        {"_id": ObjectId(repo_id)},
        {"$set": {"is_monitored": enable}}
    )
    
    if not enable:
        # Automatically stop any scheduled scans
        # (Implementation depends on your scheduler)
        # Example: scheduler.remove_job(f"scan_{repo_id}")
    
        return result.modified_count > 0
