import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
import schedule
import time
import threading
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import ScanReport, Repository, User
from app.email_service import email_service
from app.scan_service import scan_service
import os

logger = logging.getLogger(__name__)

class SchedulerService:
    def __init__(self):
        self.running = False
        self.scheduler_thread = None
        self.setup_schedules()

    def setup_schedules(self):
        """Setup all scheduled tasks"""
        try:
            # Schedule repository scans every 6 hours
            schedule.every(6).hours.do(self.run_scheduled_scans)
            
            # Schedule cleanup tasks daily at 2 AM
            schedule.every().day.at("02:00").do(self.cleanup_old_reports)
            
            # Schedule summary reports weekly on Monday at 9 AM
            schedule.every().monday.at("09:00").do(self.send_weekly_summaries)
            
            # Schedule health checks every hour
            schedule.every().hour.do(self.health_check)
            
            logger.info("📅 Scheduler setup completed")
        except Exception as e:
            logger.error(f"📅 Failed to setup scheduler: {str(e)}")

    def start(self):
        """Start the scheduler in a separate thread"""
        if self.running:
            logger.warning("📅 Scheduler is already running")
            return

        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        logger.info("📅 Scheduler started")

    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("📅 Scheduler stopped")

    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"📅 Scheduler error: {str(e)}")
                time.sleep(60)

    def run_scheduled_scans(self):
        """Run scheduled scans for all repositories"""
        try:
            logger.info("📅 Starting scheduled repository scans")
            
            with next(get_db()) as db:
                # Get all repositories that should be scanned
                repositories = db.query(Repository).filter(
                    Repository.auto_scan == True,
                    Repository.is_active == True
                ).all()

                scan_count = 0
                for repo in repositories:
                    try:
                        # Check if repo needs scanning (last scan was more than 6 hours ago)
                        last_scan = db.query(ScanReport).filter(
                            ScanReport.repository_name == repo.name,
                            ScanReport.user_id == repo.user_id
                        ).order_by(ScanReport.created_at.desc()).first()

                        if last_scan:
                            time_since_scan = datetime.utcnow() - last_scan.created_at
                            if time_since_scan < timedelta(hours=6):
                                continue

                        # Run the scan
                        logger.info(f"📅 Scanning repository: {repo.name}")
                        
                        # Get repository content for scanning
                        scan_result = self._perform_repository_scan(repo, db)
                        
                        if scan_result and scan_result.get('findings'):
                            # Send email alert if high-severity findings
                            high_severity = [f for f in scan_result['findings'] if f.get('severity', '').upper() == 'HIGH']
                            if high_severity and repo.user.email:
                                report_url = f"{os.getenv('APP_URL', 'http://localhost:8000')}/reports/{scan_result['report_id']}"
                                
                                # FIXED: Remove scan_type parameter
                                email_service.send_security_alert_with_url(
                                    to_email=repo.user.email,
                                    repository=repo.name,
                                    findings=scan_result['findings'],
                                    report_url=report_url
                                )

                        scan_count += 1
                        
                    except Exception as e:
                        logger.error(f"📅 Failed to scan repository {repo.name}: {str(e)}")
                        continue

                logger.info(f"📅 Scheduled scans completed. Scanned {scan_count} repositories")

        except Exception as e:
            logger.error(f"📅 Failed to run scheduled scans: {str(e)}")

    def _perform_repository_scan(self, repository: Repository, db: Session) -> Dict[str, Any]:
        """Perform scan on a repository"""
        try:
            # This is a simplified version - you should integrate with your actual scanning logic
            scan_request = {
                'repository_url': repository.url,
                'repository_name': repository.name,
                'user_id': repository.user_id,
                'scan_type': 'scheduled'
            }

            # Call your existing scan service
            result = scan_service.scan_repository(scan_request, db)
            return result

        except Exception as e:
            logger.error(f"📅 Failed to perform repository scan: {str(e)}")
            return None

    def cleanup_old_reports(self):
        """Cleanup old scan reports and logs"""
        try:
            logger.info("📅 Starting cleanup of old reports")
            
            with next(get_db()) as db:
                # Delete reports older than 90 days
                cutoff_date = datetime.utcnow() - timedelta(days=90)
                
                old_reports = db.query(ScanReport).filter(
                    ScanReport.created_at < cutoff_date
                ).all()

                deleted_count = 0
                for report in old_reports:
                    try:
                        # Delete associated files if they exist
                        if hasattr(report, 'report_file_path') and report.report_file_path:
                            if os.path.exists(report.report_file_path):
                                os.remove(report.report_file_path)

                        db.delete(report)
                        deleted_count += 1
                        
                    except Exception as e:
                        logger.error(f"📅 Failed to delete report {report.id}: {str(e)}")
                        continue

                db.commit()
                logger.info(f"📅 Cleanup completed. Deleted {deleted_count} old reports")

        except Exception as e:
            logger.error(f"📅 Failed to cleanup old reports: {str(e)}")

    def send_weekly_summaries(self):
        """Send weekly summary reports to users"""
        try:
            logger.info("📅 Sending weekly summary reports")
            
            with next(get_db()) as db:
                # Get all active users with repositories
                users = db.query(User).join(Repository).filter(
                    Repository.is_active == True
                ).distinct().all()

                for user in users:
                    try:
                        if not user.email:
                            continue

                        # Get user's scan reports from last week
                        week_ago = datetime.utcnow() - timedelta(days=7)
                        
                        reports = db.query(ScanReport).filter(
                            ScanReport.user_id == user.id,
                            ScanReport.created_at >= week_ago
                        ).all()

                        if not reports:
                            continue

                        # Calculate summary statistics
                        total_scans = len(reports)
                        total_findings = sum(len(report.findings) if report.findings else 0 for report in reports)
                        high_severity = sum(
                            len([f for f in report.findings if f.get('severity', '').upper() == 'HIGH']) 
                            if report.findings else 0 
                            for report in reports
                        )

                        # Send weekly summary email
                        self._send_weekly_summary_email(user, total_scans, total_findings, high_severity)

                    except Exception as e:
                        logger.error(f"📅 Failed to send weekly summary for user {user.id}: {str(e)}")
                        continue

                logger.info("📅 Weekly summaries sent")

        except Exception as e:
            logger.error(f"📅 Failed to send weekly summaries: {str(e)}")

    def _send_weekly_summary_email(self, user: User, total_scans: int, total_findings: int, high_severity: int):
        """Send weekly summary email to user"""
        try:
            subject = f"📊 Weekly Security Summary - {total_scans} Scans Completed"
            
            text_body = f"""
Weekly Security Summary - Secret Guardian

Hi {user.username},

Here's your security summary for the past week:

SCAN STATISTICS:
- Total Scans: {total_scans}
- Total Findings: {total_findings}
- High Severity Issues: {high_severity}

"""

            if high_severity > 0:
                text_body += f"""
⚠️  ATTENTION REQUIRED:
You have {high_severity} high-severity security issues that need immediate attention.
Please review your latest scan reports and take appropriate action.

"""

            text_body += """
RECOMMENDATIONS:
- Review all high and medium severity findings
- Update your security policies if needed
- Consider increasing scan frequency for critical repositories

Dashboard: """ + f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard" + """

Best regards,
Secret Guardian Team
"""

            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .container {{ background: #f8f9fa; padding: 20px; border-radius: 8px; }}
        .header {{ text-align: center; color: #007bff; margin-bottom: 20px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; background: white; padding: 15px; border-radius: 5px; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .stat-label {{ font-size: 12px; color: #6c757d; text-transform: uppercase; }}
        .alert {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
        .btn {{ display: inline-block; background: #007bff; color: white; 
               padding: 10px 20px; text-decoration: none; border-radius: 5px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #6c757d; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>📊 Weekly Security Summary</h2>
            <p>Hi {user.username}, here's your security overview for the past week</p>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total_scans}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat">
                <div class="stat-number">{total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat">
                <div class="stat-number">{high_severity}</div>
                <div class="stat-label">High Severity</div>
            </div>
        </div>
"""

            if high_severity > 0:
                html_body += f"""
        <div class="alert">
            <h4>⚠️ Attention Required</h4>
            <p>You have <strong>{high_severity} high-severity</strong> security issues that need immediate attention.</p>
        </div>
"""

            html_body += f"""
        <div style="text-align: center; margin: 30px 0;">
            <a href="{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard" class="btn">
                View Dashboard
            </a>
        </div>

        <div class="footer">
            <p>Keep your repositories secure with Secret Guardian!</p>
        </div>
    </div>
</body>
</html>
"""

            email_service.send_email(user.email, subject, text_body, html_body)
            
        except Exception as e:
            logger.error(f"📅 Failed to send weekly summary email: {str(e)}")

    def health_check(self):
        """Perform system health checks"""
        try:
            logger.info("📅 Running health check")
            
            # Check database connectivity
            with next(get_db()) as db:
                db.execute("SELECT 1")

            # Check email service
            if email_service.sender_email and email_service.sender_password:
                # Email service is configured
                pass

            # Check disk space
            import shutil
            disk_usage = shutil.disk_usage("/")
            free_gb = disk_usage.free // (1024**3)
            
            if free_gb < 1:  # Less than 1GB free
                logger.warning(f"📅 Low disk space: {free_gb}GB remaining")

            logger.info("📅 Health check completed successfully")

        except Exception as e:
            logger.error(f"📅 Health check failed: {str(e)}")

    def get_scheduler_status(self) -> Dict[str, Any]:
        """Get current scheduler status"""
        return {
            "running": self.running,
            "next_scheduled_scan": schedule.next_run().isoformat() if schedule.jobs else None,
            "total_jobs": len(schedule.jobs),
            "jobs": [
                {
                    "job": str(job.job_func),
                    "next_run": job.next_run.isoformat() if job.next_run else None,
                    "interval": str(job.interval)
                }
                for job in schedule.jobs
            ]
        }

    def trigger_immediate_scan(self, repository_id: int):
        """Trigger an immediate scan for a specific repository"""
        try:
            logger.info(f"📅 Triggering immediate scan for repository {repository_id}")
            
            with next(get_db()) as db:
                repository = db.query(Repository).filter(Repository.id == repository_id).first()
                
                if not repository:
                    logger.error(f"📅 Repository {repository_id} not found")
                    return False

                scan_result = self._perform_repository_scan(repository, db)
                
                if scan_result and scan_result.get('findings'):
                    # Send notification if findings exist
                    if repository.user.email:
                        report_url = f"{os.getenv('APP_URL', 'http://localhost:8000')}/reports/{scan_result['report_id']}"
                        
                        # FIXED: Remove scan_type parameter
                        email_service.send_security_alert_with_url(
                            to_email=repository.user.email,
                            repository=repository.name,
                            findings=scan_result['findings'],
                            report_url=report_url
                        )

                logger.info(f"📅 Immediate scan completed for repository {repository_id}")
                return True

        except Exception as e:
            logger.error(f"📅 Failed to trigger immediate scan: {str(e)}")
            return False

# Create global scheduler instance
scheduler_service = SchedulerService()
