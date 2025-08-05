

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Email configuration - EXACTLY matching your .env file
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.zoho.in")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")  # secretguardian@zohomail.in
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")  # rP2xdnF5S7MA
EMAIL_FROM = os.getenv("EMAIL_FROM")  # secretguardian@zohomail.in
BASE_URL = os.getenv("BASE_URL", "https://secretguardian.onrender.com")

async def send_security_alert_with_url(
    user_email: str,
    repository_name: str,
    findings_count: int,
    report_id: str,
):
    """Send a minimal GitHub-style alert with only essentials."""

    subject = (
        f"Action needed: Secrets detected in {repository_name}"
        if findings_count
        else f"Scan completed: No secrets detected in {repository_name}"
    )

    report_url = f"{BASE_URL}/reports/{report_id}"

    # Plain text body (very short)
    text_body = (
        f"{subject}\n\nOpen detailed report: {report_url}\n"
    )

    # Minimal dark-theme HTML body similar to official GitHub email
    html_body = f"""
<!DOCTYPE html>
<html><body style="margin:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#c9d1d9;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;margin:auto;">
    <tr><td style="padding:32px 24px;">
      <h2 style="color:#f0f6fc;font-size:24px;margin:0 0 16px;">{subject}</h2>
      <p style="margin:0 0 24px;">{findings_count} potential secret{'' if findings_count==1 else 's'} detected • <a href="{report_url}" style="color:#58a6ff;">View report</a></p>
      <a href="{report_url}" style="display:inline-block;background:#238636;color:#fff;text-decoration:none;padding:10px 16px;border-radius:6px;font-weight:600;font-size:14px;">View detailed report</a>
    </td></tr>
  </table>
</body></html>"""

    msg = MIMEMultipart('alternative')
    msg['From'] = EMAIL_FROM
    msg['To'] = user_email
    msg['Subject'] = subject
    msg.attach(MIMEText(text_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    return _send(msg, user_email)

# -----------------------------------------------------------------------------
# WELCOME EMAIL (very short)
# -----------------------------------------------------------------------------
async def send_welcome_email_for_new_user(user_email: str, username: str, repos_count: int):
    subject = "Welcome to Secret Guardian"
    dashboard = f"{BASE_URL}/dashboard"
    text = (
        f"Hi {username}, Secret Guardian is now monitoring your GitHub account. "
        f"We found {repos_count} repositories. We'll alert you only when you push new commits or create repos. "
        f"Dashboard: {dashboard}\n"
    )
    html = f"""
<html><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f6f8fa;">
  <div style="max-width:600px;margin:auto;background:#fff;padding:24px;">
    <h2 style="color:#24292f;margin:0 0 16px;">Welcome to Secret Guardian</h2>
    <p style="margin:0 0 8px;">Hi {username}, we're set up and watching {repos_count} repositories.</p>
    <p style="margin:0 0 24px;">We'll email you only when new commits or repositories contain potential secrets.</p>
    <a href="{dashboard}" style="display:inline-block;background:#2da44e;color:#fff;padding:10px 16px;text-decoration:none;border-radius:6px;font-weight:600;">Open Dashboard</a>
  </div>
</body></html>"""
    msg = MIMEMultipart('alternative')
    msg['From'] = EMAIL_FROM
    msg['To'] = user_email
    msg['Subject'] = subject
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))
    return _send(msg, user_email)



# Legacy function names for backward compatibility with existing code
async def send_security_alert(user_email: str, subject: str, findings: list, report_id: str):
    """Legacy wrapper - redirects to secure URL-based email"""
    repository_name = "Unknown"
    if findings and len(findings) > 0:
        repository_name = findings[0].get("repository", "Unknown")
    
    return await send_security_alert_with_url(
        user_email=user_email,
        repository_name=repository_name,
        findings_count=len(findings),
        report_id=report_id,
        scan_type="commit"
    )

async def send_no_findings_alert(user_email: str, repository_name: str, report_id: str):
    """Legacy wrapper - redirects to secure URL-based email"""
    return await send_security_alert_with_url(
        user_email=user_email,
        repository_name=repository_name,
        findings_count=0,
        report_id=report_id,
        scan_type="new_repository"
    )

async def send_commit_clean_alert(user_email: str, repository_name: str, report_id: str):
    """Legacy wrapper - redirects to secure URL-based email"""
    return await send_security_alert_with_url(
        user_email=user_email,
        repository_name=repository_name,
        findings_count=0,
        report_id=report_id,
        scan_type="commit"
    )


# Test function to verify email configuration
async def test_email_configuration():
    """
    Test function to verify email setup with your Zoho configuration
    """
    try:
        print("Testing email configuration...")
        print(f"SMTP Server: {SMTP_SERVER}")
        print(f"SMTP Port: {SMTP_PORT}")
        print(f"SMTP User: {SMTP_USER}")
        print(f"Email From: {EMAIL_FROM}")
        print(f"Base URL: {BASE_URL}")
        
        # Test SMTP connection
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.quit()
        
        print("✅ Email configuration is correct!")
        return True
        
    except Exception as e:
        print(f"❌ Email configuration error: {e}")
        return False
