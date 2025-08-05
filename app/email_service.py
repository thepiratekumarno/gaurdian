
import os
import ssl
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any
import logging
from . import database

logger = logging.getLogger(__name__)

async def send_security_alert(recipient_email: str, subject: str, findings: List[Dict[str, Any]], report_id: str):
    """Send email alert for security findings - DEDUPLICATION SAFE VERSION"""
    # SMTP Configuration
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    # Validate SMTP configuration
    if not all([smtp_server, smtp_user, smtp_password]):
        logger.error("SMTP configuration incomplete. Required: SMTP_SERVER, SMTP_USER, SMTP_PASSWORD")
        raise ValueError("SMTP configuration incomplete")
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = email_from
    message["To"] = recipient_email
    
    # Create report URL
    report_url = f"{base_url}/reports/{report_id}"
    
    # Create HTML content
    html_content = create_security_alert_html(findings, report_id, report_url, subject)
    
    # Create plain text content
    text_content = create_security_alert_text(findings, report_url, subject)
    
    # Add both versions to message
    part1 = MIMEText(text_content, "plain")
    part2 = MIMEText(html_content, "html")
    
    message.attach(part1)
    message.attach(part2)
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Send email
        await aiosmtplib.send(
            message,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_user,
            password=smtp_password,
            start_tls=True,
            tls_context=context
        )
        
        logger.info(f"Security alert sent to {recipient_email} for {len(findings)} findings")
        
    except Exception as e:
        logger.error(f"Failed to send security alert: {e}")
        logger.error(f"SMTP details: {smtp_server}:{smtp_port}, user: {smtp_user}")
        raise


async def send_no_findings_alert(recipient_email: str, repo_name: str, report_id: str):
    """Send email notification when no findings are detected - NEW REPO ONLY"""
    # SMTP Configuration
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    # Validate SMTP configuration
    if not all([smtp_server, smtp_user, smtp_password]):
        logger.error("SMTP configuration incomplete")
        raise ValueError("SMTP configuration incomplete")
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = f"✅ NEW REPOSITORY: {repo_name} - No Security Issues Found"
    message["From"] = email_from
    message["To"] = recipient_email
    
    # Create report URL
    report_url = f"{base_url}/reports/{report_id}"
    
    # Create HTML content for new repo with no findings
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .success {{ color: #28a745; }}
            .repo-name {{ background-color: #e8f5e8; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }}
            .btn {{ display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="success">✅ New Repository Added - Secure!</h1>
            </div>
            
            <p>Great news! We've automatically detected and scanned your new repository:</p>
            
            <div class="repo-name">
                <strong>{repo_name}</strong>
            </div>
            
            <p><strong>🔒 No security issues found!</strong></p>
            
            <p>Your new repository has been scanned and no exposed secrets or credentials were detected. This is excellent security practice!</p>
            
            <div style="background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3>✅ What we scanned:</h3>
                <ul>
                    <li>🔑 API keys and access tokens</li>
                    <li>🗄️ Database connection strings</li>
                    <li>🔐 Private keys and certificates</li>
                    <li>📧 Email and service credentials</li>
                </ul>
            </div>
            
            <p>Your repository will continue to be monitored automatically for any future commits.</p>
            
            <a href="{report_url}" class="btn">View Full Report</a>
            
            <div class="footer">
                <p><strong>SecretGuardian</strong> - Automated Security Monitoring</p>
                <p>Report ID: {report_id}</p>
                <p>This email was sent to {recipient_email} because you have security scanning enabled.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Create plain text content
    text_content = f"""
    ✅ NEW REPOSITORY ADDED - SECURE!
    
    Great news! We've automatically detected and scanned your new repository:
    
    Repository: {repo_name}
    
    🔒 NO SECURITY ISSUES FOUND!
    
    Your new repository has been scanned and no exposed secrets or credentials were detected. 
    This is excellent security practice!
    
    What we scanned:
    • API keys and access tokens
    • Database connection strings  
    • Private keys and certificates
    • Email and service credentials
    
    Your repository will continue to be monitored automatically for any future commits.
    
    View full report: {report_url}
    
    ---
    SecretGuardian - Automated Security Monitoring
    Report ID: {report_id}
    """
    
    # Add both versions to message
    part1 = MIMEText(text_content, "plain")
    part2 = MIMEText(html_content, "html")
    
    message.attach(part1)
    message.attach(part2)
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Send email
        await aiosmtplib.send(
            message,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_user,
            password=smtp_password,
            start_tls=True,
            tls_context=context
        )
        
        logger.info(f"New repository no-findings alert sent to {recipient_email}")
        
    except Exception as e:
        logger.error(f"Failed to send new repository alert: {e}")
        raise


async def send_commit_clean_alert(recipient_email: str, repo_name: str, report_id: str):
    """Send email notification for clean commits (no findings) - COMMITS ONLY"""
    # SMTP Configuration
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    # Validate SMTP configuration
    if not all([smtp_server, smtp_user, smtp_password]):
        logger.error("SMTP configuration incomplete")
        raise ValueError("SMTP configuration incomplete")
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = f"✅ COMMIT SCAN: {repo_name} - No Security Issues"
    message["From"] = email_from
    message["To"] = recipient_email
    
    # Create report URL
    report_url = f"{base_url}/reports/{report_id}"
    
    # Create HTML content for clean commits
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .success {{ color: #28a745; }}
            .repo-name {{ background-color: #e8f5e8; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }}
            .btn {{ display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="success">✅ Commit Scan Complete - All Clear!</h1>
            </div>
            
            <p>We detected new commits in your repository and automatically scanned the latest changes:</p>
            
            <div class="repo-name">
                <strong>{repo_name}</strong>
            </div>
            
            <p><strong>🔒 No security issues found in your latest commits!</strong></p>
            
            <p>Your code changes look secure and don't contain any exposed secrets. Great job maintaining secure coding practices!</p>
            
            <a href="{report_url}" class="btn">View Full Report</a>
            
            <div class="footer">
                <p><strong>SecretGuardian</strong> - Automatic Repository Security Monitoring</p>
                <p>Report ID: {report_id}</p>
                <p>This scan was triggered by detecting new commits in your repository.</p>
                <p>This email was sent to {recipient_email} because you have security scanning enabled.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Create plain text content
    text_content = f"""
    ✅ COMMIT SCAN COMPLETE - ALL CLEAR!
    
    We detected new commits in your repository and automatically scanned the latest changes:
    
    Repository: {repo_name}
    
    🔒 NO SECURITY ISSUES FOUND IN YOUR LATEST COMMITS!
    
    Your code changes look secure and don't contain any exposed secrets. 
    Great job maintaining secure coding practices!
    
    View full report: {report_url}
    
    ---
    SecretGuardian - Automatic Repository Security Monitoring
    Report ID: {report_id}
    This scan was triggered by detecting new commits in your repository.
    """
    
    # Add both versions to message
    part1 = MIMEText(text_content, "plain")
    part2 = MIMEText(html_content, "html")
    
    message.attach(part1)
    message.attach(part2)
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Send email
        await aiosmtplib.send(
            message,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_user,
            password=smtp_password,
            start_tls=True,
            tls_context=context
        )
        
        logger.info(f"Clean commit alert sent to {recipient_email}")
        
    except Exception as e:
        logger.error(f"Failed to send clean commit alert: {e}")
        raise


def create_security_alert_html(findings: List[Dict[str, Any]], report_id: str, report_url: str, subject: str) -> str:
    """Create HTML content for security alert with enhanced subject context"""
    
    # Determine email type from subject
    if "NEW REPO" in subject:
        email_type = "New Repository"
        alert_icon = "🆕"
        alert_color = "#17a2b8"
    elif "BATCH COMMIT" in subject:
        email_type = "Batch Commits"
        alert_icon = "🔓"
        alert_color = "#fd7e14"
    else:
        email_type = "Recent Commits"
        alert_icon = "🔄"
        alert_color = "#ffc107"
    
    findings_html = ""
    for i, finding in enumerate(findings, 1):
        findings_html += f"""
        <div style="border: 1px solid #dc3545; border-radius: 5px; padding: 15px; margin: 10px 0; background-color: #f8d7da;">
            <h3 style="margin-top: 0; color: #721c24;">Finding #{i}: {finding.get('type', 'Unknown')}</h3>
            <p><strong>Location:</strong> {finding.get('location', 'N/A')}</p>
            <p><strong>Line:</strong> {finding.get('line', 'N/A')}</p>
            <p><strong>Confidence:</strong> {finding.get('confidence', 0):.0%}</p>
            <p><strong>Context:</strong></p>
            <pre style="background-color: #f1f1f1; padding: 10px; border-radius: 3px; overflow-x: auto;"><code>{finding.get('context', '')}</code></pre>
            <p><strong>Recommendation:</strong> {finding.get('recommendation', 'Review and remove this secret')}</p>
        </div>
        """
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; background-color: {alert_color}; color: white; padding: 20px; border-radius: 8px; }}
            .alert {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }}
            .btn {{ display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{alert_icon} Security Alert - {email_type}</h1>
                <p>We found <strong>{len(findings)} potential secret(s)</strong> that require immediate attention</p>
            </div>
            
            <div class="alert">
                <h2>⚠️ Action Required</h2>
                <p>Security vulnerabilities have been detected in your repository. Please review and address these findings immediately to protect your application.</p>
            </div>
            
            {findings_html}
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{report_url}" class="btn">View Full Report in Dashboard</a>
            </div>
            
            <div class="footer">
                <p><strong>SecretGuardian</strong> - Automated Security Scanning</p>
                <p>Report ID: {report_id}</p>
                <p>This alert was generated by SecretGuardian's automated security scanning service.</p>
                <p>This email was sent because you have security scanning enabled for your repositories.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_content


def create_security_alert_text(findings: List[Dict[str, Any]], report_url: str, subject: str) -> str:
    """Create plain text content for security alert"""
    
    findings_text = ""
    for i, finding in enumerate(findings, 1):
        findings_text += f"""
Finding #{i}: {finding.get('type', 'Unknown')}
Location: {finding.get('location', 'N/A')}
Line: {finding.get('line', 'N/A')}
Confidence: {finding.get('confidence', 0):.0%}
Context: {finding.get('context', '')}
Recommendation: {finding.get('recommendation', 'Review and remove this secret')}

---
"""
    
    text_content = f"""
SECURITY ALERT - SECRETS DETECTED

We found {len(findings)} potential secret(s) in your repository that require immediate attention.

⚠️ ACTION REQUIRED
Security vulnerabilities have been detected in your repository. Please review and address these findings immediately to protect your application.

{findings_text}

View full report: {report_url}

---
SecretGuardian - Automated Security Scanning
This alert was generated by SecretGuardian's automated security scanning service.
"""
    
    return text_content
