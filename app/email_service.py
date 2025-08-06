# email_service.py - SECURE EMAIL SERVICE matching your .env file exactly

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

async def send_security_alert_with_url(user_email: str, repository_name: str, findings_count: int, report_id: str, scan_type: str = "commit"):
    """
    Send security alert email with URL to view full report instead of showing secrets directly
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = user_email
        
        # Determine subject based on scan type
        if scan_type == "new_repository":
            subject = f"🆕 New Repository Alert: {repository_name}"
            scan_emoji = "🆕"
            scan_description = "new repository"
        elif scan_type == "post_freeze_commits":
            subject = f"🔓 Batch Commits Alert: {repository_name}"
            scan_emoji = "🔓"
            scan_description = "recent commits"
        else:
            subject = f"🔄 Commit Alert: {repository_name}"
            scan_emoji = "🔄"
            scan_description = "latest commit"
        
        if findings_count > 0:
            subject += f" - {findings_count} potential secrets detected"
        else:
            subject += " - Clean scan"
        
        msg['Subject'] = subject
        
        # Create report URL
        report_url = f"{BASE_URL}/reports/{report_id}"
        
        # Create HTML email body with GitHub-style design
        if findings_count > 0:
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f6f8fa; }}
                    .container {{ max-width: 600px; margin: 0 auto; background-color: white; }}
                    .header {{ background: linear-gradient(135deg, #d73a49, #cb2431); color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 30px; }}
                    .alert-box {{ background-color: #fff5f5; border: 1px solid #fed7d7; border-radius: 6px; padding: 16px; margin: 20px 0; }}
                    .alert-icon {{ font-size: 24px; margin-right: 8px; }}
                    .repo-name {{ font-family: 'SFMono-Regular', Consolas, monospace; background-color: #f6f8fa; padding: 2px 6px; border-radius: 3px; }}
                    .cta-button {{ display: inline-block; background-color: #0366d6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }}
                    .cta-button:hover {{ background-color: #0256cc; }}
                    .footer {{ background-color: #f6f8fa; padding: 20px; text-align: center; font-size: 12px; color: #586069; }}
                    .warning-text {{ color: #d73a49; font-weight: 600; }}
                    .stats {{ background-color: #f6f8fa; padding: 15px; border-radius: 6px; margin: 15px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>{scan_emoji} Secret Guardian Alert</h1>
                        <p>Security scan completed for your repository</p>
                    </div>
                    
                    <div class="content">
                        <div class="alert-box">
                            <span class="alert-icon">⚠️</span>
                            <strong class="warning-text">Potential secrets detected in your {scan_description}</strong>
                        </div>
                        
                        <h2>Repository: <span class="repo-name">{repository_name}</span></h2>
                        
                        <div class="stats">
                            <p><strong>📊 Scan Results:</strong></p>
                            <ul>
                                <li>🚨 <strong>{findings_count}</strong> potential secrets found</li>
                                <li>🔍 Scan type: {scan_description.title()}</li>
                                <li>⏰ Scanned at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</li>
                            </ul>
                        </div>
                        
                        <p><strong>🔐 For security reasons, sensitive details are not included in this email.</strong></p>
                        
                        <p>Click the button below to view the complete security report on our secure platform:</p>
                        
                        <div style="text-align: center;">
                            <a href="{report_url}" class="cta-button">
                                🔍 View Detailed Security Report
                            </a>
                        </div>
                        
                        <div style="margin-top: 30px; padding: 15px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px;">
                            <p><strong>🛡️ Recommended Actions:</strong></p>
                            <ol>
                                <li>Review the detailed report immediately</li>
                                <li>Remove any confirmed secrets from your repository</li>
                                <li>Rotate any compromised credentials</li>
                                <li>Consider using environment variables or secret management tools</li>
                            </ol>
                        </div>
                        
                        <p style="margin-top: 20px; font-size: 14px; color: #586069;">
                            <strong>Note:</strong> This is an automated security scan. Please review the findings to determine if they are actual secrets or false positives.
                        </p>
                    </div>
                    
                    <div class="footer">
                        <p>This email was sent by <strong>Secret Guardian</strong> - Your automated security scanner</p>
                        <p>Visit: <a href="{BASE_URL}">{BASE_URL}</a></p>
                    </div>
                </div>
            </body>
            </html>
            """
        else:
            # Clean scan email
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f6f8fa; }}
                    .container {{ max-width: 600px; margin: 0 auto; background-color: white; }}
                    .header {{ background: linear-gradient(135deg, #28a745, #22863a); color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 30px; }}
                    .success-box {{ background-color: #f0fff4; border: 1px solid #9ae6b4; border-radius: 6px; padding: 16px; margin: 20px 0; }}
                    .repo-name {{ font-family: 'SFMono-Regular', Consolas, monospace; background-color: #f6f8fa; padding: 2px 6px; border-radius: 3px; }}
                    .cta-button {{ display: inline-block; background-color: #0366d6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }}
                    .footer {{ background-color: #f6f8fa; padding: 20px; text-align: center; font-size: 12px; color: #586069; }}
                    .success-text {{ color: #28a745; font-weight: 600; }}
                    .stats {{ background-color: #f6f8fa; padding: 15px; border-radius: 6px; margin: 15px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>✅ Secret Guardian - Clean Scan</h1>
                        <p>No security issues detected</p>
                    </div>
                    
                    <div class="content">
                        <div class="success-box">
                            <span style="font-size: 24px; margin-right: 8px;">✅</span>
                            <strong class="success-text">No potential secrets detected in your {scan_description}</strong>
                        </div>
                        
                        <h2>Repository: <span class="repo-name">{repository_name}</span></h2>
                        
                        <div class="stats">
                            <p><strong>📊 Scan Results:</strong></p>
                            <ul>
                                <li>✅ <strong>0</strong> potential secrets found</li>
                                <li>🔍 Scan type: {scan_description.title()}</li>
                                <li>⏰ Scanned at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</li>
                            </ul>
                        </div>
                        
                        <p>Great job! Your {scan_description} appears to be free of potential secrets and sensitive information.</p>
                        
                        <div style="text-align: center;">
                            <a href="{report_url}" class="cta-button">
                                📋 View Complete Report
                            </a>
                        </div>
                        
                        <div style="margin-top: 30px; padding: 15px; background-color: #d1ecf1; border: 1px solid #bee5eb; border-radius: 6px;">
                            <p><strong>🛡️ Security Best Practices:</strong></p>
                            <ul>
                                <li>Keep using environment variables for sensitive data</li>
                                <li>Regularly review your code for hardcoded credentials</li>
                                <li>Use .gitignore to exclude sensitive files</li>
                                <li>Consider using secret management tools</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>This email was sent by <strong>Secret Guardian</strong> - Your automated security scanner</p>
                        <p>Visit: <a href="{BASE_URL}">{BASE_URL}</a></p>
                    </div>
                </div>
            </body>
            </html>
            """
        
        # Create plain text version for email clients that don't support HTML
        if findings_count > 0:
            text_body = f"""
Secret Guardian Security Alert

Repository: {repository_name}
Scan Type: {scan_description.title()}
Findings: {findings_count} potential secrets detected

For security reasons, sensitive details are not included in this email.

View your detailed security report at:
{report_url}

Recommended Actions:
1. Review the detailed report immediately
2. Remove any confirmed secrets from your repository
3. Rotate any compromised credentials
4. Consider using environment variables or secret management tools

This is an automated security scan. Please review the findings to determine if they are actual secrets or false positives.

Visit Secret Guardian: {BASE_URL}
            """
        else:
            text_body = f"""
Secret Guardian - Clean Scan

Repository: {repository_name}
Scan Type: {scan_description.title()}
Result: No potential secrets detected

Great job! Your {scan_description} appears to be free of potential secrets and sensitive information.

View your complete report at:
{report_url}

Keep up the great security practices!

Visit Secret Guardian: {BASE_URL}
            """
        
        # Attach both HTML and plain text
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email using your exact SMTP settings
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, user_email, text)
        server.quit()
        
        logger.info(f"✅ Secure email alert sent to {user_email} for {repository_name} (Report: {report_id})")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send secure email alert: {e}")
        return False


async def send_welcome_email_for_new_user(user_email: str, username: str, repos_count: int):
    """
    Send welcome email to new users explaining that repos are fetched but not automatically scanned
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = user_email
        msg['Subject'] = f"🎉 Welcome to Secret Guardian, {username}!"
        
        # Create HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background-color: #f6f8fa; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; }}
                .header {{ background: linear-gradient(135deg, #0366d6, #005cc5); color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; }}
                .info-box {{ background-color: #f0f8ff; border: 1px solid #c8e1ff; border-radius: 6px; padding: 16px; margin: 20px 0; }}
                .cta-button {{ display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 20px 0; }}
                .footer {{ background-color: #f6f8fa; padding: 20px; text-align: center; font-size: 12px; color: #586069; }}
                .feature-list {{ background-color: #f6f8fa; padding: 15px; border-radius: 6px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Welcome to Secret Guardian!</h1>
                    <p>Hi {username}, your account is now active</p>
                </div>
                
                <div class="content">
                    <div class="info-box">
                        <span style="font-size: 24px; margin-right: 8px;">📋</span>
                        <strong>We've found {repos_count} repositories in your GitHub account</strong>
                    </div>
                    
                    <h2>🛡️ How Secret Guardian Works</h2>
                    
                    <div class="feature-list">
                        <p><strong>📋 Repository Discovery:</strong></p>
                        <ul>
                            <li>✅ We've automatically discovered your existing repositories</li>
                            <li>🔄 We'll monitor for new repositories you create</li>
                            <li>📧 You'll only receive alerts for actual activity</li>
                        </ul>
                    </div>
                    
                    <div class="feature-list">
                        <p><strong>🔍 Automatic Scanning Triggers:</strong></p>
                        <ul>
                            <li>🆕 When you create a new repository</li>
                            <li>📝 When you commit changes to any repository</li>
                            <li>🔄 When you push updates to existing repositories</li>
                        </ul>
                    </div>
                    
                    <div style="margin-top: 30px; padding: 15px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px;">
                        <p><strong>💡 Important:</strong></p>
                        <p>We <strong>don't automatically scan your existing repositories</strong> when you first join. This prevents spam emails and respects your privacy. Scanning only happens when you make changes to your code.</p>
                    </div>
                    
                    <h3>🚀 Want to scan existing repositories?</h3>
                    <p>You can manually trigger scans for any repository from your dashboard when you're ready.</p>
                    
                    <div style="text-align: center;">
                        <a href="{BASE_URL}/dashboard" class="cta-button">
                            🏠 Go to Dashboard
                        </a>
                    </div>
                    
                    <div class="feature-list">
                        <p><strong>🎯 What happens next:</strong></p>
                        <ul>
                            <li>🔄 We'll monitor your repositories for new activity</li>
                            <li>📧 You'll receive email alerts only when secrets are detected</li>
                            <li>🔗 Email alerts will contain secure links to detailed reports</li>
                            <li>🛡️ Your sensitive data stays secure and private</li>
                        </ul>
                    </div>
                </div>
                
                <div class="footer">
                    <p>Welcome to <strong>Secret Guardian</strong> - Your automated security scanner</p>
                    <p>Visit: <a href="{BASE_URL}">{BASE_URL}</a></p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version
        text_body = f"""
Welcome to Secret Guardian, {username}!

We've found {repos_count} repositories in your GitHub account.

How Secret Guardian Works:
- Repository Discovery: We've automatically discovered your existing repositories
- Automatic Scanning: We'll scan repositories when you create new ones or commit changes
- No Spam: We don't automatically scan existing repositories when you first join

What happens next:
1. We'll monitor your repositories for new activity
2. You'll receive email alerts only when secrets are detected  
3. Email alerts will contain secure links to detailed reports
4. Your sensitive data stays secure and private

Want to scan existing repositories? You can manually trigger scans from your dashboard.

Visit your dashboard: {BASE_URL}/dashboard

Welcome to Secret Guardian!
Visit: {BASE_URL}
        """
        
        # Attach both HTML and plain text
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email using your exact SMTP settings
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        
        text = msg.as_string()
        server.sendmail(EMAIL_FROM, user_email, text)
        server.quit()
        
        logger.info(f"✅ Welcome email sent to new user {user_email} ({repos_count} repos discovered)")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send welcome email: {e}")
        return False


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
