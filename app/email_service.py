import aiosmtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header  # Add this import
import os
from dotenv import load_dotenv
from typing import List, Dict, Any
import logging



load_dotenv()

logger = logging.getLogger(__name__)


async def send_security_alert(recipient_email: str, subject: str, findings: List[Dict[str, Any]], report_id: str):
    """Send security alert email with improved deliverability"""
    # Configuration
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM")
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    # Create message with proper headers
    message = MIMEMultipart("alternative")
    
    # Properly formatted sender address
    # ✅ This works with Zoho
    message["From"] = smtp_user
    message["To"] = recipient_email
    
    # Non-alarming subject line
    message["Subject"] = Header(f"Security Report for Your Repository - Action Required", "utf-8")
    
    # Important headers to prevent spam classification
    message["X-Mailer"] = "SecretGuardian/1.0"
    message["X-Priority"] = "1"  # Highest priority
    message["X-MSMail-Priority"] = "High"
    message["Importance"] = "High"
    message["Precedence"] = "bulk"
    message["Auto-Submitted"] = "auto-generated"
    message["List-Unsubscribe"] = f"<mailto:support@secretguardian.com?subject=Unsubscribe>"
    
    # Create report URL
    report_url = f"{base_url}/reports/{report_id}"
    
    # Create email content
    html_content = create_security_alert_html(findings, report_id, report_url)
    text_content = create_security_alert_text(findings, report_url)
    
    # Add both versions to message
    message.attach(MIMEText(text_content, "plain"))
    message.attach(MIMEText(html_content, "html"))
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Send email using Zoho's SMTP
        await aiosmtplib.send(
            message,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_user,
            password=smtp_password,
            start_tls=True,
            tls_context=context
        )
        print(f"Security alert sent to {recipient_email}")
        
    except Exception as e:
        print(f"Failed to send email: {e}")
        print(f"SMTP details: {smtp_server}:{smtp_port}, user: {smtp_user}")
        
# Add this function to email_service.py
async def send_no_findings_alert(recipient_email: str, repo_name: str, report_id: str):
    """Send email notification when no findings are detected"""
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = f"✅ Security Scan Complete: {repo_name}"
    message["From"] = email_from
    message["To"] = recipient_email
    
    # Create report URL
    report_url = f"{base_url}/reports/{report_id}"
    
    # Create HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>SecretGuardian Security Scan</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;">
                <h1 style="margin: 0; font-size: 28px;">✅ SecretGuardian</h1>
                <p style="margin: 10px 0 0 0; font-size: 16px;">Security Scan Complete - No Issues Found</p>
            </div>
            
            <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                    <h3 style="color: #155724; margin: 0 0 10px 0;">✅ Security Scan Successful</h3>
                    <p style="margin: 0; color: #155724;">We scanned <strong>{repo_name}</strong> and found no exposed secrets!</p>
                </div>
                
                <p>Great job maintaining secure coding practices! Here's what we did:</p>
                <ul>
                    <li>Scanned all files in the repository</li>
                    <li>Checked for over 15 types of sensitive data patterns</li>
                    <li>Analyzed high-entropy strings that could be secrets</li>
                </ul>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="{report_url}" style="background: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">View Full Report</a>
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">
                
                <div style="text-align: center; color: #6c757d; font-size: 14px;">
                    <p>This alert was generated by SecretGuardian - your automated security scanning service.</p>
                    <p>Report ID: {report_id}</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Create plain text version
    text_content = f"""
    ✅ SECRETGUARDIAN SECURITY SCAN COMPLETE ✅
    
    We scanned {repo_name} and found no exposed secrets!
    
    Great job maintaining secure coding practices! 
    
    View full report: {report_url}
    
    This alert was generated by SecretGuardian - your automated security scanning service.
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
        print(f"No-findings alert sent to {recipient_email}")
        
    except Exception as e:
        print(f"Failed to send no-findings email: {e}")

def create_security_alert_html(findings: List[Dict[str, Any]], report_id: str, report_url: str) -> str:
    """Create HTML email content for security alert"""
    
    findings_html = ""
    for i, finding in enumerate(findings, 1):
        severity_color = get_severity_color(finding.get('confidence', 0))
        
        findings_html += f"""
        <div style="border-left: 4px solid {severity_color}; padding-left: 15px; margin: 15px 0;">
            <h4 style="color: {severity_color}; margin: 0;">Finding #{i}: {finding.get('type', 'Unknown')}</h4>
            <p><strong>Location:</strong> {finding.get('location', 'N/A')}</p>
            <p><strong>Line:</strong> {finding.get('line', 'N/A')}</p>
            <p><strong>Confidence:</strong> {finding.get('confidence', 0):.2%}</p>
            <p><strong>Context:</strong> <code>{finding.get('context', '')}</code></p>
            <p><strong>Recommendation:</strong> {finding.get('recommendation', 'Review and remove this secret')}</p>
        </div>
        """
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>SecretGuardian Security Alert</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;">
                <h1 style="margin: 0; font-size: 28px;">🛡️ SecretGuardian</h1>
                <p style="margin: 10px 0 0 0; font-size: 16px;">Security Alert - Secrets Detected</p>
            </div>
            
            <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                    <h3 style="color: #856404; margin: 0 0 10px 0;">⚠️ Security Issue Detected</h3>
                    <p style="margin: 0; color: #856404;">We found <strong>{len(findings)} potential secret(s)</strong> in your repository that require immediate attention.</p>
                </div>
                
                <h3 style="color: #333; margin-bottom: 20px;">📋 Findings Details:</h3>
                {findings_html}
                
                <div style="background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin-top: 20px;">
                    <h4 style="color: #0c5460; margin: 0 0 10px 0;">🔒 Security Recommendations:</h4>
                    <ul style="color: #0c5460; margin: 0; padding-left: 20px;">
                        <li>Remove all detected secrets from your code immediately</li>
                        <li>Rotate any compromised credentials</li>
                        <li>Use environment variables or secure secret management systems</li>
                        <li>Review your commit history for additional exposures</li>
                        <li>Consider using .gitignore for sensitive files</li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="{report_url}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">View Full Report</a>
                </div>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">
                
                <div style="text-align: center; color: #6c757d; font-size: 14px;">
                    <p>This alert was generated by SecretGuardian - your automated security scanning service.</p>
                    <p>Report ID: {report_id}</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Add these elements to reduce spam score:
    html_template += """
    <div style="display:none; font-size:0; line-height:0;">
        This is a security alert from SecretGuardian. You're receiving this because 
        you have repositories monitored by our security scanning service.
    </div>
    <p style="font-size:12px; color:#6c757d;">
        This email was sent to ${recipient_email} because you have security scanning 
        enabled for your repositories. If you believe this was sent in error, 
        please contact support.
    </p>
    """
    
    # Add these elements to reduce spam score:
    html_template += """
    <!-- Anti-spam text -->
    <div style="display:none; font-size:0; line-height:0;">
        This is an automated security report from SecretGuardian. 
        You're receiving this because you have repositories monitored by our service.
        SecretGuardian helps you find and fix exposed secrets in your code.
    </div>
    
    <!-- Professional signature -->
    <div style="border-top:1px solid #eee; margin-top:30px; padding-top:15px;">
        <p>Best regards,<br>The SecretGuardian Security Team</p>
        <p style="font-size:12px; color:#777;">
            This is an automated message. Please do not reply directly to this email.
            Contact support@secretguardian.com for assistance.
        </p>
    </div>
    
    <!-- Physical address for compliance -->
    <p style="font-size:10px; color:#999; margin-top:20px;">
        SecretGuardian Inc.<br>
        123 Security Lane, San Francisco, CA 94107<br>
        Unsubscribe: <a href="%unsubscribe_url%">Manage Preferences</a>
    </p>
    """
    
    return html_template

def create_security_alert_text(findings: List[Dict[str, Any]], report_url: str) -> str:
    """Create plain text email content for security alert"""
    
    content = f"""
🛡️ SECRETGUARDIAN SECURITY ALERT 🛡️

⚠️  SECURITY ISSUE DETECTED ⚠️

We found {len(findings)} potential secret(s) in your repository that require immediate attention.

FINDINGS DETAILS:
{'='*50}
"""
    
    for i, finding in enumerate(findings, 1):
        content += f"""
Finding #{i}: {finding.get('type', 'Unknown')}
Location: {finding.get('location', 'N/A')}
Line: {finding.get('line', 'N/A')}
Confidence: {finding.get('confidence', 0):.2%}
Context: {finding.get('context', '')}
Recommendation: {finding.get('recommendation', 'Review and remove this secret')}

{'-'*40}
"""
    
    content += f"""
🔒 SECURITY RECOMMENDATIONS:
• Remove all detected secrets from your code immediately
• Rotate any compromised credentials  
• Use environment variables or secure secret management systems
• Review your commit history for additional exposures
• Consider using .gitignore for sensitive files

View full report: {report_url}

This alert was generated by SecretGuardian - your automated security scanning service.
"""
    
    return content

def get_severity_color(confidence: float) -> str:
    """Get color based on confidence/severity"""
    if confidence >= 0.8:
        return "#dc3545"  # Red - High
    elif confidence >= 0.6:
        return "#fd7e14"  # Orange - Medium  
    else:
        return "#ffc107"  # Yellow - Low
    
async def send_scan_notification(recipient_email: str, repo_name: str, success: bool, findings_count: int):
    """Send scan completion notification"""
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM", smtp_user)
    
    # Create message
    message = MIMEMultipart("alternative")
    subject = f"✅ Scan Complete: {repo_name}" if success else f"❌ Scan Failed: {repo_name}"
    message["Subject"] = subject
    message["From"] = email_from
    message["To"] = recipient_email
    
    # Create content
    if success:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <h2>Scan Completed Successfully</h2>
            <p>Repository: <strong>{repo_name}</strong></p>
            <p>Findings detected: <strong>{findings_count}</strong></p>
            <p>You can view detailed results in your SecretGuardian dashboard.</p>
        </body>
        </html>
        """
        text_content = f"Scan completed for {repo_name}\nFindings: {findings_count}"
    else:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <h2>Scan Failed</h2>
            <p>Repository: <strong>{repo_name}</strong></p>
            <p>The scan encountered an error. Please try again or contact support.</p>
        </body>
        </html>
        """
        text_content = f"Scan failed for {repo_name}"
    
    # Add both versions to message
    message.attach(MIMEText(text_content, "plain"))
    message.attach(MIMEText(html_content, "html"))
    
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
        logger.info(f"Scan notification sent to {recipient_email}")
        
    except Exception as e:
        logger.error(f"Failed to send scan notification: {e}")
