import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from typing import Optional, List, Dict, Any
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.sender_email = os.getenv("SENDER_EMAIL")
        self.sender_password = os.getenv("SENDER_PASSWORD")
        
        if not self.sender_email or not self.sender_password:
            logger.warning("Email credentials not configured. Email notifications will be disabled.")

    def _create_smtp_connection(self):
        """Create and return authenticated SMTP connection"""
        if not self.sender_email or not self.sender_password:
            raise ValueError("Email credentials not configured")
            
        context = ssl.create_default_context()
        server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        server.starttls(context=context)
        server.login(self.sender_email, self.sender_password)
        return server

    def send_email(self, to_email: str, subject: str, body: str, html_body: str = None, attachments: List[str] = None) -> bool:
        """Send email with optional HTML body and attachments"""
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = to_email

            # Add text part
            text_part = MIMEText(body, "plain")
            message.attach(text_part)

            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, "html")
                message.attach(html_part)

            # Add attachments if provided
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                        
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {os.path.basename(file_path)}'
                        )
                        message.attach(part)

            # Send email
            with self._create_smtp_connection() as server:
                server.send_message(message)
                
            logger.info(f"📧 Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"📧 Failed to send email to {to_email}: {str(e)}")
            return False

    def send_security_alert(self, to_email: str, repository: str, findings: List[Dict[str, Any]], report_url: str = None) -> bool:
        """Send security alert email for repository scan findings"""
        try:
            # Count findings by severity
            severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1

            total_findings = len(findings)
            critical_findings = severity_counts["HIGH"]
            
            # Email subject
            subject = f"🔒 Security Alert: {critical_findings} Critical Issues Found in {repository}"
            
            # Plain text body
            text_body = f"""
Security Scan Alert - Secret Guardian

Repository: {repository}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FINDINGS SUMMARY:
- High Severity: {severity_counts['HIGH']} issues
- Medium Severity: {severity_counts['MEDIUM']} issues  
- Low Severity: {severity_counts['LOW']} issues
- Info: {severity_counts['INFO']} issues

Total Issues Found: {total_findings}

TOP FINDINGS:
"""
            
            # Add top 5 findings to text body
            for i, finding in enumerate(findings[:5], 1):
                text_body += f"""
{i}. {finding.get('type', 'Unknown')} (Severity: {finding.get('severity', 'Unknown')})
   File: {finding.get('file_path', 'Unknown')}
   Line: {finding.get('line_number', 'Unknown')}
   Description: {finding.get('description', 'No description')}
"""

            if report_url:
                text_body += f"\n\nView Full Report: {report_url}"
            
            text_body += "\n\nBest regards,\nSecret Guardian Security Team"

            # HTML body
            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            background-color: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #dc3545;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #dc3545;
            margin: 0;
            font-size: 24px;
        }}
        .alert-badge {{
            background: #dc3545;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .summary {{
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin: 20px 0;
            border-radius: 0 5px 5px 0;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            text-align: center;
        }}
        .stat {{
            flex: 1;
            padding: 15px;
            background: #f8f9fa;
            margin: 0 5px;
            border-radius: 5px;
            border-top: 3px solid #6c757d;
        }}
        .stat.high {{ border-top-color: #dc3545; }}
        .stat.medium {{ border-top-color: #fd7e14; }}
        .stat.low {{ border-top-color: #ffc107; }}
        .stat.info {{ border-top-color: #17a2b8; }}
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: #495057;
        }}
        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            color: #6c757d;
        }}
        .findings {{
            margin: 30px 0;
        }}
        .finding {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #6c757d;
        }}
        .finding.high {{ border-left-color: #dc3545; }}
        .finding.medium {{ border-left-color: #fd7e14; }}
        .finding.low {{ border-left-color: #ffc107; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .finding-title {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 5px;
        }}
        .finding-meta {{
            font-size: 12px;
            color: #6c757d;
            margin-bottom: 8px;
        }}
        .btn {{
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
            font-size: 14px;
        }}
        @media (max-width: 600px) {{
            .stats {{ flex-direction: column; }}
            .stat {{ margin: 5px 0; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="alert-badge">Security Alert</span>
            <h1>🔒 Secret Guardian Alert</h1>
        </div>
        
        <div class="summary">
            <h3>📊 Scan Summary</h3>
            <p><strong>Repository:</strong> {repository}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Issues:</strong> {total_findings}</p>
            <p><strong>Critical Issues:</strong> {critical_findings}</p>
        </div>

        <div class="stats">
            <div class="stat high">
                <div class="stat-number">{severity_counts['HIGH']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-number">{severity_counts['MEDIUM']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-number">{severity_counts['LOW']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat info">
                <div class="stat-number">{severity_counts['INFO']}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>

        <div class="findings">
            <h3>🔍 Top Security Issues</h3>
"""
            
            # Add top findings to HTML
            for finding in findings[:5]:
                severity = finding.get('severity', 'info').lower()
                html_body += f"""
            <div class="finding {severity}">
                <div class="finding-title">{finding.get('type', 'Unknown Issue')}</div>
                <div class="finding-meta">
                    📄 {finding.get('file_path', 'Unknown file')} • 
                    📍 Line {finding.get('line_number', 'Unknown')} • 
                    🚨 {finding.get('severity', 'Unknown')} Severity
                </div>
                <p>{finding.get('description', 'No description available')}</p>
            </div>
"""
            
            if report_url:
                html_body += f"""
            <div style="text-align: center; margin: 30px 0;">
                <a href="{report_url}" class="btn">📋 View Full Report</a>
            </div>
"""

            html_body += """
        </div>

        <div class="footer">
            <p>This alert was generated by Secret Guardian automated security scanning.</p>
            <p>Please review these findings promptly to maintain your repository's security.</p>
        </div>
    </div>
</body>
</html>
"""

            return self.send_email(to_email, subject, text_body, html_body)
            
        except Exception as e:
            logger.error(f"📧 Failed to send security alert: {str(e)}")
            return False

    def send_security_alert_with_url(self, to_email: str, repository: str, findings: List[Dict[str, Any]], report_url: str) -> bool:
        """Send security alert email with report URL - FIXED: Removed scan_type parameter"""
        return self.send_security_alert(to_email, repository, findings, report_url)

    def send_scan_completion_notification(self, to_email: str, repository: str, findings_count: int, report_url: str = None) -> bool:
        """Send scan completion notification"""
        try:
            subject = f"✅ Scan Complete: {repository} - {findings_count} Issues Found"
            
            text_body = f"""
Scan Completion Notification - Secret Guardian

Repository: {repository}
Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Issues Found: {findings_count}

"""
            if report_url:
                text_body += f"View Report: {report_url}\n"
                
            text_body += "\nBest regards,\nSecret Guardian Team"

            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .container {{ background: #f8f9fa; padding: 20px; border-radius: 8px; }}
        .header {{ text-align: center; color: #28a745; }}
        .content {{ background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .btn {{ display: inline-block; background: #007bff; color: white; padding: 10px 20px; 
                text-decoration: none; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>✅ Scan Completed Successfully</h2>
        </div>
        <div class="content">
            <p><strong>Repository:</strong> {repository}</p>
            <p><strong>Scan Completed:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Issues Found:</strong> {findings_count}</p>
"""
            
            if report_url:
                html_body += f'<p><a href="{report_url}" class="btn">View Full Report</a></p>'
                
            html_body += """
        </div>
    </div>
</body>
</html>
"""
            
            return self.send_email(to_email, subject, text_body, html_body)
            
        except Exception as e:
            logger.error(f"📧 Failed to send scan completion notification: {str(e)}")
            return False

    def send_test_email(self, to_email: str) -> bool:
        """Send test email to verify configuration"""
        try:
            subject = "🧪 Secret Guardian Test Email"
            body = f"""
This is a test email from Secret Guardian.

If you receive this email, your email configuration is working correctly.

Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

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
        .container {{ background: #e3f2fd; padding: 20px; border-radius: 8px; text-align: center; }}
        .success {{ color: #1976d2; }}
    </style>
</head>
<body>
    <div class="container">
        <h2 class="success">🧪 Test Email Successful!</h2>
        <p>This is a test email from Secret Guardian.</p>
        <p>If you receive this email, your email configuration is working correctly.</p>
        <p><small>Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
    </div>
</body>
</html>
"""
            
            return self.send_email(to_email, subject, body, html_body)
            
        except Exception as e:
            logger.error(f"📧 Failed to send test email: {str(e)}")
            return False

    def send_welcome_email(self, to_email: str, username: str) -> bool:
        """Send welcome email to new users"""
        try:
            subject = "🎉 Welcome to Secret Guardian!"
            
            text_body = f"""
Welcome to Secret Guardian, {username}!

Thank you for joining Secret Guardian, your trusted companion for repository security scanning.

What you can do with Secret Guardian:
- Scan repositories for secrets and sensitive data
- Get real-time security alerts
- Monitor multiple repositories
- Generate detailed security reports
- Integrate with GitHub webhooks

Getting Started:
1. Connect your GitHub account
2. Add repositories to monitor
3. Run your first security scan
4. Set up email notifications

We're here to help keep your code secure!

Best regards,
The Secret Guardian Team
"""
            
            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .container {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                     color: white; padding: 30px; border-radius: 15px; text-align: center; }}
        .content {{ background: white; color: #333; padding: 25px; border-radius: 10px; margin: 20px 0; }}
        .feature {{ margin: 15px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }}
        .btn {{ display: inline-block; background: #007bff; color: white; 
               padding: 12px 25px; text-decoration: none; border-radius: 5px; margin: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 Welcome to Secret Guardian!</h1>
        <h3>Hi {username}, thanks for joining us!</h3>
        
        <div class="content">
            <h3>🚀 What you can do:</h3>
            <div class="feature">🔍 Scan repositories for secrets and sensitive data</div>
            <div class="feature">⚡ Get real-time security alerts</div>
            <div class="feature">📊 Monitor multiple repositories</div>
            <div class="feature">📋 Generate detailed security reports</div>
            <div class="feature">🔗 Integrate with GitHub webhooks</div>
            
            <h3>📝 Getting Started:</h3>
            <ol style="text-align: left; max-width: 300px; margin: 0 auto;">
                <li>Connect your GitHub account</li>
                <li>Add repositories to monitor</li>
                <li>Run your first security scan</li>
                <li>Set up email notifications</li>
            </ol>
            
            <p style="margin-top: 30px;">
                <strong>Ready to secure your code?</strong>
            </p>
        </div>
        
        <p>We're here to help keep your repositories secure! 🔒</p>
    </div>
</body>
</html>
"""
            
            return self.send_email(to_email, subject, text_body, html_body)
            
        except Exception as e:
            logger.error(f"📧 Failed to send welcome email: {str(e)}")
            return False

# Create global email service instance
email_service = EmailService()
