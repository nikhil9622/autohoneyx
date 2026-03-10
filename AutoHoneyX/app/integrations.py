"""Integrations with GitHub, GitLab, Slack, and more (GitGuardian-style)"""

import requests
import os
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class GitHubIntegration:
    """Integrate with GitHub API for repo scanning and alerting"""
    
    def __init__(self):
        self.token = os.getenv('GITHUB_TOKEN')
        self.api_url = 'https://api.github.com'
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    async def get_organization_repos(self, org: str) -> List[Dict]:
        """Get all repositories in an organization"""
        repos = []
        page = 1
        
        try:
            while True:
                url = f'{self.api_url}/orgs/{org}/repos'
                response = requests.get(
                    url,
                    headers=self.headers,
                    params={'page': page, 'per_page': 100}
                )
                
                if response.status_code != 200:
                    break
                
                data = response.json()
                if not data:
                    break
                
                repos.extend(data)
                page += 1
        
        except Exception as e:
            logger.error(f"Error fetching GitHub repos: {e}")
        
        return repos
    
    async def create_issue(self, repo: str, title: str, body: str, labels: List[str] = None):
        """Create GitHub issue for security finding"""
        try:
            url = f'{self.api_url}/repos/{repo}/issues'
            
            payload = {
                'title': title,
                'body': body,
                'labels': labels or ['security', 'secret-detected']
            }
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 201:
                logger.info(f"Created GitHub issue in {repo}: {title}")
                return response.json()
            else:
                logger.error(f"Failed to create GitHub issue: {response.text}")
        
        except Exception as e:
            logger.error(f"Error creating GitHub issue: {e}")
    
    async def notify_pull_request(self, repo: str, pr_number: int, comment: str):
        """Add comment to pull request about security findings"""
        try:
            url = f'{self.api_url}/repos/{repo}/issues/{pr_number}/comments'
            
            payload = {'body': comment}
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 201:
                logger.info(f"Commented on PR {pr_number} in {repo}")
                return response.json()
        
        except Exception as e:
            logger.error(f"Error commenting on PR: {e}")


class GitLabIntegration:
    """Integrate with GitLab API"""
    
    def __init__(self):
        self.token = os.getenv('GITLAB_TOKEN')
        self.gitlab_url = os.getenv('GITLAB_URL', 'https://gitlab.com')
        self.headers = {
            'PRIVATE-TOKEN': self.token
        }
    
    async def get_group_repos(self, group: str) -> List[Dict]:
        """Get all repositories in a GitLab group"""
        repos = []
        
        try:
            url = f'{self.gitlab_url}/api/v4/groups/{group}/projects'
            response = requests.get(
                url,
                headers=self.headers,
                params={'archived': False}
            )
            
            if response.status_code == 200:
                repos = response.json()
        
        except Exception as e:
            logger.error(f"Error fetching GitLab repos: {e}")
        
        return repos
    
    async def create_issue(self, project_id: str, title: str, description: str):
        """Create GitLab issue"""
        try:
            url = f'{self.gitlab_url}/api/v4/projects/{project_id}/issues'
            
            payload = {
                'title': title,
                'description': description,
                'labels': 'security,secret-detected'
            }
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 201:
                logger.info(f"Created GitLab issue: {title}")
                return response.json()
        
        except Exception as e:
            logger.error(f"Error creating GitLab issue: {e}")


class SlackIntegration:
    """Integrate with Slack for real-time alerts"""
    
    def __init__(self):
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    
    async def send_incident_alert(self, incident: Dict):
        """Send Slack alert for new security incident"""
        if not self.webhook_url:
            logger.warning("SLACK_WEBHOOK_URL not configured")
            return
        
        try:
            severity = incident.get('severity', 'UNKNOWN')
            color = {
                'CRITICAL': 'danger',
                'HIGH': 'warning',
                'MEDIUM': '#DAA520',
                'LOW': 'good'
            }.get(severity, '#808080')
            
            message = {
                'channel': self.channel,
                'username': 'AutoHoneyX Security Bot',
                'icon_emoji': ':shield:',
                'attachments': [
                    {
                        'color': color,
                        'title': f"🔒 {incident.get('secret_type', 'Secret')} Detected",
                        'title_link': f"https://autohoneyx.local/incidents/{incident.get('id')}",
                        'text': incident.get('message'),
                        'fields': [
                            {
                                'title': 'Severity',
                                'value': severity,
                                'short': True
                            },
                            {
                                'title': 'File',
                                'value': incident.get('file'),
                                'short': True
                            },
                            {
                                'title': 'Line Number',
                                'value': str(incident.get('line_number', 'N/A')),
                                'short': True
                            },
                            {
                                'title': 'Detected At',
                                'value': incident.get('detected_at', 'N/A'),
                                'short': True
                            }
                        ],
                        'footer': 'AutoHoneyX Real-Time Security Monitoring',
                        'ts': int(datetime.utcnow().timestamp())
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=message)
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent: {incident.get('secret_type')}")
            else:
                logger.error(f"Failed to send Slack alert: {response.text}")
        
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
    
    async def send_stats_update(self, stats: Dict):
        """Send regular stats update to Slack"""
        if not self.webhook_url:
            return
        
        try:
            message = {
                'channel': self.channel,
                'username': 'AutoHoneyX Stats Bot',
                'icon_emoji': ':chart_with_upwards_trend:',
                'attachments': [
                    {
                        'color': '#36a64f',
                        'title': '📊 Security Monitoring Stats',
                        'fields': [
                            {
                                'title': 'Total Incidents',
                                'value': str(stats.get('total_incidents', 0)),
                                'short': True
                            },
                            {
                                'title': 'Critical Issues',
                                'value': str(stats.get('critical_count', 0)),
                                'short': True
                            },
                            {
                                'title': 'High Priority',
                                'value': str(stats.get('high_count', 0)),
                                'short': True
                            },
                            {
                                'title': 'Risk Score',
                                'value': f"{stats.get('risk_score', 0)}/100",
                                'short': True
                            }
                        ],
                        'footer': 'AutoHoneyX',
                        'ts': int(datetime.utcnow().timestamp())
                    }
                ]
            }
            
            requests.post(self.webhook_url, json=message)
        
        except Exception as e:
            logger.error(f"Error sending Slack stats: {e}")


class EmailIntegration:
    """Integrate with email for alerts"""
    
    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
        self.from_email = os.getenv('FROM_EMAIL')
        self.from_password = os.getenv('FROM_PASSWORD')
        self.alert_email = os.getenv('ALERT_EMAIL')
    
    async def send_incident_alert(self, incident: Dict):
        """Send email alert for critical incident"""
        if not self.smtp_server or not self.from_email:
            logger.warning("Email not configured")
            return
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🔒 Security Alert: {incident.get('secret_type')} Detected"
            msg['From'] = self.from_email
            msg['To'] = self.alert_email
            
            html = f"""
            <html>
              <body>
                <h2 style="color: #d32f2f;">Security Incident Alert</h2>
                <p><strong>Type:</strong> {incident.get('secret_type')}</p>
                <p><strong>Severity:</strong> {incident.get('severity')}</p>
                <p><strong>File:</strong> {incident.get('file')}</p>
                <p><strong>Line:</strong> {incident.get('line_number')}</p>
                <p><strong>Detected:</strong> {incident.get('detected_at')}</p>
                <p><strong>Message:</strong> {incident.get('message')}</p>
                <hr>
                <p><a href="https://autohoneyx.local/incidents">View in Dashboard</a></p>
              </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.from_email, self.from_password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {self.alert_email}")
        
        except Exception as e:
            logger.error(f"Error sending email: {e}")


class WebhookIntegration:
    """Send custom webhooks for incidents"""
    
    @staticmethod
    async def send_webhook(webhook_url: str, incident: Dict):
        """Send incident data to custom webhook"""
        try:
            payload = {
                'event': 'secret_detected',
                'timestamp': datetime.utcnow().isoformat(),
                'incident': incident
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code in (200, 201, 202):
                logger.info(f"Webhook sent to {webhook_url}")
                return True
            else:
                logger.warning(f"Webhook returned {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
            return False


class IntegrationManager:
    """Manage all integrations"""
    
    def __init__(self):
        self.github = GitHubIntegration() if os.getenv('GITHUB_TOKEN') else None
        self.gitlab = GitLabIntegration() if os.getenv('GITLAB_TOKEN') else None
        self.slack = SlackIntegration() if os.getenv('SLACK_WEBHOOK_URL') else None
        self.email = EmailIntegration() if os.getenv('SMTP_SERVER') else None
        self.webhooks = self._load_webhooks()
    
    def _load_webhooks(self) -> List[str]:
        """Load custom webhooks from environment"""
        webhook_urls = os.getenv('CUSTOM_WEBHOOKS', '').split(',')
        return [url.strip() for url in webhook_urls if url.strip()]
    
    async def notify_incident(self, incident: Dict):
        """Send incident to all configured integrations"""
        
        # Slack
        if self.slack:
            await self.slack.send_incident_alert(incident)
        
        # Email (for critical)
        if self.email and incident.get('severity') == 'CRITICAL':
            await self.email.send_incident_alert(incident)
        
        # Custom webhooks
        for webhook_url in self.webhooks:
            await WebhookIntegration.send_webhook(webhook_url, incident)
        
        # GitHub issue (optional)
        # if self.github:
        #     await self.github.create_issue(...)
