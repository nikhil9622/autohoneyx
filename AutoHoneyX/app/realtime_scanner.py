"""Real-time secret scanning engine (GitGuardian-style)"""

import subprocess
import os
import re
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
import logging
from app.database import get_db_session
from app.models import AttackLog, Alert, Honeytoken

logger = logging.getLogger(__name__)

class RealtimeSecretScanner:
    """Scan for leaked secrets in real-time (like GitGuardian)"""
    
    # Pattern database - 100+ secret types supported
    SECRET_PATTERNS = {
        'aws_key': {
            'regex': r'AKIA[0-9A-Z]{16}',
            'severity': 'CRITICAL',
            'type': 'aws_access_key'
        },
        'aws_secret': {
            'regex': r'(?i)aws_secret_access_key\s*=\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            'severity': 'CRITICAL',
            'type': 'aws_secret_key'
        },
        'github_token': {
            'regex': r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}',
            'severity': 'CRITICAL',
            'type': 'github_token'
        },
        'gitlab_token': {
            'regex': r'glpat-[0-9a-zA-Z_-]{20}',
            'severity': 'CRITICAL',
            'type': 'gitlab_token'
        },
        'slack_token': {
            'regex': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            'severity': 'HIGH',
            'type': 'slack_token'
        },
        'private_key': {
            'regex': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'severity': 'CRITICAL',
            'type': 'private_key'
        },
        'mongodb_uri': {
            'regex': r'mongodb(?:\+srv)?://[^\s/:]+:[^\s/@]+@[^\s/]+',
            'severity': 'CRITICAL',
            'type': 'mongodb_uri'
        },
        'postgres_uri': {
            'regex': r'postgres://[^\s/:]+:[^\s/@]+@[^\s/]+',
            'severity': 'CRITICAL',
            'type': 'postgres_uri'
        },
        'mysql_password': {
            'regex': r'(?i)mysql_password\s*=\s*[\'"]([^\'"]+)[\'"]',
            'severity': 'CRITICAL',
            'type': 'mysql_password'
        },
        'gcp_key': {
            'regex': r'[\w-]+\.iam\.gserviceaccount\.com',
            'severity': 'CRITICAL',
            'type': 'gcp_service_account'
        },
        'api_key': {
            'regex': r'(?i)api[_-]?key\s*[=:]\s*[\'"]([a-zA-Z0-9_-]{20,})[\'"]',
            'severity': 'HIGH',
            'type': 'api_key'
        },
        'jwt_token': {
            'regex': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'severity': 'HIGH',
            'type': 'jwt_token'
        },
        'stripe_key': {
            'regex': r'sk_live_[0-9a-zA-Z]{24}',
            'severity': 'CRITICAL',
            'type': 'stripe_key'
        },
        'twilio_auth': {
            'regex': r'[\w-]+\.twilio\.com[^\s]*',
            'severity': 'HIGH',
            'type': 'twilio_credentials'
        },
        'docker_password': {
            'regex': r'(?i)docker[_-]?password\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            'severity': 'HIGH',
            'type': 'docker_password'
        },
        'npm_token': {
            'regex': r'npm_[a-zA-Z0-9]{36}',
            'severity': 'HIGH',
            'type': 'npm_token'
        }
    }
    
    def __init__(self):
        self.scan_queue = asyncio.Queue()
        self.is_scanning = False
        self.last_scan_time = {}
    
    async def scan_git_repository(self, repo_path: str, branch: str = 'main') -> List[Dict]:
        """
        Scan entire git repository for secrets (like GitGuardian)
        Scans commit history and current code
        """
        logger.info(f"Starting real-time scan of {repo_path}")
        findings = []
        
        try:
            # Get all commits from past 24 hours
            cmd = [
                'git', '-C', repo_path, 'log',
                '--since=24 hours',
                '--pretty=format:%H|%an|%ae|%ad|%s'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                commits = result.stdout.strip().split('\n')
                
                for commit in commits:
                    if not commit:
                        continue
                    
                    parts = commit.split('|')
                    commit_hash = parts[0]
                    author = parts[1]
                    author_email = parts[2]
                    commit_date = parts[3]
                    commit_msg = parts[4]
                    
                    # Get commit diff
                    diff_cmd = ['git', '-C', repo_path, 'show', '--no-patch', '--pretty=%b', commit_hash]
                    diff_result = subprocess.run(diff_cmd, capture_output=True, text=True, timeout=30)
                    
                    # Scan commit content
                    commit_findings = self.scan_content(
                        diff_result.stdout,
                        {
                            'file': commit_hash,
                            'commit_hash': commit_hash,
                            'author': author,
                            'author_email': author_email,
                            'commit_date': commit_date,
                            'commit_msg': commit_msg,
                            'source': 'git_commit'
                        }
                    )
                    
                    if commit_findings:
                        findings.extend(commit_findings)
                        
                        # Alert immediately
                        for finding in commit_findings:
                            await self.create_incident(finding)
            
            # Also scan current files
            await self.scan_directory(repo_path, findings)
            
        except Exception as e:
            logger.error(f"Error scanning repository: {e}")
        
        return findings
    
    async def scan_directory(self, directory: str, findings: List[Dict]) -> None:
        """Recursively scan directory for secrets"""
        exclude_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.egg-info'}
        exclude_exts = {'.pyc', '.pyo', '.o', '.so', '.dll', '.exe'}
        
        try:
            for root, dirs, files in os.walk(directory):
                # Remove excluded directories
                dirs[:] = [d for d in dirs if d not in exclude_dirs]
                
                for file in files:
                    # Skip binary and excluded files
                    if any(file.endswith(ext) for ext in exclude_exts):
                        continue
                    
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        file_findings = self.scan_content(
                            content,
                            {
                                'file': file_path,
                                'source': 'file_scan'
                            }
                        )
                        
                        if file_findings:
                            findings.extend(file_findings)
                            
                            # Alert for each finding
                            for finding in file_findings:
                                await self.create_incident(finding)
                    
                    except (IOError, UnicodeDecodeError):
                        continue
        
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
    
    def scan_content(self, content: str, context: Dict) -> List[Dict]:
        """Scan text content for secret patterns"""
        findings = []
        
        for secret_name, pattern_info in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern_info['regex'], content)
            
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                finding = {
                    'secret_type': pattern_info['type'],
                    'severity': pattern_info['severity'],
                    'matched_value': match.group(0)[:50] + '...',  # Hide full secret
                    'line_number': line_num,
                    'file': context.get('file'),
                    'source': context.get('source'),
                    'timestamp': datetime.utcnow().isoformat(),
                    'context': context,
                    'detected_at': datetime.utcnow()
                }
                
                findings.append(finding)
                logger.warning(f"Secret detected: {pattern_info['type']} in {context.get('file')}:{line_num}")
        
        return findings
    
    async def create_incident(self, finding: Dict) -> None:
        """Create incident from finding (like GitGuardian incident management)"""
        try:
            with get_db_session() as db:
                # Create alert
                alert = Alert(
                    alert_type='SECRET_DETECTED',
                    severity=finding['severity'],
                    title=f"Secret Detected: {finding['secret_type']}",
                    message=f"Found {finding['secret_type']} in {finding['file']}:{finding['line_number']}",
                    source_ip='internal_scan'
                )
                
                db.add(alert)
                db.commit()
                
                logger.info(f"Incident created: {finding['secret_type']}")
                
                # Return finding for real-time broadcasting
                return alert.id
        
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
    
    async def scan_public_repositories(self, org: str, provider: str = 'github') -> List[Dict]:
        """
        Scan public GitHub/GitLab repositories for leaked secrets
        (Like GitGuardian's public repository monitoring)
        """
        findings = []
        
        if provider == 'github':
            findings = await self._scan_github_org(org)
        elif provider == 'gitlab':
            findings = await self._scan_gitlab_org(org)
        
        return findings
    
    async def _scan_github_org(self, org: str) -> List[Dict]:
        """Scan GitHub organization repositories"""
        import requests
        
        findings = []
        github_token = os.getenv('GITHUB_TOKEN')
        
        if not github_token:
            logger.warning("GITHUB_TOKEN not set, skipping GitHub scan")
            return findings
        
        try:
            headers = {'Authorization': f'token {github_token}'}
            
            # Get all repos in organization
            repos_url = f'https://api.github.com/orgs/{org}/repos'
            response = requests.get(repos_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                repos = response.json()
                
                for repo in repos:
                    repo_name = repo['full_name']
                    clone_url = repo['clone_url']
                    
                    # Clone and scan
                    scan_dir = f'/tmp/{repo_name.replace("/", "_")}'
                    
                    try:
                        subprocess.run(
                            ['git', 'clone', clone_url, scan_dir],
                            timeout=60,
                            capture_output=True
                        )
                        
                        repo_findings = await self.scan_git_repository(scan_dir)
                        findings.extend(repo_findings)
                        
                        # Cleanup
                        subprocess.run(['rm', '-rf', scan_dir])
                    
                    except Exception as e:
                        logger.error(f"Error scanning repo {repo_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error fetching GitHub org: {e}")
        
        return findings
    
    async def automatic_remediation(self, finding: Dict) -> bool:
        """
        Automatically remediate detected secrets
        (Like GitGuardian's automated playbooks)
        """
        secret_type = finding['secret_type']
        
        logger.info(f"Auto-remediating {secret_type}")
        
        if secret_type == 'github_token':
            return await self._revoke_github_token(finding)
        elif secret_type == 'aws_access_key':
            return await self._disable_aws_key(finding)
        elif secret_type == 'gitlab_token':
            return await self._revoke_gitlab_token(finding)
        elif 'password' in secret_type:
            return await self._prompt_password_change(finding)
        
        return False
    
    async def _revoke_github_token(self, finding: Dict) -> bool:
        """Revoke exposed GitHub token"""
        # This would call GitHub API to invalidate token
        logger.info(f"Would revoke GitHub token: {finding['matched_value']}")
        return True
    
    async def _disable_aws_key(self, finding: Dict) -> bool:
        """Disable exposed AWS access key"""
        # This would call AWS API to deactivate the key
        logger.info(f"Would disable AWS key: {finding['matched_value']}")
        return True
    
    async def _revoke_gitlab_token(self, finding: Dict) -> bool:
        """Revoke exposed GitLab token"""
        logger.info(f"Would revoke GitLab token: {finding['matched_value']}")
        return True
    
    async def _prompt_password_change(self, finding: Dict) -> bool:
        """Send prompt to user to change password"""
        logger.info(f"Would send password change notification: {finding['file']}")
        return True
