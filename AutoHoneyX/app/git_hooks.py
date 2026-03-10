"""Git hooks integration for pre-commit secret detection (GitGuardian-style)"""

import os
import subprocess
import sys
import re
from pathlib import Path
from typing import List, Tuple

# Same secret patterns as realtime_scanner.py
SECRET_PATTERNS = {
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'github_token': r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}',
    'gitlab_token': r'glpat-[0-9a-zA-Z_-]{20}',
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}',
    'private_key': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
    'mongodb_uri': r'mongodb(?:\+srv)?://[^\s/:]+:[^\s/@]+@[^\s/]+',
    'postgres_uri': r'(postgres|postgresql)://[^\s/:]+:[^\s/@]+@',
    'mysql_password': r'(?i)mysql_password\s*=\s*[\'"]([^\'"]+)[\'"]',
    'gcp_key': r'[\w-]+\.iam\.gserviceaccount\.com',
    'api_key': r'(?i)api[_-]?key\s*[=:]\s*[\'"]([a-zA-Z0-9_-]{20,})[\'"]',
    'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
}

class PreCommitHook:
    """Pre-commit hook to prevent secrets from being committed (GitGuardian-style)"""
    
    def __init__(self, repo_path: str = '.'):
        self.repo_path = repo_path
        self.env_vars_to_check = [
            'HONEYPOT_API_KEY',
            'DATABASE_PASSWORD',
            'AWS_SECRET_ACCESS_KEY',
            'SLACK_TOKEN',
            'GITHUB_TOKEN'
        ]
    
    def scan_staged_files(self) -> Tuple[bool, List[str]]:
        """
        Scan all staged files for secrets before commit
        Returns: (all_good, list_of_findings)
        """
        try:
            # Get list of staged files
            cmd = ['git', '-C', self.repo_path, 'diff', '--name-only', '--cached']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print("Error: Could not get staged files")
                return False, []
            
            staged_files = result.stdout.strip().split('\n')
            findings = []
            
            for file in staged_files:
                if not file:
                    continue
                
                file_path = os.path.join(self.repo_path, file)
                
                # Skip binary files
                if self._is_binary(file_path):
                    continue
                
                # Get staged content
                content = self._get_staged_content(file)
                
                # Scan for secrets
                file_findings = self._scan_content(content, file)
                
                if file_findings:
                    findings.extend(file_findings)
            
            all_good = len(findings) == 0
            return all_good, findings
        
        except Exception as e:
            print(f"Error scanning staged files: {e}")
            return False, []
    
    def _get_staged_content(self, file_path: str) -> str:
        """Get content of staged file"""
        try:
            cmd = ['git', '-C', self.repo_path, 'show', f':{file_path}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except:
            return ""
    
    def _scan_content(self, content: str, file_path: str) -> List[str]:
        """Scan content for secret patterns"""
        findings = []
        
        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append(
                    f"  {secret_name.upper()} found in {file_path}:{line_num}"
                )
        
        return findings
    
    def _is_binary(self, file_path: str) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(512)
                return b'\x00' in content
        except:
            return False
    
    def install_hook(self) -> bool:
        """Install pre-commit hook in repo"""
        hook_path = os.path.join(self.repo_path, '.git', 'hooks', 'pre-commit')
        
        hook_content = '''#!/bin/bash
# AutoHoneyX Pre-Commit Secret Detection Hook

python3 << 'EOF'
import sys
sys.path.insert(0, ".")
from app.git_hooks import PreCommitHook

hook = PreCommitHook()
all_good, findings = hook.scan_staged_files()

if not all_good:
    print("\\n❌ ATTENTION: Potential secrets detected in staged files!")
    print("\\nPlease verify or remove the following:") 
    for finding in findings:
        print(finding)
    print("\\nIf these are honeytokens, add them to .honeytoken-whitelist")
    print("Or use: git commit --no-verify (NOT RECOMMENDED)")
    sys.exit(1)
else:
    print("✅ No secrets detected - proceeding with commit")
    sys.exit(0)
EOF
'''
        
        try:
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            
            with open(hook_path, 'w') as f:
                f.write(hook_content)
            
            os.chmod(hook_path, 0o755)
            print(f"✅ Pre-commit hook installed at {hook_path}")
            return True
        
        except Exception as e:
            print(f"❌ Error installing hook: {e}")
            return False
    
    def check_environment_vars(self) -> Tuple[bool, List[str]]:
        """Check if environment variables with secrets are safe"""
        issues = []
        
        for var_name in self.env_vars_to_check:
            value = os.getenv(var_name)
            
            if value and self._looks_like_real_secret(value):
                # Check if it's in process but not in .env
                issues.append(
                    f"⚠️  Environment variable {var_name} looks like a real secret"
                )
        
        return len(issues) == 0, issues
    
    def _looks_like_real_secret(self, value: str) -> bool:
        """Heuristic check if value looks like real secret"""
        # Real AWS keys start with AKIA
        if value.startswith('AKIA'):
            return True
        
        # Real GitHub tokens start with ghp_
        if value.startswith('ghp_'):
            return True
        
        # Length-based heuristics
        if len(value) > 30 and not value.startswith('FAKE_') and not value.startswith('TEST_'):
            return True
        
        return False


def install_all_hooks(repo_path: str = '.'):
    """Install all security hooks in repository"""
    hook = PreCommitHook(repo_path)
    
    if hook.install_hook():
        print("✅ All hooks installed successfully")
        return True
    else:
        print("❌ Failed to install hooks")
        return False


if __name__ == "__main__":
    hook = PreCommitHook(sys.argv[1] if len(sys.argv) > 1 else '.')
    
    if len(sys.argv) > 2 and sys.argv[2] == 'install':
        install_all_hooks(hook.repo_path)
    else:
        all_good, findings = hook.scan_staged_files()
        
        if not all_good:
            print("❌ Secrets detected:")
            for finding in findings:
                print(finding)
            sys.exit(1)
        else:
            print("✅ No secrets detected")
            sys.exit(0)
