"""
Input validation and sanitization using Pydantic validators
Prevents injection attacks and invalid data processing
"""

from pydantic import BaseModel, validator, EmailStr, Field
from typing import Optional, List
import re


class TokenInjectionRequest(BaseModel):
    """Validated request for token injection into repository"""
    repo_path: str = Field(..., min_length=1, max_length=255)
    token_types: List[str] = Field(..., min_items=1, max_items=10)
    files_per_type: int = 5
    
    @validator('repo_path')
    def validate_repo_path(cls, v):
        """Prevent path traversal attacks"""
        if '..' in v or v.startswith('/'):
            raise ValueError('Invalid repository path - path traversal detected')
        # Whitelist allowed characters
        if not re.match(r'^[a-zA-Z0-9/_\-\.]+$', v):
            raise ValueError('Repository path contains invalid characters')
        return v
    
    @validator('token_types')
    def validate_token_types(cls, v):
        """Ensure token types are valid"""
        valid_types = {'aws', 'database', 'api', 'ssh', 'github', 'slack'}
        for token_type in v:
            if token_type not in valid_types:
                raise ValueError(f'Invalid token type: {token_type}')
        return v
    
    @validator('files_per_type')
    def validate_files_per_type(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Files per type must be between 1 and 100')
        return v


class AlertConfigRequest(BaseModel):
    """Validated alert configuration"""
    slack_webhook: Optional[str] = None
    email_recipients: List[EmailStr] = []
    alert_types: List[str] = ['CRITICAL', 'HIGH']
    
    @validator('slack_webhook')
    def validate_slack_webhook(cls, v):
        if v and not v.startswith('https://hooks.slack.com/'):
            raise ValueError('Invalid Slack webhook URL')
        return v


class ScanRequest(BaseModel):
    """Validated scan request"""
    repo_path: str = Field(..., min_length=1, max_length=255)
    scan_type: str  # 'secrets', 'malware', 'all'
    
    @validator('repo_path')
    def validate_repo_path(cls, v):
        if '..' in v or v.startswith('/'):
            raise ValueError('Invalid repository path')
        if not re.match(r'^[a-zA-Z0-9/_\-\.]+$', v):
            raise ValueError('Repository path contains invalid characters')
        return v
    
    @validator('scan_type')
    def validate_scan_type(cls, v):
        if v not in ['secrets', 'malware', 'all']:
            raise ValueError('Invalid scan type')
        return v
