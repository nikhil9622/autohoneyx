"""Honeytoken Generator - Creates realistic fake credentials"""

import secrets
import hashlib
import uuid
import string
import base64
from datetime import datetime
from typing import Dict, Optional
from app.database import get_db_session
from app.models import Honeytoken

class HoneytokenGenerator:
    """Generate various types of honeytokens"""
    
    @staticmethod
    def generate_token_id() -> str:
        """Generate unique token ID"""
        return hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16]
    
    @staticmethod
    def generate_aws_key() -> Dict[str, str]:
        """Generate fake AWS access key and secret"""
        token_id = HoneytokenGenerator.generate_token_id()
        
        # AWS access keys start with AKIA (for IAM users) or ASIA (for temporary)
        access_key_id = "AKIA" + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        
        # AWS secret keys are 40 characters base64-like
        secret_chars = string.ascii_letters + string.digits + "+/="
        secret_access_key = ''.join(secrets.choice(secret_chars) for _ in range(40))
        
        token_value = f"AWS_ACCESS_KEY_ID={access_key_id}\nAWS_SECRET_ACCESS_KEY={secret_access_key}"
        
        return {
            'token_id': token_id,
            'token_type': 'aws',
            'access_key_id': access_key_id,
            'secret_access_key': secret_access_key,
            'token_value': token_value,
            'metadata': {
                'region': 'us-east-1',
                'service': 'aws',
                'format': 'credentials'
            }
        }
    
    @staticmethod
    def generate_database_credentials(db_type: str = 'postgresql') -> Dict[str, str]:
        """Generate fake database credentials"""
        token_id = HoneytokenGenerator.generate_token_id()
        
        # Generate realistic username
        username_options = ['admin', 'backup_admin', 'db_admin', 'root', 'postgres_backup']
        username = secrets.choice(username_options) + '_' + ''.join(secrets.choice(string.digits) for _ in range(3))
        
        # Generate password (looks realistic)
        password = secrets.choice(['P@ssw0rd', 'Admin123!', 'SecurePass2024', 'Backup@123'])
        password += ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        # Generate fake host
        host = f"db-{secrets.choice(['prod', 'staging', 'backup', 'internal'])}-{secrets.choice(['01', '02', 'master'])}.example.com"
        port = secrets.choice([5432, 3306, 1433])
        db_name = secrets.choice(['maindb', 'production', 'staging_db', 'backup_db'])
        
        if db_type == 'postgresql':
            connection_string = f"postgresql://{username}:{password}@{host}:{port}/{db_name}"
        elif db_type == 'mysql':
            connection_string = f"mysql://{username}:{password}@{host}:{port}/{db_name}"
        else:
            connection_string = f"{db_type}://{username}:{password}@{host}:{port}/{db_name}"
        
        token_value = f"DB_URL={connection_string}\nDB_USER={username}\nDB_PASSWORD={password}"
        
        return {
            'token_id': token_id,
            'token_type': f'db_{db_type}',
            'username': username,
            'password': password,
            'host': host,
            'port': port,
            'database': db_name,
            'token_value': token_value,
            'metadata': {
                'db_type': db_type,
                'connection_string': connection_string
            }
        }
    
    @staticmethod
    def generate_api_key(api_type: str = 'rest') -> Dict[str, str]:
        """Generate fake API key"""
        token_id = HoneytokenGenerator.generate_token_id()
        
        if api_type == 'rest':
            # REST API key format
            api_key = 'sk_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        elif api_type == 'bearer':
            # Bearer token format
            api_key = 'Bearer ' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        else:
            # Generic API key
            api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
        
        # Generate fake endpoint
        endpoints = [
            'https://api.internal.example.com/v1/admin',
            'https://api-backup.example.com/v2/legacy',
            'https://internal-api.example.com/admin/legacy',
            'https://api.staging.example.com/v1/backup'
        ]
        endpoint = secrets.choice(endpoints)
        
        token_value = f"API_KEY={api_key}\nAPI_ENDPOINT={endpoint}"
        
        return {
            'token_id': token_id,
            'token_type': 'api',
            'api_key': api_key,
            'endpoint': endpoint,
            'token_value': token_value,
            'metadata': {
                'api_type': api_type,
                'format': 'key_endpoint'
            }
        }
    
    @staticmethod
    def generate_ssh_key() -> Dict[str, str]:
        """Generate fake SSH private key"""
        token_id = HoneytokenGenerator.generate_token_id()
        
        # Generate fake SSH key (simplified version)
        ssh_key_start = "-----BEGIN RSA PRIVATE KEY-----"
        ssh_key_content = '\n'.join([''.join(secrets.choice(string.ascii_letters + string.digits + '/+=') 
                                            for _ in range(64)) for _ in range(20)])
        ssh_key_end = "-----END RSA PRIVATE KEY-----"
        
        ssh_key = f"{ssh_key_start}\n{ssh_key_content}\n{ssh_key_end}"
        
        # Generate fake host
        host = f"ssh-{secrets.choice(['backup', 'internal', 'admin', 'staging'])}.example.com"
        port = secrets.choice([22, 2222, 22222])
        
        token_value = f"SSH_PRIVATE_KEY={ssh_key}\nSSH_HOST={host}\nSSH_PORT={port}"
        
        return {
            'token_id': token_id,
            'token_type': 'ssh',
            'ssh_key': ssh_key,
            'host': host,
            'port': port,
            'token_value': token_value,
            'metadata': {
                'key_type': 'rsa',
                'format': 'private_key'
            }
        }
    
    @staticmethod
    def save_honeytoken(token_data: Dict, location_file: Optional[str] = None, 
                       location_line: Optional[int] = None, created_by: str = "system") -> Honeytoken:
        """Save honeytoken to database"""
        with get_db_session() as db:
            honeytoken = Honeytoken(
                token_id=token_data['token_id'],
                token_type=token_data['token_type'],
                token_value=token_data['token_value'],
                token_metadata=token_data.get('metadata', {}),
                location_file=location_file,
                location_line=location_line,
                created_by=created_by
            )
            db.add(honeytoken)
            db.commit()
            db.refresh(honeytoken)
            return honeytoken
    
    @staticmethod
    def generate_and_save(token_type: str, **kwargs) -> Honeytoken:
        """Generate and save honeytoken in one step"""
        generators = {
            'aws': HoneytokenGenerator.generate_aws_key,
            'db_postgresql': lambda: HoneytokenGenerator.generate_database_credentials('postgresql'),
            'db_mysql': lambda: HoneytokenGenerator.generate_database_credentials('mysql'),
            'api': HoneytokenGenerator.generate_api_key,
            'ssh': HoneytokenGenerator.generate_ssh_key
        }
        
        if token_type not in generators:
            raise ValueError(f"Unknown token type: {token_type}")
        
        token_data = generators[token_type]()
        return HoneytokenGenerator.save_honeytoken(token_data, **kwargs)

