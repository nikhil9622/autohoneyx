"""Injection Engine - Automatically injects honeytokens into code files"""

import ast
import re
import base64
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from app.honeytoken_generator import HoneytokenGenerator
from app.config import config

class InjectionEngine:
    """Inject honeytokens into code files"""
    
    SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php'}
    COMMENT_PATTERNS = {
        '.py': '#',
        '.js': '//',
        '.ts': '//',
        '.java': '//',
        '.go': '//',
        '.rb': '#',
        '.php': '//'
    }
    
    def __init__(self, repo_path: Path):
        self.repo_path = Path(repo_path)
        self.injection_points = []
    
    def find_code_files(self, exclude_dirs: Optional[List[str]] = None) -> List[Path]:
        """Find all code files in repository"""
        if exclude_dirs is None:
            exclude_dirs = ['.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env']
        
        code_files = []
        for ext in self.SUPPORTED_EXTENSIONS:
            for file_path in self.repo_path.rglob(f"*{ext}"):
                # Skip excluded directories
                if any(excluded in file_path.parts for excluded in exclude_dirs):
                    continue
                code_files.append(file_path)
        
        return code_files
    
    def get_comment_prefix(self, file_path: Path) -> str:
        """Get comment prefix for file type"""
        ext = file_path.suffix
        return self.COMMENT_PATTERNS.get(ext, '#')
    
    def format_honeytoken_comment(self, token_data: Dict, comment_prefix: str) -> str:
        """Format honeytoken as comment"""
        token_type = token_data.get('token_type', 'unknown')
        
        if token_type == 'aws':
            return f"{comment_prefix} OLD_AWS_ACCESS_KEY_ID={token_data['access_key_id']}\n{comment_prefix} OLD_AWS_SECRET_ACCESS_KEY={token_data['secret_access_key']}"
        elif token_type.startswith('db_'):
            return f"{comment_prefix} OLD_DB_URL={token_data['metadata']['connection_string']}"
        elif token_type == 'api':
            return f"{comment_prefix} OLD_API_KEY={token_data['api_key']}\n{comment_prefix} OLD_API_ENDPOINT={token_data['endpoint']}"
        elif token_type == 'ssh':
            return f"{comment_prefix} OLD_SSH_HOST={token_data['host']}:{token_data['port']}"
        else:
            return f"{comment_prefix} {token_data['token_value']}"
    
    def find_injection_points_python(self, file_path: Path) -> List[Tuple[int, str]]:
        """Find good injection points in Python files"""
        injection_points = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                tree = ast.parse(content, filename=str(file_path))
            
            # Find function definitions (good places to inject)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Inject before function definition
                    injection_points.append((node.lineno - 1, 'before_function'))
            
            # Find class definitions
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    injection_points.append((node.lineno - 1, 'before_class'))
            
        except SyntaxError:
            # If file has syntax errors, use line-based injection
            pass
        
        # If no AST-based points found, use strategic line numbers
        if not injection_points:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Inject after imports (common in most files)
                for i, line in enumerate(lines[:20]):  # Check first 20 lines
                    if re.match(r'^\s*(import|from)\s+', line):
                        injection_points.append((i + 1, 'after_imports'))
                        break
        
        return injection_points[:3]  # Limit to 3 injection points per file
    
    def inject_into_file(self, file_path: Path, token_type: str = 'aws', 
                        num_injections: int = 1) -> List[Dict]:
        """Inject honeytokens into a single file"""
        comment_prefix = self.get_comment_prefix(file_path)
        injections = []
        
        # Generate tokens
        for _ in range(num_injections):
            if token_type == 'aws':
                token_data = HoneytokenGenerator.generate_aws_key()
            elif token_type.startswith('db_'):
                token_data = HoneytokenGenerator.generate_database_credentials(
                    token_type.replace('db_', '')
                )
            elif token_type == 'api':
                token_data = HoneytokenGenerator.generate_api_key()
            elif token_type == 'ssh':
                token_data = HoneytokenGenerator.generate_ssh_key()
            else:
                token_data = HoneytokenGenerator.generate_aws_key()
            
            # Format as comment
            comment = self.format_honeytoken_comment(token_data, comment_prefix)
            
            # Find injection points
            if file_path.suffix == '.py':
                injection_points = self.find_injection_points_python(file_path)
            else:
                # For other languages, inject after first non-empty line
                injection_points = [(1, 'after_first_line')]
            
            if injection_points:
                line_num, point_type = injection_points[0]
                
                # Read file
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Inject comment
                comment_lines = comment.split('\n')
                for i, comment_line in enumerate(comment_lines):
                    lines.insert(line_num + i, comment_line + '\n')
                
                # Write back
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                
                # Save to database
                honeytoken = HoneytokenGenerator.save_honeytoken(
                    token_data,
                    location_file=str(file_path.relative_to(self.repo_path)),
                    location_line=line_num + 1
                )
                
                injections.append({
                    'file': str(file_path),
                    'line': line_num + 1,
                    'token_id': token_data['token_id'],
                    'token_type': token_data['token_type']
                })
        
        return injections
    
    def inject_into_repository(self, token_types: Optional[List[str]] = None,
                               files_per_type: int = 5, tokens_per_file: int = 1) -> Dict:
        """Inject honeytokens into multiple files in repository"""
        if token_types is None:
            token_types = ['aws', 'db_postgresql', 'api']
        
        code_files = self.find_code_files()
        results = {
            'total_files_scanned': len(code_files),
            'files_injected': 0,
            'tokens_injected': 0,
            'injections': []
        }
        
        # Distribute files across token types
        files_per_token_type = files_per_type // len(token_types)
        
        for token_type in token_types:
            files_to_inject = code_files[:files_per_token_type]
            code_files = code_files[files_per_token_type:]
            
            for file_path in files_to_inject:
                try:
                    injections = self.inject_into_file(file_path, token_type, tokens_per_file)
                    results['injections'].extend(injections)
                    results['files_injected'] += 1
                    results['tokens_injected'] += len(injections)
                except Exception as e:
                    print(f"Error injecting into {file_path}: {e}")
                    continue
        
        return results

