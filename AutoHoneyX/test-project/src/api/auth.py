"""Authentication service"""

import hashlib
import secrets
from typing import Optional, Tuple
from models.user import User

class AuthService:
    """Handles user authentication"""

    def __init__(self):
        self.users = {}  # In-memory user store for demo
        self.sessions = {}

    def setup(self):
        """Initialize authentication service"""
        print("Authentication service initialized")

    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def generate_token(self) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(32)

    def register_user(self, name: str, email: str, password: str) -> bool:
        """Register a new user"""
        if email in self.users:
            return False

        hashed_password = self.hash_password(password)
        user = User(name=name, email=email)
        self.users[email] = {
            'user': user,
            'password_hash': hashed_password
        }

        print(f"User registered: {name}")
        return True

    def authenticate(self, email: str, password: str) -> Optional[str]:
        """Authenticate user and return session token"""
        if email not in self.users:
            return None

        hashed_password = self.hash_password(password)
        stored_hash = self.users[email]['password_hash']

        if hashed_password == stored_hash:
            token = self.generate_token()
            self.sessions[token] = email
            print(f"User authenticated: {email}")
            return token

        return None

    def validate_token(self, token: str) -> Optional[str]:
        """Validate session token and return user email"""
        return self.sessions.get(token)

    def logout(self, token: str):
        """Logout user by removing session"""
        if token in self.sessions:
            email = self.sessions.pop(token)
            print(f"User logged out: {email}")

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        user_data = self.users.get(email)
        return user_data['user'] if user_data else None

