"""
Encryption at rest for sensitive data in database
Uses Fernet (symmetric encryption) for protecting tokens and credentials
"""

from cryptography.fernet import Fernet
from sqlalchemy.types import TypeDecorator, String
import os

# Get encryption key from environment or generate
ENCRYPTION_MASTER_KEY = os.getenv(
    "ENCRYPTION_MASTER_KEY",
    Fernet.generate_key().decode()  # Generate for dev only
)

# Initialize cipher suite
cipher_suite = Fernet(ENCRYPTION_MASTER_KEY.encode() if isinstance(ENCRYPTION_MASTER_KEY, str) else ENCRYPTION_MASTER_KEY)


class EncryptedString(TypeDecorator):
    """
    SQLAlchemy type decorator for automatically encrypting/decrypting string fields
    
    Usage:
        class Honeytoken(Base):
            token_value = Column(EncryptedString(500))  # Automatically encrypted at rest
    """
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database"""
        if value is not None:
            encrypted = cipher_suite.encrypt(value.encode())
            return encrypted.decode()
        return value

    def process_result_value(self, value, dialect):
        """Decrypt value when retrieving from database"""
        if value is not None:
            decrypted = cipher_suite.decrypt(value.encode())
            return decrypted.decode()
        return value


class RateLimiter:
    """
    Simple in-memory rate limiter for API protection
    In production, use Redis for distributed rate limiting
    """
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, identifier: str, limit: int, window_seconds: int) -> bool:
        """
        Check if request is within rate limit
        
        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            limit: Maximum requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            True if request is allowed, False if rate limited
        """
        import time
        current_time = time.time()
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests outside the window
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < window_seconds
        ]
        
        if len(self.requests[identifier]) < limit:
            self.requests[identifier].append(current_time)
            return True
        
        return False
