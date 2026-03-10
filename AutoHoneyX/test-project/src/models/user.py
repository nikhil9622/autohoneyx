"""User model"""

from typing import Optional
from datetime import datetime

class User:
    """User model representing a system user"""

    def __init__(self, user_id: Optional[int] = None, name: str = "",
                 email: str = "", created_at: Optional[datetime] = None):
        self.id = user_id
        self.name = name
        self.email = email
        self.created_at = created_at or datetime.now()

    def save(self) -> bool:
        """Save user to database"""
        # This would normally interact with database
        print(f"Saving user: {self.name}")
        return True

    def delete(self) -> bool:
        """Delete user from database"""
        print(f"Deleting user: {self.name}")
        return True

    def update(self, **kwargs) -> bool:
        """Update user attributes"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        print(f"Updated user: {self.name}")
        return True

    def validate_email(self) -> bool:
        """Validate email format"""
        return "@" in self.email and "." in self.email

    def __str__(self) -> str:
        return f"User(id={self.id}, name='{self.name}', email='{self.email}')"

