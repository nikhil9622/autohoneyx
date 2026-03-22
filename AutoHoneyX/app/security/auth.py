"""
JWT Authentication and Authorization using OAuth2 with FastAPI
Provides role-based access control (RBAC)
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from enum import Enum
from typing import Optional
import os

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "autohoneyx-dev-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


class UserRole(str, Enum):
    """User role enumeration for RBAC"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate bcrypt hash of password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token
    
    Args:
        data: Dictionary containing token claims (e.g., {"sub": "user_id", "role": "admin"})
        expires_delta: Optional token expiration time
    
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    Verify JWT token and extract user information
    
    Args:
        credentials: HTTP Bearer token from Authorization header
    
    Returns:
        Dictionary with user info including id, role
    
    Raises:
        HTTPException: If token is invalid or expired
    """
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role", UserRole.VIEWER)
        
        if user_id is None:
            raise credential_exception
            
    except JWTError:
        raise credential_exception
    
    return {"user_id": user_id, "role": role}


async def get_current_admin_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Require admin role for endpoint access
    
    Args:
        current_user: Current authenticated user from get_current_user dependency
    
    Returns:
        Current user if they are admin
    
    Raises:
        HTTPException: If user is not admin
    """
    if current_user['role'] != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized - admin access required"
        )
    return current_user


async def get_current_analyst_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """
    Require analyst or admin role for endpoint access
    """
    if current_user['role'] not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized - analyst or admin access required"
        )
    return current_user
