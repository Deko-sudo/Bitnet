# -*- coding: utf-8 -*-
"""
Pydantic Schemas for API - Password Manager
"""

from pydantic import BaseModel, SecretStr, EmailStr, field_validator
from datetime import datetime
from typing import Optional, List
import re

# =============================================================================
# Users
# =============================================================================

class UserCreate(BaseModel):
    """Schema for user creation."""
    username: str
    password: SecretStr
    email: EmailStr
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        if not (has_upper and has_lower and has_digit):
            raise ValueError("Password must contain uppercase, lowercase, and digits")
        return v
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "john_doe",
                "password": "**********",
                "email": "john@example.com"
            }
        }
    }


class UserResponse(BaseModel):
    """Schema for user response."""
    id: int
    username: str
    created_at: datetime
    
    model_config = {"from_attributes": True}


# =============================================================================
# Password Entries
# =============================================================================

class EntryCreateSchema(BaseModel):
    """Schema for password entry creation with validation."""
    title: str
    username: Optional[str] = None
    password: SecretStr
    url: Optional[str] = None
    notes: Optional[str] = None
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "Google Account",
                "username": "john@gmail.com",
                "password": "**********",
                "url": "https://google.com",
                "notes": "Work account"
            }
        }
    }


class EntryUpdateSchema(BaseModel):
    """Schema for updating, all fields are optional."""
    title: Optional[str] = None
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    url: Optional[str] = None
    notes: Optional[str] = None


class EntryResponseSchema(BaseModel):
    """Schema for detailed response with decrypted fields."""
    id: int
    user_id: int
    title: str
    username: Optional[str]
    url: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


class EntryListItemSchema(BaseModel):
    """Schema for listing entries without sensitive passwords."""
    id: int
    user_id: int
    title: str
    url: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    model_config = {"from_attributes": True}


# =============================================================================
# Authentication
# =============================================================================

class LoginRequest(BaseModel):
    """Schema for login request."""
    username: str
    password: SecretStr
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "john_doe",
                "password": "**********"
            }
        }
    }


class LoginResponse(BaseModel):
    """Schema for login response."""
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
