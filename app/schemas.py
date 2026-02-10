"""
Docstring for app.schemas
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from .models import UserRole


class UserSchema(BaseModel):

    """
    Docstring for UserSchema
    """

    id: int
    email: str
    hashed_password: str
    role: str

class TokenData(BaseModel):

    """
    Docstring for TokenData
    """

    id: int
    email: EmailStr
    role: str

class UserResponse(BaseModel):

    """
    Docstring for UserResponse
    """

    id: int
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: UserRole

    class Config:
        from_attributes = True

class ChangePasswordRequest(BaseModel):

    """
    Docstring for ChangePasswordRequest
    """

    old_password: str
    new_password: str = Field(min_length=6)

class UpdateProfileRequest(BaseModel):

    """
    Docstring for UpdateProfileRequest
    """

    first_name: Optional[str] = Field(min_length=3, max_length=30)
    last_name: Optional[str] = Field(min_length=3, max_length=30)
    email: Optional[EmailStr] = None

class UpdateRoleRequest(BaseModel):

    """
    Docstring for UpdateRoleRequest
    """

    role: UserRole 
    