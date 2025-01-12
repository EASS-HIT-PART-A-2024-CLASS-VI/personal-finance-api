# app/schemas.py

from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime


# -------- User Schemas --------

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr = Field(...,)
    password: str = Field(..., min_length=6)

    @field_validator('username')
    def validate_username(cls, v):
        if ' ' in v:
            raise ValueError('Username must not contain spaces')
        return v


class UserSignin(BaseModel):
    email: EmailStr = Field(...)
    password: str = Field(..., min_length=6)


class UserRead(BaseModel):
    id: str
    username: str
    email: EmailStr
    created_at: datetime
    updated_at: datetime

    # Enables compatibility with ORM objects
    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = Field(None)
    password: Optional[str] = Field(None, min_length=6)

    @field_validator('username')
    def validate_username(cls, v):
        if v and ' ' in v:
            raise ValueError('Username must not contain spaces')
        return v


# -------- Record Schemas --------

class RecordCreate(BaseModel):
    amount: float = Field(..., gt=0)
    category: str = Field(..., min_length=3, max_length=50)
    description: Optional[str] = Field(None, max_length=255)

    @field_validator('category')
    def validate_category(cls, v):
        if not v.strip():
            raise ValueError('Category must not be empty or just whitespace')
        return v


class RecordRead(BaseModel):
    id: str
    user_id: str
    amount: float
    category: str
    description: Optional[str]
    date: datetime

    # Enables compatibility with ORM objects
    model_config = {"from_attributes": True}


class RecordUpdate(BaseModel):
    amount: Optional[float] = Field(None, gt=0)
    category: Optional[str] = Field(None, min_length=3, max_length=50)
    description: Optional[str] = Field(None, max_length=255)

    @field_validator('category')
    def validate_category(cls, v):
        if v and not v.strip():
            raise ValueError('Category must not be empty or just whitespace')
        return v


# -------- Token Schema --------

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefresh(BaseModel):
    refresh_token: str


# -------- Question Schema --------

class QuestionRequest(BaseModel):
    question: str
