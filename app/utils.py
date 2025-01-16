# app/utils.py

import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
import os
from fastapi import HTTPException, status
from dotenv import load_dotenv

load_dotenv()


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
REFRESH_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", 1440))


def hash_password(plain_password: str) -> str:
    """
    Hash a plain text password.

    Args:
        plain_password (str): The user's plain text password.

    Returns:
        str: The hashed password as a string.
    """
    # Generate a salt. The higher the rounds, the more secure but slower the hashing.
    salt = bcrypt.gensalt()

    # Hash the password with the generated salt
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)

    # Decode the hashed password to convert from bytes to string
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password.

    Args:
        plain_password (str): The user's plain text password.
        hashed_password (str): The hashed password from the database.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    # Compare the plain password (encoded to bytes) with the hashed password (also encoded)
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(data: dict, expires_delta: Optional[timedelta] = None, token_type: str = "access") -> str:
    """
    Create a JWT token (access or refresh).

    Args:
        data (dict): The payload data.
        expires_delta (Optional[timedelta], optional): The token expiration time. Defaults to None.
        token_type (str): The type of token ("access" or "refresh"). Defaults to "access".

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        if token_type == "access":
            expire = datetime.now(timezone.utc) + \
                timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        else:
            expire = datetime.now(timezone.utc) + \
                timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.

    Args:
        token (str): The JWT token to decode.

    Returns:
        dict: The decoded payload data.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
