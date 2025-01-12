# app/auth.py

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
from app.utils import decode_access_token
from app.database import users_collection
from bson import ObjectId

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/signin")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Dependency to get the current user based on JWT token.
    """
    try:
        payload = decode_access_token(token)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
