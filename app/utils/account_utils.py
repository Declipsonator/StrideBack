__author__ = "Declipsonator"
__copyright__ = "Copyright (C) 2024 Declipsonator"
__license__ = "GNU General Public License v3.0"


import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel

from app.utils.mongo_utils import get_db

# Define OAuth2 scheme for token generation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Define UserInDB model, which includes hashed password
class UserInDB(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    creation_date: str


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db=Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.environ['SECRET'], algorithms=['HS256'])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user


async def get_user(db, username: str):
    """
    Fetches a user from the database using the provided username.

    Args:
        db: The database connection object.
        username (str): The username of the user to fetch.

    Returns:
        UserInDB: The fetched user object if found, else None.
    """
    user = await db['users'].find_one({"username": username})
    del(user['_id'])
    if user:
        return user
