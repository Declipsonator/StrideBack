__author__ = "Declipsonator"
__copyright__ = "Copyright (C) 2024 Declipsonator"
__license__ = "GNU General Public License v3.0"


import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.utils.account_utils import UserInDB
from app.utils.mongo_utils import get_db

# Initialize APIRouter
router = APIRouter()

# Initialize password context for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.environ['SECRET']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 3  # 3 days


class Token(BaseModel):
    access_token: str
    token_type: str


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class UserLogin(BaseModel):
    username: str
    hashed_password: str
    email: str


async def get_user_login(db, username: str):
    """
    Fetches a user login from the database using the provided username.

    Args:
        db: The database connection object.
        username (str): The username of the user login to fetch.

    Returns:
        UserLogin: The fetched user login object if found, else None.
    """
    user_login = await db['user_logins'].find_one({"username": username})
    return UserLogin(**user_login)


async def authenticate_user(db, username: str, password: str):
    """
    Authenticates a user using the provided username and password.

    Args:
        db: The database connection object.
        username (str): The username of the user to authenticate.
        password (str): The password of the user to authenticate.

    Returns:
        UserInDB: The authenticated user object if authentication is successful, else False.
    """
    user = await get_user_login(db, username)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user


@router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db=Depends(get_db)) -> Token:
    """
    Endpoint for user login. Authenticates the user and returns an access token.

    Args:
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
        db: The database connection object.

    Returns:
        Token: A dictionary containing the access token and token type if login is successful.
    """

    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


# Define User Registration model
class UserRegistration(BaseModel):
    username: str
    password: str
    email: str
    first_name: str
    last_name: str


@router.post("/users")
async def create_user(user: UserRegistration, db=Depends(get_db)):
    """
    Endpoint for user registration. Creates a new user in the database.

    Args:
        user (User): The user object containing the username and password of the user to register.
        db: The database connection object.

    Returns:
        dict: A dictionary containing the status of the registration.

    """

    hashed_password = pwd_context.hash(user.password)
    user_in_db = user.dict()
    user_in_db['creation_date'] = str(datetime.now().isoformat())
    user_login = {"username": user.username, "hashed_password": hashed_password, "email": user.email}
    await db['users'].insert_one(user_in_db)
    await db['user_logins'].insert_one(user_login)

    # return success
    return {"status": "success"}
