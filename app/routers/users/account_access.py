__author__ = "Declipsonator"
__copyright__ = "Copyright (C) 2024 Declipsonator"
__license__ = "GNU General Public License v3.0"

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.utils import account_utils
from app.utils.account_utils import UserInDB
from app.utils.mongo_utils import get_db

# Initialize APIRouter
router = APIRouter()

# Initialize password context for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.environ['SECRET']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 3  # 3 days

# Dict for storing unconfirmed users
unconfirmed_users = {}

# Dict for storing password reset codes
password_reset_codes = {}


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
    if not user_login:
        return None
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


@router.post("/users/login")
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


@router.post("/users/register")
async def create_user(user: UserRegistration, db=Depends(get_db)):
    """
    Endpoint for user registration. Creates a new user in the database.

    Args:
        user (User): The user object containing the username and password of the user to register.
        db: The database connection object.

    Returns:
        dict: A dictionary containing the status of the registration.

    """

    for user_in_db in unconfirmed_users.values():
        if user_in_db['username'] == user.username:
            return {"status": "failure", "detail": "Username already exists"}
        elif user_in_db['email'] == user.email:
            return {"status": "failure", "detail": "Email already exists"}

    if await db['users'].find_one({"username": user.username}):
        return {"status": "failure", "detail": "Username already exists"}
    elif await db['users'].find_one({"email": user.email}):
        return {"status": "failure", "detail": "Email already exists"}

    # password security
    secure, reason = account_utils.check_password_security(user.password)
    if not secure:
        return {"status": "failure", "detail": reason}

    # email security
    secure, reason = await account_utils.check_email_security(user.email)
    if not secure:
        return {"status": "failure", "detail": reason}
    hashed_password = pwd_context.hash(user.password)
    user_in_db = user.dict()
    user_in_db['password'] = hashed_password
    user_in_db['creation_date'] = str(datetime.now().isoformat())

    confirm_code = str(uuid4())
    unconfirmed_users[confirm_code] = user_in_db

    # send email with confirmation code
    await account_utils.send_email(user.email, "Account Confirmation",
                                   f"Your confirmation code is {confirm_code}, it will expire in 15 minutes.")

    # return success
    return {"status": "success"}


@router.get("/users/confirm/{code}")
async def confirm_user(code: str, db=Depends(get_db)):
    """
    Endpoint for user confirmation. Confirms the user registration.

    Args:
        code (str): The confirmation code of the user to confirm.
        db: The database connection object.

    Returns:
        dict: A dictionary containing the status of the confirmation.

    """

    for key, value in unconfirmed_users.items():
        if datetime.now() - datetime.fromisoformat(value['creation_date']) > timedelta(minutes=15):
            unconfirmed_users.pop(key)

    if code in unconfirmed_users:
        user_in_db = unconfirmed_users.pop(code)
        user_login = {"username": user_in_db["username"], "hashed_password": user_in_db["password"],
                      "email": user_in_db["email"]}
        del user_in_db['password']
        await db['users'].insert_one(user_in_db)
        await db['user_logins'].insert_one(user_login)
        return {"status": "success"}

    return {"status": "failure"}


@router.get("/users/password/reset/{username}")
async def reset_password(username: str, db=Depends(get_db)):
    """
    Endpoint for user password reset. Sends a password reset email to the user.

    Args:
        username (str): The username of the user to reset the password for.
        db: The database connection object.

    Returns:
        dict: A dictionary containing the status of the password reset.

    """

    user = await get_user_login(db, username)
    if not user:
        return {"status": "failure", "detail": "User not found"}

    user = user.dict()
    user['creation_date'] = str(datetime.now().isoformat())
    reset_code = str(uuid4())
    password_reset_codes[reset_code] = user
    await account_utils.send_email(user["email"], "Password Reset",
                                   f"Your password reset code is {reset_code}, it will expire in 15 minutes.")

    return {"status": "success"}


@router.post("/users/password/reset/{code}")
async def reset_password_final(code: str, new_password: str, db=Depends(get_db)):
    """
    Endpoint for user password reset. Resets the password for the user.

    Args:
        code (str): The reset code of the user to reset the password for.
        new_password (str): The new password to set for the user.
        db: The database connection object.

    Returns:
        dict: A dictionary containing the status of the password reset.

    """

    for key, value in password_reset_codes.items():
        if datetime.now() - datetime.fromisoformat(value['creation_date']) > timedelta(minutes=15):
            password_reset_codes.pop(key)

    if code in password_reset_codes:
        result, reason = account_utils.check_password_security(new_password)
        if not result:
            return {"status": "failure", "detail": reason}
        user = password_reset_codes.pop(code)
        hashed_password = pwd_context.hash(new_password)
        # check if user used email to log in
        if await db['user_logins'].find_one({"username": user["username"]}):
            await db['user_logins'].find_one_and_update({"username": user["username"]},
                                                        {"$set": {"hashed_password": hashed_password}})
        elif await db['user_logins'].find_one({"email": user["username"]}):
            await db['user_logins'].find_one_and_update({"email": user["email"]},
                                                        {"$set": {"hashed_password": hashed_password}})
        return {"status": "success"}

    return {"status": "failure"}
