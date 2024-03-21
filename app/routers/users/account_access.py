#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.utils import account_utils, comm_utils
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


# Define Token model
class Token(BaseModel):
    access_token: str
    token_type: str


# Function to create access token for OAuth2
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Login model
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
    if account_utils.is_email(username):
        user_login = await db['user_logins'].find_one({"email": username})
    else:
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
    if account_utils.is_email(username):
        user = await db['user_logins'].find_one({"email": username})
        if not user:
            return False
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
    await comm_utils.send_fancy_email(user.email, "Account Confirmation",
                                      "Account Confirmation",
                                      f"Click the link to confirm your account: "
                                      f"{os.environ['CONFIRM_EMAIL_URL'].format(code=confirm_code)}",
                                      "This link will expire in 15 minutes.")

    # return success
    return {"status": "success"}


@router.get("/users/confirm-email/{code}")
async def confirm_user(code: str, db=Depends(get_db)):
    """
    Endpoint for user confirmation. Confirms the user registration.

    Args:
        code (str): The confirmation code of the user to confirm.
        db: The database connection object.

    Returns:
        dict: A dictionary containing the status of the confirmation.

    """

    to_remove = []
    for key, value in unconfirmed_users.items():
        if datetime.now() - datetime.fromisoformat(value['creation_date']) > timedelta(minutes=15):
            to_remove.append(key)

    for key in to_remove:
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


@router.get("/users/reset-password/")
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
        if os.environ['DEVELOPMENT'].lower() == 'true':
            return {"status": "failure", "detail": "User not found"}
        else:
            # While it may be helpful to return a detailed error message in development,
            # it is not recommended in production to avoid leaking information about the existence of users.
            return {"status": "success"}

    user = user.dict()
    user['creation_date'] = str(datetime.now().isoformat())
    reset_code = str(uuid4())
    password_reset_codes[reset_code] = user
    await comm_utils.send_fancy_email(user["email"], "Password Reset",
                                      "Password Reset",
                                      f"Click the link to reset your password for \"{user["username"]}\": "
                                      f"{os.environ["RESET_PASSWORD_URL"].format(code=reset_code)} (Does not work yet)",
                                      "This link will expire in 15 minutes.")

    return {"status": "success"}


@router.post("/users/reset-password/{code}")
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

    to_remove = []
    for key, value in password_reset_codes.items():
        if datetime.now() - datetime.fromisoformat(value['creation_date']) > timedelta(minutes=15):
            to_remove.append(key)

    for key in to_remove:
        password_reset_codes.pop(key)

    if code in password_reset_codes:
        result, reason = account_utils.check_password_security(new_password)
        if not result:
            return {"status": "failure", "detail": reason}
        user = password_reset_codes.pop(code)
        hashed_password = pwd_context.hash(new_password)
        # check if user used email to log in
        await db['user_logins'].find_one_and_update({"username": user["username"]},
                                                    {"$set": {"hashed_password": hashed_password}})

        return {"status": "success"}

    return {"status": "failure"}


@router.get("/users/reset-password/valid/{code}")
async def check_reset_code(code: str):
    """
    Endpoint for checking the validity of a password reset code.

    Args:
        code (str): The reset code to check the validity of.

    Returns:
        dict: A dictionary containing the status of the reset code.

    """

    to_remove = []

    for key, value in password_reset_codes.items():
        if datetime.now() - datetime.fromisoformat(value['creation_date']) > timedelta(minutes=15):
            to_remove.append(key)

    for key in to_remove:
        password_reset_codes.pop(key)

    if code in password_reset_codes:
        return {"status": "success", "detail": "Code is valid"}

    return {"status": "failure", "detail": "Code is invalid"}

