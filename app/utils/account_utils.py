#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.

import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel
from pyisemail import is_email

from app.utils.mongo_utils import get_db

# Define OAuth2 scheme for token generation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")


# Define UserInDB model, which includes hashed password
class UserInDB(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    creation_date: str


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db=Depends(get_db)):
    """
    Fetches the current user from the database using the provided token.
    :param token: The token to use to fetch the user.
    :param db: The database connection object.
    :return: The user object of the currently logged-in user.
    """
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
    del (user['_id'])
    if user:
        return user


def check_password_security(password: str):
    """
    Checks the security of the provided password.

    :param password: The password to check.

    :return: Returns a list containing a boolean indicating whether the password
    is secure and a message indicating the reason if it is not secure.
    """
    # needs at least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
    valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+.-')
    special_chars = set('!@#$%^&*()_+')
    if len(password) < 8:
        return [False, "Password must be at least 8 characters long"]
    if not any(char.isupper() for char in password):
        return [False, "Password must contain at least one uppercase letter"]
    if not any(char.islower() for char in password):
        return [False, "Password must contain at least one lowercase letter"]
    if not any(char.isdigit() for char in password):
        return [False, "Password must contain at least one number"]
    if not any(char in special_chars for char in password):
        return [False, "Password must contain at least one special character"]
    if not all(char in valid_chars for char in password):
        return [False, "Password may contain only the following characters: a-z, A-Z, 0-9, !@#$%^&*()_+.-"]
    return [True, "Password is secure"]


async def check_email_security(email: str):
    """
    Checks the security of the provided email address.

    :param email: The email address to check.

    :return: Returns a list containing a boolean indicating whether the
    email is secure and a message indicating the reason if it is not secure.
    """

    check = is_email(email, check_dns=True, diagnose=True, allow_gtld=False)

    if check.code == 0:
        return [True, "Email is secure"]

    return [False, "Invalid email address"]


def check_username_security(username: str):
    """
    Checks the username viability.

    :param username: The username to check.

    :return: Returns a list containing a
    boolean indicating whether the username is secure and a message indicating the reason if it is not secure.
    """

    valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._')
    if len(username) < 4:
        return [False, "Username must be at least 4 characters long"]
    if not all(char in valid_chars for char in username):
        return [False, "Username may contain only the following characters: a-z, A-Z, 0-9, ._"]
    return [True, "Username is secure"]


def check_if_email(string: str):
    """
    Checks if the provided string is an email address.

    :param string: The string to check.

    :return: Returns a boolean indicating whether the string is an email address.
    """

    return is_email(string).code == 0
