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

from app.utils import comm_utils
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
    Args:
        token: The token to use to fetch the user.
        db: The database connection object.

    Returns:
        User: The user object of the fetched user.

    Raises:
        HTTPException: If the user is not found.
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
    return User(**user)


async def get_user(db, username: str):
    """
    Fetches a user from the database using the provided username.

    Args:
        db: The database connection object.
        username (str): The username of the user to fetch.

    Returns:
        dict: The fetched user object if found, else None.
    """
    user = await db['users'].find_one({"username": username})
    del (user['_id'])
    if user:
        return user


def check_password_security(password: str):
    """
    Checks the security of the provided password.

    Args:
        password: The password to check.

    Returns:
         dict: A dictionary containing a boolean indicating whether the password is secure and a message indicating the
            reason if it is not secure.
    """
    valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+.-')
    special_chars = set('!@#$%^&*()_+')
    if len(password) < 8:
        return {"secure": False, "reason": "Password must be at least 8 characters long"}
    if not any(char.isupper() for char in password):
        return {"secure": False, "reason": "Password must contain at least one uppercase letter"}
    if not any(char.islower() for char in password):
        return {"secure": False, "reason": "Password must contain at least one lowercase letter"}
    if not any(char.isdigit() for char in password):
        return {"secure": False, "reason": "Password must contain at least one number"}
    if not any(char in special_chars for char in password):
        return {"secure": False, "reason": "Password must contain at least one special character"}
    if not all(char in valid_chars for char in password):
        return {"secure": False, "reason": "Password may contain only the following characters: a-z, A-Z, 0-9, "
                                           "!@#$%^&*()_+.-"}
    return {"secure": True, "reason": "Password is secure"}


async def check_email_security(email: str):
    """
    Checks the security of the provided email address.

    Args:
        email: The email address to check.

    Returns:
        dict: A dictionary containing a boolean indicating whether the email is secure and a message indicating the
            reason if it is not secure.
    """

    check = is_email(email, check_dns=True, diagnose=True, allow_gtld=False)

    if check.code == 0:
        return {"secure": True, "reason": "Email is secure"}

    return {"secure": False, "reason": check.diagnosis}


def check_username_security(username: str):
    """
    Checks the username viability.

    Args:
        username: The username to check.

    Returns:
        dict: A dictionary containing a boolean indicating whether the username is secure and a message indicating the
            reason if it is not secure.

    """

    valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._')
    if len(username) < 4:
        return {"secure": False, "reason": "Username must be at least 4 characters long"}
    if not all(char in valid_chars for char in username):
        return {"secure": False, "reason": "Username may contain only the following characters: a-z, A-Z, 0-9, ., _"}
    return {"secure": True, "reason": "Username is secure"}


def check_if_email(string: str):
    """
    Checks if the provided string is an email address.

    Args:
        string: The string to check.

    Returns:
        bool: True if the string is an email address, False otherwise.
    """

    return is_email(string).code == 0


class User:
    def __init__(self, username: str, email: str, first_name: str, last_name: str, creation_date: str, profile_picture: str = None, bio: str = None):
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.creation_date = creation_date
        self.profile_picture = profile_picture
        self.bio = bio


    def __repr__(self):
        return (f"User(username={self.username}, email={self.email}, first_name={self.first_name}, "
                f"last_name={self.last_name}, creation_date={self.creation_date})")

    def send_email(self, subject: str, message: str):
        """
        Sends an email to the user with the specified subject and message.

        Args:
            subject: The subject of the email.
            message: The message of the email.

        Returns:
            bool: True if the email was sent successfully, False otherwise.
        """
        comm_utils.send_email(self.email, subject, message)

    def send_fancy_email(self, subject: str, header: str, message: str, footer: str):
        """
        Sends a fancy email to the user with the specified subject, header, message, and footer.

        Args:
            subject: The subject of the email.
            header: The header of the email.
            message: The message of the email.
            footer: The footer of the email.

        Returns:
             Returns a boolean indicating whether the email was sent successfully.
        """
        comm_utils.send_fancy_email(self.email, subject, header, message, footer)

    async def update_bio(self, bio: str):
        """
        Updates the bio of the user.

        Args:
            bio: The new bio of the user.

        Returns:
            bool: True if the bio was updated successfully, False otherwise.
        """
        # Update bio in database
        db = await get_db()
        await db['users'].find_one_and_update({"username": self.username}, {"$set": {"bio": bio}})
        return True

    async def update_profile_picture(self, profile_picture: str):
        """
        Updates the profile picture of the user.

        Args:
            profile_picture: The new profile picture of the user.

        Returns:
            Returns a boolean indicating whether the profile picture was updated successfully.
        """
        # Update profile picture in database
        db = await get_db()
        await db['users'].find_one_and_update({"username": self.username},
                                                    {"$set": {"profile_picture": profile_picture}})
        return True
