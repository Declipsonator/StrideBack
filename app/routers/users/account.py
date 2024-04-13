#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.
from enum import Enum

from fastapi import APIRouter, Depends
import requests
from app.utils.account_utils import get_current_user
from app.utils.mongo_utils import get_db

router = APIRouter()


class ReportType(Enum):
    BIO = "bio"
    PROFILE_PICTURE = "profile_picture"
    USERNAME = "username"
    OTHER = "other"


@router.get("/users/me")
async def read_users_me(user=Depends(get_current_user)):
    """
    Endpoint to fetch the details of the currently logged-in user.

    Args:
        user: The user object of the currently logged-in user.

    Returns:
        dict: A dictionary of user information.
    """
    return {"status": "success", "username": user.username, "email": user.email, "first_name": user.first_name, "last_name": user.last_name, "creation_date": user.creation_date, "profile_picture": user.profile_picture, "bio": user.bio}


@router.post("/users/me/update/profile-picture")
async def update_profile_picture(profile_picture: str, user=Depends(get_current_user), db=Depends(get_db)):
    """
    Endpoint to update the profile picture of the currently logged-in user.

    Args:
        profile_picture (str): The new profile picture of the user.
        user: The user object of the currently logged-in user.
        db: The database connection object.


    Returns:
        dict: A dictionary containing the status of the update.
    """

    image_formats = ("image/png", "image/jpeg", "image/jpg")
    r = requests.head(profile_picture)
    if not r.headers.get("content-type", '') in image_formats:
        return {"status": "error", "reason": "Invalid image format. Please provide a valid image URL."}

    await user.update_profile_picture(profile_picture)

    return {"status": "success."}


@router.post("/users/me/update/bio")
async def update_bio(bio: str, user=Depends(get_current_user), db=Depends(get_db)):
    """
    Endpoint to update the profile picture of the currently logged-in user.

    Args: profile_picture (str):
        The new profile picture of the user.
        user: The user object of the currently logged-in user.
        db: The database connection object.


    Returns:
        dict: A dictionary containing the status of the update.
    """

    if len(bio) > 500:
        return {"status": "error", "reason": "Bio must be less than 500 characters."}

    await user.update_bio(bio)

    return {"status": "success"}


@router.get("/users/view/{username}")
async def view_user(username: str, user=Depends(get_current_user), db=Depends(get_db)):
    """
    Endpoint to view the profile of another user.

    Args:
        username (str): The username of the user to view.
        user: The user object of the currently logged-in user.
        db: The database connection object.

    Returns:
        dict: A dictionary of user information if the user is found, else an error message.
    """

    user = await db['users'].find_one({"username": username})
    if not user:
        return {"status": "error", "reason": "User not found."}
    # Only keep username, profile_picture, creation_date, and bio
    user = {k: v for k, v in user.items() if k in ["username", "profile_picture", "creation_date", "bio"]}
    user["status"] = "success"
    return user


@router.post("/users/report/{username}")
async def report_user(username: str, report_type: ReportType, description: str, reporter=Depends(get_current_user),
                      db=Depends(get_db)):
    """
    Endpoint to report a user.

    Args:
        username (str): The username of the user to report.
        report_type (ReportType): The type of report.
        reporter: The user object of the currently logged-in user.
        db: The database connection object.
        description (str): The description of the report.

    Returns:
        dict: A dictionary containing the status of the report if successful, else an error message.
    """
    if len(description) > 1000:
        return {"status": "error", "reason": "Description must be less than 1000 characters."}

    user = await db['users'].find_one({"username": username})
    if not user:
        return {"status": "error", "reason": "User not found."}

    await db['reports'].insert_one(
        {"username": username, "reporter": reporter.username, "report_type": report_type.value,
         "description": description})
    return {"status": "success."}
