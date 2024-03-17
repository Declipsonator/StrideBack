__author__ = "Declipsonator"
__copyright__ = "Copyright (C) 2024 Declipsonator"
__license__ = "GNU General Public License v3.0"

from fastapi import APIRouter, Depends

from app.utils.account_utils import get_current_user

router = APIRouter()


@router.get("/users/me")
async def read_users_me(user=Depends(get_current_user)):
    """
    Endpoint to fetch the details of the currently logged-in user.

    Args: user (UserInDB, optional): The user object of the currently logged-in user. Defaults to Depends on
    get_current_user.

    Returns:
        UserInDB: The user object of the currently logged-in user.

    Raises:
        HTTPException: If the user is not found.
    """
    return user
