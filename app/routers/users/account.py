#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.

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
