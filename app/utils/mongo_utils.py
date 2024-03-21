#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.

import os

from motor.motor_asyncio import AsyncIOMotorClient


# Function to get MongoDB database
async def get_db():
    """
    Connects to the MongoDB database and returns the database object.

    Returns:
        AsyncIOMotorClient: The MongoDB database object.
    """
    client = AsyncIOMotorClient(os.environ['MONGO'])
    if os.environ['DEVELOPMENT'].lower() == 'true':
        return client['test-db']
    return client['app-db']
