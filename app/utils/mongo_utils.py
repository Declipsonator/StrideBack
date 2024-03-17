__author__ = "Declipsonator"
__copyright__ = "Copyright (C) 2024 Declipsonator"
__license__ = "GNU General Public License v3.0"


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
    return client['testdb']
