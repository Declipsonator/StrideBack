#  LICENSE: GNU General Public License v3.0
#  Copyright (c) 2024 Declipsonator
#
#  This software can be freely copied, modified, and distributed under the GPLv3
#  license, but requires inclusion of license and copyright notices, and users bear the
#  risk of open-sourcing the codebase if used for business purposes, while
#  modifications must be indicated and distributed under the same license, with no
#  warranties provided and no liability for damages on the part of the author or license.

import os
from fastapi import FastAPI
import app.routers.users.account_access as account_access
import app.routers.users.account as account
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# User Routers
app.include_router(account_access.router)
app.include_router(account.router)
