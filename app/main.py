__author__ = "Declipsonator"
__copyright__ = "Copyright (C) 2024 Declipsonator"
__license__ = "GNU General Public License v3.0"


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