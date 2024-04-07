# StrideBack
The backend for a high school NY running website. This is an api that is built in Python using FastAPI. The api can be hosted anywhere but uses MongoDB as the database.
## Info
- The frontend is currently unpublished but will be worked upon in the future.
- I'm new to FastAPI and MongoDB so this is a learning experience for me, if you have any suggestions or improvements please let me know.
- This project is licensed under the GNU General Public License v3.0.

## Installation
### Setup
- Clone the repository
- Install the required packages using `pip install -r requirements.txt`
- Create a `.env` file in the app folder like the following:
```Shell
MONGO=mongodb://yourmongoURI
SECRET=your_secret_key_for_jwt
DEVELOPMENT=True/False

# The following variables are only required if DEVELOPMENT is False
EMAIL=your_email
EMAIL_PASSWORD=your_email_password
SMTP_HOST=your_smtp_host

# The following is what is emailed out to the user
CONFIRM_EMAIL_URL=http://localhost:8000/users/confirm-email/{code}
RESET_PASSWORD_URL=http://localhost:8000/users/reset-password/{code}
```

### Usage
- Run the server using `uvicorn main:app --reload` in the app folder

## Todo
- [x] Simple login/registration system with JWT tokens
- [x] Account verification and password reset
- [x] Email system
- [x] Public profiles with bio
- [ ] Post system
- [ ] Comment system
- [ ] Like system
- [ ] Follow system
- [ ] Fantasy XC????!?!??