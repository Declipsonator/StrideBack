# StrideBack
The backend for a high school NY running website. This is an api that is built in Python using FastAPI. The api can be hosted anywhere but uses MongoDB as the database.
## Info
- The frontend is currently unpublished but will be worked upon in the future.
- I'm new to FastAPI and MongoDB so this is a learning experience for me, if you have any suggestions or improvements please let me know.
- This project is licensed under the GNU General Public License v3.0.

## Installation
- Clone the repository
- Install the required packages using `pip install -r requirements.txt`
- Add a `.env` file in the app folder with the following variables:
  - `MONGO` - The URI for the MongoDB database
  - `SECRET` - The secret key for hashing JWT tokens

- Run the server using `uvicorn main:app --reload` in the app folder

## Todo
- [x] Simple login/registration system with JWT tokens
- [x] Account verification and password reset
- [ ] Email system
- [ ] Public profiles with bio
- [ ] Post system
- [ ] Comment system
- [ ] Like system
- [ ] Follow system
- [ ] Fantasy XC????!?!??