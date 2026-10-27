# checking each demo password in .env match the hash stored in Supabase?

from sqlalchemy import select

from app import config
from app.database import AppUser, SessionLocal
from app.security import verify_password

accounts = [
    ("alice", config.DEMO_USER_PASSWORD),
    ("ben", config.DEMO_USER_PASSWORD),
    ("admin", config.DEMO_ADMIN_PASSWORD),
]

with SessionLocal() as db:
    for username, password in accounts:
        user = db.scalar(select(AppUser).where(AppUser.username == username))   # load the stored row
        if user is None:
            print(f"{username}: NOT FOUND in app_users")
        else:
            print(f"{username}: password in .env matches stored hash -> {verify_password(password, user.hashed_password)}")