# seed.py — Create demo users and give transactions owners

from sqlalchemy import select               # builds database queries
from app import config                      # demo passwords come from .env
from app.security import hash_password      # bcrcypt
from app.database import AppUser, SessionLocal, Transaction  # tables + database sessions

# Stop early with a clear message if the passwords aren't set
if not config.DEMO_ADMIN_PASSWORD or not config.DEMO_USER_PASSWORD:
    raise SystemExit("Set DEMO_USER_PASSWORD and DEMO_ADMIN_PASSWORD in .env first.")

SEED_USERS = [
    ("alice", config.DEMO_USER_PASSWORD, "user"),
    ("ben", config.DEMO_USER_PASSWORD, "user"),
    ("admin", config.DEMO_ADMIN_PASSWORD, "admin")
]

with SessionLocal() as db:                   # open one database session
    # 1. Create each user, unless they already exist
    for username, password, role in SEED_USERS:
        # Ask the database is there a user with this username?
        existing = db.scalar(select(AppUser).where(AppUser.username == username))

        if existing:
            print(f"Already exists: {username}")
            continue   # Jump straight to the next user in the list, skipping the line below

        # Not found, so a build a new user row (password hashed) and adding it to the session
        db.add(AppUser(username=username, hashed_password=hash_password(password), role=role))
        print(f"Created: {username} ({role})")

    # send the new users to the database now, so the databases give them their ids
    db.flush()

    # 2. Fetch Alice and Ben
    # load Alice and Ben from the database, need her id to give her transactions
    alice = db.scalar(select(AppUser).where(AppUser.username == "alice"))
    ben = db.scalar(select(AppUser).where(AppUser.username == "ben"))

    # 3. Find transactions with no owner
    # Ask the database for every transaction whose owner_id is empty, as a list
    unowned = db.scalars(select(Transaction).where(Transaction.owner_id.is_(None))).all()

    # 4. Share them out between alice and ben
    # going through unowned transactions
    for i, transaction in enumerate(unowned):
        transaction.owner_id = alice.id if i % 2 == 0 else ben.id

    db.commit()    # Make all the changes permanent
    print(f"Assigned owners to {len(unowned)} transaction")

