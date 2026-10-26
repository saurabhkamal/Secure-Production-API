from sqlalchemy import func, select, text   # select = build queries, func.count = SQL COUNT

from app.database import AppUser, SessionLocal, Transaction

with SessionLocal() as db:                                   # open a session, auto-closes at the end
    print("Connected:", db.execute(text("select 1")).scalar() == 1)            # can we reach Supabase?
    print("Users:", db.scalar(select(func.count()).select_from(AppUser)))       # should be 0 for now
    print("Transactions:", db.scalar(select(func.count()).select_from(Transaction)))  # your ledger rows

    for t in db.scalars(select(Transaction).limit(3)):       # read 3 rows through the model
        print(" ", t.reference, t.amount, t.currency, t.direction, t.status, "owner:", t.owner_id)