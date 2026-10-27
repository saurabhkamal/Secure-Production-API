# ============================================================
# main.py — The API's front door
# Run with:  python -m uvicorn app.main:app --reload
# ============================================================

from fastapi import Depends, FastAPI, HTTPException, status    # FastAPI building blocks
from pydantic import BaseModel, ConfigDict, Field              # request/response validation
from sqlalchemy import text, select                            # select = build queries; text = raw SQL
from sqlalchemy.orm import Session                             # type label for a database session

from app.database import get_db, AppUser                       # the users model + one session per request
from app.logging_config import logger                          # our shared logger
from app.security import create_access_token, get_current_user, hash_password, verify_password, require_admin                  

from fastapi.security import OAuth2PasswordRequestForm   # reads the OAuth2 login form

from datetime import datetime     # type for created_at
from decimal import Decimal       # exact type for money

from app.database import AppUser, Transaction, get_db
import uuid     # type for owner_id



# Create the API object that uvicorn will run

app = FastAPI(
    title = "Secure Production API",                            # shown at the top of Swagger
    description="A PayLink ledger API secured with JWT, OAuth2, API keys and more.",
    version = "0.1.0"
)

logger.info("STARTUP | Secure Production API loaded")           # one line each time the app starts

# ============================================================
# Request / response models
# ============================================================
class RegisterRequest(BaseModel):
    """What the client must send to register. Pydantic rejects anything else with 422."""
    username: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")  # letters, digits, _
    password: str = Field(min_length=8, max_length=72)        # 72 = bcrypt's limit
    # no "role" field: clients can't choose their own role

class UserOut(BaseModel):
    """What we send back about a user. The password hash is not listed, so it can never leak"""
    model_config = ConfigDict(from_attributes=True)
    username: str
    role: str


# TokenResponse makes sure the reply looks exactly like this
class TokenResponse(BaseModel):
    """What a successful login returns (the OAuth2 standard format)."""
    access_token: str           # the JWT
    token_type: str = "bearer"   # tells the client how to send it (send this token as bearer token)
                                 # So, on every request the client adds: Authorization: Bearer eyJhbGciOiJIUzI1NiIs...


class TransactionOut(BaseModel):
    """What we send back for each transaction. owner_id is deliberately left out."""
    model_config = ConfigDict(from_attributes=True)         # build it from a database row
    reference: str                                           # e.g. "INV-100"
    amount: Decimal                                          # exact money value
    currency: str                                            # e.g. "GBP"
    direction: str                                           # "debit" or "credit"
    status: str                                              # e.g. "completed"
    merchant: str                                            # who was paid / who paid
    description: str | None                                  # may be empty
    created_at: datetime                                     # when it happened


class AdminTransactionOut(TransactionOut):
    """Same as TransactionOut, plus who owns it. Only admins ever receive this."""
    owner_id: uuid.UUID | None                                # admins need to see whose transaction it is


@app.get("/health", tags=["Public"])                            # GET /health, grouped under "Public" in Swagger
def health(db: Session = Depends(get_db)):                      # FastAPI opens a session and passes it in
    """Public check: is the API running and can it reach the database?"""
    try:
        db.execute(text("select 1"))                            # the smallest possible query
    except Exception:
        logger.error("HEALTH | database unreachable")           # log the problem (no connection details)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,    # 503 = "temporarily unable to serve"
            detail="Database unreachable"
        )
    return {"status": "ok", "database": "ok"}                   # FastAPI turns this dict into JSON

# Auth endpoints
@app.post("/auth/register",                      # POST /auth/register
          response_model=UserOut,                # filter the reply through UserOut
          status_code=status.HTTP_201_CREATED,   # 201 = "a new resource was created"
          tags=["Auth"],                         # Swagger group
)

def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """Create a normal user. The password is hashed before it is stored."""
    existing = db.scalar(select(AppUser). where(AppUser.username == body.username)) 
    # look for a user with this username

    if existing:
        logger.warning("REGISTER FAIL | username taken: %s", body.username)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    user = AppUser(
        username=body.username,                          # the requested name
        hashed_password=hash_password(body.password),    # hash it; the plain password stops here
        role="user",                                     # always 'user', never chosen by the client   
    )
    db.add(user)                          # stage the new row
    db.commit()                           # save it to Supabase
    db.refresh(user)                      # reload it (gets the id and created_at from the DB)

    logger.info("REGISTER | user=%s", user.username)     # log the username, never the password
    return user                                          # UserOut strips everything but username + role


# Register this function to handle POST /auth/token; shape the reply like TokenResponse; group it under "Auth" in Swagger
@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
def login(
    # FastAPI reads the login form for us: form_data.username and form_data.password
    form_data: OAuth2PasswordRequestForm = Depends(),
    # FastAPI opens a database session for us
    db: Session = Depends(get_db),
):
    """OAuth2 password flow: username + password in, access token out."""

    # Ask Supabase for the user with this username; gives their row, or None if no such user
    user = db.scalar(select(AppUser).where(AppUser.username == form_data.username))

    # Fail if the user doesn't exist OR the password doesn't match the stored bcrypt hash
    if user is None or not verify_password(form_data.password, user.hashed_password):

        # Write a warning to the log: which username failed (never the password)
        logger.warning("LOGIN FAIL | username=%s", form_data.username)

        # Stop here and send an error back to the client
        raise HTTPException(
            # 401 = "we couldn't confirm who you are"
            status_code=status.HTTP_401_UNAUTHORIZED,
            # The same message for "no such user" and "wrong password", so attackers learn nothing
            detail="Incorrect username or password",
            # Standard OAuth2 hint telling the client to use Bearer tokens
            headers={"WWW-Authenticate": "Bearer"},
        )

    # We only reach this line if the username exists AND the password was correct
    logger.info("LOGIN OK | user=%s", user.username)

    # Make a signed JWT for this user and send it back in the standard OAuth2 shape
    return {"access_token": create_access_token(user), "token_type": "bearer"}


# Register this function to handle GET /users/me; shape the reply like UserOut; group it under "Users"
@app.get("/users/me", response_model=UserOut, tags=["Users"])

# Before running, FastAPI runs the guard: token from header → check it → find the user in Supabase.
# If any of that fails, the guard returns 401 and this function never runs.
def read_me(user: AppUser = Depends(get_current_user)):
    """Who am I? Requires a valid access token."""

    # Send back the verified user; UserOut keeps only username and role (the hash is dropped)
    return user

# /users/me has no user ID in the URL. The server works out who you are from your token, so 
# so alice can never ask for someone else’s profile by changing a number in the URL.
# The same idea protects /transactions/me

@app.get("/transactions/me", response_model=list[TransactionOut], tags=["Transactions"])
def my_transactions(user: AppUser = Depends(get_current_user), db: Session = Depends(get_db)):
    # who is asking: from the token, never the URL and database session
    
    """The logged-in user's own transactions, newest first."""
    return db.scalars(
        select(Transaction)
        .where(Transaction.owner_id == user.id)             # ONLY rows owned by this user
        .order_by(Transaction.created_at.desc())            # newest first
    ).all()                                                 # a list; each row filtered through TransactionOut


@app.get("/admin/transactions", response_model=list[AdminTransactionOut], tags=["Admin"])
def all_transactions(
    admin: AppUser = Depends(require_admin),                  # one line: admins only
    db: Session = Depends(get_db),
):
    """Every transaction from every user. Admins only."""
    logger.info("ADMIN | user=%s viewed all transactions", admin.username)  # admin actions are audited
    return db.scalars(
        select(Transaction).order_by(Transaction.created_at.desc())  # no owner filter: everything
    ).all()