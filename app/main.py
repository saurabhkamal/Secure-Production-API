# ============================================================
# main.py — The API's front door
# Run with:  python -m uvicorn app.main:app --reload
# ============================================================

from fastapi import Depends, FastAPI, HTTPException, status, Request    # FastAPI building blocks
from pydantic import BaseModel, ConfigDict, Field              # request/response validation
from sqlalchemy import text, select                            # select = build queries; text = raw SQL
from sqlalchemy.orm import Session                             # type label for a database session

from app.database import get_db, AppUser                       # the users model + one session per request
from app.logging_config import logger                          # our shared logger
from app.security import (
    create_access_token, 
    get_current_user, 
    hash_password, 
    verify_password, 
    require_admin, 
    require_api_key,
    burn_refresh_token,
    create_refresh_token)                  

from fastapi.security import OAuth2PasswordRequestForm   # reads the OAuth2 login form

from datetime import datetime     # type for created_at
from decimal import Decimal       # exact type for money

from app.database import AppUser, Transaction, get_db
import uuid     # type for owner_id
from sqlalchemy import func, select, text 

from fastapi.middleware.cors import CORSMiddleware     # adds CORS headers to replies
from app import config                                 # CORS_ORIGINS from .env

from fastapi.responses import JSONResponse             # to build 429 reply
from slowapi import Limiter                            # the rate limiter
from slowapi.errors import RateLimitExceeded           # raised when a limit is hit
from slowapi.middleware import SlowAPIMiddleware       # applies the default limit to every endpoint
from slowapi.util import get_remote_address            # identifies callers by IP address



# Create the API object that uvicorn will run

app = FastAPI(
    title = "Secure Production API",                            # shown at the top of Swagger
    description="A PayLink ledger API secured with JWT, OAuth2, API keys and more.",
    version = "0.1.0"
)

# Rate Limiting: count requests per IP address
limiter = Limiter(
    key_func=get_remote_address,                  # count separately for each IP address
    default_limits=[config.DEFAULT_RATE_LIMIT]    # 60/minute for every endpoint, from .env
)
app.state.limiter = limiter                       # slowapi - rate limiting looks for the limiter
app.add_middleware(SlowAPIMiddleware)             # enforce the default limit on every request

@app.exception_handler(RateLimitExceeded)                         # runs whenever any limit is hit
def rate_limit_exceeded(request: Request, exc: RateLimitExceeded):
    """Log the event and reply with a clean 429."""
    logger.warning("RATE LIMIT | ip=%s path=%s limit=%s",
                   get_remote_address(request), request.url.path, exc.detail)
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,            # 429 = "slow down"
        content={"detail": f"Rate limit exceeded: {exc.detail}"}, # e.g. "5 per 1 minute"
        headers={"Retry-After": "60"},                            # tell the client how long to wait
    )
    # 2026-10-29 07:35:12 | WARNING | RATE LIMIT | ip=127.0.0.1 path=/auth/token limit=5 per 1 minute

# By adding the rate limiter first and CORS after it, CORS sits on the outside and adds its headers to every reply, including 429s
# Whatever layer creates a reply, that reply only gets CORS’s note if it travels back through CORS. So CORS must be the outermost layer, which means adding it last.


# CORS: which browser origins may read our replies
app.add_middleware(
    CORSMiddleware,                                       # only the websites listed in .env
    allow_origins=config.CORS_ORIGINS,                     # only the websites listed in .env
    allow_methods = ["GET", "POST"],                       # only the methods this API uses
    allow_headers=["Authorization", "Content-Type"],       # NOT X-API-Key: keys never belong in browsers
    allow_credentials=False,                               # we use Bearer tokens, not cookies
)

logger.info("CORS | allowed origins: %s", config.CORS_ORIGINS)

# Middleware is code that runs on every request and reply, before and after the endpoints.
# The endpoints don't change at all; the middleware adds the CORS headers on the way out.

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
    access_token: str           # 15-minute token for API calls
    refresh_token: str          # 7-day token for getting new tokens
    token_type: str = "bearer"   # tells the client how to send it (send this token as bearer token)
                                 # So, on every request the client adds: Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

class RefreshRequest(BaseModel):
    """Body for /auth/refresh and /auth/logout."""
    refresh_token: str


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


class LedgerSummaryRow(BaseModel):
    """One line of the summary: totals for one user, currency and direction. No individual transactions."""
    username: str                                              # whose totals these are
    currency: str                                              # e.g. "GBP"
    direction: str                                             # "debit" or "credit"
    count: int                                                 # how many transactions
    total: Decimal                                             # sum of their amounts



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
@limiter.limit(config.LOGIN_RATE_LIMIT)          # 5/minute per IP
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
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
@limiter.limit(config.LOGIN_RATE_LIMIT)            #  5/minute per IP
def login(
    request: Request,               # slowapi reads the IP from this
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
    return {
        "access_token": create_access_token(user), 
        "refresh_token": create_refresh_token(user),
        "token_type": "bearer"
        }


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


@app.get("/service/ledger-summary", response_model=list[LedgerSummaryRow], tags=["Service"])
def ledger_summary(
    api_key: str = Depends(require_api_key),                   # one line: valid API key required
    db: Session = Depends(get_db),
):
    """Totals per user, currency and direction, for internal reporting services."""
    rows = db.execute(
        select(
            AppUser.username,                                  # who
            Transaction.currency,                              # which currency
            Transaction.direction,                             # debit or credit
            func.count().label("count"),                       # how many
            func.sum(Transaction.amount).label("total"),       # how much in total
        )
        .join(AppUser, AppUser.id == Transaction.owner_id)     # attach each transaction to its owner
        .group_by(AppUser.username, Transaction.currency, Transaction.direction)  # one row per group
        .order_by(AppUser.username, Transaction.currency, Transaction.direction)  # tidy order
    ).all()

    logger.info("SERVICE | ledger summary served (%d rows)", len(rows))
    return [row._asdict() for row in rows]                     # each row becomes a dictionary

# This endpoint
# Suppose for e.g. When alice's access token has expired, her app sends her refresh token.
# The server checks it, voids it, and hands back a fresh pair of tokens, so she stays
# logged in without typing her password.
@app.post("/auth/refresh", response_model=TokenResponse, tags=["Auth"])
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    """Swap a refresh token for a NEW access + refresh pair. The old refresh token is voided."""
    user = burn_refresh_token(db, body.refresh_token)    # check the refresh tokens (genuine, expired), 
                                                         # if any check fails, 401 raised and below lines never run
    logger.info("TOKEN REFRESH | user=%s", user.username)

    # Send bank brand new pair of tokens
    return {
        "access_token": create_access_token(user),       # fresh 15-minute token
        "refresh_token": create_refresh_token(user),     # fresh 7-day token (rotation)
        "token_type": "bearer",                          # tells the app to send it as "Bearer <token>"
    }

# This endpoint
# The website or app calls it when alice clicks logout. 
# For e.g. It voids the refresh token, so it can never be used to get new access tokens again.
# That ends the user's session
@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["Auth"])
def logout(body: RefreshRequest, db: Session = Depends(get_db)):
    """Log out: void the refresh token so no new access tokens can be obtained."""
    user = burn_refresh_token(db, body.refresh_token)    # same check + void, no new tokens given
    logger.info("LOGOUT | user=%s", user.username)
    # 204 = "done, nothing to send back"