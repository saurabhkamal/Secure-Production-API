# ============================================================
# security.py — The security toolbox
# Phase 4: password hashing (more tools added in later phases)
# ============================================================

import bcrypt # slow, salted password hashing
from datetime import datetime, timedelta, timezone  # token issue and expiry times
import jwt                                           # PyJWT: create and check tokens
from fastapi import HTTPException, status, Depends            # to return 401 errors
from app import config                               # JWT secret, algorithm, lifetime from .env
from app.logging_config import logger                # log every failed token check
from fastapi.security import OAuth2PasswordBearer    # reads Authorization: Bearer... headers
from app.database import AppUser, get_db             # the users table + one session per request
from sqlalchemy.orm import Session                    # type label for a database session
from sqlalchemy import select                         # to look up the user



def hash_password(plain_password: str) -> str:
    """Turn a plain password into a bcrypt hash for storage."""
    password_bytes = plain_password.encode("utf-8")      # bcrypt works on bytes, not text
    salt = bcrypt.gensalt()                              # new random salt every time (cost factor 12)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)   # salt + slow hashing -> 60-character result
    return hashed_bytes.decode("utf-8")                          # back to text so it fits a varchar column

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check a login attempt against a stored hash. True if it matches."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),          # the password being tried, as bytes
        hashed_password.encode("utf-8")           # the stored hash (contains its own salt), as bytes
                                                  # re-hashes the attempt with that salt and compares
    )

# the verify_password needs no separate salt. bcrypt reads the salt out of the stored hash, 

# JWT access tokens

def create_access_token(user) -> str:
    """Create a signed token for a user who has just logged in."""
    now = datetime.now(timezone.utc)                # current time in UTC (never local time)
    payload = {
        "sub": user.username,                   # who the token belongs to
        "role": user.role,                      # for information; the server re-checks the DB
        "type": "access",                       # marks this as an access token
        "iat": now,                             # issued at
        "exp": now + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES), # expires in 15 minutes
    }
    return jwt.encode(                          # build header.payload.signature
        payload,
        config.JWT_SECRET_KEY,                  # the secret that creates the seal
        algorithm=config.JWT_ALGORITHM,         # HS256 
    )

def _unauthorized(reason: str) -> HTTPException:
    """Log the failure, then build a 401 error to raise."""
    logger.warning("AUTH FAIL | %s", reason)                 # every rejected token gets logged
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,           # 401 = "we don't know who you are"
        detail=reason,                                      # the same reason goes to the client
        headers={"WWW-Authenticate": "Bearer"},             # tells the client to send a Bearer token
    )

def decode_token(token: str, expected_type: str = "access") -> dict:
    """check the token's seal, expiry and type. Return its payload, or raise 401"""
    try:
        # Check the seal with our secret, accept only our algorithm, and check "exp"
        payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:          # real token, but too old
        raise _unauthorized("Token has expired")        
    except jwt.InvalidTokenError:    # forged, edited or garbage
        raise _unauthorized("Invalid token")

    if payload.get("type") != expected_type:    # real token, but the wrong kind
        raise _unauthorized(f"Wrong token type: expected {expected_type} token")

    return payload   # all checks passed

# OAuth2: the guard for protected endpoints
# Reads "Authorization: Bearer <token>" and adds Swagger's Authorize button.

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")  # tokenUrl tells Swagger where to send the username and password.

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> AppUser:
    # the token from the header, and a database session
    """Any endpoint that depends on this requires a valid access token."""
    payload = decode_token(token)
    user = db.scalar(select(AppUser).where(AppUser.username == payload["sub"]))

    if user is None:
        raise _unauthorized("User no longer exists")
    return user

# get_current_user takes the token from the header, checks it, finds the matching user in Supabase, and gives that user to the 
# endpoint


