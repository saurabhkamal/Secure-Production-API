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
from app.database import AppUser, get_db, RevokedToken   # the users table + one session per request
from sqlalchemy.orm import Session                    # type label for a database session
from sqlalchemy import select                         # to look up the user
import secrets                                       # compare_digest: constant-time comparison
from fastapi.security import APIKeyHeader            # add next to your OAuth2PasswordBearer import
import uuid                                          # makes each token's unique ID (jti)



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

def _create_token(user, token_type: str, lifetime: timedelta) -> str:
    """Build and sign one token of the given type and lifetime."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,                        # who the token belongs to
        "role": user.role,                           # for information only
        "type": token_type,                          # "access" or "refresh"
        "iat": now,                                  # issued at
        "exp": now + lifetime,                       # expires at
        "jti": uuid.uuid4().hex,                     # unique ID, so this exact token can be revoked
    }
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)

def create_access_token(user) -> str:
    """Short-lived token (15 min) for calling the API."""
    return _create_token(user, "access", timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(user) -> str:
    """Long-lived token (7 days) used ONLY to get new tokens."""
    return _create_token(user, "refresh", timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS))

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

# Role-based access control
def require_admin(user: AppUser = Depends(get_current_user)) -> AppUser:
    """Only admins pass. First checks the token (401), then the role (403)."""
    if user.role != "admin":          # role from the database, not the token
        logger.warning("ACCESS DENIED | user=%s role=%s needed=admin", user.username, user.role)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"          
        )
    return user       # an admin: let them through




# API keys (machine-to-machine)

# Reads the "X-API-Key" header and adds it to Swagger's Authorize popup.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def _is_valid_key(api_key: str) -> bool:
    """True if api_key matches any key in .env. constant time"""
    for valid_key in config.API_KEYS:      # check each allowed key
        if secrets.compare_digest(api_key.encode(), valid_key.encode()):  # safely checks whether the two keys are identical.
            return True                 # found a match
    return False                    # no key matched

def require_api_key(api_key: str | None = Depends(api_key_header)) -> str:
    """Only callers with a valid X-API-Key pass. Used by /service/* endpoints."""
    if not api_key:                                                     # header missing or empty
        raise _unauthorized("Missing API key")
    if not _is_valid_key(api_key):                                      # header present but wrong
        raise _unauthorized(f"Invalid API key ending ...{api_key[-4:]}")  # last 4 chars only
    return api_key          


# Refresh tokens: each works once, then it's revoked
def burn_refresh_token(db: Session, refresh_token: str) -> AppUser:
    """Check a refresh token, revoke it so it can't be reused, and return its user."""
    payload = decode_token(refresh_token, expected_type="refresh")   # seal, expiry, type (401 if bad)

    if db.get(RevokedToken, payload["jti"]):         # is its ID already in revoked_tokens?
        raise _unauthorized("Refresh token has been revoked")

    user = db.scalar(select(AppUser).where(AppUser.username == payload["sub"]))  # load the user
    if user is None:
        raise _unauthorized("User no longer exists")

    db.add(RevokedToken(jti=payload["jti"]))         # punch it "VOID"
    db.commit()                                      # save to Supabase
    return user                                      # the caller decides what happens next

