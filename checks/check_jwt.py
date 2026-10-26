# Checks decode_token() against good and bad tokens.


from datetime import datetime, timedelta, timezone
from types import SimpleNamespace                 # a quick object with attributes, e.g. user.username

import jwt
from fastapi import HTTPException

from app import config
from app.security import create_access_token, decode_token

def make_token(secret, minutes):
    """Build a test token signed with `secret` that expires in `minutes` (negative = already expired)."""
    exp = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    payload = {"sub": "alice", "role": "admin", "type": "access", "exp": exp}
    return jwt.encode(payload, secret, algorithm="HS256")
    # Build the token: turn the payload into text, seal it with secret using HS256, 
    # and hand back header.payload.signature

alice = SimpleNamespace(username="alice", role="user")    # stand-in for alice's database row
token = create_access_token(alice)                        # a genuine token from our own function
print("Token:", token, "\n" )

tests = [
    ("1. Genuine Token", token),           # should be accepted
    ("2. Tampered Token", token + "x"),    # signature changed
    ("3. Forged Admin Token", make_token("attacker-guessed-secret-1234567890", 5)),   # wrong secret
    ("4. Expired token", make_token(config.JWT_SECRET_KEY, -1)),         # right secret, expired
    ("5. Not a token",        "hello-i-am-not-a-jwt"),                        # garbage"
]

for label, test_token in tests:
    try:
        payload = decode_token(test_token)
        print(f"{label}: ACCEPTED -> sub={payload['sub']}, role={payload['role']}")
    except HTTPException as error:
        print(f"{label}: REJECTED -> {error.status_code} {error.detail}")


