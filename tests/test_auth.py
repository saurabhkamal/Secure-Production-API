# Authentication: hashing, register, login, JWT, refresh tokens.

from datetime import datetime, timedelta, timezone

import jwt

from app import config
from app.security import hash_password, verify_password
from tests.conftest import bearer, login


def test_password_hashing():
    h1, h2 = hash_password("pass-123"), hash_password("pass-123")
    assert h1 != h2                                  # salted: same password, different hashes
    assert verify_password("pass-123", h1)           # correct password accepted
    assert not verify_password("wrong", h1)          # wrong password rejected


def test_register_hides_hash_and_blocks_admin(client, new_username):
    r = client.post("/auth/register",
                    json={"username": new_username, "password": "test-pass-123", "role": "admin"})
    assert r.status_code == 201
    assert r.json() == {"username": new_username, "role": "user"}   # no hash, and not admin


def test_login_failure_gives_same_message(client):
    wrong_password = login(client, "alice", "wrong-password")
    unknown_user = login(client, "nobody_here", "whatever-123")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()             # no username enumeration


def test_valid_token_opens_protected_route(client, alice):
    r = client.get("/users/me", headers=bearer(alice["access_token"]))
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_missing_token_is_rejected(client):
    assert client.get("/users/me").status_code == 401


def test_tampered_token_is_rejected(client, alice):
    r = client.get("/users/me", headers=bearer(alice["access_token"] + "x"))
    assert r.status_code == 401


def test_expired_token_is_rejected(client):
    expired = jwt.encode(
        {"sub": "alice", "type": "access", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)
    r = client.get("/users/me", headers=bearer(expired))
    assert r.status_code == 401
    assert r.json()["detail"] == "Token has expired"


def test_refresh_rotates_and_old_token_dies(client, alice):
    r = client.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    assert r.status_code == 200                                      # new pair issued
    replay = client.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    assert replay.status_code == 401                                 # old one can't be reused


def test_logout_revokes_refresh_token(client, alice):
    assert client.post("/auth/logout", json={"refresh_token": alice["refresh_token"]}).status_code == 204
    r = client.post("/auth/refresh", json={"refresh_token": alice["refresh_token"]})
    assert r.status_code == 401