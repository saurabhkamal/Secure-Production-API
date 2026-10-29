# Shared test setup. pytest loads this file automatically.

import uuid

import pytest
from fastapi.testclient import TestClient            # runs our API inside the test, no server needed
from sqlalchemy import delete

from app import config
from app.database import AppUser, SessionLocal
from app.main import app, limiter


def login(client, username, password):
    """Log in with the OAuth2 form; return the response."""
    return client.post("/auth/token", data={"username": username, "password": password})


def bearer(token):
    """Build the Authorization header for a token."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    """Our API, with rate-limit counters reset so tests don't block each other."""
    limiter.reset()
    return TestClient(app)


@pytest.fixture
def alice(client):
    """alice's access and refresh tokens."""
    return login(client, "alice", config.DEMO_USER_PASSWORD).json()


@pytest.fixture
def new_username():
    """A fresh username; the user is deleted from Supabase after the test."""
    name = f"test_{uuid.uuid4().hex[:8]}"
    yield name                                       # the test runs here
    with SessionLocal() as db:                       # then clean up
        db.execute(delete(AppUser).where(AppUser.username == name))
        db.commit()