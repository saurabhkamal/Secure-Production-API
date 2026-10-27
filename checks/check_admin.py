# Proves only admins can open /admin/transactions.

import httpx
from app import config

BASE = "http://127.0.0.1:8000"

def login(username, password):
    """Log in and return the access token."""
    r = httpx.post(f"{BASE}/auth/token", data={"username": username, "password": password}, timeout=30)
    return r.json()["access_token"]


def call_admin(token=None):
    """Call /admin/transactions, with a token if given; return the response."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}   # no header when there's no token
    return httpx.get(f"{BASE}/admin/transactions", headers=headers, timeout=30)


no_token = call_admin()
print("No token ->", no_token.status_code, no_token.json()["detail"])      # expect 401

alice = call_admin(login("alice", config.DEMO_USER_PASSWORD))
print("alice    ->", alice.status_code, alice.json()["detail"])            # expect 403

admin = call_admin(login("admin", config.DEMO_ADMIN_PASSWORD))
print("admin    ->", admin.status_code, len(admin.json()), "transactions") # expect 200, 11