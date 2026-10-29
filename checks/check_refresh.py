# This file's purpose is to prove three things:
# - a refresh token gives new tokens, 
# - works only once, 
# - and stops working after logout.

import httpx
from app import config

BASE = "http://127.0.0.1:8000"

def post(path, body):
    """Send a JSON POST to our API."""
    return httpx.post(f"{BASE}{path}", json=body, timeout=30)

# Log in once to get the first refresh token (login uses form data, not JSON)
login = httpx.post(f"{BASE}/auth/token", 
                   data={"username": "alice", "password": config.DEMO_USER_PASSWORD},
                   timeout=30)
old_refresh = login.json()["refresh_token"]        # saves first refresh token(R1), from the login
                                                   # Its old because by then it has been replaced by R2


# 1. # Send the old refresh token (R1) to /auth/refresh; the server voids it and returns a new pair
r = post("/auth/refresh", {"refresh_token": old_refresh})

# Read the reply: new = {"access_token": "A2", "refresh_token": "R2", "token_type": "bearer"}
new = r.json()

# Call /users/me using the NEW access token (A2), to prove it really works
me = httpx.get(f"{BASE}/users/me", headers={"Authorization":f"Bearer {new['access_token']}"}, timeout=30)

# Show both results: the refresh's status code and /users/me's status code
print("1: Refresh ->", r.status_code, "| new access token works:", me.status_code)

# 2. Reuse the old refresh token: must fail (works only once)
r = post("/auth/refresh", {"refresh_token": old_refresh})
print("2. Reuse old refresh token ->", r.status_code, r.json()["detail"])

# 3. Log out with the new refresh token
r = post("/auth/logout", {"refresh_token": new["refresh_token"]})
print("3. Logout  ->", r.status_code)

# 4. Try to refresh after logout: must fail
r = post("/auth/refresh", {"refresh_token": new["refresh_token"]})
print("4. Refresh after logout    ->", r.status_code, r.json()["detail"])