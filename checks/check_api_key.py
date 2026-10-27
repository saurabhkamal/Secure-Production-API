# Proves API keys open /service/* only, and JWTs don't.


import httpx

from app import config

BASE = "http://127.0.0.1:8000"
SUMMARY = f"{BASE}/service/ledger-summary"
VALID_KEY = config.API_KEYS[0]                                 # the first key from .env


def get(url, headers=None):
    """Send a GET request and return the response."""
    return httpx.get(url, headers=headers or {}, timeout=30)


# 1. No key at all
r = get(SUMMARY)
print("1. No key            ->", r.status_code, r.json()["detail"])

# 2. A wrong key
r = get(SUMMARY, {"X-API-Key": "guessed-key-1234"})
print("2. Wrong key         ->", r.status_code, r.json()["detail"])

# 3. A valid key
r = get(SUMMARY, {"X-API-Key": VALID_KEY})
print("3. Valid key         ->", r.status_code)
for row in r.json():
    print("     ", row)

# 4. alice's JWT on the service route (wrong kind of credential)
token = httpx.post(f"{BASE}/auth/token",
                   data={"username": "alice", "password": config.DEMO_USER_PASSWORD},
                   timeout=30).json()["access_token"]
r = get(SUMMARY, {"Authorization": f"Bearer {token}"})
print("4. JWT on service    ->", r.status_code, r.json()["detail"])

# 5. The API key on a user route (also the wrong kind)
r = get(f"{BASE}/transactions/me", {"X-API-Key": VALID_KEY})
print("5. Key on user route ->", r.status_code, r.json()["detail"])