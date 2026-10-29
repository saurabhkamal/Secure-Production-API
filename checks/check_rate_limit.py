# Proves login is limited to 5 attempts per minute per IP
# Afterwards logins from the machine are blocked for about 1 minute

import httpx

for attempt in range(1, 7):
    r = httpx.post(
        "http://127.0.0.1:8000/auth/token", 
        data={"username": "alice", "password": "wrong-password"},  # always wrong
        timeout=30
    )
    print(f"attempt {attempt}: {r.status_code} {r.text}")

# five 401s, then one 429.