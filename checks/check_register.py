# Runs the 5 register tests against the running server.
# Start the server first:  python -m uvicorn app.main:app --reload
# Then run:                python -m checks.check_register

import uuid    # makes a random ending, so usernames are new on every run

import httpx   # sends HTTP requests from Python (like Swagger, but in code)

BASE = "http://127.0.0.1:8000"            # where the server is running
suffix = uuid.uuid4().hex[:6]             # e.g. "a1b2c3"
new_user = f"bob_{suffix}"                # a username that doesn't exist yet
attacker = f"mallory_{suffix}"            # another fresh username

# Each test: (description, JSON body to send, status code we expect)
tests = [
    ("1. New user",               {"username": new_user, "password": "bob-pass-123"},   201),
    ("2. Same user again",        {"username": new_user, "password": "bob-pass-123"},   409),
    ("3. Password too short",     {"username": "eve", "password": "123"},               422),
    ("4. Invalid username",       {"username": "e!", "password": "eve-pass-123"},       422),
    ("5. Tries to become admin",  {"username": attacker, "password": "mallory-pass-1",
                                   "role": "admin"},                                     201),
]

for description, body, expected in tests:                             # run each test in turn
    response = httpx.post(f"{BASE}/auth/register", json=body, timeout=30)         # send it as JSON
    result = "PASS" if response.status_code == expected else "FAIL"   # did we get what we expected?
    print(f"{result}  {description}: got {response.status_code}, expected {expected}")
    print(f"      response: {response.json()}")                       # show what the server replied

    if description.startswith("5.") and response.status_code == 201:  # extra check for the attacker
        role = response.json()["role"]
        print(f"      role is '{role}' -> {'PASS' if role == 'user' else 'FAIL: became admin!'}")