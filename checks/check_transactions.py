# Proves alice and ben each see only their own transactions.


import httpx                  # Library for sending HTTP requests from Python (like Swagger, but in code)
from app import config        # read the demo password from .env

BASE = "http://127.0.0.1:8000"

def login(username, password):
    """Log in with the OAuth2 form and return the access token."""
    r = httpx.post(f"{BASE}/auth/token", data={"username": username, "password":password}, timeout=30)
    # Send POST http://127.0.0.1:8000/auth/token with the username and password as FORM fields

    return r.json()["access_token"]   # The reply is {"access_token": "eyJ...", "token_type": "bearer"}; take out just the token



# A helper function: fetch a user's transactions and give back just their reference codes
def my_references(token):
    """Fetch /transactions/me with this token; return the set of references."""

    # Send GET http://127.0.0.1:8000/transactions/me, with the token in the Authorization header
    r = httpx.get(f"{BASE}/transactions/me", headers={"Authorization": f"Bearer {token}"}, timeout=30)

    # The reply is a list of transactions; collect each one's "reference" into a set, e.g. {"INV-100", "INV-301"}
    return {t["reference"] for t in r.json()}


# Log in as alice, use her token to fetch her transactions, keep her references
alice_refs = my_references(login("alice", config.DEMO_USER_PASSWORD))

# Do exactly the same for ben (same demo password)
ben_refs = my_references(login("ben", config.DEMO_USER_PASSWORD))

# Show how many each sees, and which ones (sorted alphabetically to read easily)
print("alice sees", len(alice_refs), "transactions:", sorted(alice_refs))
print("ben sees  ", len(ben_refs), "transactions:", sorted(ben_refs))

# & finds references that are in BOTH sets; if there are none, print "None"
print("Any overlap? ", alice_refs & ben_refs or "None")

# Ask for transactions WITHOUT any token: the server should refuse
no_token = httpx.get(f"{BASE}/transactions/me", timeout=30)

# Show the status code we got back; expected 401
print("No token ->", no_token.status_code)