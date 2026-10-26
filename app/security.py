# ============================================================
# security.py — The security toolbox
# Phase 4: password hashing (more tools added in later phases)
# ============================================================

import bcrypt # slow, salted password hashing

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