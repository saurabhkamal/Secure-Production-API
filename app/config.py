# ============================================================
# config.py — Environment Variables
# Reads .env ONCE and exposes every setting as a Python constant.
# No other file in the app should call os.getenv().
# ============================================================

import os                       # os.getenv()  reads environment variables
from dotenv import load_dotenv  # loads key=value pairs from .env

load_dotenv()  # read .env into the environment

def _required(name: str) -> str:
    """Return an env var, or stop the app at startup if it's missing."""
    value = os.getenv(name)  # None if the variable doesn't exist
    if not value:  # catches both None and an empty string
        raise RuntimeError(f"Missing required environment variable: {name}")  # fail fast, clear message
    return value  # the variable exists and has a value


def _list(name: str, default: str = "") -> list[str]:
    """Turn 'a, b, c' into ['a', 'b', 'c']."""
    raw = os.getenv(name, default)  # use the default if the variable isn't set
    return [item.strip() for item in raw.split(",") if item.strip()]  # split, trim spaces, drop blanks


# ---------- Database ----------
DATABASE_URL = _required("DATABASE_URL")  # Supabase connection string, contains the DB password

# ---------- JWT ----------
JWT_SECRET_KEY = _required("JWT_SECRET_KEY")  # signs tokens; anyone with this can forge them
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")  # not secret, so a default is fine
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # int(): env vars are always strings
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))  # long-lived refresh token

# ---------- API keys ----------
API_KEYS = _list("API_KEYS")  # list of keys allowed to call /service/* endpoints

# ---------- CORS ----------
CORS_ORIGINS = _list("CORS_ORIGINS", "http://localhost:3000")  # browser origins we trust

# ---------- Rate limiting ----------
LOGIN_RATE_LIMIT = os.getenv("LOGIN_RATE_LIMIT", "5/minute")  # strict limit on login attempts
DEFAULT_RATE_LIMIT = os.getenv("DEFAULT_RATE_LIMIT", "60/minute")  # limit for everything else

# ---------- Logging ----------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")  # how much detail to log
LOG_FILE = os.getenv("LOG_FILE", "logs/app.log")  # log file path

# ---------- Demo users (only used by scripts/seed.py) ----------
DEMO_USER_PASSWORD = os.getenv("DEMO_USER_PASSWORD")    # password for alice and ben; may be None
DEMO_ADMIN_PASSWORD = os.getenv("DEMO_ADMIN_PASSWORD")  # password for admin; may be None