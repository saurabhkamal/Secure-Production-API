# ============================================================
# main.py — The API's front door
# Run with:  python -m uvicorn app.main:app --reload
# ============================================================

from fastapi import Depends, FastAPI, HTTPException, status    # FastAPI building blocks
from pydantic import BaseModel, ConfigDict, Field              # request/response validation
from sqlalchemy import text, select                            # select = build queries; text = raw SQL
from sqlalchemy.orm import Session                             # type label for a database session

from app.database import get_db, AppUser                       # the users model + one session per request
from app.logging_config import logger                          # our shared logger
from app.security import hash_password                        # bcrypt hashing from Step 1

# Create the API object that uvicorn will run

app = FastAPI(
    title = "Secure Production API",                            # shown at the top of Swagger
    description="A PayLink ledger API secured with JWT, OAuth2, API keys and more.",
    version = "0.1.0"
)

logger.info("STARTUP | Secure Production API loaded")           # one line each time the app starts

# ============================================================
# Request / response models
# ============================================================
class RegisterRequest(BaseModel):
    """What the client must send to register. Pydantic rejects anything else with 422."""
    username: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")  # letters, digits, _
    password: str = Field(min_length=8, max_length=72)        # 72 = bcrypt's limit
    # no "role" field: clients can't choose their own role

class UserOut(BaseModel):
    """What we send back about a user. The password hash is not listed, so it can never leak"""
    model_config = ConfigDict(from_attributes=True)
    username: str
    role: str


@app.get("/health", tags=["Public"])                            # GET /health, grouped under "Public" in Swagger
def health(db: Session = Depends(get_db)):                      # FastAPI opens a session and passes it in
    """Public check: is the API running and can it reach the database?"""
    try:
        db.execute(text("select 1"))                            # the smallest possible query
    except Exception:
        logger.error("HEALTH | database unreachable")           # log the problem (no connection details)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,    # 503 = "temporarily unable to serve"
            detail="Database unreachable"
        )
    return {"status": "ok", "database": "ok"}                   # FastAPI turns this dict into JSON

# Auth endpoints
@app.post("/auth/register",                      # POST /auth/register
          response_model=UserOut,                # filter the reply through UserOut
          status_code=status.HTTP_201_CREATED,   # 201 = "a new resource was created"
          tags=["Auth"],                         # Swagger group
)

def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """Create a normal user. The password is hashed before it is stored."""
    existing = db.scalar(select(AppUser). where(AppUser.username == body.username)) 
    # look for a user with this username

    if existing:
        logger.warning("REGISTER FAIL | username taken: %s", body.username)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    user = AppUser(
        username=body.username,                          # the requested name
        hashed_password=hash_password(body.password),    # hash it; the plain password stops here
        role="user",                                     # always 'user', never chosen by the client   
    )
    db.add(user)                          # stage the new row
    db.commit()                           # save it to Supabase
    db.refresh(user)                      # reload it (gets the id and created_at from the DB)

    logger.info("REGISTER | user=%s", user.username)     # log the username, never the password
    return user                                          # UserOut strips everything but username + role

