# ============================================================
# main.py — The API's front door
# Run with:  python -m uvicorn app.main:app --reload
# ============================================================

from fastapi import Depends, FastAPI, HTTPException, status    # FastAPI building blocks
from sqlalchemy import text                                    # lets us run raw SQL like "select 1"
from sqlalchemy.orm import session                             # type label for a database session

from app.database import get_db                                # gives each request its own session
from app.logging_config import logger                          # our shared logger

# Create the API object that uvicorn will run

app = FastAPI(
    title = "Secure Production API",                            # shown at the top of Swagger
    description="A PayLink ledger API secured with JWT, OAuth2, API keys and more.",
    version = "0.1.0"
)

logger.info("STARTUP | Secure Production API loaded")           # one line each time the app starts

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