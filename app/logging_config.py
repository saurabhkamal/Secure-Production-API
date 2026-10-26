# ============================================================
# logging_config.py — Logging
# Every log line goes to the screen AND to logs/app.log. 
# Golden rule: never log passwords, tokens or API keys
# ============================================================

import logging   # Python's built-in logging library
import os        # used to create the logs/ folder
from app import config     # LOG_LEVEL and LOG_FILE come from .env

# Create the logs/ folder if it doesn't exist yet ("or '.'" covers a path with no folder)
os.makedirs(os.path.dirname(config.LOG_FILE) or ".", exist_ok=True)  # exist_ok=True means “if it’s already there, Python would not crash

# Set up logging once: minimum level, line layout, and the two destinations
logging.basicConfig(
    level=config.LOG_LEVEL,                               # ignore anything below this (e.g. DEBUG at INFO)
    format="%(asctime)s | %(levelname)-7s | %(message)s",  # time | level | message
    handlers=[
        logging.StreamHandler(),                                  # destination 1: the screen
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),   # destination 2: the file
    ],    
)

# The named logger the rest of the app imports: from app.logging_config import logger
logger = logging.getLogger("secure_api")