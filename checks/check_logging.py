from app.logging_config import logger   # loads our logging setup

logger.debug("DEBUG line - should be HIDDEN")
logger.info("INFO line - normal activity")
logger.warning("WARNING line - LOGIN FAIL | username=alice")
logger.error("ERROR line - something broke")