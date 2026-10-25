# Config loads. It confirms Python can read your .env and turn it into settings. We print only harmless values, 
# so no secret appears on screen.

from app import config  # loads .env through config.py

print(config.JWT_ALGORITHM)                # HS256
print(config.ACCESS_TOKEN_EXPIRE_MINUTES)  # 15
print(config.CORS_ORIGINS)                 # ['http://localhost:3000']
print(len(config.API_KEYS), "keys")        # 2 keys (count only, never the keys)