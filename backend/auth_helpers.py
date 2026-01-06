# auth_helpers.py
# Optional helper module for future JWT-based authentication
# NOT actively used in the current system

import jwt
from datetime import datetime, timedelta
import os

# Read secret safely from environment (NO Flask context dependency)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "development_secret_key")

# ------------------------------------------------------------
# JWT Helpers (Future Use)
# ------------------------------------------------------------
def create_jwt_token(user_id: int, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=1),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_jwt_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
