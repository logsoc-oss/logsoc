"""JWT configuration.

T64.1.7: single source of truth = config.yaml (jwt.secret).
No more os.environ.get("JWT_SECRET"), no more /tmp/.secrets.json.
"""
from app.config_loader import require, get

JWT_SECRET = require("jwt.secret")
JWT_EXPIRE_HOURS = int(get("jwt.expire_hours", 24))
JWT_REFRESH_EXPIRE_DAYS = int(get("jwt.refresh_expire_days", 7))
JWT_ALGORITHM = get("jwt.algorithm", "HS256")
