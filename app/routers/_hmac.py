"""HMAC-SHA256 verify helper for agent-facing endpoints.

Shared by:
  - app/routers/agent_config.py  (policy GET)
  - app/routers/yara.py          (ruleset GET, ruleset/download, /results POST)

Message format: f"{timestamp}.{agent_id}.{method}.{path}"
Window: 60s (replay protection).
Method+path binding: prevents reusing a signature on a different endpoint
    (e.g. an /agent-config GET signature can't be replayed on /yara/results).

PITFALL: if you change the message format here, the C++ side
MUST change too. The agent uses
`compute_policy_get_hmac` in agent_auth.{hpp,cpp} — same
helper works for any method/path as long as you pass them
as plain string args.

PITFALL: this helper does NOT cover the request body. For
POST endpoints the body is in clear over HTTPS — replay
protection comes from the timestamp+method+path, NOT from
the body. If you ever need body integrity, you must add a
separate `body_sha256` field to the message format AND a
matching change in the agent's HMAC computation.
"""
import hmac
import hashlib
import time

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import Agent


def verify_agent_hmac(
    agent_id: str,
    timestamp: str,
    signature: str,
    method: str,
    path: str,
    db: Session,
) -> Agent:
    """Verify HMAC-SHA256 and return the Agent row.

    Returns the Agent on success. Raises 401/403/404 on
    failure (timestamp / signature / agent-not-active /
    agent-not-found respectively). All error responses are
    JSON-formatted by FastAPI's default exception handler.
    """
    # 1. Parse timestamp (must be Unix seconds, integer)
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    # 2. Replay protection: 60s window
    if abs(int(time.time()) - ts) > 60:
        raise HTTPException(status_code=401, detail="Request expired")

    # 3. Agent lookup (404 if unknown — same convention as
    #    upstream nginx auth, which also returns 404 for unknown
    #    paths to avoid leaking which agents exist).
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # 4. Agent must be active (revoked/suspended agents can't pull)
    if agent.status != "active":
        raise HTTPException(status_code=403, detail="Agent not active")

    # 5. HMAC-SHA256 over the canonical message
    secret = agent.hmac_secret_enc
    message = f"{timestamp}.{agent_id}.{method}.{path}"
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    # 6. Constant-time compare (prevents timing oracle)
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")

    return agent
