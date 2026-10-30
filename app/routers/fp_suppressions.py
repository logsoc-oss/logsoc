"""routers/fp_suppressions.py — False-positive suppression endpoints.

GET    /api/v1/correlation/suppressions          List suppressions (user)
POST   /api/v1/correlation/suppressions          Create suppression (soc_analyst+)
DELETE /api/v1/correlation/suppressions/{id}     Delete suppression (admin)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import FalsePositiveSuppression, User
from app.routers.auth import require_role

logger = logging.getLogger("logsoc.fp_suppressions")

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────

class SuppressionCreate(BaseModel):
    rule_id: str
    suppression_type: str  # field_match, regex, time_window
    field_name: Optional[str] = None
    field_value: Optional[str] = None
    regex_pattern: Optional[str] = None
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    expires_at: Optional[str] = None  # ISO datetime string
    reason: Optional[str] = None


# ── Endpoints ──────────────────────────────────────────────────────

@router.get("/suppressions")
def list_suppressions(
    rule_id: Optional[str] = Query(None, description="Filter by rule_id"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List false-positive suppressions. Optionally filter by rule_id."""
    q = db.query(FalsePositiveSuppression)
    if rule_id:
        q = q.filter(FalsePositiveSuppression.rule_id == rule_id)
    rows = q.order_by(FalsePositiveSuppression.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "count": len(rows),
        "suppressions": [
            {
                "id": s.id,
                "rule_id": s.rule_id,
                "suppression_type": s.suppression_type,
                "field_name": s.field_name,
                "field_value": s.field_value,
                "regex_pattern": s.regex_pattern,
                "time_window_start": s.time_window_start,
                "time_window_end": s.time_window_end,
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                "created_by": s.created_by,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "reason": s.reason,
            }
            for s in rows
        ],
    }


@router.post("/suppressions", status_code=201)
def create_suppression(
    payload: SuppressionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Create a new false-positive suppression (soc_analyst+)."""
    valid_types = ("field_match", "regex", "time_window")
    if payload.suppression_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid suppression_type. Must be one of: {valid_types}",
        )

    from datetime import datetime, timezone
    expires_at = None
    if payload.expires_at:
        try:
            expires_at = datetime.fromisoformat(payload.expires_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expires_at format. Use ISO 8601.")

    suppression = FalsePositiveSuppression(
        rule_id=payload.rule_id,
        suppression_type=payload.suppression_type,
        field_name=payload.field_name,
        field_value=payload.field_value,
        regex_pattern=payload.regex_pattern,
        time_window_start=payload.time_window_start,
        time_window_end=payload.time_window_end,
        expires_at=expires_at,
        created_by=current_user.id,
        reason=payload.reason,
    )
    db.add(suppression)
    db.commit()
    db.refresh(suppression)
    return {
        "id": suppression.id,
        "rule_id": suppression.rule_id,
        "suppression_type": suppression.suppression_type,
        "field_name": suppression.field_name,
        "field_value": suppression.field_value,
        "regex_pattern": suppression.regex_pattern,
        "time_window_start": suppression.time_window_start,
        "time_window_end": suppression.time_window_end,
        "expires_at": suppression.expires_at.isoformat() if suppression.expires_at else None,
        "created_by": suppression.created_by,
        "created_at": suppression.created_at.isoformat() if suppression.created_at else None,
        "reason": suppression.reason,
    }


@router.delete("/suppressions/{suppression_id}")
def delete_suppression(
    suppression_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a false-positive suppression (admin only)."""
    suppression = db.query(FalsePositiveSuppression).filter(
        FalsePositiveSuppression.id == suppression_id
    ).first()
    if not suppression:
        raise HTTPException(status_code=404, detail="Suppression not found")
    db.delete(suppression)
    db.commit()
    return {"detail": "Suppression deleted", "id": suppression_id}