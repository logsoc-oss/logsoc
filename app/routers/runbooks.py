"""Phase 8 — Alert runbook CRUD + detection query execution.

Endpoints for managing alert runbooks (playbooks) and executing
their detection_query against ClickHouse.
"""

import datetime
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from app.database import get_db
from app.models import AlertRunbook, User
from app.routers.auth import require_role
from app.clickhouse_client import get_client

router = APIRouter()


# ── Pydantic schemas ──

class RunbookCreate(BaseModel):
    alert_type: str
    title: str
    severity: Optional[str] = None
    steps: list  # JSON array of step objects
    detection_query: Optional[str] = None
    false_positive_check: Optional[str] = None
    escalation_contact: Optional[str] = None


class RunbookUpdate(BaseModel):
    alert_type: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    steps: Optional[list] = None
    detection_query: Optional[str] = None
    false_positive_check: Optional[str] = None
    escalation_contact: Optional[str] = None


class RunbookResponse(BaseModel):
    id: int
    alert_type: str
    title: str
    severity: Optional[str] = None
    steps: Optional[list] = None
    detection_query: Optional[str] = None
    false_positive_check: Optional[str] = None
    escalation_contact: Optional[str] = None
    created_by: Optional[int] = None
    created_at: Optional[datetime.datetime] = None
    updated_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


def _runbook_to_dict(r: AlertRunbook) -> dict:
    """Serialize an AlertRunbook ORM object to a plain dict."""
    return {
        "id": r.id,
        "alert_type": r.alert_type,
        "title": r.title,
        "severity": r.severity,
        "steps": r.steps,
        "detection_query": r.detection_query,
        "false_positive_check": r.false_positive_check,
        "escalation_contact": r.escalation_contact,
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


# ── Endpoints ──

@router.get("", response_model=List[RunbookResponse])
def list_runbooks(
    alert_type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List all runbooks, optionally filtered by alert_type."""
    q = db.query(AlertRunbook)
    if alert_type:
        q = q.filter(AlertRunbook.alert_type == alert_type)
    q = q.order_by(AlertRunbook.id)
    runbooks = q.offset(skip).limit(limit).all()
    return [_runbook_to_dict(r) for r in runbooks]


@router.get("/by-type/{alert_type}", response_model=RunbookResponse)
def get_runbook_by_type(
    alert_type: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get the first runbook matching a specific alert type."""
    r = db.query(AlertRunbook).filter(AlertRunbook.alert_type == alert_type).first()
    if not r:
        raise HTTPException(status_code=404, detail="Runbook not found for this alert type")
    return _runbook_to_dict(r)


@router.get("/{runbook_id}", response_model=RunbookResponse)
def get_runbook(
    runbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get a single runbook by ID."""
    r = db.query(AlertRunbook).filter(AlertRunbook.id == runbook_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Runbook not found")
    return _runbook_to_dict(r)


@router.post("", response_model=RunbookResponse, status_code=201)
def create_runbook(
    payload: RunbookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Create a new runbook (admin only)."""
    runbook = AlertRunbook(
        alert_type=payload.alert_type,
        title=payload.title,
        severity=payload.severity,
        steps=payload.steps,
        detection_query=payload.detection_query,
        false_positive_check=payload.false_positive_check,
        escalation_contact=payload.escalation_contact,
        created_by=current_user.id,
    )
    db.add(runbook)
    db.commit()
    db.refresh(runbook)
    return _runbook_to_dict(runbook)


@router.put("/{runbook_id}", response_model=RunbookResponse)
def update_runbook(
    runbook_id: int,
    payload: RunbookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update a runbook (admin only)."""
    r = db.query(AlertRunbook).filter(AlertRunbook.id == runbook_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Runbook not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(r, key, value)

    db.commit()
    db.refresh(r)
    return _runbook_to_dict(r)


@router.delete("/{runbook_id}")
def delete_runbook(
    runbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a runbook (admin only)."""
    r = db.query(AlertRunbook).filter(AlertRunbook.id == runbook_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Runbook not found")
    db.delete(r)
    db.commit()
    return {"message": "Runbook deleted"}


@router.post("/{runbook_id}/execute-detection")
def execute_detection(
    runbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Execute the runbook's detection_query in ClickHouse (admin only).

    Only SELECT queries are allowed. The query is executed as-is
    against ClickHouse and results are returned as a JSON array.
    """
    r = db.query(AlertRunbook).filter(AlertRunbook.id == runbook_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Runbook not found")

    if not r.detection_query:
        raise HTTPException(status_code=400, detail="Runbook has no detection_query defined")

    query = r.detection_query.strip()

    # Only allow SELECT queries — block any INSERT/UPDATE/DELETE/ALTER/DROP/etc.
    first_word = query.split()[0].upper() if query else ""
    if first_word != "SELECT":
        raise HTTPException(
            status_code=400,
            detail="Only SELECT queries are allowed for detection execution",
        )

    # Extra safety: reject queries containing DML/DDL keywords
    dangerous_pattern = re.compile(
        r'\b(INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE|REPLACE|GRANT|REVOKE)\b',
        re.IGNORECASE,
    )
    if dangerous_pattern.search(query):
        raise HTTPException(
            status_code=400,
            detail="Query contains disallowed SQL keywords",
        )

    try:
        ch = get_client()
        result = ch.query(query)
        columns = result.column_names
        rows = result.result_rows
        results = []
        for row in rows:
            row_dict = {}
            for i, col in enumerate(columns):
                val = row[i]
                if isinstance(val, (datetime.datetime, datetime.date)):
                    val = val.isoformat()
                row_dict[col] = val
            results.append(row_dict)
        return {
            "runbook_id": runbook_id,
            "alert_type": r.alert_type,
            "query": query,
            "columns": list(columns),
            "row_count": len(results),
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"ClickHouse query failed: {str(e)}")