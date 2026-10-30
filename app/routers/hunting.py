"""routers/hunting.py — Threat hunting endpoints.

POST /api/v1/hunting/run            Execute a ClickHouse query (soc_analyst+)
GET  /api/v1/hunting/saved          List saved hunts (user)
POST /api/v1/hunting/saved          Create saved hunt (soc_analyst+)
GET  /api/v1/hunting/saved/{id}     Get one saved hunt (user)
PUT  /api/v1/hunting/saved/{id}     Update saved hunt (soc_analyst+)
DELETE /api/v1/hunting/saved/{id}   Delete saved hunt (admin)
GET  /api/v1/hunting/results/{hunt_id}  List past results for a hunt (user)
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.clickhouse_client import get_client as get_ch_client
from app.database import get_db
from app.models import SavedHunt, HuntResult, User
from app.routers.auth import get_current_user, require_role

logger = logging.getLogger("logsoc.hunting")

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────

class HuntCreate(BaseModel):
    name: str
    description: Optional[str] = None
    query: str
    query_type: Optional[str] = "clickhouse"
    is_public: Optional[bool] = False
    tags: Optional[list] = None


class HuntUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    query: Optional[str] = None
    query_type: Optional[str] = None
    is_public: Optional[bool] = None
    tags: Optional[list] = None


class HuntRunRequest(BaseModel):
    query: str
    hunt_id: Optional[int] = None


# ── Saved Hunts CRUD ──────────────────────────────────────────────

@router.get("/saved")
def list_saved_hunts(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List saved hunts. Non-admin users see their own + public hunts."""
    q = db.query(SavedHunt)
    if current_user.role not in ("superadmin", "admin"):
        q = q.filter(
            (SavedHunt.created_by == current_user.id) | (SavedHunt.is_public == True)
        )
    hunts = q.order_by(SavedHunt.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "count": len(hunts),
        "hunts": [
            {
                "id": h.id,
                "name": h.name,
                "description": h.description,
                "query": h.query,
                "query_type": h.query_type,
                "created_by": h.created_by,
                "created_at": h.created_at.isoformat() if h.created_at else None,
                "last_run_at": h.last_run_at.isoformat() if h.last_run_at else None,
                "last_run_count": h.last_run_count,
                "is_public": bool(h.is_public),
                "tags": h.tags,
            }
            for h in hunts
        ],
    }


@router.post("/saved", status_code=201)
def create_saved_hunt(
    payload: HuntCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Create a new saved hunt (soc_analyst+)."""
    hunt = SavedHunt(
        name=payload.name,
        description=payload.description,
        query=payload.query,
        query_type=payload.query_type or "clickhouse",
        created_by=current_user.id,
        is_public=payload.is_public or False,
        tags=payload.tags,
    )
    db.add(hunt)
    db.commit()
    db.refresh(hunt)
    return {
        "id": hunt.id,
        "name": hunt.name,
        "description": hunt.description,
        "query": hunt.query,
        "query_type": hunt.query_type,
        "created_by": hunt.created_by,
        "created_at": hunt.created_at.isoformat() if hunt.created_at else None,
        "is_public": bool(hunt.is_public),
        "tags": hunt.tags,
    }


@router.get("/saved/{hunt_id}")
def get_saved_hunt(
    hunt_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get a single saved hunt by ID."""
    hunt = db.query(SavedHunt).filter(SavedHunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail="Saved hunt not found")
    # Non-owners can only see public hunts
    if current_user.role not in ("superadmin", "admin"):
        if hunt.created_by != current_user.id and not hunt.is_public:
            raise HTTPException(status_code=404, detail="Saved hunt not found")
    return {
        "id": hunt.id,
        "name": hunt.name,
        "description": hunt.description,
        "query": hunt.query,
        "query_type": hunt.query_type,
        "created_by": hunt.created_by,
        "created_at": hunt.created_at.isoformat() if hunt.created_at else None,
        "last_run_at": hunt.last_run_at.isoformat() if hunt.last_run_at else None,
        "last_run_count": hunt.last_run_count,
        "is_public": bool(hunt.is_public),
        "tags": hunt.tags,
    }


@router.put("/saved/{hunt_id}")
def update_saved_hunt(
    hunt_id: int,
    payload: HuntUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Update a saved hunt (soc_analyst+). Only the creator or admin can update."""
    hunt = db.query(SavedHunt).filter(SavedHunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail="Saved hunt not found")
    if current_user.role not in ("superadmin", "admin") and hunt.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this hunt")
    if payload.name is not None:
        hunt.name = payload.name
    if payload.description is not None:
        hunt.description = payload.description
    if payload.query is not None:
        hunt.query = payload.query
    if payload.query_type is not None:
        hunt.query_type = payload.query_type
    if payload.is_public is not None:
        hunt.is_public = payload.is_public
    if payload.tags is not None:
        hunt.tags = payload.tags
    db.commit()
    db.refresh(hunt)
    return {
        "id": hunt.id,
        "name": hunt.name,
        "description": hunt.description,
        "query": hunt.query,
        "query_type": hunt.query_type,
        "created_by": hunt.created_by,
        "created_at": hunt.created_at.isoformat() if hunt.created_at else None,
        "last_run_at": hunt.last_run_at.isoformat() if hunt.last_run_at else None,
        "last_run_count": hunt.last_run_count,
        "is_public": bool(hunt.is_public),
        "tags": hunt.tags,
    }


@router.delete("/saved/{hunt_id}")
def delete_saved_hunt(
    hunt_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a saved hunt (admin only)."""
    hunt = db.query(SavedHunt).filter(SavedHunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail="Saved hunt not found")
    # Also delete associated hunt results
    db.query(HuntResult).filter(HuntResult.hunt_id == hunt_id).delete()
    db.delete(hunt)
    db.commit()
    return {"detail": "Saved hunt deleted", "id": hunt_id}


# ── Run hunt (execute ClickHouse query) ──────────────────────────

@router.post("/run")
def run_hunt(
    payload: HuntRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Execute a ClickHouse query and optionally save results to a saved hunt.

    Body: {query: "SELECT ...", hunt_id?: int}
    Returns: {count, results, duration_ms}
    """
    if not payload.query or not payload.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    # Basic safety: block writes
    q_lower = payload.query.strip().lower()
    forbidden_prefixes = ("insert ", "update ", "delete ", "drop ", "alter ", "create ", "truncate ", "grant ")
    for prefix in forbidden_prefixes:
        if q_lower.startswith(prefix):
            raise HTTPException(status_code=400, detail="Only SELECT queries are allowed")

    # Validate hunt_id if provided
    hunt = None
    if payload.hunt_id is not None:
        hunt = db.query(SavedHunt).filter(SavedHunt.id == payload.hunt_id).first()
        if not hunt:
            raise HTTPException(status_code=404, detail="Saved hunt not found")

    start = time.monotonic()
    try:
        client = get_ch_client()
        result = client.query(payload.query)
        rows = result.result_rows
        column_names = result.column_names
    except Exception as e:
        logger.error("ClickHouse hunt query failed: %s", e)
        raise HTTPException(status_code=503, detail=f"ClickHouse query failed: {str(e)}")

    duration_ms = int((time.monotonic() - start) * 1000)

    # Convert rows to list of dicts
    results = []
    for row in rows:
        row_dict = {}
        for i, col in enumerate(column_names):
            val = row[i]
            if hasattr(val, "isoformat"):
                val = val.isoformat()
            row_dict[col] = val
        results.append(row_dict)

    # Limit result set to avoid huge payloads
    MAX_RESULTS = 500
    results = results[:MAX_RESULTS]

    # Save result if hunt_id was provided
    if hunt is not None:
        hunt_result = HuntResult(
            hunt_id=hunt.id,
            result_count=len(rows),
            result_data=results[:MAX_RESULTS],
            executed_by=current_user.id,
            duration_ms=duration_ms,
        )
        db.add(hunt_result)
        hunt.last_run_at = datetime.now(timezone.utc)
        hunt.last_run_count = len(rows)
        db.commit()

    return {
        "count": len(rows),
        "results": results,
        "duration_ms": duration_ms,
    }


# ── Hunt Results ──────────────────────────────────────────────────

@router.get("/results/{hunt_id}")
def list_hunt_results(
    hunt_id: int,
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List past execution results for a saved hunt."""
    hunt = db.query(SavedHunt).filter(SavedHunt.id == hunt_id).first()
    if not hunt:
        raise HTTPException(status_code=404, detail="Saved hunt not found")
    # Access control: non-owners can only see public hunts
    if current_user.role not in ("superadmin", "admin"):
        if hunt.created_by != current_user.id and not hunt.is_public:
            raise HTTPException(status_code=404, detail="Saved hunt not found")

    results = (
        db.query(HuntResult)
        .filter(HuntResult.hunt_id == hunt_id)
        .order_by(HuntResult.executed_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "hunt_id": hunt_id,
        "count": len(results),
        "results": [
            {
                "id": r.id,
                "result_count": r.result_count,
                "result_data": r.result_data,
                "executed_by": r.executed_by,
                "executed_at": r.executed_at.isoformat() if r.executed_at else None,
                "duration_ms": r.duration_ms,
            }
            for r in results
        ],
    }