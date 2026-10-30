"""app/routers/runbook.py — Runbook wiki (C2 Compliance Infra).
v0.11.1 - 2026-06-09.

Markdown-based procedures, grouped in 6 sections (pra/pca/pri/sc/fore/test)
plus 'general'. Each PUT increments the version. Reviews are an append-only
audit log used to track when procedures were last validated.
"""
from __future__ import annotations

import datetime
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RunbookProcedure, RunbookReview
from app.routers.auth import get_current_user, require_role
from app.models import User
from app.schemas import (
    RunbookProcedureCreate, RunbookProcedureUpdate, RunbookProcedureResponse,
    RunbookStatsResponse, RunbookReviewCreate, RunbookReviewResponse,
)

logger = logging.getLogger("logsoc.runbook")
router = APIRouter()


def _to_response(p: RunbookProcedure) -> RunbookProcedureResponse:
    return RunbookProcedureResponse(
        id=p.id,
        section=p.section,
        slug=p.slug,
        title=p.title,
        markdown=p.markdown,
        version=p.version,
        owner_email=p.owner_email,
        last_reviewed_at=p.last_reviewed_at.isoformat() if p.last_reviewed_at else None,
        next_review_at=p.next_review_at.isoformat() if p.next_review_at else None,
        created_at=p.created_at,
        updated_at=p.updated_at,
        updated_by=p.updated_by,
    )


# ── list & stats ──

@router.get("/", response_model=List[RunbookProcedureResponse])
def list_procedures(
    section: Optional[str] = Query(None, pattern="^(pra|pca|pri|sc|fore|test|general)$"),
    overdue: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    q = db.query(RunbookProcedure)
    if section:
        q = q.filter(RunbookProcedure.section == section)
    if overdue:
        today = datetime.date.today()
        q = q.filter(RunbookProcedure.next_review_at != None,
                     RunbookProcedure.next_review_at < today)
    q = q.order_by(RunbookProcedure.section, RunbookProcedure.slug)
    return [_to_response(p) for p in q.limit(limit).all()]


@router.get("/stats", response_model=RunbookStatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    total = db.query(func.count(RunbookProcedure.id)).scalar() or 0
    by_section_rows = db.query(RunbookProcedure.section, func.count(RunbookProcedure.id)).group_by(RunbookProcedure.section).all()
    by_section = {s: c for s, c in by_section_rows}
    today = datetime.date.today()
    overdue = db.query(func.count(RunbookProcedure.id)).filter(
        RunbookProcedure.next_review_at != None,
        RunbookProcedure.next_review_at < today
    ).scalar() or 0
    last_30d = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    last_30d_naive = last_30d.replace(tzinfo=None)
    recent = db.query(func.count(RunbookProcedure.id)).filter(
        RunbookProcedure.updated_at != None,
        RunbookProcedure.updated_at >= last_30d_naive
    ).scalar() or 0
    return RunbookStatsResponse(
        total=total, by_section=by_section, overdue_reviews=overdue, recently_updated=recent,
    )


# ── CRUD ──

@router.get("/{procedure_id}", response_model=RunbookProcedureResponse)
def get_procedure(procedure_id: int, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    p = db.query(RunbookProcedure).filter(RunbookProcedure.id == procedure_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Procedure {procedure_id} not found")
    return _to_response(p)


@router.post("/", response_model=RunbookProcedureResponse, status_code=status.HTTP_201_CREATED)
def create_procedure(
    data: RunbookProcedureCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("compliance_officer", "admin")),
):
    existing = db.query(RunbookProcedure).filter(
        RunbookProcedure.section == data.section,
        RunbookProcedure.slug == data.slug,
    ).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Procedure already exists: {data.section}/{data.slug}",
        )
    last_reviewed = None
    if data.last_reviewed_at:
        try:
            last_reviewed = datetime.date.fromisoformat(data.last_reviewed_at)
        except ValueError:
            raise HTTPException(status_code=422, detail="last_reviewed_at must be YYYY-MM-DD")
    next_review = None
    if data.next_review_at:
        try:
            next_review = datetime.date.fromisoformat(data.next_review_at)
        except ValueError:
            raise HTTPException(status_code=422, detail="next_review_at must be YYYY-MM-DD")
    p = RunbookProcedure(
        section=data.section,
        slug=data.slug,
        title=data.title,
        markdown=data.markdown,
        owner_email=data.owner_email,
        last_reviewed_at=last_reviewed,
        next_review_at=next_review,
        updated_by=user.id if user else None,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return _to_response(p)


@router.put("/{procedure_id}", response_model=RunbookProcedureResponse)
def update_procedure(
    procedure_id: int,
    data: RunbookProcedureUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("compliance_officer", "admin")),
):
    p = db.query(RunbookProcedure).filter(RunbookProcedure.id == procedure_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Procedure {procedure_id} not found")
    payload = data.model_dump(exclude_unset=True)
    for date_field in ("last_reviewed_at", "next_review_at"):
        if date_field in payload and payload[date_field] is not None:
            try:
                setattr(p, date_field, datetime.date.fromisoformat(payload[date_field]))
                del payload[date_field]
            except ValueError:
                raise HTTPException(status_code=422, detail=f"{date_field} must be YYYY-MM-DD")
    for k, v in payload.items():
        setattr(p, k, v)
    p.version += 1
    p.updated_by = user.id if user else None
    db.commit()
    db.refresh(p)
    return _to_response(p)


@router.delete("/{procedure_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_procedure(
    procedure_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    p = db.query(RunbookProcedure).filter(RunbookProcedure.id == procedure_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Procedure {procedure_id} not found")
    db.delete(p)
    db.commit()
    return None


# ── reviews ──

@router.post(
    "/{procedure_id}/reviews",
    response_model=RunbookReviewResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_review(
    procedure_id: int,
    data: RunbookReviewCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("compliance_officer", "admin")),
):
    p = db.query(RunbookProcedure).filter(RunbookProcedure.id == procedure_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Procedure {procedure_id} not found")
    r = RunbookReview(
        procedure_id=procedure_id,
        reviewed_by=user.id if user else None,
        review_note=data.review_note,
    )
    # Bump the last_reviewed_at + push next_review_at +6 months
    p.last_reviewed_at = datetime.date.today()
    if p.next_review_at and p.next_review_at <= p.last_reviewed_at:
        p.next_review_at = p.last_reviewed_at + datetime.timedelta(days=180)
    db.add(r)
    db.commit()
    db.refresh(r)
    return RunbookReviewResponse(
        id=r.id, procedure_id=r.procedure_id,
        reviewed_by=r.reviewed_by, review_note=r.review_note, reviewed_at=r.reviewed_at,
    )


@router.get("/{procedure_id}/reviews", response_model=List[RunbookReviewResponse])
def list_reviews(
    procedure_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    p = db.query(RunbookProcedure).filter(RunbookProcedure.id == procedure_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Procedure {procedure_id} not found")
    reviews = (
        db.query(RunbookReview)
        .filter(RunbookReview.procedure_id == procedure_id)
        .order_by(RunbookReview.reviewed_at.desc())
        .all()
    )
    return [
        RunbookReviewResponse(
            id=r.id, procedure_id=r.procedure_id,
            reviewed_by=r.reviewed_by, review_note=r.review_note, reviewed_at=r.reviewed_at,
        )
        for r in reviews
    ]
