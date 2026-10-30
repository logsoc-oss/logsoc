from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from app.database import get_db
from app.models import ComplianceControl, User
from app.schemas import ComplianceControlResponse, ComplianceScoreResponse
from app.routers.auth import get_current_user, require_permission

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/controls", response_model=List[ComplianceControlResponse])
def list_compliance_controls(
    framework: Optional[str] = None,
    category: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("compliance", "read")),
):
    """List compliance controls with optional filters."""
    q = db.query(ComplianceControl)
    if framework:
        q = q.filter(ComplianceControl.framework == framework)
    if category:
        q = q.filter(ComplianceControl.category == category)
    if status_filter:
        q = q.filter(ComplianceControl.status == status_filter)
    controls = q.order_by(ComplianceControl.control_id).offset(skip).limit(limit).all()
    return controls


@router.get("/scores", response_model=List[ComplianceScoreResponse])
def get_compliance_scores(
    framework: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("compliance", "read")),
):
    """Get compliance scores by framework."""
    q = db.query(ComplianceControl)
    if framework:
        q = q.filter(ComplianceControl.framework == framework)
    controls = q.all()

    # Group by framework
    from collections import defaultdict
    grouped = defaultdict(list)
    for c in controls:
        grouped[c.framework].append(c)

    scores = []
    for fw, fw_controls in grouped.items():
        total = len(fw_controls)
        pass_count = sum(1 for c in fw_controls if c.status == "pass")
        fail_count = sum(1 for c in fw_controls if c.status == "fail")
        na_count = sum(1 for c in fw_controls if c.status == "na")
        unknown_count = sum(1 for c in fw_controls if c.status == "unknown")
        # Score: pass / (pass + fail), ignore na/unknown
        scored = pass_count + fail_count
        score_pct = round((pass_count / scored) * 100, 1) if scored > 0 else 0
        scores.append(ComplianceScoreResponse(
            framework=fw,
            total_controls=total,
            pass_count=pass_count,
            fail_count=fail_count,
            na_count=na_count,
            unknown_count=unknown_count,
            score_percent=score_pct,
        ))

    return scores


@router.get("/controls/{control_id}", response_model=ComplianceControlResponse)
def get_compliance_control(
    control_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single compliance control."""
    control = db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    return control


@router.put("/controls/{control_id}", response_model=ComplianceControlResponse)
def update_compliance_control(
    control_id: int,
    status_val: Optional[str] = None,
    score: Optional[int] = None,
    evidence: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("compliance", "write")),
):
    """Update a compliance control status/score/evidence."""
    control = db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    if status_val:
        control.status = status_val
    if score is not None:
        control.score = score
    if evidence is not None:
        control.evidence = evidence
    control.last_checked = datetime.now(timezone.utc)
    control.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(control)
    return control