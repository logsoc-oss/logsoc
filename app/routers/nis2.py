# app/routers/nis2.py — T87
# NIS2 compliance: 10 measures (Art. 21), governance (Art. 20), classification (EE/EI)
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, get_current_user
from app.models_nis2 import Nis2Classification, Nis2Measure, Nis2Assessment, Nis2Governance
from app.schemas_nis2 import (
    ClassificationUpdate, AssessmentUpdate, GovernanceCreate,
    MeasureResponse, AssessmentResponse, MeasureWithAssessment,
    ClassificationResponse, GovernanceResponse
)

router = APIRouter()


# ── Classification ──

@router.get("/classification", response_model=ClassificationResponse)
def get_classification(db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("user"))):
    c = db.query(Nis2Classification).first()
    if not c:
        c = Nis2Classification()
        db.add(c)
        db.commit()
        db.refresh(c)
    return c


@router.put("/classification", response_model=ClassificationResponse)
def update_classification(update: ClassificationUpdate, db: Session = Depends(get_db),
                         current_user: User = Depends(require_role("admin"))):
    c = db.query(Nis2Classification).first()
    if not c:
        c = Nis2Classification()
        db.add(c)
        db.flush()
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(c, field, value)
    if update.entity_type or update.employee_count or update.annual_revenue_eur:
        c.self_assessed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(c)
    return c


# ── Measures ──

@router.get("/measures", response_model=List[MeasureWithAssessment])
def list_measures(db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("user"))):
    measures = db.query(Nis2Measure).filter(Nis2Measure.is_active == True).order_by(Nis2Measure.display_order).all()
    result = []
    for m in measures:
        assessment = db.query(Nis2Assessment).filter(Nis2Assessment.measure_id == m.id).first()
        result.append({
            **{c.name: getattr(m, c.name) for c in m.__table__.columns},
            "assessment": {c.name: getattr(assessment, c.name) for c in assessment.__table__.columns} if assessment else None,
        })
    return result

@router.get("/measures/{measure_code}", response_model=MeasureWithAssessment)
def get_measure(measure_code: str, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("user"))):
    m = db.query(Nis2Measure).filter(Nis2Measure.measure_code == measure_code).first()
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    assessment = db.query(Nis2Assessment).filter(Nis2Assessment.measure_id == m.id).first()
    return {
        **{c.name: getattr(m, c.name) for c in m.__table__.columns},
        "assessment": {c.name: getattr(assessment, c.name) for c in assessment.__table__.columns} if assessment else None,
    }

@router.put("/measures/{measure_id}/assessment", response_model=AssessmentResponse)
def update_assessment(measure_id: int, update: AssessmentUpdate, db: Session = Depends(get_db),
                      current_user: User = Depends(require_role("admin"))):
    m = db.query(Nis2Measure).filter(Nis2Measure.id == measure_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    a = db.query(Nis2Assessment).filter(Nis2Assessment.measure_id == measure_id).first()
    if not a:
        a = Nis2Assessment(measure_id=measure_id)
        db.add(a)
        db.flush()
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(a, field, value)
    a.last_reviewed_at = datetime.now(timezone.utc)
    a.last_reviewed_by = update.updated_by
    db.commit()
    db.refresh(a)
    return a


# ── Governance (Art. 20) ──

@router.get("/governance", response_model=List[GovernanceResponse])
def list_governance(db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    return db.query(Nis2Governance).order_by(Nis2Governance.approved_at.desc()).all()

@router.post("/governance", response_model=GovernanceResponse)
def create_governance(gov: GovernanceCreate, db: Session = Depends(get_db),
                      current_user: User = Depends(require_role("admin"))):
    g = Nis2Governance(
        policy_name=gov.policy_name,
        policy_version=gov.policy_version,
        approved_by=gov.approved_by,
        approved_role=gov.approved_role,
        training_required=gov.training_required,
        training_frequency_months=gov.training_frequency_months,
        last_training_date=gov.last_training_date,
        last_training_attendees=gov.last_training_attendees,
    )
    if gov.last_training_date:
        from datetime import timedelta
        g.next_training_due = gov.last_training_date + timedelta(days=gov.training_frequency_months * 30)
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


# ── Summary ──

@router.get("/summary")
def nis2_summary(db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("user"))):
    measures = db.query(Nis2Measure).filter(Nis2Measure.is_active == True).all()
    total = len(measures)
    status_counts = {}
    maturity_sum = 0
    for m in measures:
        a = db.query(Nis2Assessment).filter(Nis2Assessment.measure_id == m.id).first()
        status = a.status if a else 'not_started'
        status_counts[status] = status_counts.get(status, 0) + 1
        if a and a.maturity_level:
            maturity_sum += a.maturity_level
    avg_maturity = round(maturity_sum / total, 1) if total > 0 else 0
    classification = db.query(Nis2Classification).first()
    return {
        "total_measures": total,
        "status_breakdown": status_counts,
        "average_maturity": avg_maturity,
        "entity_type": classification.entity_type if classification else "unclassified",
        "compliance_score": round(sum(1 for s in status_counts if s in ['implemented', 'verified']) / total * 100, 1) if total > 0 else 0,
    }