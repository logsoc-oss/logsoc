# app/routers/dora.py — T88
# DORA: 5 piliers, classification incident majeur, registre tiers TIC, tests résilience
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, get_current_user
from app.models_dora import DoraIncident, DoraThirdParty, DoraResilienceTest, DoraGovernance
from app.schemas_dora import (
    DoraIncidentClassify, DoraIncidentResponse,
    DoraThirdPartyCreate, DoraThirdPartyUpdate, DoraThirdPartyResponse,
    DoraResilienceTestCreate, DoraResilienceTestUpdate, DoraResilienceTestResponse,
    DoraGovernanceUpdate, DoraGovernanceResponse
)

router = APIRouter()


# ── Governance (5 piliers) ──

@router.get("/pillars", response_model=List[DoraGovernanceResponse])
def list_pillars(db: Session = Depends(get_db),
                current_user: User = Depends(require_role("user"))):
    return db.query(DoraGovernance).all()


@router.put("/pillars/{pillar}", response_model=DoraGovernanceResponse)
def update_pillar(pillar: str, update: DoraGovernanceUpdate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    g = db.query(DoraGovernance).filter(DoraGovernance.pillar == pillar).first()
    if not g:
        raise HTTPException(status_code=404, detail="Pillar not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(g, field, value)
    g.last_reviewed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(g)
    return g

# ── Incidents (classification incident majeur) ──

@router.post("/incidents", response_model=DoraIncidentResponse)
def classify_incident(data: DoraIncidentClassify, db: Session = Depends(get_db),
                      current_user: User = Depends(require_role("admin"))):
    """Classify an incident as major or not based on DORA thresholds."""
    thresholds_met = 0
    if data.crit_clients_affected: thresholds_met += 1
    if data.crit_reputational: thresholds_met += 1
    if data.crit_duration_hours >= 24: thresholds_met += 1
    if data.crit_cross_border: thresholds_met += 1
    if data.crit_data_loss: thresholds_met += 1
    if data.crit_economic_loss_eur >= 100000: thresholds_met += 1

    # Major if all 3 main conditions OR at least 2 thresholds
    is_major = thresholds_met >= 2

    inc = DoraIncident(
        case_id=data.case_id,
        is_major=is_major,
        classification_date=datetime.now(timezone.utc),
        crit_clients_affected=data.crit_clients_affected,
        crit_clients_pct=data.crit_clients_pct,
        crit_clients_count=data.crit_clients_count,
        crit_transactions_pct=data.crit_transactions_pct,
        crit_reputational=data.crit_reputational,
        crit_duration_hours=data.crit_duration_hours,
        crit_cross_border=data.crit_cross_border,
        crit_data_loss=data.crit_data_loss,
        crit_economic_loss_eur=data.crit_economic_loss_eur,
        thresholds_met=thresholds_met,
        authority="AMF (Sesterce) / ACPR" if is_major else "",
        created_by=data.created_by,
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return inc


@router.get("/incidents", response_model=List[DoraIncidentResponse])
def list_incidents(
    is_major: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(DoraIncident)
    if is_major is not None:
        q = q.filter(DoraIncident.is_major == is_major)
    return q.order_by(DoraIncident.created_at.desc()).limit(limit).all()


@router.get("/incidents/{incident_id}", response_model=DoraIncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("user"))):
    inc = db.query(DoraIncident).filter(DoraIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


# ── Third parties TIC ──

@router.get("/third-parties", response_model=List[DoraThirdPartyResponse])
def list_third_parties(
    criticality: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(DoraThirdParty)
    if criticality:
        q = q.filter(DoraThirdParty.criticality == criticality)
    return q.order_by(DoraThirdParty.name).limit(limit).all()


@router.post("/third-parties", response_model=DoraThirdPartyResponse)
def create_third_party(tp: DoraThirdPartyCreate, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    t = DoraThirdParty(**tp.model_dump())
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@router.put("/third-parties/{tp_id}", response_model=DoraThirdPartyResponse)
def update_third_party(tp_id: int, update: DoraThirdPartyUpdate, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    t = db.query(DoraThirdParty).filter(DoraThirdParty.id == tp_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Third party not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(t, field, value)
    db.commit()
    db.refresh(t)
    return t


@router.delete("/third-parties/{tp_id}")
def delete_third_party(tp_id: int, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    t = db.query(DoraThirdParty).filter(DoraThirdParty.id == tp_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Third party not found")
    db.delete(t)
    db.commit()
    return {"id": tp_id, "deleted": True}


# ── Resilience tests ──

@router.get("/resilience-tests", response_model=List[DoraResilienceTestResponse])
def list_tests(
    status: Optional[str] = Query(None),
    test_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(DoraResilienceTest)
    if status:
        q = q.filter(DoraResilienceTest.status == status)
    if test_type:
        q = q.filter(DoraResilienceTest.test_type == test_type)
    return q.order_by(DoraResilienceTest.scheduled_date.desc()).limit(limit).all()

@router.post("/resilience-tests", response_model=DoraResilienceTestResponse)
def create_test(test: DoraResilienceTestCreate, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("admin"))):
    t = DoraResilienceTest(**test.model_dump())
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@router.put("/resilience-tests/{test_id}", response_model=DoraResilienceTestResponse)
def update_test(test_id: int, update: DoraResilienceTestUpdate, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("admin"))):
    t = db.query(DoraResilienceTest).filter(DoraResilienceTest.id == test_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Test not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(t, field, value)
    db.commit()
    db.refresh(t)
    return t


# ── Summary ──

@router.get("/summary")
def dora_summary(db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("user"))):
    pillars = db.query(DoraGovernance).all()
    pillar_status = {p.pillar: p.status for p in pillars}
    total_third_parties = db.query(DoraThirdParty).count()
    critical_third_parties = db.query(DoraThirdParty).filter(
        DoraThirdParty.criticality == 'critical'
    ).count()
    major_incidents = db.query(DoraIncident).filter(DoraIncident.is_major == True).count()
    pending_tests = db.query(DoraResilienceTest).filter(
        DoraResilienceTest.status.in_(['scheduled', 'in_progress'])
    ).count()
    return {
        "pillars": pillar_status,
        "pillars_implemented": sum(1 for s in pillar_status.values() if s in ['implemented', 'verified']),
        "pillars_total": len(pillars),
        "third_parties_total": total_third_parties,
        "third_parties_critical": critical_third_parties,
        "major_incidents": major_incidents,
        "pending_tests": pending_tests,
    }