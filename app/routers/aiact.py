# app/routers/aiact.py — T91
# AI Act: inventaire IA, classification 4 niveaux, obligations déployeur, incidents sérieux, transparence
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, get_current_user
from app.models_aiact import (
    AiSystem, AiClassification, AiDeployerObligation, AiIncident, AiTransparency
)
from app.schemas_aiact import (
    AiSystemCreate, AiSystemResponse,
    AiClassificationCreate, AiClassificationResponse,
    AiIncidentCreate, AiIncidentUpdate, AiIncidentResponse,
    AiTransparencyUpdate, AiTransparencyResponse
)

router = APIRouter()


def _classify_risk(c: AiClassificationCreate) -> str:
    """Auto-classify risk level based on questionnaire."""
    # Prohibited practices = unacceptable
    if any([c.uses_subliminal, c.uses_vulnerability_exploitation, c.uses_social_scoring,
            c.uses_criminal_prediction, c.uses_facial_scraping, c.uses_realtime_biometric,
            c.uses_emotion_inference, c.uses_biocategorization, c.uses_untargeted_surveillance]):
        return 'unacceptable'
    # High risk: safety component in regulated product OR Annex III categories
    if c.is_safety_component and c.is_in_regulated_product:
        return 'high'
    if any([c.used_critical_infrastructure, c.used_education, c.used_employment,
            c.used_essential_services, c.used_law_enforcement, c.used_migration,
            c.used_justice, c.used_democracy]):
        return 'high'
    # Limited risk: transparency required
    if any([c.interacts_with_humans, c.generates_content, c.uses_emotion_recognition,
            c.uses_biometric_categorization]):
        return 'limited'
    return 'minimal'


# ── AI Systems inventory ──

@router.get("/systems", response_model=List[AiSystemResponse])
def list_systems(
    risk_level: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(AiSystem)
    if risk_level:
        q = q.filter(AiSystem.risk_level == risk_level)
    if status:
        q = q.filter(AiSystem.status == status)
    return q.order_by(AiSystem.name).limit(limit).all()

@router.post("/systems", response_model=AiSystemResponse)
def create_system(s: AiSystemCreate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    sys = AiSystem(**s.model_dump())
    db.add(sys)
    db.commit()
    db.refresh(sys)
    return sys


@router.get("/systems/{system_id}", response_model=AiSystemResponse)
def get_system(system_id: int, db: Session = Depends(get_db),
               current_user: User = Depends(require_role("user"))):
    sys = db.query(AiSystem).filter(AiSystem.id == system_id).first()
    if not sys:
        raise HTTPException(status_code=404, detail="AI system not found")
    return sys


@router.delete("/systems/{system_id}")
def delete_system(system_id: int, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    sys = db.query(AiSystem).filter(AiSystem.id == system_id).first()
    if not sys:
        raise HTTPException(status_code=404, detail="AI system not found")
    sys.status = 'retired'
    db.commit()
    return {"id": system_id, "status": "retired"}

# ── Classification ──

@router.post("/classify", response_model=AiClassificationResponse)
def classify_system(c: AiClassificationCreate, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin"))):
    """Classify an AI system based on the questionnaire (4 risk levels)."""
    sys = db.query(AiSystem).filter(AiSystem.id == c.ai_system_id).first()
    if not sys:
        raise HTTPException(status_code=404, detail="AI system not found")

    risk = _classify_risk(c)
    transparency = risk == 'limited' or any([c.interacts_with_humans, c.generates_content,
                                             c.uses_emotion_recognition, c.uses_biometric_categorization])

    rationale_parts = []
    if risk == 'unacceptable':
        prohibited = []
        if c.uses_subliminal: prohibited.append('subliminal manipulation')
        if c.uses_social_scoring: prohibited.append('social scoring')
        if c.uses_facial_scraping: prohibited.append('facial scraping')
        if c.uses_realtime_biometric: prohibited.append('real-time biometric')
        rationale_parts.append(f"Prohibited practices: {', '.join(prohibited)}")
    elif risk == 'high':
        if c.is_safety_component and c.is_in_regulated_product:
            rationale_parts.append("Safety component in regulated product (Annex II)")
        annex3 = []
        if c.used_critical_infrastructure: annex3.append('critical infrastructure')
        if c.used_education: annex3.append('education')
        if c.used_employment: annex3.append('employment')
        if c.used_essential_services: annex3.append('essential services')
        if annex3:
            rationale_parts.append(f"Annex III categories: {', '.join(annex3)}")
    elif risk == 'limited':
        rationale_parts.append("Transparency obligations (Art. 50)")
    else:
        rationale_parts.append("Minimal risk — no specific obligations")

    cls = AiClassification(
        **c.model_dump(),
        risk_level=risk,
        transparency_required=transparency,
        rationale='; '.join(rationale_parts),
        classified_at=datetime.now(timezone.utc),
    )
    db.add(cls)

    # Update system
    sys.risk_level = risk
    sys.classification_date = datetime.now(timezone.utc)
    sys.classified_by = c.classified_by

    # Create deployer obligations if deployer
    if sys.entity_role == 'deployer' and risk == 'high':
        dep = AiDeployerObligation(ai_system_id=sys.id, dpia_required=sys.has_personal_data)
        db.add(dep)

    # Create transparency record if needed
    if transparency:
        trans = AiTransparency(ai_system_id=sys.id)
        db.add(trans)

    db.commit()
    db.refresh(cls)
    return cls


# ── Deployer obligations ──

@router.get("/systems/{system_id}/obligations")
def get_obligations(system_id: int, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("user"))):
    dep = db.query(AiDeployerObligation).filter(
        AiDeployerObligation.ai_system_id == system_id).first()
    if not dep:
        raise HTTPException(status_code=404, detail="No obligations for this system")
    return {c.name: getattr(dep, c.name) for c in dep.__table__.columns}

@router.put("/systems/{system_id}/obligations")
def update_obligations(system_id: int, updates: dict, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    dep = db.query(AiDeployerObligation).filter(
        AiDeployerObligation.ai_system_id == system_id).first()
    if not dep:
        dep = AiDeployerObligation(ai_system_id=system_id)
        db.add(dep)
        db.flush()
    for field, value in updates.items():
        if hasattr(dep, field):
            setattr(dep, field, value)
    dep.last_reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": dep.id, "compliance_status": dep.compliance_status}

# ── Incidents ──

@router.get("/incidents", response_model=List[AiIncidentResponse])
def list_incidents(
    system_id: Optional[int] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(AiIncident)
    if system_id:
        q = q.filter(AiIncident.ai_system_id == system_id)
    return q.order_by(AiIncident.created_at.desc()).limit(limit).all()


@router.post("/incidents", response_model=AiIncidentResponse)
def create_incident(inc: AiIncidentCreate, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("admin"))):
    i = AiIncident(**inc.model_dump())
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


@router.put("/incidents/{incident_id}", response_model=AiIncidentResponse)
def update_incident(incident_id: int, update: AiIncidentUpdate, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("admin"))):
    i = db.query(AiIncident).filter(AiIncident.id == incident_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(i, field, value)
    if update.provider_notified:
        i.provider_notified_at = datetime.now(timezone.utc)
    if update.authority_notified:
        i.authority_notified_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(i)
    return i


# ── Transparency ──

@router.get("/transparency", response_model=List[AiTransparencyResponse])
def list_transparency(db: Session = Depends(get_db),
                      current_user: User = Depends(require_role("user"))):
    return db.query(AiTransparency).all()


@router.put("/transparency/{trans_id}", response_model=AiTransparencyResponse)
def update_transparency(trans_id: int, update: AiTransparencyUpdate, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    t = db.query(AiTransparency).filter(AiTransparency.id == trans_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Transparency record not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(t, field, value)
    t.last_verified_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(t)
    return t


# ── Summary ──

@router.get("/summary")
def aiact_summary(db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("user"))):
    systems = db.query(AiSystem).all()
    risk_dist = {}
    for s in systems:
        risk_dist[s.risk_level] = risk_dist.get(s.risk_level, 0) + 1
    return {
        'total_systems': len(systems),
        'risk_distribution': risk_dist,
        'high_risk': risk_dist.get('high', 0),
        'unacceptable': risk_dist.get('unacceptable', 0),
        'limited_risk': risk_dist.get('limited', 0),
        'incidents_total': db.query(AiIncident).count(),
        'incidents_open': db.query(AiIncident).filter(
            AiIncident.authority_notified == False).count(),
        'transparency_records': db.query(AiTransparency).count(),
    }