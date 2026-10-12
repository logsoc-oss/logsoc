# app/routers/iso27001.py — T90
# ISO 27001: SoA 93 controls, audits, NC, management reviews, certification
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, get_current_user
from app.models_iso27001 import (
    IsoSoa, IsoAudit, IsoNonconformity, IsoManagementReview, IsoCertification
)
from app.schemas_iso27001 import (
    SoaUpdate, SoaResponse,
    AuditCreate, AuditUpdate, AuditResponse,
    NonconformityCreate, NonconformityUpdate, NonconformityResponse,
    ManagementReviewCreate, ManagementReviewResponse,
    CertificationCreate, CertificationResponse
)

router = APIRouter()


# ── SoA (93 controls) ──

@router.get("/soa", response_model=List[SoaResponse])
def list_soa(
    theme: Optional[str] = Query(None),
    implementation_status: Optional[str] = Query(None),
    is_applicable: Optional[bool] = Query(None),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(IsoSoa)
    if theme:
        q = q.filter(IsoSoa.theme == theme)
    if implementation_status:
        q = q.filter(IsoSoa.implementation_status == implementation_status)
    if is_applicable is not None:
        q = q.filter(IsoSoa.is_applicable == is_applicable)
    return q.order_by(IsoSoa.control_id).limit(limit).all()

@router.get("/soa/{control_id}", response_model=SoaResponse)
def get_soa_control(control_id: str, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    c = db.query(IsoSoa).filter(IsoSoa.control_id == control_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    return c


@router.put("/soa/{control_id}", response_model=SoaResponse)
def update_soa_control(control_id: str, update: SoaUpdate, db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("admin"))):
    c = db.query(IsoSoa).filter(IsoSoa.control_id == control_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(c, field, value)
    c.last_reviewed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(c)
    return c


# ── Audits ──

@router.get("/audits", response_model=List[AuditResponse])
def list_audits(
    status: Optional[str] = Query(None),
    audit_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(IsoAudit)
    if status:
        q = q.filter(IsoAudit.status == status)
    if audit_type:
        q = q.filter(IsoAudit.audit_type == audit_type)
    return q.order_by(IsoAudit.planned_date.desc()).limit(limit).all()

@router.post("/audits", response_model=AuditResponse)
def create_audit(audit: AuditCreate, db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("admin"))):
    a = IsoAudit(**audit.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


@router.put("/audits/{audit_id}", response_model=AuditResponse)
def update_audit(audit_id: int, update: AuditUpdate, db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("admin"))):
    a = db.query(IsoAudit).filter(IsoAudit.id == audit_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Audit not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(a, field, value)
    db.commit()
    db.refresh(a)
    return a


# ── Non-conformities ──

@router.get("/nonconformities", response_model=List[NonconformityResponse])
def list_ncs(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(IsoNonconformity)
    if status:
        q = q.filter(IsoNonconformity.status == status)
    if severity:
        q = q.filter(IsoNonconformity.severity == severity)
    return q.order_by(IsoNonconformity.created_at.desc()).limit(limit).all()

@router.post("/nonconformities", response_model=NonconformityResponse)
def create_nc(nc: NonconformityCreate, db: Session = Depends(get_db),
              current_user: User = Depends(require_role("admin"))):
    n = IsoNonconformity(**nc.model_dump())
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


@router.put("/nonconformities/{nc_id}", response_model=NonconformityResponse)
def update_nc(nc_id: int, update: NonconformityUpdate, db: Session = Depends(get_db),
              current_user: User = Depends(require_role("admin"))):
    n = db.query(IsoNonconformity).filter(IsoNonconformity.id == nc_id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Non-conformity not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(n, field, value)
    if update.effectiveness_checked:
        n.effectiveness_checked_at = datetime.now(timezone.utc).date()
    db.commit()
    db.refresh(n)
    return n


# ── Management reviews ──

@router.get("/management-reviews", response_model=List[ManagementReviewResponse])
def list_reviews(status: Optional[str] = Query(None), db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("user"))):
    q = db.query(IsoManagementReview)
    if status:
        q = q.filter(IsoManagementReview.status == status)
    return q.order_by(IsoManagementReview.review_date.desc()).all()

@router.post("/management-reviews", response_model=ManagementReviewResponse)
def create_review(r: ManagementReviewCreate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    rev = IsoManagementReview(**r.model_dump())
    db.add(rev)
    db.commit()
    db.refresh(rev)
    return rev


# ── Certification ──

@router.get("/certification", response_model=List[CertificationResponse])
def list_certifications(db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("user"))):
    return db.query(IsoCertification).all()


@router.post("/certification", response_model=CertificationResponse)
def create_certification(c: CertificationCreate, db: Session = Depends(get_db),
                         current_user: User = Depends(require_role("admin"))):
    cert = IsoCertification(**c.model_dump())
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return cert


# ── Summary ──

@router.get("/summary")
def iso27001_summary(db: Session = Depends(get_db),
                     current_user: User = Depends(require_role("user"))):
    total = db.query(IsoSoa).count()
    applicable = db.query(IsoSoa).filter(IsoSoa.is_applicable == True).count()
    implemented = db.query(IsoSoa).filter(
        IsoSoa.implementation_status.in_(['implemented', 'verified'])).count()
    not_implemented = db.query(IsoSoa).filter(
        IsoSoa.implementation_status == 'not_implemented').count()
    partial = db.query(IsoSoa).filter(IsoSoa.implementation_status == 'partial').count()
    nc_open = db.query(IsoNonconformity).filter(
        IsoNonconformity.status.in_(['open', 'in_progress'])).count()
    nc_major_open = db.query(IsoNonconformity).filter(
        IsoNonconformity.severity == 'major',
        IsoNonconformity.status.in_(['open', 'in_progress'])).count()
    audits_planned = db.query(IsoAudit).filter(IsoAudit.status == 'planned').count()
    reviews_planned = db.query(IsoManagementReview).filter(
        IsoManagementReview.status == 'planned').count()
    by_theme = {}
    for theme in ['A.5', 'A.6', 'A.7', 'A.8']:
        by_theme[theme] = {
            'total': db.query(IsoSoa).filter(IsoSoa.theme == theme).count(),
            'implemented': db.query(IsoSoa).filter(
                IsoSoa.theme == theme,
                IsoSoa.implementation_status.in_(['implemented', 'verified'])).count(),
        }
    return {
        'total_controls': total,
        'applicable': applicable,
        'implemented': implemented,
        'partial': partial,
        'not_implemented': not_implemented,
        'implementation_rate': round(implemented / applicable * 100, 1) if applicable > 0 else 0,
        'nc_open': nc_open,
        'nc_major_open': nc_major_open,
        'audits_planned': audits_planned,
        'reviews_planned': reviews_planned,
        'by_theme': by_theme,
    }