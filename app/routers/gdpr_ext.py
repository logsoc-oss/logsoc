# app/routers/gdpr_ext.py — T89
# RGPD extended: registre Art. 30, DPIA Art. 35, droits Art. 12-22, sous-traitants Art. 28, transferts Art. 44-49, violations Art. 33-34
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, get_current_user
from app.models_gdpr_ext import (
    GdprTreatment, GdprDpia, GdprDataRequest, GdprSubprocessor,
    GdprTransfer, GdprBreach
)
from app.schemas_gdpr_ext import (
    TreatmentCreate, TreatmentResponse,
    DpiaCreate, DpiaResponse,
    DataRequestCreate, DataRequestUpdate, DataRequestResponse,
    SubprocessorCreate, SubprocessorResponse,
    TransferCreate, TransferResponse,
    BreachCreate, BreachUpdate, BreachResponse
)

router = APIRouter()


# ── Treatments (Art. 30) ──

@router.get("/treatments", response_model=List[TreatmentResponse])
def list_treatments(limit: int = Query(100, le=500), db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    return db.query(GdprTreatment).order_by(GdprTreatment.name).limit(limit).all()


@router.post("/treatments", response_model=TreatmentResponse)
def create_treatment(t: TreatmentCreate, db: Session = Depends(get_db),
                     current_user: User = Depends(require_role("admin"))):
    tr = GdprTreatment(**t.model_dump())
    db.add(tr)
    db.commit()
    db.refresh(tr)
    return tr


@router.get("/treatments/{treatment_id}", response_model=TreatmentResponse)
def get_treatment(treatment_id: int, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("user"))):
    tr = db.query(GdprTreatment).filter(GdprTreatment.id == treatment_id).first()
    if not tr:
        raise HTTPException(status_code=404, detail="Treatment not found")
    return tr


@router.delete("/treatments/{treatment_id}")
def delete_treatment(treatment_id: int, db: Session = Depends(get_db),
                     current_user: User = Depends(require_role("admin"))):
    tr = db.query(GdprTreatment).filter(GdprTreatment.id == treatment_id).first()
    if not tr:
        raise HTTPException(status_code=404, detail="Treatment not found")
    db.delete(tr)
    db.commit()
    return {"id": treatment_id, "deleted": True}


# ── DPIA (Art. 35) ──

@router.get("/dpia", response_model=List[DpiaResponse])
def list_dpia(status: Optional[str] = Query(None), db: Session = Depends(get_db),
              current_user: User = Depends(require_role("user"))):
    q = db.query(GdprDpia)
    if status:
        q = q.filter(GdprDpia.status == status)
    return q.order_by(GdprDpia.created_at.desc()).all()


@router.post("/dpia", response_model=DpiaResponse)
def create_dpia(d: DpiaCreate, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("admin"))):
    dpia = GdprDpia(**d.model_dump())
    if dpia.residual_risk_level in ['high', 'very_high']:
        dpia.cnil_consultation_required = True
    db.add(dpia)
    db.commit()
    db.refresh(dpia)
    return dpia


@router.put("/dpia/{dpia_id}/approve", response_model=DpiaResponse)
def approve_dpia(dpia_id: int, approved_by: int = 0, db: Session = Depends(get_db),
                current_user: User = Depends(require_role("admin"))):
    dpia = db.query(GdprDpia).filter(GdprDpia.id == dpia_id).first()
    if not dpia:
        raise HTTPException(status_code=404, detail="DPIA not found")
    dpia.status = 'approved'
    dpia.approved_by = approved_by
    dpia.approved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(dpia)
    return dpia

# ── Data requests (Art. 12-22) ──

@router.get("/requests", response_model=List[DataRequestResponse])
def list_requests(
    status: Optional[str] = Query(None),
    right_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(GdprDataRequest)
    if status:
        q = q.filter(GdprDataRequest.status == status)
    if right_type:
        q = q.filter(GdprDataRequest.right_type == right_type)
    return q.order_by(GdprDataRequest.received_at.desc()).limit(limit).all()

@router.post("/requests", response_model=DataRequestResponse)
def create_request(r: DataRequestCreate, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("admin"))):
    req = GdprDataRequest(
        **r.model_dump(),
        response_deadline=(datetime.now(timezone.utc) + timedelta(days=30)).date(),
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return req


@router.put("/requests/{request_id}", response_model=DataRequestResponse)
def update_request(request_id: int, update: DataRequestUpdate, db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("admin"))):
    req = db.query(GdprDataRequest).filter(GdprDataRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(req, field, value)
    if update.status == 'responded':
        req.responded_at = datetime.now(timezone.utc)
    if update.extended:
        req.extended_deadline = (datetime.now(timezone.utc) + timedelta(days=60)).date()
    db.commit()
    db.refresh(req)
    return req


# ── Subprocessors (Art. 28) ──

@router.get("/subprocessors", response_model=List[SubprocessorResponse])
def list_subprocessors(status: Optional[str] = Query(None), db: Session = Depends(get_db),
                       current_user: User = Depends(require_role("user"))):
    q = db.query(GdprSubprocessor)
    if status:
        q = q.filter(GdprSubprocessor.status == status)
    return q.order_by(GdprSubprocessor.name).all()


@router.post("/subprocessors", response_model=SubprocessorResponse)
def create_subprocessor(s: SubprocessorCreate, db: Session = Depends(get_db),
                        current_user: User = Depends(require_role("admin"))):
    sub = GdprSubprocessor(**s.model_dump())
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return sub


@router.delete("/subprocessors/{sub_id}")
def delete_subprocessor(sub_id: int, db: Session = Depends(get_db),
                        current_user: User = Depends(require_role("admin"))):
    sub = db.query(GdprSubprocessor).filter(GdprSubprocessor.id == sub_id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="Subprocessor not found")
    sub.status = 'terminated'
    sub.terminated_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": sub_id, "status": "terminated"}


# ── Transfers (Art. 44-49) ──

@router.get("/transfers", response_model=List[TransferResponse])
def list_transfers(country: Optional[str] = Query(None), db: Session = Depends(get_db),
                   current_user: User = Depends(require_role("user"))):
    q = db.query(GdprTransfer)
    if country:
        q = q.filter(GdprTransfer.destination_country == country)
    return q.order_by(GdprTransfer.destination_country).all()

@router.post("/transfers", response_model=TransferResponse)
def create_transfer(t: TransferCreate, db: Session = Depends(get_db),
                    current_user: User = Depends(require_role("admin"))):
    tr = GdprTransfer(**t.model_dump())
    db.add(tr)
    db.commit()
    db.refresh(tr)
    return tr


# ── Breaches (Art. 33-34) ──

@router.get("/breaches", response_model=List[BreachResponse])
def list_breaches(
    risk_level: Optional[str] = Query(None),
    cnil_notified: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(GdprBreach)
    if risk_level:
        q = q.filter(GdprBreach.risk_level == risk_level)
    if cnil_notified is not None:
        q = q.filter(GdprBreach.cnil_notified == cnil_notified)
    return q.order_by(GdprBreach.created_at.desc()).limit(limit).all()

@router.post("/breaches", response_model=BreachResponse)
def create_breach(b: BreachCreate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    breach = GdprBreach(**b.model_dump())
    breach.cnil_notification_deadline = datetime.now(timezone.utc) + timedelta(hours=72)
    db.add(breach)
    db.commit()
    db.refresh(breach)
    return breach


@router.put("/breaches/{breach_id}", response_model=BreachResponse)
def update_breach(breach_id: int, update: BreachUpdate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_role("admin"))):
    breach = db.query(GdprBreach).filter(GdprBreach.id == breach_id).first()
    if not breach:
        raise HTTPException(status_code=404, detail="Breach not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(breach, field, value)
    if update.cnil_notified:
        breach.cnil_notification_date = datetime.now(timezone.utc)
    if update.persons_notified:
        breach.persons_notification_date = datetime.now(timezone.utc)
    db.commit()
    db.refresh(breach)
    return breach


# ── Summary ──

@router.get("/summary")
def gdpr_summary(db: Session = Depends(get_db),
                 current_user: User = Depends(require_role("user"))):
    return {
        "treatments": db.query(GdprTreatment).count(),
        "dpia_total": db.query(GdprDpia).count(),
        "dpia_approved": db.query(GdprDpia).filter(GdprDpia.status == 'approved').count(),
        "dpia_pending": db.query(GdprDpia).filter(GdprDpia.status.in_(['draft', 'in_review'])).count(),
        "requests_open": db.query(GdprDataRequest).filter(
            GdprDataRequest.status.in_(['received', 'in_progress'])).count(),
        "requests_overdue": db.query(GdprDataRequest).filter(
            GdprDataRequest.response_deadline < datetime.now(timezone.utc).date(),
            GdprDataRequest.status.in_(['received', 'in_progress'])).count(),
        "subprocessors_active": db.query(GdprSubprocessor).filter(
            GdprSubprocessor.status == 'active').count(),
        "transfers_total": db.query(GdprTransfer).count(),
        "breaches_total": db.query(GdprBreach).count(),
        "breaches_high_risk": db.query(GdprBreach).filter(GdprBreach.risk_level == 'high').count(),
        "breaches_cnil_notified": db.query(GdprBreach).filter(GdprBreach.cnil_notified == True).count(),
    }