# app/routers/nis2_countries.py — T96
# NIS2 multi-country: 27 EU member states, authorities, transposition status, requirements
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.models import User
from app.routers.auth import require_role
from app.models_nis2_countries import Nis2Country, Nis2CountryAuthority, Nis2CountryRequirement

router = APIRouter()


@router.get("/countries")
def list_countries(
    transposition_status: Optional[str] = Query(None),
    limit: int = Query(50, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(Nis2Country).filter(Nis2Country.is_active == True)
    if transposition_status:
        q = q.filter(Nis2Country.transposition_status == transposition_status)
    countries = q.order_by(Nis2Country.country_name).limit(limit).all()
    return [{c.name: getattr(c, c.name) for c in c.__table__.columns} for c in countries]


@router.get("/countries/{country_code}")
def get_country(country_code: str, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    c = db.query(Nis2Country).filter(Nis2Country.country_code == country_code).first()
    if not c:
        raise HTTPException(status_code=404, detail="Country not found")
    result = {col.name: getattr(c, col.name) for col in c.__table__.columns}
    auths = db.query(Nis2CountryAuthority).filter(
        Nis2CountryAuthority.country_code == country_code).all()
    reqs = db.query(Nis2CountryRequirement).filter(
        Nis2CountryRequirement.country_code == country_code).first()
    result["authorities"] = [{col.name: getattr(a, col.name) for col in a.__table__.columns} for a in auths]
    result["requirements"] = {col.name: getattr(reqs, col.name) for col in reqs.__table__.columns} if reqs else None
    return result


@router.get("/countries/{country_code}/authority")
def get_authority(country_code: str, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    auths = db.query(Nis2CountryAuthority).filter(
        Nis2CountryAuthority.country_code == country_code).all()
    if not auths:
        raise HTTPException(status_code=404, detail="No authority found for this country")
    return [{col.name: getattr(a, col.name) for col in a.__table__.columns} for a in auths]


@router.get("/summary")
def countries_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    countries = db.query(Nis2Country).filter(Nis2Country.is_active == True).all()
    by_status = {}
    for c in countries:
        by_status[c.transposition_status] = by_status.get(c.transposition_status, 0) + 1
    return {
        "total_countries": len(countries),
        "by_status": by_status,
        "in_force": by_status.get('in_force', 0),
        "in_progress": by_status.get('in_progress', 0),
        "with_national_framework": sum(1 for c in countries if c.national_framework),
        "extended_scope": sum(1 for c in countries if c.notes and 'élargi' in c.notes.lower()),
    }