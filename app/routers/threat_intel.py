# app/routers/threat_intel.py — T93
# Threat Intelligence: IOCs, TTPs, feeds, actors, bulletins, correlations, lookup
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from datetime import datetime, timezone

from app.database import get_db
from app.models import User
from app.routers.auth import require_role, require_permission
from app.models_ti import TiIndicator, TiActor, TiFeed, TiBulletin, TiCorrelation
from app.schemas_ti import (
    IndicatorCreate, IndicatorResponse, LookupRequest, LookupResponse,
    ActorCreate, ActorResponse, FeedCreate, FeedResponse,
    BulletinCreate, BulletinResponse
)

router = APIRouter()


# ── Indicators (IOCs) ──

@router.get("/indicators", response_model=List[IndicatorResponse])
def list_indicators(
    indicator_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel", "read")),
):
    q = db.query(TiIndicator)
    if indicator_type:
        q = q.filter(TiIndicator.indicator_type == indicator_type)
    if is_active is not None:
        q = q.filter(TiIndicator.is_active == is_active)
    if source:
        q = q.filter(TiIndicator.source == source)
    return q.order_by(TiIndicator.created_at.desc()).limit(limit).all()

@router.post("/indicators", response_model=IndicatorResponse)
def create_indicator(ind: IndicatorCreate, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "write"))):
    i = TiIndicator(**ind.model_dump())
    i.first_seen = datetime.now(timezone.utc)
    i.last_seen = datetime.now(timezone.utc)
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


@router.delete("/indicators/{indicator_id}")
def delete_indicator(indicator_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "delete"))):
    i = db.query(TiIndicator).filter(TiIndicator.id == indicator_id).first()
    if not i:
        raise HTTPException(status_code=404, detail="Indicator not found")
    i.is_active = False
    db.commit()
    return {"id": indicator_id, "is_active": False}


# ── Lookup ──

@router.post("/lookup", response_model=LookupResponse)
def lookup_ioc(req: LookupRequest, db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    """Lookup an IOC in the local database and return matches + correlations."""
    q = db.query(TiIndicator).filter(
        TiIndicator.value == req.value,
        TiIndicator.is_active == True
    )
    if req.indicator_type:
        q = q.filter(TiIndicator.indicator_type == req.indicator_type)
    indicators = q.all()

    correlations = []
    if indicators:
        ind_ids = [i.id for i in indicators]
        corr = db.query(TiCorrelation).filter(TiCorrelation.indicator_id.in_(ind_ids)).all()
        correlations = [{c.name: getattr(c, c.name) for c in c.__table__.columns} for c in corr]

    return {
        "value": req.value,
        "found": len(indicators) > 0,
        "indicators": [{c.name: getattr(i, c.name) for c in i.__table__.columns} for i in indicators],
        "correlations": correlations,
    }


# ── Actors ──

@router.get("/actors", response_model=List[ActorResponse])
def list_actors(
    actor_type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel", "read")),
):
    q = db.query(TiActor)
    if actor_type:
        q = q.filter(TiActor.actor_type == actor_type)
    if is_active is not None:
        q = q.filter(TiActor.is_active == is_active)
    return q.order_by(TiActor.name).limit(limit).all()

@router.post("/actors", response_model=ActorResponse)
def create_actor(a: ActorCreate, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "write"))):
    actor = TiActor(**a.model_dump())
    db.add(actor)
    db.commit()
    db.refresh(actor)
    return actor


# ── Feeds ──

@router.get("/feeds", response_model=List[FeedResponse])
def list_feeds(is_active: Optional[bool] = Query(None), db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "read"))):
    q = db.query(TiFeed)
    if is_active is not None:
        q = q.filter(TiFeed.is_active == is_active)
    return q.order_by(TiFeed.name).all()

@router.post("/feeds", response_model=FeedResponse)
def create_feed(f: FeedCreate, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "write"))):
    feed = TiFeed(**f.model_dump())
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return feed


@router.post("/feeds/{feed_id}/sync")
def sync_feed(feed_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "write"))):
    """Mark a feed as synced (placeholder — actual sync logic depends on feed type)."""
    feed = db.query(TiFeed).filter(TiFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    feed.last_sync_at = datetime.now(timezone.utc)
    feed.last_sync_status = 'ok'
    db.commit()
    return {"id": feed.id, "last_sync_at": feed.last_sync_at.isoformat(), "status": "ok"}


# ── Bulletins ──

@router.get("/bulletins", response_model=List[BulletinResponse])
def list_bulletins(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel", "read")),
):
    q = db.query(TiBulletin)
    if severity:
        q = q.filter(TiBulletin.severity == severity)
    if status:
        q = q.filter(TiBulletin.status == status)
    return q.order_by(TiBulletin.created_at.desc()).limit(limit).all()

@router.post("/bulletins", response_model=BulletinResponse)
def create_bulletin(b: BulletinCreate, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "write"))):
    bull = TiBulletin(**b.model_dump())
    db.add(bull)
    db.commit()
    db.refresh(bull)
    return bull


@router.put("/bulletins/{bulletin_id}/publish", response_model=BulletinResponse)
def publish_bulletin(bulletin_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_permission("threat_intel", "write"))):
    b = db.query(TiBulletin).filter(TiBulletin.id == bulletin_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Bulletin not found")
    b.status = 'published'
    b.published_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(b)
    return b


# ── Correlations ──

@router.get("/correlations")
def list_correlations(
    indicator_id: Optional[int] = Query(None),
    alert_id: Optional[int] = Query(None),
    case_id: Optional[int] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(TiCorrelation)
    if indicator_id:
        q = q.filter(TiCorrelation.indicator_id == indicator_id)
    if alert_id:
        q = q.filter(TiCorrelation.alert_id == alert_id)
    if case_id:
        q = q.filter(TiCorrelation.case_id == case_id)
    rows = q.order_by(TiCorrelation.created_at.desc()).limit(limit).all()
    return [{c.name: getattr(r, c.name) for c in r.__table__.columns} for r in rows]

# ── Summary ──

@router.get("/summary")
def ti_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    total_iocs = db.query(TiIndicator).filter(TiIndicator.is_active == True).count()
    by_type = {}
    for t in ['ip', 'domain', 'url', 'hash_md5', 'hash_sha256', 'email', 'filename']:
        by_type[t] = db.query(TiIndicator).filter(
            TiIndicator.indicator_type == t, TiIndicator.is_active == True).count()
    total_actors = db.query(TiActor).filter(TiActor.is_active == True).count()
    total_feeds = db.query(TiFeed).filter(TiFeed.is_active == True).count()
    total_bulletins = db.query(TiBulletin).filter(TiBulletin.status == 'published').count()
    total_correlations = db.query(TiCorrelation).count()
    return {
        'active_iocs': total_iocs,
        'iocs_by_type': by_type,
        'active_actors': total_actors,
        'active_feeds': total_feeds,
        'published_bulletins': total_bulletins,
        'total_correlations': total_correlations,
    }