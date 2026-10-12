# app/routers/cross_mapping.py — T95
# Cross-framework mapping: NIS2 ↔ DORA ↔ RGPD ↔ AI Act ↔ ISO 27001 ↔ NIST CSF ↔ CIS ↔ ANSSI ↔ PCI-DSS ↔ SOC 2 ↔ EBIOS
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import List, Optional
from collections import defaultdict

from app.database import get_db
from app.models import User
from app.routers.auth import require_role
from app.models_mapping import FrameworkControl, FrameworkMapping

router = APIRouter()


@router.get("/frameworks")
def list_frameworks(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    """List all frameworks with control counts."""
    controls = db.query(FrameworkControl).filter(FrameworkControl.is_active == True).all()
    by_fw = defaultdict(int)
    for c in controls:
        by_fw[c.framework] += 1
    return {"frameworks": dict(by_fw), "total_controls": len(controls)}

@router.get("/controls")
def list_controls(
    framework: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(200, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    q = db.query(FrameworkControl).filter(FrameworkControl.is_active == True)
    if framework:
        q = q.filter(FrameworkControl.framework == framework)
    if category:
        q = q.filter(FrameworkControl.category == category)
    return q.order_by(FrameworkControl.framework, FrameworkControl.display_order).limit(limit).all()

@router.get("/cross")
def get_cross_mapping(
    framework: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """Get cross-framework mapping. If framework specified, returns mappings from that framework to all others."""
    if framework:
        mappings = db.query(FrameworkMapping).filter(
            or_(
                FrameworkMapping.source_framework == framework,
                FrameworkMapping.target_framework == framework
            )
        ).all()
    else:
        mappings = db.query(FrameworkMapping).all()

    result = defaultdict(list)
    for m in mappings:
        key = f"{m.source_framework}:{m.source_control_id}"
        result[key].append({
            "target_framework": m.target_framework,
            "target_control_id": m.target_control_id,
            "match_quality": m.match_quality,
        })
        # Reverse mapping
        key_rev = f"{m.target_framework}:{m.target_control_id}"
        result[key_rev].append({
            "target_framework": m.source_framework,
            "target_control_id": m.source_control_id,
            "match_quality": m.match_quality,
        })
    return {"mappings": dict(result), "total_mappings": len(mappings)}


@router.get("/{fw1}/{fw2}")
def get_framework_pair_mapping(fw1: str, fw2: str, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    """Get mapping between two specific frameworks."""
    mappings = db.query(FrameworkMapping).filter(
        or_(
            and_(FrameworkMapping.source_framework == fw1, FrameworkMapping.target_framework == fw2),
            and_(FrameworkMapping.source_framework == fw2, FrameworkMapping.target_framework == fw1),
        )
    ).all()
    return {
        "framework1": fw1,
        "framework2": fw2,
        "mappings": [
            {
                "source": f"{m.source_framework}:{m.source_control_id}",
                "target": f"{m.target_framework}:{m.target_control_id}",
                "match_quality": m.match_quality,
            }
            for m in mappings
        ],
        "total": len(mappings),
    }


@router.get("/unified-dashboard")
def unified_dashboard(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    """Unified compliance dashboard across all frameworks."""
    # Get all controls grouped by ISO 27001 pivot
    controls = db.query(FrameworkControl).filter(FrameworkControl.is_active == True).all()
    by_iso = defaultdict(list)
    for c in controls:
        if c.iso27001_ref:
            by_iso[c.iso27001_ref].append({
                "framework": c.framework,
                "control_id": c.control_id,
                "title": c.title,
            })

    # Count by framework
    by_fw = defaultdict(int)
    for c in controls:
        by_fw[c.framework] += 1

    # Count mappings
    total_mappings = db.query(FrameworkMapping).count()
    exact_matches = db.query(FrameworkMapping).filter(FrameworkMapping.match_quality == 'exact').count()

    return {
        "frameworks": dict(by_fw),
        "total_controls": len(controls),
        "total_mappings": total_mappings,
        "exact_matches": exact_matches,
        "pivot": "iso27001",
        "pivot_groups": dict(by_iso),
    }


@router.get("/summary")
def mapping_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    controls = db.query(FrameworkControl).filter(FrameworkControl.is_active == True).all()
    by_fw = defaultdict(int)
    for c in controls:
        by_fw[c.framework] += 1
    mappings = db.query(FrameworkMapping).all()
    by_quality = defaultdict(int)
    for m in mappings:
        by_quality[m.match_quality] += 1
    return {
        "frameworks": dict(by_fw),
        "total_controls": len(controls),
        "total_mappings": len(mappings),
        "by_quality": dict(by_quality),
    }