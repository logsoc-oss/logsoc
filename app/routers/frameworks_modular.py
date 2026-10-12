# app/routers/frameworks_modular.py — T97
# Frameworks modulaires: NIST CSF 2.0, CIS v8, ANSSI 42, PCI-DSS v4, SOC 2, EBIOS RM
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from collections import defaultdict

from app.database import get_db
from app.models import User
from app.routers.auth import require_role
from app.models_frameworks_modular import FrameworkAssessment

router = APIRouter()

FRAMEWORKS = {
    'nist_csf': {'name': 'NIST CSF 2.0', 'controls': 6, 'levels': 'Tier 1-4'},
    'cis': {'name': 'CIS Controls v8', 'controls': 18, 'levels': 'IG1-IG3'},
    'anssi': {'name': 'ANSSI Guide dhygiene', 'controls': 4, 'levels': 'Familles'},
    'pci_dss': {'name': 'PCI-DSS v4.0', 'controls': 12, 'levels': 'Requirements'},
    'soc2': {'name': 'SOC 2 Type II', 'controls': 5, 'levels': 'Type I/II'},
    'ebios': {'name': 'EBIOS RM', 'controls': 5, 'levels': 'Phases'},
}


@router.get("/")
def list_frameworks(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    result = []
    for fw_code, fw_info in FRAMEWORKS.items():
        assessments = db.query(FrameworkAssessment).filter(
            FrameworkAssessment.framework == fw_code).all()
        total = len(assessments)
        implemented = sum(1 for a in assessments if a.status in ['implemented', 'verified'])
        result.append({
            'code': fw_code,
            'name': fw_info['name'],
            'total_controls': fw_info['controls'],
            'assessed': total,
            'implemented': implemented,
            'progress': round(implemented / total * 100, 1) if total > 0 else 0,
            'levels': fw_info['levels'],
        })
    return result


# ── Summary (MUST be before /{framework} to avoid path conflict) ──

@router.get("/summary")
def frameworks_summary(db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    assessments = db.query(FrameworkAssessment).all()
    by_fw = defaultdict(lambda: {'total': 0, 'implemented': 0, 'gap': 0})
    for a in assessments:
        by_fw[a.framework]['total'] += 1
        if a.status in ['implemented', 'verified']:
            by_fw[a.framework]['implemented'] += 1
        elif a.status == 'gap':
            by_fw[a.framework]['gap'] += 1
    result = {}
    for fw_code, fw_info in FRAMEWORKS.items():
        data = by_fw[fw_code]
        result[fw_code] = {
            'name': fw_info['name'],
            'total': data['total'],
            'implemented': data['implemented'],
            'gap': data['gap'],
            'progress': round(data['implemented'] / data['total'] * 100, 1) if data['total'] > 0 else 0,
        }
    return result


# ── Framework assessment (after /summary) ──

@router.get("/{framework}")
def get_framework_assessment(framework: str, db: Session = Depends(get_db), current_user: User = Depends(require_role("user"))):
    if framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework '{framework}' not found")
    assessments = db.query(FrameworkAssessment).filter(
        FrameworkAssessment.framework == framework).all()
    return {
        'framework': framework,
        'name': FRAMEWORKS[framework]['name'],
        'controls': [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in assessments],
        'total': len(assessments),
        'implemented': sum(1 for a in assessments if a.status in ['implemented', 'verified']),
    }

@router.put("/{framework}/{control_id}")
def update_assessment(
    framework: str,
    control_id: str,
    status: Optional[str] = None,
    maturity_level: Optional[int] = None,
    evidence_description: Optional[str] = None,
    gap_description: Optional[str] = None,
    remediation_plan: Optional[str] = None,
    target_level: Optional[str] = None,
    current_level: Optional[str] = None,
    next_review_due: Optional[str] = None,
    updated_by: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    a = db.query(FrameworkAssessment).filter(
        FrameworkAssessment.framework == framework,
        FrameworkAssessment.control_id == control_id
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="Control assessment not found")
    if status is not None: a.status = status
    if maturity_level is not None: a.maturity_level = maturity_level
    if evidence_description is not None: a.evidence_description = evidence_description
    if gap_description is not None: a.gap_description = gap_description
    if remediation_plan is not None: a.remediation_plan = remediation_plan
    if target_level is not None: a.target_level = target_level
    if current_level is not None: a.current_level = current_level
    if next_review_due is not None: a.next_review_due = next_review_due
    a.last_reviewed_at = datetime.now(timezone.utc)
    a.updated_by = updated_by
    db.commit()
    return {"framework": framework, "control_id": control_id, "status": a.status}