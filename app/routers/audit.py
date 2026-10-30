# app/routers/audit.py — Ticket #29
# Auditor role: cross-mapping with human+technical proofs, export PDF, audit trail
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, UTC
from typing import Optional, List

from pydantic import BaseModel

from app.database import get_db
from app.models import User, AuditTrail, Alert, PolicyAcknowledgment, SecurityPolicy
from app.models_mapping import FrameworkControl
from app.routers.auth import require_role
from app.services.audit_service import (
    build_cross_mapping_data,
    generate_cross_mapping_pdf,
)

router = APIRouter()


# ── Schemas ──

class HumanProof(BaseModel):
    read_rate: float
    read_count: int
    total: int


class TechnicalProof(BaseModel):
    alert_count: int
    last_alert_date: Optional[str] = None


class ControlMappingItem(BaseModel):
    id: int
    title: str
    status: str
    policy_link: Optional[str] = None
    human_proof: Optional[HumanProof] = None
    technical_proof: Optional[TechnicalProof] = None


class CrossMappingResponse(BaseModel):
    framework: str
    period: Optional[str] = None
    controls: List[ControlMappingItem]
    total_controls: int


class AuditTrailEntry(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    framework: Optional[str]
    period: Optional[str]
    ip_address: Optional[str]
    created_at: Optional[datetime]
    model_config = {"from_attributes": True}


class AuditTrailResponse(BaseModel):
    entries: List[AuditTrailEntry]
    total: int


# ── Helper: log audit trail ──

def _log_audit_trail(
    db: Session,
    user_id: Optional[int],
    action: str,
    framework: Optional[str] = None,
    period: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None,
):
    entry = AuditTrail(
        user_id=user_id,
        action=action,
        framework=framework,
        period=period,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
    )
    db.add(entry)
    db.commit()


# ── Helper: check auditor expiration ──

def _check_auditor_expiration(user: User):
    """Raise 403 if auditor role has expired."""
    if user.role == 'auditor' and user.role_expires_at:
        if user.role_expires_at < datetime.now(UTC):
            raise HTTPException(
                status_code=403,
                detail="Auditor access has expired. Contact your administrator.",
            )


# ══════════════════════════════════════════════════════════════════════════
# GET /api/v1/audit/cross-mapping — Cross-mapping with human & technical proofs
# ══════════════════════════════════════════════════════════════════════════

@router.get(
    "/cross-mapping",
    response_model=CrossMappingResponse,
    summary="Cross-mapping with human and technical proofs",
    description="Get framework controls with human proof (policy acknowledgment rate) "
    "and technical proof (alert counts). Auth: admin/superadmin/compliance_officer/auditor.",
)
def get_cross_mapping(
    framework: str = Query("iso27001", description="Framework name, e.g. 'iso27001', 'nis2', 'rgpd'"),
    period: Optional[str] = Query(None, description="Date range, e.g. '2026-01-01:2026-06-23'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role('superadmin', 'admin', 'compliance_officer', 'auditor')),
):
    # Check auditor expiration
    _check_auditor_expiration(current_user)

    # Parse period for date filtering
    date_from = None
    date_to = None
    if period and ':' in period:
        parts = period.split(':')
        try:
            date_from = datetime.strptime(parts[0], '%Y-%m-%d')
            date_to = datetime.strptime(parts[1], '%Y-%m-%d')
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid period format. Use YYYY-MM-DD:YYYY-MM-DD")

    # Get framework controls
    controls = db.query(FrameworkControl).filter(
        FrameworkControl.framework == framework,
        FrameworkControl.is_active == True,
    ).order_by(FrameworkControl.display_order).all()

    if not controls:
        raise HTTPException(status_code=404, detail=f"No controls found for framework '{framework}'")

    # Get all policy acknowledgments
    policy_ack_query = db.query(PolicyAcknowledgment)
    if date_from:
        policy_ack_query = policy_ack_query.filter(PolicyAcknowledgment.read_at >= date_from)
    if date_to:
        policy_ack_query = policy_ack_query.filter(PolicyAcknowledgment.read_at <= date_to)
    policy_acks = policy_ack_query.all()

    # Count total active users for acknowledgment rate
    total_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 1

    # Group policy acks by policy_id
    ack_by_policy = {}
    for ack in policy_acks:
        ack_by_policy.setdefault(ack.policy_id, []).append(ack)

    # Get alerts for the period
    alert_query = db.query(Alert)
    if date_from:
        alert_query = alert_query.filter(Alert.created_at >= date_from)
    if date_to:
        alert_query = alert_query.filter(Alert.created_at <= date_to)
    alerts = alert_query.all()

    # Build response
    result_controls = []
    for ctrl in controls:
        status = 'active'

        # Human proof: policy acknowledgment rate
        human_proof = None
        related_policies = []
        if ctrl.category:
            for pol in db.query(SecurityPolicy).filter(
                SecurityPolicy.status.in_(['published', 'approved'])
            ).all():
                if pol.category and pol.category.lower() == ctrl.category.lower():
                    related_policies.append(pol)

        if related_policies or ctrl.iso27001_ref:
            total_reads = 0
            total_possible = len(related_policies) * total_users if related_policies else 0
            for pol in related_policies:
                acks_count = len(ack_by_policy.get(pol.id, []))
                total_reads += acks_count

            if total_possible > 0:
                read_rate = round(total_reads / total_possible * 100, 1)
            else:
                # Fallback: use overall acknowledgment stats
                total_ack_count = len(policy_acks)
                read_rate = round(total_ack_count / max(total_users, 1) * 100, 1) if total_users > 0 else 0.0
                total_reads = total_ack_count
                total_possible = total_users

            human_proof = HumanProof(
                read_rate=min(read_rate, 100.0),
                read_count=total_reads,
                total=total_possible,
            )

        # Technical proof: alerts count
        alert_count = len(alerts)
        last_alert_date = None
        if alerts:
            latest = max(alerts, key=lambda a: a.created_at if a.created_at else datetime.min)
            if latest.created_at:
                last_alert_date = latest.created_at.isoformat()

        technical_proof = TechnicalProof(
            alert_count=alert_count,
            last_alert_date=last_alert_date,
        )

        # Policy link
        policy_link = None
        if related_policies:
            policy_link = f"/api/v1/governance/policies/{related_policies[0].id}"

        result_controls.append(ControlMappingItem(
            id=ctrl.id,
            title=ctrl.title,
            status=status,
            policy_link=policy_link,
            human_proof=human_proof,
            technical_proof=technical_proof,
        ))

    # Log audit trail
    _log_audit_trail(
        db,
        user_id=current_user.id,
        action='view_cross_mapping',
        framework=framework,
        period=period,
        details={'total_controls': len(result_controls)},
    )

    return CrossMappingResponse(
        framework=framework,
        period=period,
        controls=result_controls,
        total_controls=len(result_controls),
    )


# ══════════════════════════════════════════════════════════════════════════
# GET /api/v1/audit/export — Export cross-mapping as PDF
# ══════════════════════════════════════════════════════════════════════════

@router.get(
    "/export",
    summary="Export cross-mapping report as PDF",
    description="Generate and download a PDF report of the cross-mapping data. "
    "Auth: admin/superadmin/compliance_officer/auditor.",
    responses={200: {"content": {"application/pdf": {}}}},
)
def export_cross_mapping_pdf(
    framework: str = Query("iso27001", description="Framework name"),
    period: Optional[str] = Query(None, description="Date range, e.g. '2026-01-01:2026-06-23'"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role('superadmin', 'admin', 'compliance_officer', 'auditor')),
):
    # Check auditor expiration
    _check_auditor_expiration(current_user)

    # Build the cross-mapping data
    data = build_cross_mapping_data(db, framework, period)

    # Generate PDF
    pdf_bytes = generate_cross_mapping_pdf(data, framework, period)

    # Log audit trail
    _log_audit_trail(
        db,
        user_id=current_user.id,
        action='export_pdf',
        framework=framework,
        period=period,
        details={'format': 'pdf'},
    )

    filename = f"audit_cross_mapping_{framework}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ══════════════════════════════════════════════════════════════════════════
# GET /api/v1/audit/trail — View audit trail (admin only)
# ══════════════════════════════════════════════════════════════════════════

@router.get(
    "/trail",
    response_model=AuditTrailResponse,
    summary="View auditor audit trail",
    description="View all audit trail entries for auditor consultations. Auth: admin/superadmin only.",
)
def get_audit_trail(
    user_id: Optional[int] = Query(None),
    action: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role('superadmin', 'admin')),
):
    query = db.query(AuditTrail)

    if user_id is not None:
        query = query.filter(AuditTrail.user_id == user_id)
    if action:
        query = query.filter(AuditTrail.action == action)
    if framework:
        query = query.filter(AuditTrail.framework == framework)

    total = query.count()
    entries = query.order_by(AuditTrail.created_at.desc()).offset(skip).limit(limit).all()

    return AuditTrailResponse(entries=entries, total=total)