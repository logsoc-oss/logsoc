"""app/routers/retention.py — Ticket #9 Option B: Generic retention module endpoints.

8 endpoints for managing retention policies, tracking purge jobs,
and maintaining the personal data registry (GDPR coverage).

Authorization: superadmin | admin | compliance_officer | dpo
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app.models import RetentionPolicy, RetentionJob, PersonalDataRegistry, User
from app.routers.auth import require_role
from app.services.retention_service import run_retention_job, run_all_enabled_policies, detect_personal_data

logger = logging.getLogger("logsoc.retention")

router = APIRouter()


# ─── Pydantic Schemas ───────────────────────────────────────────────────────

class RetentionPolicyCreate(BaseModel):
    """Create/update payload for a retention policy."""
    data_domain: str = Field(..., min_length=1, max_length=64, description="Logical domain name (e.g. 'alerts')")
    table_name: Optional[str] = Field(None, max_length=64, description="MariaDB table name for purge (defaults to data_domain)")
    hot_days: int = Field(365, ge=1, le=36500, description="Days to keep data in primary store")
    warm_days: int = Field(0, ge=0, le=36500)
    cold_days: int = Field(0, ge=0, le=36500)
    auto_purge: bool = Field(True)
    purge_after_days: Optional[int] = Field(None, ge=1, le=36500)
    archive_enabled: bool = Field(True, description="Export data to archive before purging")
    archive_path: str = Field("/var/logsoc/archive", max_length=256)
    purge_cron: str = Field("0 2 * * *", max_length=32, description="Cron schedule for automated purge")
    is_active: bool = Field(True)
    anonymize_after_days: Optional[int] = Field(None, ge=1, le=36500)
    erase_after_days: Optional[int] = Field(None, ge=1, le=36500)
    notes: Optional[str] = None


class RetentionPolicyResponse(BaseModel):
    id: int
    name: Optional[str] = None
    data_domain: str
    table_name: Optional[str] = None
    hot_days: int
    warm_days: int = 0
    cold_days: int = 0
    auto_purge: bool = True
    purge_after_days: Optional[int] = None
    archive_enabled: bool = True
    archive_path: str = "/var/logsoc/archive"
    purge_cron: str = "0 2 * * *"
    is_active: bool = True
    anonymize_after_days: Optional[int] = None
    erase_after_days: Optional[int] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    updated_by: Optional[int] = None

    class Config:
        from_attributes = True


class RetentionJobResponse(BaseModel):
    id: int
    policy_id: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    records_archived: int = 0
    records_purged: int = 0
    status: str = "running"
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class PersonalDataRegistryEntry(BaseModel):
    table_name: str = Field(..., max_length=64)
    column_name: str = Field(..., max_length=64)
    data_type: str = Field("other", pattern="^(username|ip|email|hostname|mac|other)$")
    gdpr_article: str = Field("5(1)(e)", max_length=32)
    notes: Optional[str] = None


class PersonalDataRegistryResponse(BaseModel):
    id: int
    table_name: str
    column_name: str
    data_type: str
    gdpr_article: str
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class RetentionRunRequest(BaseModel):
    dry_run: bool = Field(True, description="If true, count only without purging")


# ─── Helper ──────────────────────────────────────────────────────────────────

def _policy_to_dict(p: RetentionPolicy) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "data_domain": p.data_domain,
        "table_name": getattr(p, "table_name", None),
        "hot_days": p.hot_days,
        "warm_days": p.warm_days,
        "cold_days": p.cold_days,
        "auto_purge": p.auto_purge if p.auto_purge is not None else True,
        "purge_after_days": p.purge_after_days,
        "archive_enabled": getattr(p, "archive_enabled", True),
        "archive_path": getattr(p, "archive_path", "/var/logsoc/archive"),
        "purge_cron": getattr(p, "purge_cron", "0 2 * * *"),
        "is_active": p.is_active if p.is_active is not None else True,
        "anonymize_after_days": p.anonymize_after_days,
        "erase_after_days": p.erase_after_days,
        "notes": p.notes,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "updated_by": p.updated_by,
    }


# ─── Endpoints ──────────────────────────────────────────────────────────────

# 1. GET /api/v1/retention/policies — List all retention policies
@router.get(
    "/retention/policies",
    response_model=List[RetentionPolicyResponse],
    summary="List all retention policies",
)
def list_retention_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "superadmin", "compliance_officer", "dpo")),
):
    """List all retention policies (MVP: siem_logs, access_logs, alerts, yara_scan_results)."""
    policies = db.query(RetentionPolicy).order_by(RetentionPolicy.id).all()
    return [_policy_to_dict(p) for p in policies]


# 2. POST /api/v1/retention/policies — Create or update a retention policy
@router.post(
    "/retention/policies",
    response_model=RetentionPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a retention policy",
)
def create_retention_policy(
    payload: RetentionPolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "compliance_officer", "dpo")),
):
    """Create a new retention policy or update an existing one by data_domain."""
    existing = (
        db.query(RetentionPolicy)
        .filter(RetentionPolicy.data_domain == payload.data_domain)
        .first()
    )
    if existing:
        # Update
        update_data = payload.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(existing, key, value)
        existing.updated_by = current_user.id
        existing.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        return _policy_to_dict(existing)

    # Create
    policy = RetentionPolicy(
        data_domain=payload.data_domain,
        table_name=payload.table_name or payload.data_domain,
        hot_days=payload.hot_days,
        warm_days=payload.warm_days,
        cold_days=payload.cold_days,
        auto_purge=payload.auto_purge,
        purge_after_days=payload.purge_after_days,
        archive_enabled=payload.archive_enabled,
        archive_path=payload.archive_path,
        purge_cron=payload.purge_cron,
        is_active=payload.is_active,
        anonymize_after_days=payload.anonymize_after_days,
        erase_after_days=payload.erase_after_days,
        notes=payload.notes,
        name=f"Retention - {payload.data_domain}",
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return _policy_to_dict(policy)


# 3. DELETE /api/v1/retention/policies/{id} — Delete a retention policy
@router.delete(
    "/retention/policies/{policy_id}",
    summary="Delete a retention policy",
)
def delete_retention_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "dpo")),
):
    """Delete a retention policy by ID. Cannot delete if active jobs are running."""
    policy = db.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Retention policy not found")

    # Check for running jobs
    running = (
        db.query(RetentionJob)
        .filter(RetentionJob.policy_id == policy_id, RetentionJob.status == "running")
        .count()
    )
    if running > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete policy {policy_id}: {running} running jobs exist",
        )

    db.delete(policy)
    db.commit()
    return {"message": f"Retention policy {policy_id} deleted", "data_domain": policy.data_domain}


# 4. POST /api/v1/retention/policies/{id}/run — Trigger a manual purge
@router.post(
    "/retention/policies/{policy_id}/run",
    summary="Trigger a manual retention purge for a policy",
)
def run_manual_purge(
    policy_id: int,
    payload: RetentionRunRequest = RetentionRunRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "compliance_officer", "dpo")),
):
    """Manually trigger a retention purge job for a specific policy.

    By default runs in dry_run mode (count only). Set dry_run=false to actually purge.
    """
    policy = db.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Retention policy not found")

    result = run_retention_job(db, policy_id, dry_run=payload.dry_run)
    return result


# 5. GET /api/v1/retention/jobs — List retention jobs
@router.get(
    "/retention/jobs",
    response_model=List[RetentionJobResponse],
    summary="List retention purge jobs",
)
def list_retention_jobs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    policy_id: Optional[int] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "superadmin", "compliance_officer", "dpo")),
):
    """List retention purge job history with optional filters."""
    q = db.query(RetentionJob)
    if policy_id:
        q = q.filter(RetentionJob.policy_id == policy_id)
    if status_filter:
        q = q.filter(RetentionJob.status == status_filter)
    q = q.order_by(RetentionJob.id.desc())
    jobs = q.offset(skip).limit(limit).all()
    return [
        {
            "id": j.id,
            "policy_id": j.policy_id,
            "started_at": j.started_at,
            "completed_at": j.completed_at,
            "records_archived": j.records_archived,
            "records_purged": j.records_purged,
            "status": j.status,
            "error_message": j.error_message,
        }
        for j in jobs
    ]


# 6. GET /api/v1/retention/registry — List personal data registry
@router.get(
    "/retention/registry",
    response_model=List[PersonalDataRegistryResponse],
    summary="List personal data registry (GDPR column mapping)",
)
def list_personal_data_registry(
    table_name: Optional[str] = None,
    data_type: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "superadmin", "compliance_officer", "dpo")),
):
    """List the personal data registry. Optional filters by table_name and data_type."""
    q = db.query(PersonalDataRegistry)
    if table_name:
        q = q.filter(PersonalDataRegistry.table_name == table_name)
    if data_type:
        q = q.filter(PersonalDataRegistry.data_type == data_type)
    q = q.order_by(PersonalDataRegistry.id)
    entries = q.all()
    return [
        {
            "id": e.id,
            "table_name": e.table_name,
            "column_name": e.column_name,
            "data_type": e.data_type,
            "gdpr_article": e.gdpr_article,
            "notes": e.notes,
        }
        for e in entries
    ]


# 7. POST /api/v1/retention/registry — Add an entry to the personal data registry
@router.post(
    "/retention/registry",
    response_model=PersonalDataRegistryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an entry to the personal data registry",
)
def create_personal_data_entry(
    payload: PersonalDataRegistryEntry,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "superadmin", "compliance_officer", "dpo")),
):
    """Register a column as containing personal data (GDPR mapping)."""
    # Check for duplicate
    existing = (
        db.query(PersonalDataRegistry)
        .filter(
            PersonalDataRegistry.table_name == payload.table_name,
            PersonalDataRegistry.column_name == payload.column_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Entry for {payload.table_name}.{payload.column_name} already exists (id={existing.id})",
        )

    entry = PersonalDataRegistry(
        table_name=payload.table_name,
        column_name=payload.column_name,
        data_type=payload.data_type,
        gdpr_article=payload.gdpr_article,
        notes=payload.notes,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return {
        "id": entry.id,
        "table_name": entry.table_name,
        "column_name": entry.column_name,
        "data_type": entry.data_type,
        "gdpr_article": entry.gdpr_article,
        "notes": entry.notes,
    }


# 8. GET /api/v1/retention/report — GDPR retention coverage report
@router.get(
    "/retention/report",
    summary="GDPR retention coverage report",
)
def retention_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("analyst", "admin", "superadmin", "compliance_officer", "dpo")),
):
    """Generate a coverage report: which tables have a retention policy,
    which columns are registered as personal data, and job statistics.

    Returns:
      - policies: list of all retention policies with status
      - registry: summary of personal data columns by table
      - coverage: tables with policies vs without
      - jobs: recent job statistics
      - auto_detect: suggested new entries for the registry (based on naming conventions)
    """
    # 1. All policies
    policies = db.query(RetentionPolicy).order_by(RetentionPolicy.id).all()
    policy_list = [_policy_to_dict(p) for p in policies]

    # 2. Personal data registry grouped by table
    registry_entries = db.query(PersonalDataRegistry).order_by(
        PersonalDataRegistry.table_name, PersonalDataRegistry.column_name
    ).all()
    registry_by_table = {}
    for entry in registry_entries:
        tbl = entry.table_name
        if tbl not in registry_by_table:
            registry_by_table[tbl] = []
        registry_by_table[tbl].append({
            "column_name": entry.column_name,
            "data_type": entry.data_type,
            "gdpr_article": entry.gdpr_article,
        })

    # 3. Coverage analysis
    policy_tables = {p.data_domain for p in policies}
    registry_tables = {e.table_name for e in registry_entries}

    # Known tables that should have policies
    expected_tables = {"alerts", "yara_scan_results", "logs_raw", "access_logs", "audit_logs"}

    covered_tables = policy_tables & expected_tables
    uncovered_tables = expected_tables - policy_tables

    # Tables with registry but no policy
    registered_no_policy = registry_tables - policy_tables

    # 4. Job statistics (last 30 days)
    thirty_days_ago = datetime.now(timezone.utc) - __import__("datetime").timedelta(days=30)
    recent_jobs = (
        db.query(RetentionJob)
        .filter(RetentionJob.started_at >= thirty_days_ago)
        .order_by(RetentionJob.id.desc())
        .limit(50)
        .all()
    )
    job_stats = {
        "total": len(recent_jobs),
        "completed": sum(1 for j in recent_jobs if j.status == "completed"),
        "failed": sum(1 for j in recent_jobs if j.status == "failed"),
        "running": sum(1 for j in recent_jobs if j.status == "running"),
        "total_records_purged": sum(j.records_purged for j in recent_jobs if j.status == "completed"),
        "total_records_archived": sum(j.records_archived for j in recent_jobs if j.status == "completed"),
    }

    # 5. Auto-detect suggestions
    try:
        auto_suggestions = detect_personal_data(db)
    except Exception as e:
        logger.warning("auto-detect failed: %s", e)
        auto_suggestions = []

    return {
        "policies": policy_list,
        "registry_by_table": registry_by_table,
        "coverage": {
            "expected_tables": sorted(expected_tables),
            "covered_tables": sorted(covered_tables),
            "uncovered_tables": sorted(uncovered_tables),
            "registered_no_policy": sorted(registered_no_policy),
        },
        "job_stats": job_stats,
        "recent_jobs": [
            {
                "id": j.id,
                "policy_id": j.policy_id,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
                "records_archived": j.records_archived,
                "records_purged": j.records_purged,
                "status": j.status,
                "error_message": j.error_message,
            }
            for j in recent_jobs[:10]
        ],
        "auto_detect_suggestions": auto_suggestions,
    }