"""Phase 7 — Infrastructure endpoints (retention, backups, health).

Provides:
  - Retention policies CRUD + ClickHouse stats
  - Backup history CRUD
  - System health (Docker, disk, MariaDB/ClickHouse table counts)
"""

import datetime
import shutil
import subprocess

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List

from app.database import get_db
from app.models import RetentionPolicy, BackupHistory, User
from app.routers.auth import require_role
from app.clickhouse_client import get_client

router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────

class RetentionPolicyResponse(BaseModel):
    id: int
    name: Optional[str] = None
    data_domain: str
    hot_days: int
    warm_days: int
    cold_days: int
    auto_purge: Optional[bool] = False
    purge_after_days: Optional[int] = None
    is_active: Optional[bool] = True
    anonymize_after_days: Optional[int] = None
    erase_after_days: Optional[int] = None
    notes: Optional[str] = None
    created_at: Optional[datetime.datetime] = None
    updated_at: Optional[datetime.datetime] = None
    updated_by: Optional[int] = None

    class Config:
        from_attributes = True


class RetentionPolicyUpdate(BaseModel):
    name: Optional[str] = None
    hot_days: Optional[int] = None
    warm_days: Optional[int] = None
    cold_days: Optional[int] = None
    auto_purge: Optional[bool] = None
    purge_after_days: Optional[int] = None
    is_active: Optional[bool] = None
    notes: Optional[str] = None


class BackupHistoryCreate(BaseModel):
    backup_type: str
    status: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    s3_uploaded: Optional[bool] = False
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None


class BackupHistoryResponse(BaseModel):
    id: int
    backup_type: str
    status: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    s3_uploaded: Optional[bool] = False
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


# ── Helpers ────────────────────────────────────────────────────────

def _policy_to_dict(p: RetentionPolicy) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "data_domain": p.data_domain,
        "hot_days": p.hot_days,
        "warm_days": p.warm_days,
        "cold_days": p.cold_days,
        "auto_purge": p.auto_purge,
        "purge_after_days": p.purge_after_days,
        "is_active": p.is_active,
        "anonymize_after_days": p.anonymize_after_days,
        "erase_after_days": p.erase_after_days,
        "notes": p.notes,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "updated_by": p.updated_by,
    }


def _backup_to_dict(b: BackupHistory) -> dict:
    return {
        "id": b.id,
        "backup_type": b.backup_type,
        "status": b.status,
        "file_path": b.file_path,
        "file_size": b.file_size,
        "s3_uploaded": b.s3_uploaded,
        "started_at": b.started_at.isoformat() if b.started_at else None,
        "completed_at": b.completed_at.isoformat() if b.completed_at else None,
        "error_message": b.error_message,
    }


# ══════════════════════════════════════════════════════════════════
# RETENTION POLICIES
# ══════════════════════════════════════════════════════════════════

@router.get("/retention", response_model=List[RetentionPolicyResponse])
def list_retention_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List all retention policies."""
    policies = db.query(RetentionPolicy).order_by(RetentionPolicy.id).all()
    return [_policy_to_dict(p) for p in policies]


@router.put("/retention/{policy_id}", response_model=RetentionPolicyResponse)
def update_retention_policy(
    policy_id: int,
    payload: RetentionPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update a retention policy (admin only)."""
    policy = db.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Retention policy not found")

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(policy, key, value)

    policy.updated_by = current_user.id
    db.commit()
    db.refresh(policy)
    return _policy_to_dict(policy)


@router.get("/retention/stats")
def retention_stats(
    current_user: User = Depends(require_role("user")),
):
    """Return ClickHouse row counts and oldest timestamp per SIEM table."""
    tables = ["siem_logs", "siem_alerts", "siem_events"]
    result = {}

    try:
        ch = get_client()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"ClickHouse connection failed: {e}")

    for table in tables:
        try:
            count_result = ch.query(f"SELECT count() FROM {table}")
            row_count = count_result.result_rows[0][0] if count_result.result_rows else 0
        except Exception:
            row_count = None

        try:
            ts_result = ch.query(
                f"SELECT min(received_at) FROM {table}"
            )
            oldest = ts_result.result_rows[0][0] if ts_result.result_rows else None
            if isinstance(oldest, datetime.datetime):
                oldest = oldest.isoformat()
            elif isinstance(oldest, datetime.date):
                oldest = oldest.isoformat()
        except Exception:
            oldest = None

        result[table] = {
            "row_count": row_count,
            "oldest_timestamp": oldest,
        }

    return result


# ══════════════════════════════════════════════════════════════════
# BACKUP HISTORY
# ══════════════════════════════════════════════════════════════════

@router.get("/backups", response_model=List[BackupHistoryResponse])
def list_backups(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    backup_type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List backup history with pagination and optional filters."""
    q = db.query(BackupHistory)
    if backup_type:
        q = q.filter(BackupHistory.backup_type == backup_type)
    if status:
        q = q.filter(BackupHistory.status == status)
    q = q.order_by(BackupHistory.id.desc())
    backups = q.offset(skip).limit(limit).all()
    return [_backup_to_dict(b) for b in backups]


@router.post("/backups", response_model=BackupHistoryResponse, status_code=201)
def create_backup(
    payload: BackupHistoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Record a new backup entry (admin only)."""
    valid_types = {"mariadb", "clickhouse", "config", "full"}
    valid_statuses = {"success", "failed", "partial"}
    if payload.backup_type not in valid_types:
        raise HTTPException(status_code=422, detail=f"Invalid backup_type. Must be one of {valid_types}")
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=422, detail=f"Invalid status. Must be one of {valid_statuses}")

    backup = BackupHistory(
        backup_type=payload.backup_type,
        status=payload.status,
        file_path=payload.file_path,
        file_size=payload.file_size,
        s3_uploaded=payload.s3_uploaded if payload.s3_uploaded is not None else False,
        started_at=payload.started_at,
        completed_at=payload.completed_at,
        error_message=payload.error_message,
    )
    db.add(backup)
    db.commit()
    db.refresh(backup)
    return _backup_to_dict(backup)


@router.delete("/backups/{backup_id}")
def delete_backup(
    backup_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a backup record (admin only)."""
    backup = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup record not found")
    db.delete(backup)
    db.commit()
    return {"message": "Backup record deleted"}


# ══════════════════════════════════════════════════════════════════
# SYSTEM HEALTH
# ══════════════════════════════════════════════════════════════════

@router.get("/health")
def system_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Return system health: Docker containers, disk usage, MariaDB and
    ClickHouse table counts + row counts (admin only)."""

    # ── Docker container status ────────────────────────────────────
    containers = []
    try:
        proc = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    containers.append({
                        "name": parts[0],
                        "status": parts[1],
                        "image": parts[2],
                    })
    except Exception:
        pass  # Docker might not be available

    # ── Disk usage ────────────────────────────────────────────────
    disk = {}
    try:
        usage = shutil.disk_usage("/")
        disk = {
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "used_gb": round(usage.used / (1024 ** 3), 2),
            "free_gb": round(usage.free / (1024 ** 3), 2),
            "used_pct": round(usage.used / usage.total * 100, 1) if usage.total else 0,
        }
    except Exception:
        pass

    # ── MariaDB table count + row counts ──────────────────────────
    mariadb_tables = []
    try:
        from sqlalchemy import text
        tables_result = db.execute(text(
            "SELECT TABLE_NAME, TABLE_ROWS FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME"
        ))
        for row in tables_result:
            mariadb_tables.append({
                "table": row[0],
                "row_count": row[1],
            })
    except Exception:
        pass

    # ── ClickHouse table count + row counts ───────────────────────
    ch_tables = []
    try:
        ch = get_client()
        tables_result = ch.query(
            "SELECT name FROM system.tables WHERE database = currentDatabase() ORDER BY name"
        )
        for row in tables_result.result_rows:
            tname = row[0]
            try:
                cnt_result = ch.query(f"SELECT count() FROM `{tname}`")
                cnt = cnt_result.result_rows[0][0] if cnt_result.result_rows else 0
            except Exception:
                cnt = None
            ch_tables.append({"table": tname, "row_count": cnt})
    except Exception:
        pass

    return {
        "docker_containers": containers,
        "disk_usage": disk,
        "mariadb_tables": mariadb_tables,
        "clickhouse_tables": ch_tables,
    }