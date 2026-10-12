"""app/services/retention_service.py — Ticket #9 Option B: Generic retention service.

Provides purge + archive logic for the 4 MVP tables (alerts, yara_scan_results,
logs_raw, and future access_logs). Each retention policy defines a retention_days
(hot_days + warm_days) and optional anonymize_after_days / erase_after_days.

The service:
  1. Queries expired records (created_at/matched_at < NOW() - retention_days)
  2. If archive_enabled: exports to JSON file in archive_path before deletion
  3. Deletes expired records
  4. Logs the job in retention_jobs
  5. detect_personal_data(): scans the DB schema for PII columns by naming convention

This is MariaDB-only (ClickHouse siem_logs retention is handled by the existing
app/retention/jobs.py module). The generic module operates on MariaDB tables
that have a created_at / matched_at timestamp column.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import text, inspect
from sqlalchemy.orm import Session

from app.models import RetentionPolicy, RetentionJob, PersonalDataRegistry

logger = logging.getLogger("logsoc.retention.service")

# Map of data_domain -> timestamp column used for age calculation
# (different tables use different column names for their timestamp)
TIMESTAMP_COLUMNS = {
    "alerts": "created_at",
    "yara_scan_results": "matched_at",
    "logs_raw": "received_at",
    "access_logs": "created_at",
    "audit_logs": "created_at",
    "case_comments": "created_at",
    "user_sessions": "created_at",
}

# PII column naming patterns for auto-detection
PII_PATTERNS = {
    "username": ["username", "user_name", "actor_username", "assigned_to", "closed_by", "created_by", "updated_by", "owner"],
    "ip": ["source_ip", "dst_ip", "ip_address", "client_ip", "remote_ip", "src_ip", "dest_ip"],
    "email": ["email", "mail", "e_mail"],
    "hostname": ["hostname", "source_host", "host_name", "server_name"],
    "mac": ["mac_address", "mac_addr"],
}


def _get_timestamp_col(policy: RetentionPolicy) -> str:
    """Determine the timestamp column for a policy's target table.

    Uses the explicit table_name from the policy, falling back to
    the TIMESTAMP_COLUMNS map keyed by data_domain.
    """
    tbl = policy.table_name or policy.data_domain
    return TIMESTAMP_COLUMNS.get(tbl, "created_at")


def run_retention_job(db: Session, policy_id: int, dry_run: bool = False) -> dict:
    """Execute a single retention purge job for a given policy.

    Steps:
      1. Load policy from DB
      2. Compute cutoff = NOW() - hot_days
      3. Count expired records
      4. If archive_enabled: export to JSON before deletion
      5. Delete expired records (or skip if dry_run)
      6. Create/update retention_jobs row

    Returns a summary dict.
    """
    policy = db.query(RetentionPolicy).filter(RetentionPolicy.id == policy_id).first()
    if not policy:
        return {"error": f"Policy {policy_id} not found"}

    if not policy.is_active:
        return {"skipped": "policy is not active", "policy_id": policy_id}

    tbl = policy.table_name or policy.data_domain
    ts_col = _get_timestamp_col(policy)
    retention_days = policy.hot_days  # total retention in primary store

    if not retention_days or retention_days <= 0:
        return {"skipped": "hot_days is 0 or negative, no retention limit", "policy_id": policy_id}

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    # Create job tracking row
    job = RetentionJob(
        policy_id=policy_id,
        started_at=datetime.now(timezone.utc),
        status="running",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        # 1. Count expired records
        count_sql = text(
            f"SELECT COUNT(*) FROM `{tbl}` WHERE `{ts_col}` < :cutoff"
        )
        result = db.execute(count_sql, {"cutoff": cutoff_str})
        count_row = result.fetchone()
        expired_count = count_row[0] if count_row else 0

        logger.info(
            "retention_job: table=%s, cutoff=%s, expired_count=%d, dry_run=%s",
            tbl, cutoff_str, expired_count, dry_run,
        )

        records_archived = 0
        records_purged = 0

        if expired_count == 0:
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            job.records_archived = 0
            job.records_purged = 0
            db.commit()
            return {
                "policy_id": policy_id,
                "table": tbl,
                "cutoff": cutoff_str,
                "expired_count": 0,
                "records_archived": 0,
                "records_purged": 0,
                "dry_run": dry_run,
                "status": "completed",
            }

        # 2. Archive if enabled
        if policy.archive_enabled and not dry_run:
            records_archived = _archive_records(db, tbl, ts_col, cutoff_str, policy)

        # 3. Purge expired records
        if not dry_run:
            purge_sql = text(
                f"DELETE FROM `{tbl}` WHERE `{ts_col}` < :cutoff"
            )
            db.execute(purge_sql, {"cutoff": cutoff_str})
            db.commit()
            records_purged = expired_count
            logger.info(
                "retention_job: purged %d records from %s (cutoff=%s)",
                records_purged, tbl, cutoff_str,
            )
        else:
            logger.info(
                "retention_job: dry run, would purge %d records from %s (cutoff=%s)",
                expired_count, tbl, cutoff_str,
            )

        job.status = "completed"
        job.completed_at = datetime.now(timezone.utc)
        job.records_archived = records_archived
        job.records_purged = records_purged if not dry_run else 0
        db.commit()

        return {
            "policy_id": policy_id,
            "table": tbl,
            "cutoff": cutoff_str,
            "expired_count": expired_count,
            "records_archived": records_archived,
            "records_purged": records_purged if not dry_run else 0,
            "dry_run": dry_run,
            "status": "completed",
        }

    except Exception as e:
        logger.exception("retention_job: failed for policy %d", policy_id)
        job.status = "failed"
        job.error_message = str(e)[:4000]
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        return {
            "policy_id": policy_id,
            "table": tbl,
            "status": "failed",
            "error": str(e),
        }


def _archive_records(
    db: Session,
    table_name: str,
    ts_col: str,
    cutoff_str: str,
    policy: RetentionPolicy,
) -> int:
    """Export expired records to a JSON file before purging.

    Writes to policy.archive_path (default: /var/logsoc/archive).
    Returns the number of records archived.
    """
    archive_dir = Path(policy.archive_path or "/var/logsoc/archive")
    archive_dir.mkdir(parents=True, exist_ok=True)

    # Fetch expired records for archiving
    select_sql = text(
        f"SELECT * FROM `{table_name}` WHERE `{ts_col}` < :cutoff"
    )
    result = db.execute(select_sql, {"cutoff": cutoff_str})
    columns = list(result.keys())
    rows = [dict(zip(columns, row)) for row in result.fetchall()]

    if not rows:
        return 0

    # Convert datetime objects to ISO strings for JSON serialization
    for row in rows:
        for key, value in row.items():
            if isinstance(value, datetime):
                row[key] = value.isoformat()

    # Write archive file
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_file = archive_dir / f"{table_name}_{timestamp}.json"

    with open(archive_file, "w", encoding="utf-8") as f:
        json.dump({
            "table": table_name,
            "policy_id": policy.id,
            "data_domain": policy.data_domain,
            "cutoff": cutoff_str,
            "archived_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(rows),
            "records": rows,
        }, f, indent=2, default=str)

    logger.info(
        "archived %d records from %s to %s",
        len(rows), table_name, archive_file,
    )
    return len(rows)


def run_all_enabled_policies(db: Session, dry_run: bool = False) -> list[dict]:
    """Run retention jobs for all enabled policies.

    Called by the daily cron scheduler.
    """
    policies = (
        db.query(RetentionPolicy)
        .filter(RetentionPolicy.is_active == True)
        .all()
    )

    results = []
    for policy in policies:
        # Only process policies that have a MariaDB table_name (skip ClickHouse-only)
        tbl = policy.table_name or policy.data_domain
        # siem_logs data_domain is ClickHouse; skip it (handled by retention/jobs.py)
        if policy.data_domain == "siem_logs" and (policy.table_name or "") in ("", "siem_logs"):
            # The siem_logs ClickHouse data is handled by the existing retention sidecar
            # Only process if table_name explicitly points to a MariaDB table
            continue
        try:
            result = run_retention_job(db, policy.id, dry_run=dry_run)
            results.append(result)
        except Exception as e:
            logger.exception("run_all_enabled_policies: failed for policy %d", policy.id)
            results.append({"policy_id": policy.id, "error": str(e)})

    return results


def detect_personal_data(db: Session) -> list[dict]:
    """Auto-detect PII columns from DB schema by naming convention.

    Scans all tables in the database for columns matching PII patterns
    (username, ip_address, email, hostname, mac_address).
    Returns a list of dicts suitable for insertion into personal_data_registry.
    Does NOT auto-insert — returns suggestions for the operator to review.
    """
    engine = db.get_bind()
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    suggestions = []
    for tbl in existing_tables:
        columns = inspector.get_columns(tbl)
        for col in columns:
            col_lower = col["name"].lower()
            for data_type, patterns in PII_PATTERNS.items():
                if col_lower in patterns:
                    # Check if already registered
                    existing = (
                        db.query(PersonalDataRegistry)
                        .filter(
                            PersonalDataRegistry.table_name == tbl,
                            PersonalDataRegistry.column_name == col["name"],
                        )
                        .first()
                    )
                    if not existing:
                        suggestions.append({
                            "table_name": tbl,
                            "column_name": col["name"],
                            "data_type": data_type,
                            "gdpr_article": "5(1)(e)",
                            "notes": f"Auto-detected as {data_type} by naming convention",
                        })

    return suggestions