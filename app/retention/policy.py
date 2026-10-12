"""retention/policy.py — Retention policy model + DB loader.

A `RetentionPolicy` is a per-data-domain configuration (e.g. siem_logs
keeps raw for 90d, then anonymizes PII, then erases after 2y).

The DB schema is in `sql/migrations/2026_06_09_retention_phase1.sql`:
    CREATE TABLE retention_policies (
        id, data_domain, hot_days, warm_days, cold_days,
        anonymize_after_days, erase_after_days, notes, ...
    )

This module is the SINGLE source of truth for the Python-side
interpretation of those columns. The MariaDB ORM lives in
app.models.RetentionPolicy; this file is a *value object* layer
that decouples job logic from SQLAlchemy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from app.models import RetentionPolicy as RetentionPolicyORM

logger = logging.getLogger("logsoc.retention.policy")


@dataclass(frozen=True)
class RetentionPolicy:
    """Immutable policy value object.

    `data_domain` is the lookup key (e.g. 'siem_logs', 'access_logs').
    Days are ints; `None` means "no action at this stage".

    `policy_hash` is a quick fingerprint used by the registry to detect
    when a policy was changed in the DB without reading the full row.
    """

    data_domain: str
    hot_days: int
    warm_days: int
    cold_days: int
    anonymize_after_days: Optional[int]
    erase_after_days: Optional[int]
    notes: str
    policy_hash: str

    def is_anonymization_enabled(self) -> bool:
        return self.anonymize_after_days is not None and self.anonymize_after_days > 0

    def is_erasure_enabled(self) -> bool:
        return self.erase_after_days is not None and self.erase_after_days > 0

    def __str__(self) -> str:
        return (
            f"RetentionPolicy({self.data_domain}: "
            f"hot={self.hot_days}d, warm={self.warm_days}d, cold={self.cold_days}d, "
            f"anonymize_after={self.anonymize_after_days}d, "
            f"erase_after={self.erase_after_days}d)"
        )


def _compute_hash(orm_row: RetentionPolicyORM) -> str:
    """Quick fingerprint for cache invalidation.

    Hashes the policy fields, not the row id or updated_at, so two
    identical policies on different rows produce the same hash
    (defensive against accidental duplication).
    """
    import hashlib
    raw = "|".join(
        str(x) for x in (
            orm_row.data_domain,
            orm_row.hot_days,
            orm_row.warm_days,
            orm_row.cold_days,
            orm_row.anonymize_after_days or "",
            orm_row.erase_after_days or "",
        )
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def from_orm(orm_row: RetentionPolicyORM) -> RetentionPolicy:
    """Convert SQLAlchemy ORM row to immutable value object."""
    return RetentionPolicy(
        data_domain=orm_row.data_domain,
        hot_days=orm_row.hot_days,
        warm_days=orm_row.warm_days,
        cold_days=orm_row.cold_days,
        anonymize_after_days=orm_row.anonymize_after_days,
        erase_after_days=orm_row.erase_after_days,
        notes=orm_row.notes or "",
        policy_hash=_compute_hash(orm_row),
    )


def load_all(db: Session) -> list[RetentionPolicy]:
    """Load all retention policies from MariaDB.

    Used by the registry to build the in-memory cache. Returns an
    empty list if the table is empty (logs a warning — operator should
    have run the seed migration).
    """
    rows = db.query(RetentionPolicyORM).all()
    policies = [from_orm(r) for r in rows]
    if not policies:
        logger.warning(
            "retention_policies table is empty. "
            "Did you apply migration 2026_06_09_retention_phase1.sql? "
            "Anonymization/erasure jobs will be no-ops until policies exist."
        )
    return policies


def load_one(db: Session, data_domain: str) -> Optional[RetentionPolicy]:
    """Load a single policy by data_domain. Returns None if not found."""
    row = db.query(RetentionPolicyORM).filter_by(data_domain=data_domain).first()
    return from_orm(row) if row else None
