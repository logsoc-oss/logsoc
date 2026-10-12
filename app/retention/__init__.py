"""retention/__init__.py — Retention module v0.10.0 (issue #4 + #9).

Public API:
    from app.retention import policy, registry, anonymize, erasure, jobs

The module is intentionally self-contained: it depends only on
app.database (MariaDB session), app.clickhouse_client (CH session),
and app.models (for the retention_policies ORM). No FastAPI imports
here — endpoint wiring is in app/routers/gdpr.py (separate ticket B11).

Components:
    policy    : RetentionPolicy dataclass + DB loader
    registry  : Process-local cache of policies, refresh on SIGHUP/demand
    anonymize : Deterministic PII rewriter (sha256 with system salt)
    erasure   : High-level "forget this user" orchestrator
    jobs      : Callable batch jobs (daily sweep, anonymize, erase)
                Wired to a Docker sidecar `logsoc-retention` in B10.

Pattern: NO module-level asyncio loops here. jobs.run_daily() is a
blocking function. The Docker sidecar (B10) calls it on a cron schedule.
This keeps the API process responsive and avoids the "background task
crashes silently" footgun.

Configuration:
    All runtime parameters come from the `retention_policies` MariaDB
    table seeded by migration 2026_06_09_retention_phase1.sql. The
    module reads them at job start. No in-process config override.
    To change policy: UPDATE retention_policies; next job picks it up.
"""
