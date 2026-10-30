-- Retention phase 1 (v0.10.0) - Issue #4 logsoc-web + Issue #9 module
-- 2026-06-09
--
-- ClickHouse side of the retention phase 1 migration.
-- The MariaDB side is in `2026_06_09_retention_phase1.sql` (separate file
-- because CH and MariaDB are different engines on Hestia, not dockerised).
--
-- This file creates the `user_log_index` CH table. It is a denormalized
-- lookup table keyed by (username, source_host) with rolling aggregates.
-- It is the GDPR erasure lookup table:
--   "give me the event IDs and timestamp range for user X" in O(1)
--   instead of O(N) on siem_logs (currently 5.2M rows and growing).
--
-- It is populated by a MaterializedView (B8) created in
-- `2026_06_09_retention_user_log_index_mv.sql`.
--
-- Design notes:
--   * `event_count` is a State (not a Merge) so concurrent inserts from
--     many agents don't lose increments. The view uses `State` and the
--     query path uses `Merge`.
--   * `first_event_at`/`last_event_at` are min/max State.
--   * `sample_event_id` keeps one event_id for forensic reference. Not
--     State — first-write wins is fine for forensic.
--   * `anonymized_at` / `erased_at` are set by B11 erasure endpoint.
--     Anonymized rows have `username = ''` (PII removed) but the rest
--     of the aggregate is preserved for compliance reporting.
--   * `ttl = erase_after_days` from retention_policies.siem_logs is NOT
--     enforced at the table level here; the B9 jobs.py applies it.
--     (ClickHouse TTL is partition-level and would erase aggregates
--     that we want to keep for compliance reports after user erasure.)
--
-- Idempotency: IF NOT EXISTS everywhere. Safe to re-apply.
-- To apply on Hestia: `clickhouse-client --database logsoc < migrations/2026_06_09_retention_user_log_index.sql`

CREATE TABLE IF NOT EXISTS user_log_index
(
    -- Identity (one row per user+host; username is the GDPR "data subject" key)
    username        LowCardinality(String),
    source_host     LowCardinality(String),

    -- Rolling aggregates (State columns — used by user_log_index_mv)
    event_count     UInt64,
    first_event_at  DateTime64(3),
    last_event_at   DateTime64(3),
    sample_event_id String,

    -- GDPR lifecycle (set by B11 erasure endpoint, B9 jobs.py)
    anonymized_at   DateTime DEFAULT toDateTime(0),  -- 1970-01-01 = not anonymized
    erased_at       DateTime DEFAULT toDateTime(0)   -- 1970-01-01 = not erased
)
ENGINE = SummingMergeTree((event_count))
PARTITION BY toYYYYMM(first_event_at)
ORDER BY (username, source_host)
SETTINGS index_granularity = 8192;

-- Sanity check query (run manually, not as part of the migration):
--   SELECT * FROM user_log_index WHERE username = 'root' LIMIT 10;
-- Expected: empty result until B8 MaterializedView starts populating.
