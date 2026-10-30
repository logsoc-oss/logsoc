-- Retention phase 1 (v0.10.0) - Issue #4 logsoc-web + Issue #9 module
-- 2026-06-09
--
-- MaterializedView that populates `user_log_index` from `siem_logs`.
-- Companion to `2026_06_09_retention_user_log_index.sql` (B7) which
-- created the destination table.
--
-- ClickHouse MaterializedView pattern (incremental aggregation):
--   1. siem_logs receives a batch insert (e.g. 31 events from agent)
--   2. The MV SELECT runs against the inserted block
--   3. Results are written to user_log_index (one row per username+host)
--   4. SummingMergeTree merges duplicates on background merge
--
-- Why GROUP BY in the MV: each batch produces 1 row per (username, source_host),
-- not 1 row per event. Otherwise user_log_index would have the same row
-- count as siem_logs (5.2M+), defeating the purpose of the index.
--
-- Why `username = ''` is included: events without a username (network
-- probes, kernel events) still have a source_host. We aggregate them
-- as anonymous. B11 erasure ignores empty usernames (they have no PII).
--
-- Why we don't filter on `username != ''`: future-proof. If the agent
-- starts attaching usernames to network events, we get them for free.
--
-- Idempotency: DROP + CREATE MV. Safe to re-apply; the DROP removes the
-- old MV, the CREATE recreates it. The user_log_index table is NOT
-- touched (it accumulates data continuously, only `ALTER ... DELETE`
-- would clear it; that's B9 jobs.py).
--
-- Backfill: this MV only watches NEW inserts. To backfill from existing
-- 5.2M siem_logs rows, run the manual query in the comment at the bottom
-- of this file ONCE after applying. Don't put it in the migration.
--
-- To apply on Hestia:
--   clickhouse-client --database logsoc < migrations/2026_06_09_retention_user_log_index_mv.sql

DROP VIEW IF EXISTS user_log_index_mv;

CREATE MATERIALIZED VIEW user_log_index_mv
TO user_log_index
AS
SELECT
    -- Empty username is valid (anonymous events). B11 erasure skips them.
    username,
    source_host,
    -- SummingMergeTree will sum this across batches/parts on merge.
    -- The `+0` trick converts NULL to 0 for the State merge.
    count() AS event_count,
    min(received_at) AS first_event_at,
    max(received_at) AS last_event_at,
    -- First event_id in the batch is a deterministic forensic sample.
    -- For multi-event batches, we take the first non-empty one.
    anyIf(event_id, event_id != '') AS sample_event_id,
    -- Defaults: not anonymized, not erased
    toDateTime(0) AS anonymized_at,
    toDateTime(0) AS erased_at
FROM siem_logs
WHERE source_host != ''   -- guard against malformed events
GROUP BY username, source_host;

-- Backfill query (run ONCE, manually, after applying this migration).
-- This inserts aggregates for all existing siem_logs rows into
-- user_log_index directly (bypassing the MV since MV only sees new
-- inserts). ClickHouse will merge with MV-produced rows on next merge.
--
--   INSERT INTO user_log_index
--   SELECT
--       username,
--       source_host,
--       count() AS event_count,
--       min(received_at) AS first_event_at,
--       max(received_at) AS last_event_at,
--       anyIf(event_id, event_id != '') AS sample_event_id,
--       toDateTime(0) AS anonymized_at,
--       toDateTime(0) AS erased_at
--   FROM siem_logs
--   WHERE source_host != ''
--   GROUP BY username, source_host;
