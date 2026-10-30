-- Backfill query for user_log_index (issue #4, v0.10.0)
-- Run ONCE after applying 2026_06_09_retention_user_log_index_mv.sql
-- to populate the index from existing 5.2M+ siem_logs rows.
--
-- This is NOT a migration - it's a one-shot backfill that the
-- operator runs manually. The MaterializedView in the migration
-- only sees NEW inserts; this query pre-populates from the past.

INSERT INTO user_log_index
SELECT
    username,
    source_host,
    count() AS event_count,
    min(received_at) AS first_event_at,
    max(received_at) AS last_event_at,
    anyIf(event_id, event_id != '') AS sample_event_id,
    toDateTime(0) AS anonymized_at,
    toDateTime(0) AS erased_at
FROM siem_logs
WHERE source_host != ''
GROUP BY username, source_host;
