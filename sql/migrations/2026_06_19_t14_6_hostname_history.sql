-- T14.6 (2026-06-19): hostname rename tracking
-- Adds source_host_history (JSON array of old hostnames) and
-- hostname_updated_at (timestamp of last rename) to the agents table.
-- The agent sends hostname on every heartbeat; the backend compares
-- it with the stored value and appends the old one to history if
-- they differ.
-- See doc/developer-backend.md § 7. Identité d'agent et renames d'hôte.

ALTER TABLE agents ADD COLUMN source_host_history LONGTEXT NULL DEFAULT '[]';
ALTER TABLE agents ADD COLUMN hostname_updated_at DATETIME NULL;