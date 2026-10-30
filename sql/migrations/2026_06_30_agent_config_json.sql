-- Agent config_json column: stores per-agent configuration override
-- that the admin pushes from the UI. Stored as JSON text.
-- NULL means "use defaults / no override".

ALTER TABLE agents ADD COLUMN config_json LONGTEXT NULL DEFAULT NULL;

-- Add index for quick lookup (already covered by agent_id unique index).