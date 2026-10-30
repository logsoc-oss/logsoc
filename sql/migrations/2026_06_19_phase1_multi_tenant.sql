-- Phase 1.4 — Multi-tenant preparation
-- Adds tenant_id column to key tables. Does NOT implement filtering
-- yet — just prepares the schema so we can add tenant isolation later.
-- All columns are nullable (NULL = legacy mono-tenant data).

CREATE TABLE IF NOT EXISTS tenants (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  slug VARCHAR(64) NOT NULL UNIQUE,
  plan VARCHAR(32) DEFAULT 'standard',
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME
);

-- Add tenant_id to key tables (nullable for backward compat)
ALTER TABLE users ADD COLUMN tenant_id INT NULL;
ALTER TABLE agents ADD COLUMN tenant_id INT NULL;
ALTER TABLE alerts ADD COLUMN tenant_id INT NULL;
ALTER TABLE cases ADD COLUMN tenant_id INT NULL;
ALTER TABLE risks ADD COLUMN tenant_id INT NULL;
ALTER TABLE compliance_controls ADD COLUMN tenant_id INT NULL;
ALTER TABLE gdpr_treatments ADD COLUMN tenant_id INT NULL;
ALTER TABLE nis2_classification ADD COLUMN tenant_id INT NULL;
ALTER TABLE iso_soa ADD COLUMN tenant_id INT NULL;
ALTER TABLE dora_incidents ADD COLUMN tenant_id INT NULL;
ALTER TABLE ai_systems ADD COLUMN tenant_id INT NULL;
ALTER TABLE crisis_events ADD COLUMN tenant_id INT NULL;
ALTER TABLE soar_playbooks ADD COLUMN tenant_id INT NULL;
ALTER TABLE ti_indicators ADD COLUMN tenant_id INT NULL;