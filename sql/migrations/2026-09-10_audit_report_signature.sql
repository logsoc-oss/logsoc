-- Migration: rapport d'audit signé (10/09/2026)
-- practice_audits: PDF rapport + signature RSSI + notification direction (info, sans validation)
ALTER TABLE practice_audits
  ADD COLUMN report_path VARCHAR(512) NULL,
  ADD COLUMN report_signed_path VARCHAR(512) NULL,
  ADD COLUMN report_signed BOOLEAN NOT NULL DEFAULT 0,
  ADD COLUMN report_signed_by VARCHAR(128) NULL,
  ADD COLUMN report_signed_at DATETIME NULL,
  ADD COLUMN report_sha256 VARCHAR(128) NULL,
  ADD COLUMN direction_notified_at DATETIME NULL;