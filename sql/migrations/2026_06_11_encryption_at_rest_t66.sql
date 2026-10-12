-- T66 / encryption_at_rest heartbeat (v0.13.0)
-- 2026-06-11
--
-- Contexte (logsoc-web#15):
-- Le champ AssetCompliance.encryption_at_rest existe dans schemas.py:805
-- et dans routers/assets.py:282-306 mais n'est jamais peuplé. L'agent
-- SOC-AGENT 3.10.x ne l'envoie pas dans son heartbeat.
--
-- Impact:
-- L'endpoint GET /api/v1/compliance/suggestions (B4) suggère l'encryption
-- at rest pour TOUS les assets qui matchent classification+data_category,
-- au lieu de suggérer seulement ceux qui ne l'ont PAS activé.
--
-- Plan:
-- 1. Ajouter colonne encryption_at_rest à asset_compliance
-- 2. SOC-AGENT v3.21+ détecte LUKS/eCryptfs/ZFS encrypted, envoie dans
--    le heartbeat (champ encryption_at_rest, encryption_detection_method)
-- 3. Backend update la valeur depuis le heartbeat (route /agents/heartbeat)
-- 4. /compliance/suggestions filtre (encryption_at_rest IS NULL OR false)
--    pour ne suggérer que les assets non chiffrés
--
-- Idempotence: IF NOT EXISTS / IF EXISTS pour permettre replay.

-- ── Add column to asset_compliance ──────────────────────────────────────
SET @col_exists := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'asset_compliance'
      AND COLUMN_NAME = 'encryption_at_rest'
);
SET @sql := IF(@col_exists = 0,
    'ALTER TABLE asset_compliance
     ADD COLUMN encryption_at_rest BOOLEAN NULL DEFAULT NULL
     AFTER risk_score,
     ADD COLUMN encryption_detection_method VARCHAR(32) NULL DEFAULT NULL
     AFTER encryption_at_rest,
     ADD COLUMN encryption_detected_at DATETIME NULL DEFAULT NULL
     AFTER encryption_detection_method',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
