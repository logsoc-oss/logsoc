-- T67 (logsoc-web#18, v0.16.0-t67) : split `gdpr_audit` de
-- `compliance_audit`. Clôture du TODO `app/routers/gdpr.py:84`
-- (ouvert depuis B11).
--
-- Les érasures RGPD ont maintenant leur propre table avec rétention
-- indépendante (10 ans par RGPD art. 5(2)) et un schéma adapté
-- (erasure_id, dry_run, source_hosts, counters).
--
-- Cette migration est idempotente : rejouable sans erreur.

-- ── 1. CREATE TABLE gdpr_audit ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gdpr_audit (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    -- UUID v4 retourné par /gdpr/erasure. NULL pour les rows
    -- backfillées pré-T67 (l'ancien schéma ne stockait pas l'UUID
    -- dans tous les cas).
    erasure_id VARCHAR(36) NULL,
    -- Qui a déclenché (FK users.id). NOT NULL pour les nouvelles
    -- erasures, NULL pour les backfill si l'utilisateur a été supprimé.
    user_id INT NULL,
    -- Cible de l'oubli (le user oublié). Toujours rempli.
    target_username VARCHAR(64) NOT NULL,
    -- Raison métier saisie par le DPO ("user requested account deletion"
    -- free text, search-friendly).
    reason TEXT NULL,
    -- true = dry-run (pas de modification), false = real erasure.
    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
    -- Timing précis pour audit (deux champs car on calcule duration en Python).
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    -- Counters retournés au DPO.
    siem_logs_anonymized INT NOT NULL DEFAULT 0,
    siem_logs_deleted INT NOT NULL DEFAULT 0,
    user_log_index_updated INT NOT NULL DEFAULT 0,
    -- Hosts touchés et erreurs per-host (stockés en JSON pour
    -- flexibilité d'évolution du schéma).
    source_hosts JSON NULL,
    errors JSON NULL,
    -- Server timestamp (toujours set, default current_timestamp).
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Index : queries typiques = "toutes les erasures des N derniers
    -- jours" (idx_created_at), "toutes les erasures d'un user précis"
    -- (idx_target_username), "retrouver un erasure précis par UUID"
    -- (idx_erasure_id).
    INDEX idx_created_at (created_at),
    INDEX idx_target_username (target_username),
    INDEX idx_erasure_id (erasure_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 2. Backfill depuis compliance_audit ────────────────────────────────────
-- Les erasures historiques ont event_type='delete' et old_value contient
-- {"username": "...", "erasure_id": "..."} (cf app/routers/gdpr.py:148
-- pre-T67). On les migre vers la nouvelle table.
--
-- En pratique, 0 row à migrer : le code T64 swallowait l'erreur du
-- NOT NULL sur asset_compliance_id, donc aucune row d'event_type='delete'
-- n'a jamais été persistée. On garde le backfill par défense en
-- profondeur (idempotence + couverture si une version non-swallowée
-- a existé à un moment).
--
-- Counters (siem_logs_anonymized, etc.) = 0 pour les rows backfillées
-- car l'ancien schéma ne les stockait pas.
--
-- Note compliance_audit : la colonne est `timestamp` (pas created_at).
INSERT INTO gdpr_audit (
    erasure_id, user_id, target_username, reason, dry_run,
    started_at, finished_at,
    siem_logs_anonymized, siem_logs_deleted, user_log_index_updated,
    source_hosts, errors, created_at
)
SELECT
    -- old_value est du JSON, on extrait les champs avec JSON_EXTRACT
    JSON_UNQUOTE(JSON_EXTRACT(ca.old_value, '$.erasure_id')) AS erasure_id,
    ca.user_id AS user_id,
    JSON_UNQUOTE(JSON_EXTRACT(ca.old_value, '$.username')) AS target_username,
    ca.note AS reason,
    FALSE AS dry_run,  -- les anciennes erasures étaient toujours real
    ca.`timestamp` AS started_at,
    ca.`timestamp` AS finished_at,  -- pas de timing précis dans l'ancien schéma
    0 AS siem_logs_anonymized,
    0 AS siem_logs_deleted,
    0 AS user_log_index_updated,
    JSON_ARRAY() AS source_hosts,
    JSON_ARRAY() AS errors,
    ca.`timestamp` AS created_at
FROM compliance_audit ca
WHERE ca.event_type = 'delete'
  AND ca.old_value IS NOT NULL
  AND JSON_EXTRACT(ca.old_value, '$.username') IS NOT NULL
  -- Anti-double-backfill : skip si on a déjà migré cet erasure_id
  -- (le NOT EXISTS protège contre le rejeu de la migration).
  AND NOT EXISTS (
      SELECT 1 FROM gdpr_audit g
      WHERE g.erasure_id = JSON_UNQUOTE(JSON_EXTRACT(ca.old_value, '$.erasure_id'))
        AND g.erasure_id IS NOT NULL
  );
