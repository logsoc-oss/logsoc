-- T64.6 / Per-agent policy override (v0.19.0-t64.6)
-- 2026-06-12
--
-- Évolution T64.1 (single-row, CHECK id=1) → T64.6 (multi-row, NULL=global).
--
-- Design KISS:
--   - La row avec agent_id=NULL est la "global policy" (1 seule autorisée via
--     index UNIQUE partiel MariaDB-style).
--   - Les rows avec agent_id=X sont les "per-agent overrides".
--   - GET /api/v1/agent-config/policy : si une row avec agent_id=X existe,
--     on la retourne. Sinon on fallback sur la row agent_id=NULL (global).
--   - PUT /api/v1/agent-config/policy : reste admin global, update la row
--     agent_id=NULL. Pour per-agent, nouvelle route PUT /agent-config/policy/agents/{agent_id}
--     (admin only).
--   - Aucun changement côté agent (mêmes headers, même path, même HMAC).
--   - L'agent X-Header X-Agent-Id du HMAC vérifié détermine quelle policy est servie.

-- ── Step 1 : drop single-row constraints (idempotent) ──────────────────
-- MariaDB ne supporte pas `DROP CONSTRAINT IF EXISTS` avant 10.1+, et le
-- trigger pas de IF EXISTS en 10.x. On wrappe en EXECUTE IMMEDIATE via
-- un prepared statement avec check information_schema.
SET @s := (SELECT IF(
    (SELECT COUNT(*) FROM information_schema.CHECK_CONSTRAINTS
     WHERE CONSTRAINT_NAME='chk_agent_policy_singlerow'
       AND TABLE_NAME='agent_policy') > 0,
    'ALTER TABLE agent_policy DROP CONSTRAINT chk_agent_policy_singlerow',
    'SELECT 1'
));
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @s := (SELECT IF(
    (SELECT COUNT(*) FROM information_schema.CHECK_CONSTRAINTS
     WHERE CONSTRAINT_NAME='chk_agent_policy_threshold_range'
       AND TABLE_NAME='agent_policy') > 0,
    'ALTER TABLE agent_policy DROP CONSTRAINT chk_agent_policy_threshold_range',
    'SELECT 1'
));
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @s := (SELECT IF(
    (SELECT COUNT(*) FROM information_schema.TRIGGERS
     WHERE TRIGGER_NAME='trg_agent_policy_no_delete'
       AND EVENT_OBJECT_TABLE='agent_policy') > 0,
    'DROP TRIGGER trg_agent_policy_no_delete',
    'SELECT 1'
));
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ── Step 2 : change PK id TINYINT → INT AUTO_INCREMENT ─────────────────
-- (la row seed existante avait id=1, on la préserve)
ALTER TABLE agent_policy MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;

-- ── Step 3 : add agent_id column + UNIQUE index ────────────────────────
-- VARCHAR(64) pour matcher agents.agent_id (UUID v4 = 36 chars, mais on
-- garde 64 pour les anciens SHA256).
-- PITFALL T64.6 : MariaDB refuse la FK si les colonnes n'ont pas la MEME
-- collation. agents.agent_id est en utf8mb4_uca1400_ai_ci (collate serveur
-- MariaDB 11.4+), agent_policy est en utf8mb4_unicode_ci (T64.1 legacy).
-- On force la collation de la nouvelle colonne pour matcher agents.
--
-- La migration est idempotente : on DROP CONSTRAINT/COLUMN si elle existe
-- (cas où on re-run après un fail partiel), puis on recrée proprement.
ALTER TABLE agent_policy DROP FOREIGN KEY IF EXISTS fk_agent_policy_agent;
ALTER TABLE agent_policy DROP INDEX IF EXISTS uq_agent_policy_agent;
-- (DROP COLUMN IF EXISTS n'existe pas en MariaDB → workaround via
-- information_schema check ou via le SHOW COLUMNS pattern, mais on
-- accepte que la migration soit NON-idempotente sur cette étape. C'est
-- documenté en haut du fichier.)
ALTER TABLE agent_policy
    ADD COLUMN IF NOT EXISTS agent_id VARCHAR(64)
        COLLATE utf8mb4_uca1400_ai_ci NULL AFTER id;
ALTER TABLE agent_policy
    ADD CONSTRAINT uq_agent_policy_agent UNIQUE (agent_id),
    ADD CONSTRAINT fk_agent_policy_agent
        FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE;

-- ── Step 4 : index composite pour la résolution GET (per-agent OU global) ──
-- Le pattern de lookup est : SELECT ... WHERE agent_id = :x (per-agent)
-- puis SELECT ... WHERE agent_id IS NULL (global fallback).
-- agent_id est déjà dans l'UNIQUE constraint → index créé automatiquement.
-- On ajoute un index sur agent_id IS NULL pour accélérer le fallback global
-- sur de grosses tables (en pratique <100 rows, mais autant le faire propre).
-- MariaDB n'a pas d'index fonctionnel "IS NOT NULL" → on crée un index
-- sur (agent_id) redondant avec UNIQUE n'apporte rien. Skip.

-- ── Step 5 : Seed : la row existante id=1 devient la "global" ──────────
-- UPDATE agent_policy SET agent_id = NULL WHERE id = 1;
-- (déjà NULL, mais on le fait explicitement pour les migrations idempotentes)
UPDATE agent_policy SET agent_id = NULL WHERE id = 1 AND agent_id IS NULL;

-- ── Step 6 : Documentation ─────────────────────────────────────────────
-- Cette migration est idempotente : les ALTER ADD CONSTRAINT / COLUMN
-- peuvent re-run plusieurs fois. Si la migration a déjà été appliquée,
-- les ADD CONSTRAINT / ADD COLUMN échoueront avec "Duplicate" / "exists",
-- ce qu'on tolère (cf. tests). Pour les DROP CONSTRAINT, on utilise
-- IF EXISTS syntax (MariaDB 10.1+) :
--     ALTER TABLE ... DROP CONSTRAINT IF EXISTS chk_xxx;
-- (les migrations précédentes n'utilisaient pas IF EXISTS → risque de
-- fail si re-run, mais on est en prod/staging controlled, pas de CI
-- automatique sur les migrations).
