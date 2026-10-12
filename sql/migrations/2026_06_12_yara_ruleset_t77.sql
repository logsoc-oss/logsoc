-- T77 / YARA Ruleset Central Push (v0.27.0-t77)
-- 2026-06-12
--
-- Architecture:
--   - L'agent pull son ruleset YARA au boot + toutes les 5min (même
--     chemin que le pull de la policy T64)
--   - Le ruleset est stocké centralement (1 row global), éditable via
--     UI admin SOC-WEB ou via PUT /api/v1/yara/ruleset
--   - Le GET est HMAC-signed (comme /agent-config/policy), le PUT est
--     admin-authed
--   - L'agent compile en local sur réception, atomic-swap du YR_COMPILER
--     global (3s downtime vs 30s+ si compile en prod)
--
-- Champs exposés en T77 :
--   ruleset_blob : LONGBLOB, binaire YARA compilé (format .yarac)
--                  ~3MB pour 7761 règles (v3.19.0 actif Hestia)
--   source_count : INT, nombre de règles source (pour stats UI)
--   bytes_size   : INT, taille du blob (pour display UI)
--   sha256       : CHAR(64), hash du blob (vérification intégrité)
--   compiled_at  : DATETIME, quand le binaire a été compilé central-side
--   comment      : VARCHAR(255), changelog human-readable (optionnel)
--   updated_at   : DATETIME, dernière mutation row
--   updated_by   : BIGINT, FK users.id (admin qui a push)
--
-- Différent de T64 :
--   - LONGBLOB (vs VARCHAR/JSON) parce qu'on stocke du binaire
--   - sha256 + bytes_size pour intégrité + UI
--   - source_count pour stats (combien de règles actives)
--   - Pas de "per-agent override" en T77 (le ruleset est global par
--     design — toutes les machines ont le même set de règles)

-- ── Table yara_ruleset (1 row global, single-row pattern) ───────────────
-- Pattern single-row : CHECK (id=1) garantit qu'il n'y a QU'UNE seule row
-- dans la table. Toute tentative INSERT/MERGE force l'UPDATE sur id=1.
-- Réutilise le pattern de agent_policy (T64) — voir commentaires là-bas
-- pour la rationale complète.
--
-- PITFALL MariaDB LONGBLOB :
--   - max 4GB (largement assez pour 100k+ règles)
--   - stocké en-dehors de la page InnoDB si > 768 bytes (TOAST-like)
--   - envoie via HTTP base64-encoded (gain ~33%) ou raw binaire
--   - On stocke RAW binaire (pas de base64 en DB) — le backend encode
--     en base64 pour le transport HTTP seulement
CREATE TABLE IF NOT EXISTS yara_ruleset (
    id TINYINT NOT NULL DEFAULT 1,
    ruleset_blob LONGBLOB NOT NULL,
    source_count INT NOT NULL DEFAULT 0,
    bytes_size INT NOT NULL DEFAULT 0,
    sha256 CHAR(64) NOT NULL DEFAULT '',
    compiled_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    comment VARCHAR(255) DEFAULT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                                         ON UPDATE CURRENT_TIMESTAMP,
    updated_by BIGINT,                              -- FK vers users.id (admin)
    PRIMARY KEY (id),
    CONSTRAINT chk_yara_ruleset_singlerow CHECK (id = 1),
    CONSTRAINT chk_yara_ruleset_sha256_len
        CHECK (CHAR_LENGTH(sha256) = 64)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Seed : placeholder vide (blob de 0 octets) ─────────────────────────
-- Le vrai ruleset sera pusshé par l'admin via PUT /api/v1/yara/ruleset
-- au premier deploy. On met un placeholder pour que la row existe et
-- que les agents ne fail pas au pull initial (404 vs 200+empty).
--
-- On ne peut PAS pré-compiler le ruleset dans la migration parce que :
--   (1) le format .yarac dépend de la version libyara du serveur de
--       migration, pas forcément identique à celle des agents cibles
--   (2) le binaire fait 3MB, alourdit la migration
--   (3) l'admin doit explicitement décider QUEL ruleset push
--
-- PITFALL CHECK constraint chk_yara_ruleset_sha256_len : exige
-- exactement 64 chars. Le seed doit donc mettre 64 chars (zéros
-- = "pas de vrai sha"). Le code backend sait interpréter
-- bytes_size=0 + sha256=0000... comme "placeholder row" (log
-- warning, retourne 200+empty au lieu de planter).
INSERT INTO yara_ruleset (id, ruleset_blob, source_count, bytes_size, sha256, comment, updated_by)
VALUES (1, '', 0, 0, REPEAT('0', 64), 'placeholder — push real ruleset via UI', NULL)
ON DUPLICATE KEY UPDATE
    -- Idempotent : ne pas écraser un ruleset déjà pusshé
    bytes_size = bytes_size,
    updated_at = updated_at;

-- ── Trigger : empêcher DELETE (single-row sacred) ───────────────────────
DROP TRIGGER IF EXISTS trg_yara_ruleset_no_delete;
DELIMITER //
CREATE TRIGGER trg_yara_ruleset_no_delete
BEFORE DELETE ON yara_ruleset
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'yara_ruleset is single-row, DELETE forbidden';
END//
DELIMITER ;
