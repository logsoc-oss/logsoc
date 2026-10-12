-- T64 / Agent Policy Push (v3.20.0)
-- 2026-06-11
--
-- Architecture:
--   - L'agent pull sa policy au boot + toutes les 5min (thread background,
--     même chemin que le pull des YARA rules)
--   - Le policy est stockée centralement (1 row global), éditable via UI admin
--     SOC-WEB ou via PUT /api/v1/agent-config/policy
--   - Le GET est HMAC-signed (comme /yara/active), le PUT est admin-authed
--   - Policy > local config : si la policy pull OK, elle écrase la conf locale ;
--     si la pull fail, fallback sur la conf locale (robustesse réseau)
--
-- Champs exposés en T64 (minimal+ui) :
--   metrics_bind_address    : str, IP d'écoute du MetricsServer
--                             (défaut "127.0.0.1", 0.0.0.0 pour exposition LAN)
--   fim_watch_paths         : JSON array de paths absolus à surveiller par
--                             FanotifyCollector (défaut : 5 fichiers Hestia)
--   ship_heuristic_threshold: int 0-10, score minimum pour ship un fichier
--                             (défaut 3 ; 0 = ship tout ce qui match une YARA rule)
--
-- Évolutions futures (FULL scope, post T64) :
--   - Per-agent override (colonne agent_id NULL = global)
--   - Push SSE/WebSocket instantané (vs poll 5min)
--   - Audit log des changements de policy
--   - Autres sections : yara.scan_timeout_ms, fanotify.events, fim.max_file_size

-- ── Table agent_policy (1 row global, single-row pattern) ───────────────
-- Pattern single-row : CHECK (id=1) garantit qu'il n'y a QU'UNE seule row
-- dans la table. Toute tentative INSERT/MERGE force l'UPDATE sur id=1.
-- Plus simple qu'une table key-value, plus SQL-native qu'un fichier YAML.
CREATE TABLE IF NOT EXISTS agent_policy (
    id TINYINT NOT NULL DEFAULT 1,
    metrics_bind_address VARCHAR(64) NOT NULL DEFAULT '127.0.0.1',
    fim_watch_paths JSON NOT NULL,                  -- JSON array of strings
    ship_heuristic_threshold TINYINT UNSIGNED NOT NULL DEFAULT 3,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                                         ON UPDATE CURRENT_TIMESTAMP,
    updated_by BIGINT,                              -- FK vers users.id (admin)
    PRIMARY KEY (id),
    CONSTRAINT chk_agent_policy_singlerow CHECK (id = 1),
    CONSTRAINT chk_agent_policy_threshold_range
        CHECK (ship_heuristic_threshold BETWEEN 0 AND 10)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Seed : default policy matchant l'état Hestia v3.19.0 actuel ─────────
-- C'est crucial : 0 régression à l'upgrade. Tous les agents déployés avant
-- T64 continueront à fonctionner exactement comme avant.
-- 5 watch_paths = ceux actuellement dans /etc/logsoc-agent/config.json
--   (sshd_config, passwd, shadow, sudoers, crontab)
-- bind 127.0.0.1, threshold 3 = T62 settings
INSERT INTO agent_policy (id, metrics_bind_address, fim_watch_paths,
                          ship_heuristic_threshold, updated_by)
VALUES (
    1,
    '127.0.0.1',
    JSON_ARRAY(
        '/etc/ssh/sshd_config',
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/crontab'
    ),
    3,
    NULL                                            -- system default
)
ON DUPLICATE KEY UPDATE
    -- Si une row existe déjà (dev/staging), on update SEULEMENT les champs
    -- NULL/empty (sécurité anti-écrasement accidentel via re-migration)
    metrics_bind_address = COALESCE(NULLIF(metrics_bind_address, '127.0.0.1'),
                                     VALUES(metrics_bind_address)),
    fim_watch_paths = COALESCE(
        NULLIF(JSON_LENGTH(fim_watch_paths), 5),    -- ne pas écraser si déjà 5+
        VALUES(fim_watch_paths)
    ),
    ship_heuristic_threshold = COALESCE(
        NULLIF(ship_heuristic_threshold, 3),       -- ne pas écraser si déjà ≠ 3
        VALUES(ship_heuristic_threshold)
    );

-- ── Trigger : empêcher DELETE (single-row sacred) ───────────────────────
-- Toute tentative de DELETE doit être bloquée. Seuls UPDATE autorisés.
DROP TRIGGER IF EXISTS trg_agent_policy_no_delete;
DELIMITER //
CREATE TRIGGER trg_agent_policy_no_delete
BEFORE DELETE ON agent_policy
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'agent_policy is single-row, DELETE forbidden';
END//
DELIMITER ;
