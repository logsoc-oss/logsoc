-- T28 / Agent Actions Queue (v0.28.0-t28)
-- 2026-06-15
--
-- Architecture:
--   L'agent est un **capteur pur**, jamais un acteur. Toute action de défense
--   (kill, block_ip, quarantine, rmmod, fim_add) est :
--     1. proposée par l'agent sous forme de suggestion dans un event
--     2. stockée dans `agent_actions` (status=pending) par l'UI / API
--     3. récupérée par l'agent via le heartbeat (one-shot, HMAC-signed)
--     4. exécutée localement (kill via syscall, iptables via nft, etc.)
--     5. le résultat est shippé comme event action_executed
--
-- Le backend garde la trace. L'humain approuve dans le dashboard.
-- L'agent n'ouvre AUCUN port — le canal est l'heartbeat sortant (déjà HMAC).
--
-- This migration is idempotent (uses information_schema guards).

-- ── Table agent_actions ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_actions (
    id              VARCHAR(36)    PRIMARY KEY,                -- UUID
    agent_id        VARCHAR(36)    NOT NULL,
    action_type     VARCHAR(32)    NOT NULL,                   -- kill_pid, block_ip, quarantine_file, rmmod, fim_add
    payload_json    JSON           NOT NULL,                   -- action-specific fields
    target_summary  VARCHAR(255)   NOT NULL,                   -- human-readable: "kill pid 2347 (apache2)"
    reason          VARCHAR(512)   NOT NULL,                   -- "rootkit install by uid=0 non-modprobe"
    confidence      DECIMAL(3,2)   NOT NULL,                   -- 0.00..1.00 from agent
    dry_run         TINYINT(1)     NOT NULL DEFAULT 1,         -- 1=dry, 0=execute
    status          ENUM('pending','delivered','succeeded','failed','cancelled')
                    NOT NULL DEFAULT 'pending',
    proposed_by     VARCHAR(64)    NOT NULL DEFAULT 'agent',   -- 'agent' or 'user:<id>'
    approved_by     INTEGER,                                   -- user.id who approved
    approved_at     DATETIME,
    delivered_at    DATETIME,                                  -- when agent acknowledged via heartbeat
    executed_at     DATETIME,                                  -- when agent reported success/fail
    result_message  VARCHAR(512),                              -- "killed (SIGKILL sent)" or "EPERM"
    created_at      DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_agent_status     (agent_id, status),
    INDEX idx_status_created   (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
