-- T58 / YARA content fetch from agent → central (v3.14.0)
-- 2026-06-10
--
-- Architecture (validée par Nova RSSI + Codeur, 2026-06-10 issue #3):
--   - L'agent capture l'event FIM (inode + filename + fd) — déjà en v3.13
--   - Sur heuristique (extension suspecte, taille anormale, chemin sensible)
--     l'agent push le CONTENU au central via POST /api/v1/yara/scan
--   - Le central (Hestia) scanne avec libyara + charge les rules depuis
--     yara_rules (existante), puis INSERT dans yara_scan_results (existante)
--   - 0 régression sur l'agent (qui reste un capteur, pas un analyste)
--   - Pas de bypass AppArmor (l'agent ne scanne pas)
--
-- Tables existantes réutilisées:
--   yara_rules        : registre des rules (déjà là, schéma AppArmor+scan_flags)
--   yara_scan_results : table des matches (déjà là, schéma post-yara_result)
--
-- Cette migration ajoute:
--   1. yara_match_samples  : extrait du contenu (premiers 1KB) pour analyse
--   2. yara_agent_stats    : compteurs par agent (débit scans + drops)
--   3. yara_scan_queue     : queue des scans pending (worker background)

-- ── 1. Extrait du contenu (preview 1KB) ─────────────────────────────────
-- Pour analyse forensic rapide sans re-pull le contenu original.
-- Le contenu complet transite via yara_scan_queue (purgé après 24h).
CREATE TABLE IF NOT EXISTS yara_match_samples (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scan_result_id BIGINT NOT NULL,           -- FK vers yara_scan_results.id
    content_preview VARCHAR(2048) NOT NULL,  -- premiers 1KB (tronqué UTF-8)
    is_truncated TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_yara_samples_result (scan_result_id),
    INDEX idx_yara_samples_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Note: pas de FK sur yara_scan_results.id car cette table est gérée par
-- un autre module (yara.py). On s'appuie sur l'application pour maintenir
-- la cohérence (et l'absence de cascade pour ne pas casser ce module).

-- ── 2. Métriques agent (débit scans) ────────────────────────────────────
-- Compteurs agrégés par agent. Mis à jour par l'endpoint /yara/scan.
-- Permet dashboard "qui ship le plus, qui drop le plus".
CREATE TABLE IF NOT EXISTS yara_agent_stats (
    agent_id VARCHAR(64) NOT NULL PRIMARY KEY,
    total_submitted BIGINT NOT NULL DEFAULT 0,
    total_scanned BIGINT NOT NULL DEFAULT 0,
    total_matches BIGINT NOT NULL DEFAULT 0,
    last_submitted_at DATETIME,
    last_match_at DATETIME,
    drop_oldest_total BIGINT NOT NULL DEFAULT 0,  -- côté agent (shipper)
    queue_drops_total BIGINT NOT NULL DEFAULT 0   -- côté central (worker)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── 3. Queue des scans (worker background) ──────────────────────────────
-- L'agent push le contenu via POST /api/v1/yara/scan → INSERT ici.
-- Le worker ramasse les pending, scanne avec libyara, INSERT dans yara_scan_results.
-- Status: pending → scanning → done | failed
-- Retry: 3 tentatives avant failed (transient errors only).
-- Le contenu est purgé après 24h (voir retention config).
CREATE TABLE IF NOT EXISTS yara_scan_queue (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    file_inode BIGINT,
    file_size BIGINT NOT NULL,
    file_mtime DATETIME,
    content_b64 LONGTEXT NOT NULL,         -- base64(gzip(content)) ou base64(content) si <64KB
    is_gzipped TINYINT(1) NOT NULL DEFAULT 0,
    heuristic_score TINYINT NOT NULL DEFAULT 0,  -- 0-10 (10 = highly suspicious)
    status ENUM('pending','scanning','done','failed') NOT NULL DEFAULT 'pending',
    attempts TINYINT NOT NULL DEFAULT 0,
    error_message TEXT,
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME,
    completed_at DATETIME,
    INDEX idx_yara_queue_status_time (status, submitted_at),
    INDEX idx_yara_queue_agent (agent_id, submitted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
