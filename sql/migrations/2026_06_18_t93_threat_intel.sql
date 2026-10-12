-- T93: Threat Intelligence module — IOCs, TTPs, feeds, actors, bulletins, correlations
-- 2026-06-18

CREATE TABLE IF NOT EXISTS ti_indicators (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    -- IOC
    indicator_type ENUM('ip','domain','url','hash_md5','hash_sha256','email','filename','mutex','registry','certificate','other') NOT NULL,
    value VARCHAR(512) NOT NULL,
    -- Source
    source VARCHAR(100) NOT NULL DEFAULT '',
    source_id VARCHAR(100) DEFAULT '',
    -- Confidence
    confidence TINYINT DEFAULT 50,
    -- Threat classification
    threat_type VARCHAR(100) DEFAULT '',
    malware_family VARCHAR(100) DEFAULT '',
    -- MITRE ATT&CK
    ttp_techniques VARCHAR(255) DEFAULT '',
    -- Validity
    first_seen DATETIME NULL,
    last_seen DATETIME NULL,
    expires_at DATETIME NULL,
    is_active BOOLEAN DEFAULT TRUE,
    -- Tags
    tags TEXT,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (indicator_type),
    INDEX idx_value (value(255)),
    INDEX idx_active (is_active),
    INDEX idx_source (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ti_actors (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    aliases TEXT,
    -- Classification
    actor_type ENUM('apt','cybercriminal','hacktivist','insider','nation_state','unknown') NOT NULL DEFAULT 'unknown',
    motivation VARCHAR(100) DEFAULT '',
    origin_country VARCHAR(10) DEFAULT '',
    target_countries TEXT,
    target_sectors TEXT,
    -- TTPs
    mitre_techniques TEXT,
    known_malware TEXT,
    -- Description
    description TEXT,
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_activity DATE NULL,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_type (actor_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ti_feeds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    feed_type ENUM('misp','opencti','virustotal','abuseipdb','otx','csirt_fr','commercial','custom') NOT NULL DEFAULT 'custom',
    -- Connection
    base_url VARCHAR(255) DEFAULT '',
    api_key VARCHAR(255) DEFAULT '',
    -- Sync
    sync_interval_minutes INT DEFAULT 60,
    last_sync_at DATETIME NULL,
    last_sync_status VARCHAR(50) DEFAULT '',
    last_sync_count INT DEFAULT 0,
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_type (feed_type),
    INDEX idx_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ti_bulletins (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,
    -- Content
    body LONGTEXT NOT NULL,
    -- Classification
    severity ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
    -- Related
    related_indicators TEXT,
    related_actors TEXT,
    -- Distribution
    distribution ENUM('internal','partners','public') NOT NULL DEFAULT 'internal',
    -- Status
    status ENUM('draft','published','archived') NOT NULL DEFAULT 'draft',
    published_at DATETIME NULL,
    -- Metadata
    created_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_distribution (distribution)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ti_correlations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    indicator_id BIGINT NULL,
    alert_id BIGINT NULL,
    case_id BIGINT NULL,
    -- Correlation
    correlation_type ENUM('alert_match','incident_match','ioc_enrichment','actor_attribution') NOT NULL DEFAULT 'alert_match',
    -- Details
    matched_field VARCHAR(100) DEFAULT '',
    matched_value VARCHAR(512) DEFAULT '',
    description TEXT,
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_indicator (indicator_id),
    INDEX idx_alert (alert_id),
    INDEX idx_case (case_id),
    INDEX idx_type (correlation_type),
    CONSTRAINT fk_corr_indicator FOREIGN KEY (indicator_id) REFERENCES ti_indicators(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed default feeds
INSERT INTO ti_feeds (name, feed_type, base_url, sync_interval_minutes) VALUES
('AbuseIPDB', 'abuseipdb', 'https://api.abuseipdb.com/api/v2', 60),
('AlienVault OTX', 'otx', 'https://otx.alienvault.com/api/v1', 120),
('CSIRT-FR', 'csirt_fr', 'https://www.cert.ssi.gouv.fr', 60),
('MISP (local)', 'misp', 'https://misp.local', 30),
('OpenCTI (local)', 'opencti', 'http://opencti.local', 30)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;