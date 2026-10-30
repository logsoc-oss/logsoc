-- Migration: create mitre_rules table for MITRE ATT&CK mapping
-- 2026-06-02 — v0.6.0

CREATE TABLE IF NOT EXISTS mitre_rules (
    id                  INTEGER PRIMARY KEY AUTO_INCREMENT,
    rule_id             VARCHAR(64) NOT NULL,
    technique_id        VARCHAR(20) NOT NULL,
    technique_name      VARCHAR(255) NOT NULL,
    tactic              VARCHAR(64) NOT NULL,
    detection_source    ENUM('ebpf','journald','syslog','fim','correlation','network') NOT NULL,
    query_template      TEXT NOT NULL,
    correlation_window  INT DEFAULT 0,
    correlation_after   VARCHAR(64) DEFAULT NULL,
    is_sub_rule         TINYINT DEFAULT 0,
    parent_rule_id      VARCHAR(64) DEFAULT NULL,
    notes               TEXT DEFAULT NULL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_technique (technique_id),
    INDEX idx_tactic (tactic),
    INDEX idx_rule_id (rule_id),
    INDEX idx_source (detection_source)
);
