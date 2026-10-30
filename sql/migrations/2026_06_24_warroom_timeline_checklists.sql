-- T25: War Room Timeline + T26: War Room Checklists
-- 2026-06-24

-- ── T25: crisis_timeline ──
CREATE TABLE IF NOT EXISTS crisis_timeline (
    id INT PRIMARY KEY AUTO_INCREMENT,
    incident_id INT NOT NULL,
    user_id INT,
    event_type ENUM('human','system') NOT NULL DEFAULT 'human',
    content TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    locked BOOLEAN DEFAULT FALSE,
    locked_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_incident_ts (incident_id, timestamp DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── T26: crisis_checklists ──
CREATE TABLE IF NOT EXISTS crisis_checklists (
    id INT PRIMARY KEY AUTO_INCREMENT,
    incident_id INT NOT NULL,
    template_type VARCHAR(50) NOT NULL,
    tasks JSON NOT NULL,
    completed_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_incident (incident_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;