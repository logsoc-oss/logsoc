-- Migration: crisis session tables (steps, assets, timeline, playbook_steps)
-- Crisis warroom: playbook steps, session steps, affected assets, timeline
-- Date: 2026-06-29

CREATE TABLE IF NOT EXISTS crisis_playbook_steps (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    playbook_id INT NOT NULL,
    step_number INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT DEFAULT NULL,
    action TEXT DEFAULT NULL,
    responsible_role VARCHAR(64) DEFAULT 'admin',
    validation_criteria TEXT DEFAULT NULL,
    escalation TEXT DEFAULT NULL,
    KEY playbook_id (playbook_id),
    CONSTRAINT crisis_playbook_steps_ibfk_1 FOREIGN KEY (playbook_id) REFERENCES crisis_playbooks (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_session_steps (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT NOT NULL,
    step_number INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT DEFAULT NULL,
    action TEXT DEFAULT NULL,
    status VARCHAR(16) DEFAULT 'pending',
    completed_by INT DEFAULT NULL,
    completed_at DATETIME DEFAULT NULL,
    notes TEXT DEFAULT NULL,
    KEY session_id (session_id),
    CONSTRAINT crisis_session_steps_ibfk_1 FOREIGN KEY (session_id) REFERENCES crisis_events (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_session_assets (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT NOT NULL,
    agent_id INT NOT NULL,
    impact_level VARCHAR(16) DEFAULT 'affected',
    notes TEXT DEFAULT NULL,
    KEY session_id (session_id),
    CONSTRAINT crisis_session_assets_ibfk_1 FOREIGN KEY (session_id) REFERENCES crisis_events (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS crisis_session_timeline (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    session_id BIGINT NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT DEFAULT NULL,
    created_by INT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY session_id (session_id),
    CONSTRAINT crisis_session_timeline_ibfk_1 FOREIGN KEY (session_id) REFERENCES crisis_events (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;