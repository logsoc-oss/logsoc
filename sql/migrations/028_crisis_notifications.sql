-- Migration T28: Crisis notifications table
-- War Room -- Notifications IA + SMTP

CREATE TABLE IF NOT EXISTS crisis_notifications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  incident_id INT NOT NULL,
  authority VARCHAR(50) NOT NULL,
  regulation VARCHAR(20) NOT NULL,
  content TEXT NOT NULL,
  status ENUM('draft','sent','acknowledged') DEFAULT 'draft',
  sent_at DATETIME DEFAULT NULL,
  sent_by INT DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_crisis_notif_incident (incident_id),
  INDEX idx_crisis_notif_status (status),
  INDEX idx_crisis_notif_authority (authority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;