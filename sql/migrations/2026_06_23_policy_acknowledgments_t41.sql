-- Ticket #41 — Policy acknowledgment (accusé de lecture)
-- Table: policy_acknowledgments
-- Purpose: Track which users have acknowledged which policy version.

CREATE TABLE IF NOT EXISTS policy_acknowledgments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  policy_id INT NOT NULL,
  user_id INT NOT NULL,
  version VARCHAR(20) NOT NULL,
  read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ip_address VARCHAR(45),
  UNIQUE KEY uniq_ack (policy_id, user_id, version),
  INDEX idx_policy (policy_id),
  INDEX idx_user (user_id),
  CONSTRAINT fk_ack_policy FOREIGN KEY (policy_id)
    REFERENCES security_policies(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Add recipients column to security_policies (JSON array of user IDs)
-- NULL or empty = all authenticated users are recipients
ALTER TABLE security_policies ADD COLUMN IF NOT EXISTS recipients JSON NULL;