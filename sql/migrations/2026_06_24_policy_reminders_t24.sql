-- Ticket #24 — Politiques: cron relance J+7 + endpoint diffusion + export PDF
-- Table: policy_reminders
-- Purpose: Track reminder notifications sent to users who haven't acknowledged
--          a published policy within 7+ days.

-- MariaDB doesn't allow DATE() in UNIQUE KEY constraints, so we use a
-- generated column to extract the date for the unique constraint.

CREATE TABLE IF NOT EXISTS policy_reminders (
  id INT PRIMARY KEY AUTO_INCREMENT,
  policy_id INT NOT NULL,
  user_id INT NOT NULL,
  version VARCHAR(32) NOT NULL,
  sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  sent_date DATE GENERATED ALWAYS AS (DATE(sent_at)) STORED,
  reminder_count INT DEFAULT 1,
  delivery_channel ENUM('dashboard','email','both') DEFAULT 'dashboard',
  FOREIGN KEY (policy_id) REFERENCES security_policies(id) ON DELETE CASCADE,
  UNIQUE KEY uk_policy_user_day (policy_id, user_id, sent_date),
  INDEX idx_policy (policy_id),
  INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;