-- Phase 1.2 — MFA (TOTP) support
-- Adds user_mfa table for TOTP secret + backup codes.

CREATE TABLE IF NOT EXISTS user_mfa (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  secret VARCHAR(64) NOT NULL,
  backup_codes JSON DEFAULT NULL,
  enabled BOOLEAN DEFAULT FALSE,
  enabled_at DATETIME DEFAULT NULL,
  last_used_at DATETIME DEFAULT NULL,
  UNIQUE KEY uniq_user_mfa_user_id (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;