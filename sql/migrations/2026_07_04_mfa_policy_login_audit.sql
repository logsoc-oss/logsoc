-- MFA global policy + login audit trail + unknown LAN detection
-- 2026-07-04 (updated 2026-07-07)

-- 1. Add mfa_setup_required and phone to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_setup_required TINYINT(1) DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(32) DEFAULT NULL;

-- 2. Login audit trail table
CREATE TABLE IF NOT EXISTS login_audit (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  username VARCHAR(64) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  user_agent TEXT,
  status ENUM('success', 'mfa_required', 'mfa_failed', 'invalid_password', 'invalid_mfa', 'backup_code_used', 'account_locked', 'unknown_user', 'mfa_setup_required', 'unknown_lan') NOT NULL,
  mfa_used TINYINT(1) DEFAULT 0,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id),
  INDEX idx_ip (source_ip),
  INDEX idx_timestamp (timestamp),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. User MFA table (TOTP secrets + backup codes)
CREATE TABLE IF NOT EXISTS user_mfa (
  id INT NOT NULL AUTO_INCREMENT,
  user_id INT NOT NULL,
  secret VARCHAR(64) NOT NULL,
  backup_codes LONGTEXT DEFAULT NULL,
  enabled TINYINT(1) DEFAULT 0,
  enabled_at DATETIME DEFAULT NULL,
  last_used_at DATETIME DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY ix_user_mfa_user_id (user_id),
  CONSTRAINT user_mfa_ibfk_1 FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Add exceptions and is_template to rules
ALTER TABLE rules ADD COLUMN IF NOT EXISTS exceptions TEXT DEFAULT NULL;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS is_template TINYINT(1) DEFAULT 0;