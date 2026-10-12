-- Ticket #35 — Onboarding wizard configuration table
-- CDC LOGSOC-WEB Part 6 §23.1
-- Stores the onboarding wizard answers and auto-generated config per user.

CREATE TABLE IF NOT EXISTS onboarding_config (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  country VARCHAR(10) NOT NULL,
  sector VARCHAR(50) NOT NULL,
  company_size VARCHAR(20) NOT NULL,
  nis2_category VARCHAR(50),
  auto_config JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  INDEX idx_onboarding_user (user_id)
);