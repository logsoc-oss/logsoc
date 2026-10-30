-- Ticket #38: policy_summaries table for AI-generated diff summaries
CREATE TABLE IF NOT EXISTS policy_summaries (
  id INT PRIMARY KEY AUTO_INCREMENT,
  policy_id INT NOT NULL,
  version VARCHAR(20) NOT NULL,
  summary TEXT NOT NULL,
  generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_policy_summaries_policy FOREIGN KEY (policy_id) REFERENCES security_policies(id) ON DELETE CASCADE,
  UNIQUE KEY uq_policy_version (policy_id, version)
);
