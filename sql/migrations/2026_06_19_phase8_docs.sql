-- Phase 8 — Documentation & gouvernance
-- Runbooks par type d'alerte + playbooks de réponse humaine + charte

CREATE TABLE IF NOT EXISTS alert_runbooks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_type VARCHAR(128) NOT NULL,
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(16),
  steps JSON NOT NULL,
  detection_query TEXT,
  false_positive_check TEXT,
  escalation_contact VARCHAR(255),
  created_by INT,
  created_at DATETIME,
  updated_at DATETIME,
  INDEX idx_alert_type (alert_type)
);

-- Seed default runbooks
INSERT INTO alert_runbooks (alert_type, title, severity, steps, detection_query, false_positive_check, escalation_contact, created_at, updated_at) VALUES
  ('brute_force', 'Runbook: Brute Force Login', 'high',
   JSON_ARRAY(JSON_OBJECT('step', 1, 'action', 'Check source IP in CMDB — is it a known asset?', 'expected', 'If internal, check with owner. If external, block IP.'),
              JSON_OBJECT('step', 2, 'action', 'Verify failed login count in last 15min', 'expected', 'If >10 failures, confirm brute force.'),
              JSON_OBJECT('step', 3, 'action', 'Check if any login succeeded after failures', 'expected', 'If yes, treat as compromised account.'),
              JSON_OBJECT('step', 4, 'action', 'Disable affected account(s) and reset passwords', 'expected', 'Accounts locked, user notified.'),
              JSON_OBJECT('step', 5, 'action', 'Block source IP at firewall', 'expected', 'IP blocked, rule documented.')),
   'SELECT source_host, COUNT(*) as failures FROM siem_logs WHERE event_type = ''auth_failed'' AND received_at > now() - INTERVAL 15 MINUTE GROUP BY source_host HAVING failures > 10',
   'Check if source is a legitimate service with expired credentials (e.g. monitoring, backup). Check scheduled tasks that might use old passwords.',
   'soc-team@demo-logsoc.example', NOW(), NOW()),

  ('priv_esc', 'Runbook: Privilege Escalation', 'critical',
   JSON_ARRAY(JSON_OBJECT('step', 1, 'action', 'Identify the user and target privilege level', 'expected', 'User and privilege documented.'),
              JSON_OBJECT('step', 2, 'action', 'Check if escalation was authorized (change ticket, approval)', 'expected', 'If unauthorized, treat as incident.'),
              JSON_OBJECT('step', 3, 'action', 'Review command history for the user session', 'expected', 'Commands logged and analyzed.'),
              JSON_OBJECT('step', 4, 'action', 'Revert privileges and investigate scope', 'expected', 'Privileges reverted, impact assessed.'),
              JSON_OBJECT('step', 5, 'action', 'Escalate to CISO if unauthorized', 'expected', 'CISO notified, incident opened.')),
   'SELECT * FROM siem_logs WHERE event_type IN (''sudo_success'', ''su_success'', ''priv_change'') AND received_at > now() - INTERVAL 1 HOUR',
   'Check if this is a scheduled admin task (cron, ansible, etc.). Check if user has a valid change window.',
   'ciso@demo-logsoc.example', NOW(), NOW()),

  ('lateral_move', 'Runbook: Lateral Movement Detection', 'high',
   JSON_ARRAY(JSON_OBJECT('step', 1, 'action', 'Identify source and destination hosts', 'expected', 'Both hosts identified in CMDB.'),
              JSON_OBJECT('step', 2, 'action', 'Check if movement is expected (admin activity, deployment)', 'expected', 'If unexpected, isolate destination host.'),
              JSON_OBJECT('step', 3, 'action', 'Analyze protocols used (RDP, SSH, SMB, WMI)', 'expected', 'Protocol and tooling documented.'),
              JSON_OBJECT('step', 4, 'action', 'Check for data exfiltration on destination', 'expected', 'No exfiltration or documented.'),
              JSON_OBJECT('step', 5, 'action', 'Trace back to original compromise point', 'expected', 'Attack chain mapped.')),
   'SELECT source_host, dest_host, COUNT(*) as connections FROM siem_logs WHERE event_type IN (''remote_login'', ''smb_connect'', ''rdp_connect'') AND received_at > now() - INTERVAL 1 HOUR GROUP BY source_host, dest_host',
   'Check if this is a legitimate admin session, deployment tool (Ansible, Puppet), or monitoring system.',
   'soc-team@demo-logsoc.example', NOW(), NOW()),

  ('malware_detected', 'Runbook: Malware Detection', 'critical',
   JSON_ARRAY(JSON_OBJECT('step', 1, 'action', 'Identify the infected host and malware type', 'expected', 'Host and malware signature documented.'),
              JSON_OBJECT('step', 2, 'action', 'Isolate host from network immediately', 'expected', 'Host isolated, network access blocked.'),
              JSON_OBJECT('step', 3, 'action', 'Collect forensic evidence (memory dump, disk image)', 'expected', 'Evidence collected and stored.'),
              JSON_OBJECT('step', 4, 'action', 'Identify infection vector and scope', 'expected', 'Vector identified, other hosts checked.'),
              JSON_OBJECT('step', 5, 'action', 'Clean or rebuild host, restore from clean backup', 'expected', 'Host clean, verified before reconnecting.'),
              JSON_OBJECT('step', 6, 'action', 'Update detection rules with IOCs', 'expected', 'Rules updated, scan all hosts.')),
   'SELECT * FROM siem_logs WHERE event_type = ''malware_detected'' AND received_at > now() - INTERVAL 24 HOUR',
   'Check if this is a false positive from a penetration test, known safe file flagged by heuristics, or admin testing security tools.',
   'ciso@demo-logsoc.example', NOW(), NOW()),

  ('data_exfiltration', 'Runbook: Data Exfiltration', 'critical',
   JSON_ARRAY(JSON_OBJECT('step', 1, 'action', 'Identify source host and destination IP/domain', 'expected', 'Source and destination documented.'),
              JSON_OBJECT('step', 2, 'action', 'Check volume of data transferred', 'expected', 'Data volume and type assessed.'),
              JSON_OBJECT('step', 3, 'action', 'Block destination IP/domain at firewall', 'expected', 'Destination blocked.'),
              JSON_OBJECT('step', 4, 'action', 'Identify what data was exfiltrated', 'expected', 'Data classification assessed (RGPD impact?).'),
              JSON_OBJECT('step', 5, 'action', 'If personal data involved, notify DPO within 72h', 'expected', 'DPO notified, breach assessment started.'),
              JSON_OBJECT('step', 6, 'action', 'Investigate source compromise', 'expected', 'Root cause identified.')),
   'SELECT source_host, dest_ip, SUM(bytes_out) as total FROM siem_logs WHERE event_type = ''network_connection'' AND bytes_out > 104857600 AND received_at > now() - INTERVAL 1 HOUR GROUP BY source_host, dest_ip',
   'Check if this is a legitimate large file transfer (backup, replication, cloud sync, software update). Verify with asset owner.',
   'dpo@demo-logsoc.example', NOW(), NOW())
ON DUPLICATE KEY UPDATE updated_at = NOW();