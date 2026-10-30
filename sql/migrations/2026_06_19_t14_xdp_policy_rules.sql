-- T14: New event type alert rules — xdp_syn_scan (T13.4) + policy_violation (T13.3)
-- Created: 2026-06-19
-- These rules trigger alerts when the agent sends xdp_syn_scan or policy_violation events.
-- The agent generates these events but the backend had no alert rules for them.

INSERT INTO rules (rule_id, name, description, is_active, severity, pattern, condition_logic, action, created_at)
VALUES
('LSOC-XDP-SYN-SCAN', 'XDP SYN Port Scan Detection', 'Detects SYN port scans captured by XDP eBPF (event=xdp_syn_scan). Multiple SYN packets to different ports from same source IP within time window.', 1, 'critical', 'event = ''xdp_syn_scan''', 'event = ''xdp_syn_scan''', 'alert', NOW()),
('LSOC-POLICY-VIOLATION', 'Policy Violation Detection', 'Detects policy violations flagged by the ActionRecommender (event=policy_violation). Indicates a process violated a configured security policy.', 1, 'high', 'event = ''policy_violation''', 'event = ''policy_violation''', 'alert', NOW())
ON DUPLICATE KEY UPDATE is_active=1;

INSERT INTO mitre_rules (rule_id, technique_id, technique_name, tactic, detection_source, query_template, is_sub_rule, notes)
VALUES
('LSOC-XDP-SYN-SCAN', 'T1046', 'Network Service Discovery', 'discovery', 'network', 'event = ''xdp_syn_scan''', 0, 'XDP eBPF detects SYN scans at kernel level before they reach userspace'),
('LSOC-POLICY-VIOLATION', 'T1059', 'Command and Scripting Interpreter', 'execution', 'ebpf', 'event = ''policy_violation''', 0, 'Policy violation detected by ActionRecommender — process executed a command that violates configured policy');