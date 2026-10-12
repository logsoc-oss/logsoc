-- Insert 20 MITRE rules into rules + mitre_rules tables
-- 2026-06-02 — v0.6.0
-- Notes: Some rules have query_template that won't trigger YET because
-- the agent doesn't capture that event type (ptrace, chmod, bpf_prog_load).
-- We mark them with notes='NEEDS_COLLECTOR' so they can be enabled later.

-- 1) Insert into rules (20 rules)
INSERT INTO rules (rule_id, name, description, is_active, severity) VALUES
('LSOC-001', 'Web Shell Detection', 'Shell or interpreter executed by web server user (www-data/apache/nginx)', 1, 'critical'),
('LSOC-002', 'Log File Deletion', 'Critical log files deleted under /var/log/ (T1070.001)', 1, 'critical'),
('LSOC-003', 'Bash History Cleared', 'Bash history file deleted (T1070.002)', 1, 'high'),
('LSOC-004', 'Ptrace Process Injection', 'Process injection via ptrace syscall (T1055.008) — NEEDS_COLLECTOR', 1, 'critical'),
('LSOC-005', 'Setuid/Setgid Binary', 'chmod +s applied to binary (T1166) — NEEDS_COLLECTOR (no chmod event)', 1, 'critical'),
('LSOC-006', 'Auditd Disabled', 'auditd stopped / rules flushed (T1562.004)', 1, 'critical'),
('LSOC-007', 'SSH Brute Force', '5+ failed SSH logins from same IP in 5 minutes (T1110.001)', 1, 'high'),
('LSOC-008', 'User Account Creation', 'useradd/adduser executed (T1136.001)', 1, 'high'),
('LSOC-009', 'Non-Standard Port Outbound', 'Outbound connection to non-standard port (T1571)', 1, 'high'),
('LSOC-010', 'Download Then Execute', 'wget/curl followed by exec from /tmp within 60s (T1105)', 1, 'high'),
('LSOC-011', 'Kernel Module Load', 'insmod/modprobe or BPF prog by non-root (T1215) — NEEDS_COLLECTOR', 1, 'critical'),
('LSOC-012', 'Shadow File Read', '/etc/shadow read by non-whitelisted process (T1003.001)', 1, 'high'),
('LSOC-013', 'Systemd Service Created', 'New systemd .service file (T1501.001)', 1, 'high'),
('LSOC-014', 'Crontab Modified', 'crontab command executed (T1053.003)', 1, 'high'),
('LSOC-015', 'Rootkit Indicators', 'Kernel module or BPF prog by non-root (T1014) — NEEDS_COLLECTOR', 1, 'critical'),
('LSOC-016', 'Mass Encryption (Ransomware)', 'Encryption cmd + mass file mods (T1486)', 1, 'critical'),
('LSOC-017', 'Crypto Mining', 'Known miner binary or stratum connection (T1496)', 1, 'high'),
('LSOC-018', 'Process Masquerading', 'Legit process name from suspicious path (T1036.005)', 1, 'medium'),
('LSOC-019', 'Private SSH Key Access', 'SSH private key read by non-SSH process (T1552.004)', 1, 'high'),
('LSOC-020', 'Dynamic Linker Hijacking', 'ld.so.preload / ld.so.conf modified (T1574.006)', 1, 'high');

-- 2) Insert into mitre_rules — query_template is the WHERE clause for ClickHouse.
-- Only rules with event types actually captured by agent have working queries.

INSERT INTO mitre_rules (rule_id, technique_id, technique_name, tactic, detection_source, query_template, notes) VALUES
-- LSOC-001 Web Shell
('LSOC-001', 'T1100', 'Web Shell', 'persistence', 'ebpf',
 "event='execve' AND comm IN ('bash','sh','dash','python3','python','perl','php','nc','ncat') AND uid IN (33,48,997)",
 'Active — relies on uid 33/48/997 (www-data/apache/nginx)'),
('LSOC-001', 'T1059.004', 'Bash', 'execution', 'ebpf',
 "event='execve' AND comm IN ('bash','sh','dash') AND uid IN (33,48,997)",
 NULL),

-- LSOC-002 Log deletion
('LSOC-002', 'T1070.001', 'Clear Linux Logs', 'stealth', 'ebpf',
 "event='unlink' AND filename LIKE '%/var/log/%'",
 'Active — fires on /var/log/* deletions'),

-- LSOC-003 Bash history
('LSOC-003', 'T1070.002', 'Clear Bash History', 'stealth', 'ebpf',
 "event='unlink' AND (filename LIKE '%.bash_history%' OR filename LIKE '%.zsh_history%')",
 NULL),
('LSOC-003', 'T1070.002', 'Clear Bash History', 'stealth', 'ebpf',
 "event='execve' AND (message LIKE '%history -c%' OR message LIKE '%unset HISTFILE%')",
 NULL),

-- LSOC-004 ptrace (NEEDS_COLLECTOR)
('LSOC-004', 'T1055.008', 'Ptrace System Calls', 'privilege-escalation', 'ebpf',
 "event='ptrace'",
 'NEEDS_COLLECTOR — ptrace event not emitted by agent v3.8.0'),

-- LSOC-005 chmod +s (NEEDS_COLLECTOR)
('LSOC-005', 'T1166', 'Setuid and Setgid', 'persistence', 'ebpf',
 "event='chmod' AND message LIKE '%+s%'",
 'NEEDS_COLLECTOR — chmod event count=0'),

-- LSOC-006 auditd stop
('LSOC-006', 'T1562.004', 'Disable Linux Audit', 'stealth', 'ebpf',
 "event='execve' AND (message LIKE '%systemctl stop auditd%' OR message LIKE '%auditctl -D%' OR message LIKE '%service auditd stop%')",
 NULL),

-- LSOC-007 SSH brute force
('LSOC-007', 'T1110.001', 'Password Guessing', 'credential-access', 'syslog',
 "message LIKE '%Failed password%' AND source_ip != toIPv4('0.0.0.0')",
 'Group by source_ip threshold >= 5 in 5min — correlation_window 300'),

-- LSOC-008 useradd
('LSOC-008', 'T1136.001', 'Local Account', 'persistence', 'ebpf',
 "event='execve' AND comm IN ('useradd','adduser','newusers')",
 NULL),

-- LSOC-009 non-standard port
('LSOC-009', 'T1571', 'Non-Standard Port', 'command-and-control', 'ebpf',
 "event='tcp_connect' AND dst_port NOT IN (22,53,80,443,8080,8443,3306,5432,6379,27017,9090,9091,25,110,143,993,995,587,3000,8000) AND dst_ip NOT LIKE '127.%' AND dst_ip NOT LIKE '192.168.%' AND dst_ip NOT LIKE '10.%'",
 NULL),

-- LSOC-010 download
('LSOC-010', 'T1105', 'Ingress Tool Transfer', 'command-and-control', 'ebpf',
 "event='execve' AND comm IN ('wget','curl','lwp-download')",
 'Step 1 — also needs step 2 (exec from /tmp within 60s) for full correlation'),
('LSOC-010', 'T1059', 'Command Interpreter', 'execution', 'ebpf',
 "event='execve' AND (message LIKE '%/tmp/%' OR message LIKE '%/dev/shm/%' OR message LIKE '%/var/tmp/%')",
 'Step 2 — fires independently, fine'),

-- LSOC-011 kernel module (NEEDS_COLLECTOR)
('LSOC-011', 'T1215', 'Kernel Modules and Extensions', 'persistence', 'ebpf',
 "event='execve' AND comm IN ('insmod','modprobe')",
 'NEEDS_COLLECTOR — comm insmod/modprobe not yet observed in 24h'),

-- LSOC-012 shadow read
('LSOC-012', 'T1003.001', 'OS Credential Dumping', 'credential-access', 'ebpf',
 "event='open' AND filename LIKE '%/etc/shadow%' AND comm NOT IN ('login','sshd','su','sudo','passwd','useradd','usermod','chpasswd','pam_unix')",
 NULL),

-- LSOC-013 systemd service
('LSOC-013', 'T1501.001', 'Create Service', 'persistence', 'ebpf',
 "(event='open' OR event='fim') AND filename LIKE '%/etc/systemd/system/%' AND filename LIKE '%.service'",
 NULL),

-- LSOC-014 crontab
('LSOC-014', 'T1053.003', 'Cron', 'persistence', 'ebpf',
 "event='execve' AND (comm='crontab' OR message LIKE '%crontab%')",
 NULL),

-- LSOC-015 rootkit (NEEDS_COLLECTOR)
('LSOC-015', 'T1014', 'Rootkit', 'stealth', 'ebpf',
 "ebpf_event='bpf_prog_load' AND uid != 0",
 'NEEDS_COLLECTOR — ebpf_event field never populated'),

-- LSOC-016 ransomware
('LSOC-016', 'T1486', 'Data Encrypted for Impact', 'impact', 'ebpf',
 "event='execve' AND comm IN ('openssl','gpg') AND (message LIKE '%enc%' OR message LIKE '%--encrypt%' OR message LIKE '%-e %')",
 NULL),

-- LSOC-017 mining
('LSOC-017', 'T1496', 'Resource Hijacking', 'impact', 'ebpf',
 "event='execve' AND (comm IN ('xmrig','minerd','cgminer','bfgminer','cpuminer','nicehash','minergate') OR message LIKE '%stratum+tcp%' OR message LIKE '%pool.minexmr%')",
 NULL),

-- LSOC-018 masquerading
('LSOC-018', 'T1036.005', 'Match Legitimate Name', 'stealth', 'ebpf',
 "event='execve' AND comm IN ('sshd','nginx','apache2','cron','systemd','rsyslogd','auditd') AND (message LIKE '%/tmp/%' OR message LIKE '%/dev/shm/%' OR message LIKE '%/var/tmp/%')",
 NULL),

-- LSOC-019 SSH key
('LSOC-019', 'T1552.004', 'Private Keys', 'credential-access', 'ebpf',
 "event='open' AND (filename LIKE '%id_rsa%' OR filename LIKE '%id_ed25519%' OR filename LIKE '%.pem%') AND comm NOT IN ('sshd','ssh','ssh-agent','ssh-keygen','scp','sftp','rsync')",
 NULL),

-- LSOC-020 ld.so.preload
('LSOC-020', 'T1574.006', 'Dynamic Linker Hijacking', 'stealth', 'ebpf',
 "(event='open' OR event='fim') AND (filename LIKE '%/etc/ld.so.preload%' OR filename LIKE '%/etc/ld.so.conf%')",
 NULL);
