"""
enrichment.py — MITRE ATT&CK mapping, Sigma matching, and severity scoring.

Ported from the Linux agent C++ code (mitre_mapping.cpp, sigma_engine.cpp,
severity_scorer.cpp) to Python. Runs server-side so all agents (Linux,
Windows, future) benefit from a single enrichment source.

The enrichment is applied in events.py BEFORE the ClickHouse INSERT,
only when the agent did not already provide enrichment (severity_score=0
and mitre=[] and sigma=''). This preserves backward compat with the
Linux agent which still enriches client-side.
"""

import re
import json
from typing import List, Dict, Any, Optional


# ── MITRE path-based rules ─────────────────────────────────────────
# (pattern, [techniques]) — uses fnmatch-style globbing
MITRE_PATH_RULES = [
    ("/etc/shadow",            ["T1003.008"]),
    ("/etc/passwd",            ["T1003.008"]),
    ("/etc/sudoers",           ["T1548.003"]),
    ("/etc/ssh/sshd_config",   ["T1098.004"]),
    ("*authorized_keys*",      ["T1098.004"]),
    ("/etc/ld.so.preload",     ["T1574.006"]),
    ("/etc/cron*",             ["T1053.003"]),
    ("/etc/rc.local",          ["T1037.004"]),
    ("/etc/systemd/system/*",  ["T1543.002"]),
    ("/var/log/*",             ["T1070.002"]),
    ("/proc/kallsyms",         ["T1003"]),
    ("/proc/kcore",            ["T1003"]),
    ("/proc/keys",             ["T1003"]),
    ("/lib/modules/*",         ["T1547.006", "T1014"]),
    ("*diamorphine*",          ["T1547.006", "T1014"]),
    ("*reptile*",              ["T1547.006", "T1014"]),
    ("*suterusu*",            ["T1547.006", "T1014"]),
]

# ── Sigma rules (25) ────────────────────────────────────────────────
# (id, level, pattern_substring, techniques_csv)
SIGMA_RULES = [
    # Modload / rootkit
    ("modload_by_root",        "critical", '"event":"modload"',                    "T1547.006,T1014"),
    ("finit_module_by_root",    "critical", '"subtype":"finit_module"',             "T1547.006,T1014"),
    ("init_module_by_root",     "critical", '"subtype":"init_module"',              "T1547.006,T1014"),
    # Credential access
    ("etc_shadow_read",         "critical", '"event":"vfs_open","path":"/etc/shadow', "T1003.008"),
    ("etc_passwd_read",         "high",     '"event":"vfs_open","path":"/etc/passwd', "T1003.008"),
    ("etc_sudoers_modify",      "high",     "/etc/sudoers",                          "T1548.003"),
    ("ssh_authorized_keys",     "critical", "authorized_keys",                       "T1098.004"),
    ("sshd_config_modify",      "high",     "sshd_config",                           "T1098.004"),
    ("proc_kallsyms_read",      "high",     "/proc/kallsyms",                        "T1003"),
    ("proc_kcore_read",         "critical", "/proc/kcore",                           "T1003"),
    # Persistence
    ("ld_so_preload_modify",    "critical", "/etc/ld.so.preload",                   "T1574.006"),
    ("systemd_service_create",  "high",     "/etc/systemd/system/",                  "T1543.002"),
    ("crontab_modify",          "medium",   "/etc/cron",                             "T1053.003"),
    ("rc_local_modify",         "high",     "/etc/rc.local",                         "T1037.004"),
    # Defense evasion
    ("var_log_unlink",          "high",     '"event":"unlink","path":"/var/log/',   "T1070.002"),
    ("bpf_program_attached",   "high",     '"event":"bpf"',                         "T1562.001"),
    # Execution / command
    ("ptrace_attached",         "high",     '"event":"ptrace"',                      "T1055"),
    ("ptrace_proc_mem",         "critical", '"event":"ptrace","path":"/proc/',       "T1003.007"),
    # Network C2
    ("outbound_to_shell_port",  "critical", '"dst_port":4444',                       "T1059.003"),
    ("outbound_to_31337",       "critical", '"dst_port":31337',                      "T1059"),
    ("bind_shell_port",         "critical", '"event":"bind","dst_port":4444',        "T1505.003"),
    ("accept_non_standard",     "medium",   '"event":"accept"',                      "T1505"),
    # Privilege escalation
    ("commit_creds_root",       "high",     '"event":"commit_creds","uid":0',        "T1548"),
    # Process injection (interpreter spawned)
    ("python_exec",             "low",      '"comm":"python',                       "T1059.006"),
    ("nc_exec",                 "high",     '"comm":"nc"',                           "T1059.004"),
    ("socat_exec",              "high",     '"comm":"socat"',                        "T1059"),
    ("curl_download",           "medium",   '"comm":"curl"',                         "T1105"),
]

# ── Severity scoring ───────────────────────────────────────────────
# Type baseline scores (event type → base score)
TYPE_BASELINE = {
    "modload":       70,
    "ptrace":        60,
    "bpf":           65,
    "commit_creds": 35,
    "unlink":        15,
    "bind":          30,
    "accept":        35,
    "vfs_open":      15,
    "fim":           10,
    "tcp_v4_connect": 25,
    "tcp_connect":   25,
    "execve":        12,
    "fork":          5,
    "write":         8,
    "write_fd":      5,
    # Windows equivalents
    "open":          15,
    "create":        12,
    "write":         8,
    "exit":          5,
    "rename":        10,
    "modload":       70,
}

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/sudoers", "/etc/pam.d/", "/etc/ssh/sshd_config",
    "authorized_keys", "/proc/kallsyms", "/proc/kcore", "/proc/keys",
    "/etc/ld.so.preload", "/var/log/", "/lib/modules/",
    # Windows equivalents
    "C:\\Windows\\System32\\config",
    "C:\\Windows\\System32\\drivers\\etc",
    "SAM", "SYSTEM", "SECURITY",
]

SUSPICIOUS_COMMS = {
    "nc", "ncat", "netcat", "socat", "curl", "wget",
    "python", "python3", "perl", "ruby", "php", "msfconsole",
    # Windows equivalents
    "powershell", "powershell.exe", "cmd.exe", "wscript", "cscript",
    "mshta", "rundll32", "regsvr32",
}

SHELL_PORTS = {4444, 31337, 1337, 9001, 8888}


def _fnmatch(pattern: str, path: str) -> bool:
    """Simple fnmatch with * and / support (like C fnmatch FNM_PATHNAME)."""
    if pattern.startswith("/") and not path.startswith("/"):
        # Absolute Linux pattern — skip for Windows paths
        # But still try substring match for patterns like /etc/shadow
        if pattern in path:
            return True
        return False
    # Convert glob to regex
    regex = "^"
    for ch in pattern:
        if ch == "*":
            regex += "[^/]*"
        elif ch == "?":
            regex += "."
        else:
            regex += re.escape(ch)
    regex += "$"
    return re.match(regex, path) is not None


def map_mitre(event_type: str, comm: str, path: str, uid: int,
              dst_port: int) -> List[str]:
    """Map an event to MITRE ATT&CK techniques."""
    techniques = set()

    # 1. Path-based rules
    if path:
        for pattern, techs in MITRE_PATH_RULES:
            if "*" in pattern:
                if _fnmatch(pattern, path):
                    techniques.update(techs)
            elif path.startswith(pattern) or pattern in path:
                techniques.update(techs)

    # 2. Type-based rules
    et = event_type.lower() if event_type else ""

    if et in ("execve", "process_start"):
        if comm in ("nc", "ncat", "netcat", "socat", "bash", "sh", "zsh", "dash"):
            techniques.add("T1059.004")
        if comm in ("curl", "wget", "fetch"):
            techniques.add("T1105")
        if comm in ("python", "python3", "perl", "ruby", "php"):
            techniques.add("T1059.006")
        if uid == 0 and comm in ("sudo", "su"):
            techniques.add("T1548.003")
        # Windows
        if comm in ("powershell", "powershell.exe", "cmd.exe", "wscript", "cscript"):
            techniques.add("T1059.001")  # PowerShell / Command and Scripting
        if comm in ("mshta", "rundll32", "regsvr32"):
            techniques.add("T1218")  # System Binary Proxy Execution

    elif et in ("tcp_connect", "tcp_v4_connect", "connect"):
        techniques.add("T1071")
        if dst_port == 53:
            techniques.add("T1071.004")
        elif dst_port in (443, 80):
            techniques.add("T1071.001")
        elif dst_port == 4444:
            techniques.add("T1059.003")
        elif dst_port in (31337, 1337):
            techniques.add("T1059")

    elif et in ("unlink", "file_delete"):
        techniques.add("T1070.004")
        if path and "/var/log/" in path:
            techniques.add("T1070.002")
        if path and ("/etc/" in path or "/usr/" in path or "/lib/" in path):
            techniques.add("T1485")

    elif et == "ptrace":
        techniques.add("T1055")
        if path and "/proc/" in path:
            techniques.add("T1003.007")

    elif et in ("modload", "image_load"):
        techniques.add("T1547.006")
        techniques.add("T1014")
        if uid == 0:
            techniques.add("T1547")

    elif et == "bpf":
        techniques.add("T1562.001")
        if uid != 0:
            techniques.add("T1068")

    elif et in ("open", "vfs_open", "fim", "file_create", "file_modify"):
        if path and "/proc/" in path and "/proc/self/" not in path:
            techniques.add("T1083")
        if path and ("/proc/kallsyms" in path or "/proc/kcore" in path):
            techniques.add("T1003")

    return sorted(techniques)


def match_sigma(event_json_str: str) -> List[Dict[str, Any]]:
    """Match an event JSON string against Sigma rules. Returns list of hits."""
    hits = []
    for rule_id, level, pattern, techniques in SIGMA_RULES:
        if pattern in event_json_str:
            hits.append({
                "id": rule_id,
                "level": level,
                "techniques": techniques,
            })
    return hits


def compute_severity_score(event_type: str, comm: str, path: str,
                            uid: int, dst_port: int,
                            mitre_count: int) -> int:
    """Compute a severity score 0-100."""
    et = event_type.lower() if event_type else ""
    s = TYPE_BASELINE.get(et, 10)

    # MITRE technique count boost (cap +30)
    s += min(mitre_count * 6, 30)

    # Sensitive path boost
    if path:
        for sp in SENSITIVE_PATHS:
            if sp in path:
                s += 25
                break
        else:
            if path.startswith("/etc/"):
                s += 8
            elif path.startswith("C:\\Windows\\System32\\"):
                s += 8

    # Root UID boost
    if uid == 0:
        s += 10

    # Suspicious comm boost
    if comm and comm.lower() in SUSPICIOUS_COMMS:
        s += 15

    # Shell port boost
    if dst_port in SHELL_PORTS:
        s += 20

    return max(0, min(100, s))


def score_to_severity(s: int) -> str:
    if s >= 90:
        return "critical"
    if s >= 75:
        return "high"
    if s >= 50:
        return "medium"
    if s >= 20:
        return "low"
    return "info"


def enrich_event(line: Any) -> Dict[str, Any]:
    """
    Enrich a single event line with MITRE, sigma, and severity_score.

    Called from events.py BEFORE the ClickHouse INSERT.
    Only enriches if the agent did not already provide enrichment
    (severity_score=0 AND mitre=[]) to preserve backward compat with
    the Linux agent which still enriches client-side.

    Returns a dict with: severity_score (int), mitre (list), sigma (str)
    """
    # Extract fields from the line
    event_type = getattr(line, 'event', None) or ''
    comm = getattr(line, 'comm', '') or ''
    path = getattr(line, 'filename', '') or ''
    uid = getattr(line, 'uid', 0) or 0
    dst_port = getattr(line, 'dst_port', 0) or 0
    message = getattr(line, 'message', '') or ''

    # Check if agent already provided enrichment
    existing_score = getattr(line, 'severity_score', 0) or 0
    existing_mitre = getattr(line, 'mitre', []) or []

    if existing_score > 0 and existing_mitre:
        # Agent already enriched — use agent values
        _sigma = getattr(line, 'sigma', '') or ''
        if isinstance(_sigma, (list, dict)):
            _sigma = json.dumps(_sigma)
        return {
            'severity_score': existing_score,
            'mitre': existing_mitre,
            'sigma': _sigma,
        }

    # Agent did not enrich — do it server-side

    # Build a JSON string for sigma matching
    # Use the line's message which contains the event JSON
    event_json_str = message if message else ''

    # 1. MITRE mapping
    mitre = map_mitre(event_type, comm, path, uid, dst_port)

    # 2. Sigma matching
    sigma_hits = match_sigma(event_json_str)
    _sigma = json.dumps(sigma_hits) if sigma_hits else ''

    # 3. Severity score
    severity_score = compute_severity_score(
        event_type, comm, path, uid, dst_port, len(mitre)
    )

    return {
        'severity_score': severity_score,
        'mitre': mitre,
        'sigma': _sigma,
    }