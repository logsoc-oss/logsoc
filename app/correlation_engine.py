"""correlation_engine.py — v0.3 backend correlation analyzer.

Reads from ClickHouse siem_logs, computes sliding-window correlation metrics,
detects anomalies (CORRELATION_DROP, CORRELATION_MISS, HIDDEN_PROCESS, LOG_TAMPERING),
persists alerts in MariaDB.

Spec: the agent FLAGS events (journald_match, ebpf_match) — the backend DECIDES
when those flags warrant an alert.

Architecture: this module runs in a background asyncio task, started by lifespan
in main.py. It scans ClickHouse on a configurable interval (default 30s).
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.clickhouse_client import get_client
from app.database import SessionLocal
from app.models import Alert

logger = logging.getLogger("logsoc.correlation")


# ── Thresholds (configurable via /api/v1/correlation/config) ──
DEFAULT_CONFIG = {
    "scan_interval_sec": 30,
    "window_minutes": 5,
    "ratio_threshold": 0.90,        # < this ratio over window => CORRELATION_DROP
    "miss_count_threshold": 10,     # > this many mismatches in window => CORRELATION_MISS
    "hidden_process_threshold": 3,  # > this many journald entries without eBPF match => HIDDEN_PROCESS
    "tamper_paths": [               # paths whose deletion = LOG_TAMPERING
        "/var/log/", "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"
    ],
    "enabled": True,
    # ── v0.6.3 — detector toggles ──
    # CORRELATION_DROP and CORRELATION_MISS use fixed thresholds on the eBPF/journald
    # ratio. That logic is INVERTED: eBPF inherently captures more than journald
    # (kernel-level syscalls vs user-level logging), so the ratio is expected to
    # be < 100% on a healthy system. The old thresholds generated 1904 false
    # positives in 24h. Reactivation requires a baseline-based implementation
    # (see docs/correlation-ebpf-journald.md, task 4). HIDDEN_PROCESS remains
    # the only valid correlation rule (journald without eBPF = rootkit signal).
    "correlation_drop_enabled": False,   # v0.6.3 — disabled (logic inverted)
    "correlation_miss_enabled": False,   # v0.6.3 — disabled (logic inverted)
    "hidden_process_enabled":  False,     # v0.7 — disabled (ebpf_match never set for journald events; 61k false positives)
    "log_tampering_enabled":  True,
    "mitre_rules_enabled":    True,
    # v0.7: AppArmor noise filtering
    "exclude_apparmor_allowed": True,     # exclude apparmor-allowed tagged events from all detectors
    "exclude_self_noise":      True,      # exclude self-noise tagged events from all detectors
}


# In-memory state (per process)
_state = {
    "config": dict(DEFAULT_CONFIG),
    "last_scan_at": None,
    "last_alerts": [],   # last batch of alerts emitted
    "stats_history": [], # recent snapshots
}


def get_config() -> Dict[str, Any]:
    return dict(_state["config"])


def update_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in updates.items():
        if k in DEFAULT_CONFIG:
            _state["config"][k] = v
    return get_config()


def reset_config() -> Dict[str, Any]:
    _state["config"] = dict(DEFAULT_CONFIG)
    return get_config()


def _query_clickhouse(sql: str, params: Optional[dict] = None) -> List[tuple]:
    """Execute a ClickHouse query and return result_rows."""
    try:
        client = get_client()
        result = client.query(sql, parameters=params or {})
        return result.result_rows
    except Exception as e:
        logger.error("ClickHouse query failed: %s", e)
        return []


def _persist_alert(db: Session, alert_data: Dict[str, Any]) -> Optional[int]:
    """Insert an alert into MariaDB. Returns the alert_id (UUID) or None on dup."""
    # Dedupe: don't insert if an alert with same rule_id + source_host + same fingerprint in last 5 min
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    existing = db.query(Alert).filter(
        Alert.rule_id == alert_data["rule_id"],
        Alert.source_host == alert_data.get("source_host", ""),
        Alert.title == alert_data["title"],
        Alert.created_at >= cutoff,
    ).first()
    if existing:
        return None

    alert = Alert(
        alert_id=str(uuid.uuid4()),
        severity=alert_data["severity"],
        status="new",
        title=alert_data["title"],
        description=alert_data["description"],
        source_host=alert_data.get("source_host", ""),
        rule_id=alert_data["rule_id"],
        related_log_ids=json.dumps(alert_data.get("related_log_ids", []))[:65000],
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert.id


# ── Detection routines ──
def detect_correlation_drop(window_min: int, threshold: float) -> List[Dict[str, Any]]:
    """For each host, compute the ratio of eBPF events with journald_match=1
    over the last `window_min` minutes. If ratio < threshold, emit CORRELATION_DROP."""
    alerts = []
    rows = _query_clickhouse(f"""
        SELECT source_host,
               count() AS total_ebpf,
               countIf(journald_match = 1) AS matched,
               countIf(journald_match = 0) AS unmatched,
               if(count() = 0, 1.0, countIf(journald_match = 1) / count()) AS ratio
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL {int(window_min)} MINUTE
          AND service = 'ebpf'
        GROUP BY source_host
        HAVING total_ebpf >= 20
    """)
    for row in rows:
        host, total, matched, unmatched, ratio = row
        ratio = float(ratio)
        if ratio < threshold and unmatched > 5:
            alerts.append({
                "rule_id": "CORRELATION_DROP",
                "severity": "critical" if ratio < 0.70 else "high",
                "title": f"eBPF/journald correlation dropped to {ratio*100:.0f}% on {host}",
                "description": (
                    f"Over the last {window_min} minutes, {host} produced {total} eBPF events "
                    f"but only {matched} ({ratio*100:.1f}%) have a matching journald entry. "
                    f"{unmatched} events have NO journald counterpart, suggesting log suppression "
                    f"or a rootkit hiding eBPF events. Threshold: {threshold*100:.0f}%."
                ),
                "source_host": host,
                "related_log_ids": [],
                "stats": {
                    "total_ebpf": int(total),
                    "matched": int(matched),
                    "unmatched": int(unmatched),
                    "ratio": ratio,
                    "window_min": window_min,
                },
            })
    return alerts


def detect_correlation_miss(window_min: int, miss_count_threshold: int) -> List[Dict[str, Any]]:
    """Detect hosts with too many consecutive eBPF events without journald match."""
    alerts = []
    rows = _query_clickhouse(f"""
        SELECT source_host, countIf(journald_match = 0) AS misses
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL {int(window_min)} MINUTE
          AND service = 'ebpf'
        GROUP BY source_host
        HAVING misses > {int(miss_count_threshold)}
    """)
    for row in rows:
        host, misses = row
        alerts.append({
            "rule_id": "CORRELATION_MISS",
            "severity": "high" if misses > miss_count_threshold * 3 else "medium",
            "title": f"{misses} eBPF events without journald correlate on {host}",
            "description": (
                f"Over the last {window_min} minutes, {host} had {misses} eBPF events "
                f"with no journald counterpart (>{miss_count_threshold}). "
                f"This may indicate an attacker clearing journald entries or "
                f"a service that's not logging its activities."
            ),
            "source_host": host,
            "related_log_ids": [],
            "stats": {
                "misses": int(misses),
                "window_min": window_min,
                "threshold": miss_count_threshold,
            },
        })
    return alerts


def detect_hidden_process(window_min: int, threshold: int) -> List[Dict[str, Any]]:
    """Detect journald entries with pid that have NO eBPF correlate — possible rootkit.

    v0.7: Added tag-based exclusions for apparmor-allowed and self-noise events.
    """
    alerts = []
    rows = _query_clickhouse(f"""
        SELECT source_host, countIf(ebpf_match = 0) AS journald_unmatched
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL {int(window_min)} MINUTE
          AND service = 'journald'
          AND pid > 0
          AND NOT has(tags, 'apparmor-allowed')
          AND NOT has(tags, 'self-noise')
          AND NOT has(tags, 'no-alert')
        GROUP BY source_host
        HAVING journald_unmatched > {int(threshold)}
    """)
    for row in rows:
        host, unmatched = row
        alerts.append({
            "rule_id": "HIDDEN_PROCESS",
            "severity": "critical",
            "title": f"{unmatched} journald entries without eBPF correlate on {host}",
            "description": (
                f"Over the last {window_min} minutes, {host} had {unmatched} journald entries "
                f"with a valid PID but no matching eBPF event. This STRONGLY suggests "
                f"a rootkit or process hiding that bypasses the BPF tracepoints. "
                f"Investigate immediately."
            ),
            "source_host": host,
            "related_log_ids": [],
            "stats": {
                "journald_unmatched": int(unmatched),
                "window_min": window_min,
                "threshold": threshold,
            },
        })
    return alerts


def detect_log_tampering(tamper_paths: List[str]) -> List[Dict[str, Any]]:
    """Detect unlink/open events on log file paths."""
    if not tamper_paths:
        return []
    alerts = []
    # Build the path filter
    path_filters = " OR ".join([f"filename LIKE '{p}%'" for p in tamper_paths])
    rows = _query_clickhouse(f"""
        SELECT source_host, event, comm, pid, filename, count() AS occurrences
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL 5 MINUTE
          AND service = 'ebpf'
          AND event IN ('unlink', 'fim')
          AND ({path_filters})
          AND NOT has(tags, 'apparmor-allowed')
          AND NOT has(tags, 'self-noise')
          AND NOT has(tags, 'no-alert')
        GROUP BY source_host, event, comm, pid, filename
        HAVING occurrences >= 1
    """)
    for row in rows:
        host, event, comm, pid, filename, occurrences = row
        if event == "unlink":
            severity = "critical"
            title = f"Log file deleted: {filename} on {host}"
        else:
            severity = "high"
            title = f"Log file modified: {filename} on {host}"
        alerts.append({
            "rule_id": "LOG_TAMPERING",
            "severity": severity,
            "title": title,
            "description": (
                f"eBPF detected {event} on log path '{filename}' "
                f"by process {comm} (pid={pid}) on {host}. "
                f"Count: {occurrences}. This may indicate log tampering."
            ),
            "source_host": host,
            "related_log_ids": [],
            "stats": {
                "event": event,
                "comm": comm,
                "pid": int(pid),
                "filename": filename,
                "occurrences": int(occurrences),
            },
        })
    return alerts


# ── MITRE ATT&CK Rules (v0.6.0) ──
def detect_mitre_rules(window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Execute MITRE-mapped rules from `rules` + `mitre_rules` against ClickHouse.

    Loads active rules at scan time (so DB changes are picked up live),
    runs each query_template with a configurable window, and emits alerts
    for the parent rule_id. Sub-rules (e.g. LSOC-010 step 2) are skipped
    here — they will be wired with full correlation in v0.7.
    """
    from app.models import Rule, MitreRule  # lazy import to avoid circular

    alerts: List[Dict[str, Any]] = []
    window_sec = max(int(window_minutes * 60), 60)
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()

    db = SessionLocal()
    try:
        # Load active rules + their mitre mappings
        parent_mappings = (
            db.query(MitreRule, Rule)
            .join(Rule, MitreRule.rule_id == Rule.rule_id)
            .filter(Rule.is_active == 1)
            .filter(MitreRule.is_sub_rule == 0)
            .all()
        )
        logger.info("MITRE: loaded %d active rule mappings", len(parent_mappings))
    finally:
        db.close()

    if not parent_mappings:
        return alerts

    # Group by rule_id (one rule can have multiple technique mappings)
    by_rule: Dict[str, Dict[str, Any]] = {}
    for m, r in parent_mappings:
        rid = r.rule_id
        if rid not in by_rule:
            by_rule[rid] = {
                "rule_id": rid,
                "name": r.name,
                "severity": r.severity or "medium",
                "description": r.description or "",
                "techniques": [],
                "templates": [],
            }
        by_rule[rid]["techniques"].append(
            f"{m.technique_id} ({m.technique_name}, {m.tactic})"
        )
        by_rule[rid]["templates"].append(m.query_template)

    for rid, info in by_rule.items():
        # Combine all templates for this rule with OR
        # Each template is a complete WHERE clause fragment
        where_clauses = " OR ".join(f"({t})" for t in info["templates"])
        # No GROUP BY — fetch raw matching events, group in Python.
        # Simpler than ClickHouse strict-mode gymnastics over arbitrary templates.
        sql = f"""
        SELECT
            event, comm, filename, pid, uid, message, source_host, source_ip, dst_ip, dst_port,
            received_at
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL {window_sec} SECOND
          AND ({where_clauses})
          AND NOT has(tags, 'no-alert')
        ORDER BY received_at DESC
        LIMIT 200
        """
        try:
            rows = _query_clickhouse(sql)
        except Exception as e:
            logger.error("MITRE rule %s query failed: %s", rid, e)
            continue

        if not rows:
            continue

        # Group rows by source_host in Python
        by_host: Dict[str, List[tuple]] = {}
        for row in rows:
            sh = row[6] or "unknown"
            by_host.setdefault(sh, []).append(row)

        for source_host, host_rows in by_host.items():
            n_events = len(host_rows)
            first_seen = host_rows[-1][10]  # oldest of the (sorted DESC) batch
            last_seen = host_rows[0][10]   # newest
            # Sample from most recent
            sample = host_rows[0]
            (event, comm, filename, pid, uid, message,
             _sh, source_ip, dst_ip, dst_port, _received) = sample
            title = f"[{rid}] {info['name']}"
            desc_lines = [
                f"MITRE: {', '.join(info['techniques'])}",
                f"Source host: {source_host}",
                f"Events in last {window_minutes}min: {n_events}",
                f"First seen: {first_seen}",
                f"Last seen: {last_seen}",
                f"Sample: {str(message)[:200]}",
            ]
            if filename:
                desc_lines.append(f"Filename: {filename}")
            if dst_ip and dst_port:
                desc_lines.append(f"Connection: {dst_ip}:{dst_port}")
            if pid and uid:
                desc_lines.append(f"Process: comm={comm} pid={pid} uid={uid}")
            alerts.append({
                "rule_id": rid,
                "severity": info["severity"],
                "title": title,
                "description": "\n".join(desc_lines),
                "source_host": source_host or "",
                "related_log_ids": [],
                "stats": {
                    "rule_id": rid,
                    "techniques": info["techniques"],
                    "n_events": int(n_events),
                    "event": event,
                    "comm": comm,
                    "filename": filename,
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port) if dst_port else 0,
                    "pid": int(pid) if pid else 0,
                    "uid": int(uid) if uid else 0,
                    "first_seen": str(first_seen),
                    "last_seen": str(last_seen),
                },
            })
    return alerts


def run_scan() -> Dict[str, Any]:
    """Run all detectors once. Returns a summary dict.

    v0.6.3: each detector is gated by an `*_enabled` flag in DEFAULT_CONFIG.
    CORRELATION_DROP and CORRELATION_MISS are disabled by default — their
    fixed-threshold logic on the eBPF/journald ratio is inverted (eBPF always
    captures more than journald, so the ratio is expected to be < 100%).
    Re-enable them only when a baseline-based implementation lands.
    """
    cfg = get_config()
    if not cfg["enabled"]:
        return {"skipped": True, "reason": "disabled"}

    started = time.time()
    all_alerts: List[Dict[str, Any]] = []
    try:
        if cfg.get("correlation_drop_enabled", False):
            all_alerts.extend(detect_correlation_drop(cfg["window_minutes"], cfg["ratio_threshold"]))
        if cfg.get("correlation_miss_enabled", False):
            all_alerts.extend(detect_correlation_miss(cfg["window_minutes"], cfg["miss_count_threshold"]))
        if cfg.get("hidden_process_enabled", False):
            all_alerts.extend(detect_hidden_process(cfg["window_minutes"], cfg["hidden_process_threshold"]))
        if cfg.get("log_tampering_enabled", True):
            all_alerts.extend(detect_log_tampering(cfg["tamper_paths"]))
        if cfg.get("mitre_rules_enabled", True):
            all_alerts.extend(detect_mitre_rules(cfg["window_minutes"]))
    except Exception as e:
        logger.exception("Scan error: %s", e)
        return {"error": str(e)}

    # Persist
    db = SessionLocal()
    inserted = 0
    try:
        for a in all_alerts:
            try:
                rid = _persist_alert(db, a)
                if rid is not None:
                    inserted += 1
            except Exception as e:
                logger.warning("Failed to persist alert %s: %s", a.get("title"), e)
                db.rollback()
    finally:
        db.close()

    summary = {
        "scan_started_at": datetime.now(timezone.utc).isoformat() + "Z",
        "scan_duration_ms": int((time.time() - started) * 1000),
        "alerts_detected": len(all_alerts),
        "alerts_inserted": inserted,
        "config_used": cfg,
    }
    _state["last_scan_at"] = summary["scan_started_at"]
    _state["last_alerts"] = all_alerts
    return summary


def get_stats() -> Dict[str, Any]:
    """Return current ratio/metrics from ClickHouse."""
    cfg = get_config()
    win = cfg["window_minutes"]

    ebpf_rows = _query_clickhouse(f"""
        SELECT count() AS total,
               countIf(journald_match = 1) AS matched,
               countIf(journald_match = 0) AS unmatched,
               if(count() = 0, 1.0, countIf(journald_match = 1) / count()) AS ratio
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL {int(win)} MINUTE
          AND service = 'ebpf'
    """)
    jrn_rows = _query_clickhouse(f"""
        SELECT count() AS total,
               countIf(ebpf_match = 1) AS matched,
               countIf(ebpf_match = 0) AS unmatched,
               if(count() = 0, 1.0, countIf(ebpf_match = 1) / count()) AS ratio
        FROM logsoc.siem_logs
        WHERE received_at >= now() - INTERVAL {int(win)} MINUTE
          AND service = 'journald'
          AND pid > 0
    """)

    ebpf_total, ebpf_matched, ebpf_unmatched, ebpf_ratio = (
        (int(ebpf_rows[0][0]), int(ebpf_rows[0][1]), int(ebpf_rows[0][2]), float(ebpf_rows[0][3]))
        if ebpf_rows else (0, 0, 0, 1.0)
    )
    jrn_total, jrn_matched, jrn_unmatched, jrn_ratio = (
        (int(jrn_rows[0][0]), int(jrn_rows[0][1]), int(jrn_rows[0][2]), float(jrn_rows[0][3]))
        if jrn_rows else (0, 0, 0, 1.0)
    )

    return {
        "window_minutes": win,
        "last_scan_at": _state["last_scan_at"],
        "ebpf": {
            "total": ebpf_total,
            "matched": ebpf_matched,
            "unmatched": ebpf_unmatched,
            "match_ratio": ebpf_ratio,
        },
        "journald": {
            "total": jrn_total,
            "matched": jrn_matched,
            "unmatched": jrn_unmatched,
            "match_ratio": jrn_ratio,
        },
        "thresholds": {
            "ratio_threshold": cfg["ratio_threshold"],
            "miss_count_threshold": cfg["miss_count_threshold"],
            "hidden_process_threshold": cfg["hidden_process_threshold"],
        },
    }


# ── Background task ──
async def correlation_worker(stop_event: asyncio.Event):
    """Background asyncio task: scan every scan_interval_sec."""
    cfg = get_config()
    logger.info("Correlation worker started (interval=%ds, window=%dmin)",
                cfg["scan_interval_sec"], cfg["window_minutes"])
    while not stop_event.is_set():
        try:
            summary = run_scan()
            logger.info("Correlation scan: detected=%d inserted=%d duration=%dms",
                        summary.get("alerts_detected", 0),
                        summary.get("alerts_inserted", 0),
                        summary.get("scan_duration_ms", 0))
        except Exception as e:
            logger.exception("Correlation worker error: %s", e)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=cfg["scan_interval_sec"])
        except asyncio.TimeoutError:
            pass
        # Re-read config each loop
        cfg = get_config()
    logger.info("Correlation worker stopped")
