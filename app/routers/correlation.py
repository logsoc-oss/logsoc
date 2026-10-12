"""routers/correlation.py — endpoints for the correlation engine.

GET  /stats          current correlation metrics from ClickHouse
GET  /config         current detection thresholds
PUT  /config         update detection thresholds
POST /scan           run a scan on-demand (does not persist alerts that were already inserted in the last 5 min)
GET  /alerts         recent correlation alerts (from MariaDB)
GET  /rules          list the rule_ids we detect
GET  /mitre/rules        list MITRE-mapped rules (active) with their techniques (v0.6.0)
PATCH /mitre/rules/{rid} toggle is_active on a rule (v0.6.0)
GET  /mitre/coverage     coverage stats grouped by tactic (v0.6.0)
GET  /mitre/navigator    ATT&CK Navigator layer JSON (v0.6.0)
GET  /mitre/alerts       list MITRE-generated alerts (LSOC-*) (v0.6.0)
GET  /ebpf-enriched      eBPF events enriched with journald context via ASOF JOIN (v0.6.4)
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.clickhouse_client import get_client
from app.database import get_db
from app.models import Alert, Rule, MitreRule, User
from app.routers.auth import get_current_user, require_role, require_permission
from pydantic import BaseModel
from app.correlation_engine import (
    get_config, update_config, reset_config, get_stats, run_scan,
    DEFAULT_CONFIG,
)

logger = logging.getLogger("logsoc.correlation")

router = APIRouter()


@router.get("/stats")
def stats(current_user: User = Depends(require_permission("correlation", "read"))):
    """Return current correlation metrics over the configured sliding window."""
    return get_stats()


@router.get("/config")
def get_threshold_config(
    current_user: User = Depends(require_permission("correlation", "read"))):
    """Return the current detection thresholds."""
    return get_config()


@router.put("/config")
def update_threshold_config(payload: dict,
    current_user: User = Depends(require_role("admin"))):
    """Update detection thresholds. Only known keys are accepted."""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Body must be a JSON object")
    unknown = set(payload.keys()) - set(DEFAULT_CONFIG.keys())
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown keys: {unknown}")
    return update_config(payload)


@router.post("/config/reset")
def reset_threshold_config(
    current_user: User = Depends(require_role("admin"))):
    """Reset to default thresholds."""
    return reset_config()


@router.post("/scan")
def trigger_scan(
    current_user: User = Depends(require_role("admin"))):
    """Run an on-demand scan. Returns the scan summary (does not wait for the next interval)."""
    return run_scan()


@router.get("/rules")
def list_rules(
    current_user: User = Depends(require_permission("correlation", "read"))):
    """List the correlation rule_ids emitted by the engine."""
    return {
        "rules": [
            {
                "id": "CORRELATION_DROP",
                "description": "Ratio of eBPF events with journald match fell below threshold over sliding window",
                "default_severity": "high",
            },
            {
                "id": "CORRELATION_MISS",
                "description": "Too many eBPF events without journald counterpart",
                "default_severity": "medium",
            },
            {
                "id": "HIDDEN_PROCESS",
                "description": "Journald entries with valid PID but no eBPF correlate — possible rootkit",
                "default_severity": "critical",
            },
            {
                "id": "LOG_TAMPERING",
                "description": "unlink or modification of /var/log/* paths detected by eBPF",
                "default_severity": "critical",
            },
        ],
        "thresholds": DEFAULT_CONFIG,
    }


@router.get("/alerts")
def list_correlation_alerts(
    rule_id: Optional[str] = Query(None, description="Filter by rule_id prefix (e.g. CORRELATION_)"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    source_host: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("correlation", "read")),
):
    """List recent correlation alerts persisted in MariaDB."""
    q = db.query(Alert).filter(Alert.rule_id.like("CORRELATION_%") | Alert.rule_id.in_(
        ["CORRELATION_DROP", "CORRELATION_MISS", "HIDDEN_PROCESS", "LOG_TAMPERING"]
    ))
    if rule_id:
        q = q.filter(Alert.rule_id == rule_id)
    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    if source_host:
        q = q.filter(Alert.source_host == source_host)
    rows = q.order_by(Alert.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "alert_id": r.alert_id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "status": r.status,
            "rule_id": r.rule_id,
            "source_host": r.source_host,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "related_log_ids": r.related_log_ids,
        }
        for r in rows
    ]


# ── MITRE ATT&CK endpoints (v0.6.0) ──

@router.get("/mitre/rules")
def list_mitre_rules(
    include_inactive: bool = Query(False, description="Include disabled rules"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List all MITRE-mapped rules from `rules` + `mitre_rules`.

    Returns one entry per parent rule, with aggregated technique mappings.
    """
    q = db.query(Rule)
    if not include_inactive:
        q = q.filter(Rule.is_active == 1)
    rules = q.order_by(Rule.rule_id).all()

    result = []
    for r in rules:
        mappings = db.query(MitreRule).filter(
            MitreRule.rule_id == r.rule_id,
            MitreRule.is_sub_rule == 0,
        ).all()
        result.append({
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "is_active": bool(r.is_active),
            "techniques": [
                {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name,
                    "tactic": m.tactic,
                    "detection_source": m.detection_source,
                    "query_template": m.query_template,
                    "notes": m.notes,
                }
                for m in mappings
            ],
        })
    return {
        "count": len(result),
        "active_count": sum(1 for r in result if r["is_active"]),
        "rules": result,
    }


@router.patch("/mitre/rules/{rule_id}")
def toggle_mitre_rule(rule_id: str, payload: dict, db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))):
    """Toggle is_active on a rule. Body: {"is_active": true|false}."""
    rule = db.query(Rule).filter(Rule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    if "is_active" not in payload:
        raise HTTPException(status_code=400, detail="Body must contain 'is_active' boolean")
    rule.is_active = 1 if payload["is_active"] else 0
    db.commit()
    return {"rule_id": rule_id, "is_active": bool(rule.is_active)}


@router.get("/mitre/coverage")
def mitre_coverage(db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    """Return MITRE ATT&CK coverage grouped by tactic.

    Each entry lists:
    - techniques: set of technique_ids covered by active rules
    - rules:      rule_ids contributing to coverage
    - count:      number of unique techniques
    """
    rows = (
        db.query(MitreRule, Rule)
        .join(Rule, MitreRule.rule_id == Rule.rule_id)
        .filter(Rule.is_active == 1, MitreRule.is_sub_rule == 0)
        .all()
    )
    by_tactic: dict = defaultdict(lambda: {"techniques": set(), "rules": set()})
    for m, r in rows:
        by_tactic[m.tactic]["techniques"].add(m.technique_id)
        by_tactic[m.tactic]["rules"].add(r.rule_id)
    out = {}
    total_techs = set()
    for tactic, info in sorted(by_tactic.items()):
        out[tactic] = {
            "count": len(info["techniques"]),
            "techniques": sorted(info["techniques"]),
            "rule_count": len(info["rules"]),
            "rules": sorted(info["rules"]),
        }
        total_techs.update(info["techniques"])
    return {
        "tactics": out,
        "total_unique_techniques": len(total_techs),
        "total_tactics_covered": len(out),
    }


@router.get("/mitre/navigator")
def mitre_navigator(db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user"))):
    """Return ATT&CK Navigator layer JSON (v4.2 format).

    Compatible with https://mitre-attack.github.io/attack-navigator/
    """
    rows = (
        db.query(MitreRule, Rule)
        .join(Rule, MitreRule.rule_id == Rule.rule_id)
        .filter(Rule.is_active == 1, MitreRule.is_sub_rule == 0)
        .all()
    )
    techniques = []
    for m, r in rows:
        # Color by severity
        color_map = {
            "critical": "#ff0000",
            "high": "#ff6666",
            "medium": "#ffaa00",
            "low": "#ffff00",
        }
        techniques.append({
            "techniqueID": m.technique_id,
            "tactic": m.tactic,
            "color": color_map.get(r.severity or "medium", "#ffaa00"),
            "comment": f"{r.rule_id} [{r.severity}] via {m.detection_source}",
            "enabled": True,
            "score": {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(r.severity, 2),
        })
    return {
        "version": "4.2",
        "name": "LogSOC Coverage",
        "domain": "enterprise-attack",
        "description": "LogSOC SIEM detection coverage — MITRE ATT&CK mapping (Linux)",
        "gradient": {
            "colors": ["#ffffff", "#ffff00", "#ffaa00", "#ff6666", "#ff0000"],
            "minValue": 1,
            "maxValue": 4,
        },
        "techniques": techniques,
        "legendItems": [
            {"label": "Critical detection", "color": "#ff0000"},
            {"label": "High detection", "color": "#ff6666"},
            {"label": "Medium detection", "color": "#ffaa00"},
            {"label": "Low detection", "color": "#ffff00"},
        ],
        "metadata": [
            {"name": "Platform", "value": "Linux"},
            {"name": "SOC Version", "value": "LogSOC v0.6.0"},
            {"name": "Date", "value": "2026-06-02"},
        ],
    }


@router.get("/mitre/alerts")
def list_mitre_alerts(
    rule_id: Optional[str] = Query(None, description="Filter by rule_id (e.g. LSOC-001)"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    source_host: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List alerts generated by MITRE-mapped rules (rule_id LIKE 'LSOC-%')."""
    q = db.query(Alert).filter(Alert.rule_id.like("LSOC-%"))
    if rule_id:
        q = q.filter(Alert.rule_id == rule_id)
    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    if source_host:
        q = q.filter(Alert.source_host == source_host)
    rows = q.order_by(Alert.created_at.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "alerts": [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "title": r.title,
                "description": r.description,
                "severity": r.severity,
                "status": r.status,
                "rule_id": r.rule_id,
                "source_host": r.source_host,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


# ── eBPF ↔ journald correlation (v0.6.4) ──

@router.get("/ebpf-enriched")
def ebpf_enriched(
    since: str = Query("24h", description="Time window: e.g. '1h', '24h', '7d', or ISO timestamp"),
    limit: int = Query(100, le=500, description="Max rows to return"),
    journald_match: Optional[int] = Query(None, description="Filter: 1=matched, 0=unmatched"),
    source_host: Optional[str] = Query(None, description="Filter by source_host"),
    ev_type: Optional[str] = Query(None, description="Filter by event type (open, execve, fim, ...)"),
    current_user: User = Depends(require_role("user")),
):
    """eBPF events enriched with journald context via ClickHouse ASOF JOIN.
    
    Returns eBPF events with the nearest matching journald entry (same host, same PID,
    within ±2s time window). journald_match=1 means a journald correlate was found;
    journald_match=0 means no journald entry matched within the window (NORMAL status,
    not an alert — many legitimate processes simply don't log to journald).
    
    Requires Bearer token auth.
    """
    # Parse since parameter
    interval_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
    hours = interval_map.get(since, 24)
    
    try:
        client = get_client()
        # Query the v_correlation_ebpf_journald view with time filter
        conditions = [f"received_at >= now() - INTERVAL {hours} HOUR"]
        if journald_match is not None:
            conditions.append(f"journald_match = {int(journald_match)}")
        if source_host:
            conditions.append(f"source_host = '{source_host}'")
        if ev_type:
            conditions.append(f"ev_type = '{ev_type}'")
        
        where_clause = " AND ".join(conditions)
        sql = f"""
        SELECT received_at, source_host, pid, ev_type, comm, filename,
               journald_match, journald_unit, journald_identifier,
               journald_message, correlation_window_ms
        FROM logsoc.v_correlation_ebpf_journald
        WHERE {where_clause}
        ORDER BY received_at DESC
        LIMIT {min(limit, 500)}
        """
        result = client.query(sql)
        rows = result.result_rows
    except Exception as e:
        logger.error("ClickHouse query for ebpf-enriched failed: %s", e)
        raise HTTPException(status_code=503, detail=f"ClickHouse query failed: {str(e)}")
    
    return {
        "count": len(rows),
        "since_hours": hours,
        "rows": [
            {
                "received_at": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                "source_host": row[1] or "",
                "pid": int(row[2]) if row[2] else 0,
                "ev_type": row[3] or "",
                "comm": row[4] or "",
                "filename": row[5] or "",
                "journald_match": int(row[6]) if row[6] else 0,
                "journald_unit": row[7] or "",
                "journald_identifier": row[8] or "",
                "journald_message": row[9] or "",
                "correlation_window_ms": int(row[10]) if row[10] else 0,
            }
            for row in rows
        ],
    }


# ── Custom Detection Rules (Phase 4) ──────────────────────────────

import uuid as _uuid
import json as _json


class CustomRuleCreate(BaseModel):
    name: str
    description: str | None = None
    query: str
    severity: str = "medium"
    mitre_techniques: list[str] | None = None
    exceptions: str | None = None  # JSON string: {"ignore_ips": [], "ignore_users": [], "ignore_paths": [], "ignore_hours": []}
    is_template: bool | None = None


class CustomRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    query: str | None = None
    severity: str | None = None
    is_active: bool | None = None
    mitre_techniques: list[str] | None = None
    exceptions: str | None = None  # JSON string
    is_template: bool | None = None


@router.get("/rules/custom")
def list_custom_rules(
    include_inactive: bool = Query(False, description="Include disabled rules"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("user")),
):
    """List custom and template detection rules stored in the `rules` table.
    
    Returns both CUSTOM- prefixed rules and TPL- prefixed template rules.
    """
    q = db.query(Rule).filter(
        (Rule.rule_id.like("CUSTOM-%")) | (Rule.rule_id.like("TPL-%"))
    )
    if not include_inactive:
        q = q.filter(Rule.is_active == 1)
    rules = q.order_by(Rule.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "query": r.pattern,
                "condition_logic": r.condition_logic,
                "is_active": bool(r.is_active),
                "is_template": bool(r.is_template) if r.is_template is not None else False,
                "exceptions": (_json.loads(r.exceptions) if r.exceptions and r.exceptions.strip().startswith("{") else None),
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rules
        ],
    }


@router.post("/rules/custom", status_code=201)
def create_custom_rule(
    payload: CustomRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Create a custom detection rule (soc_analyst+).

    Stores the rule in the `rules` table with a CUSTOM- prefixed rule_id.
    The `query` field is stored in the `pattern` column (SQL WHERE fragment).
    Optionally attaches MITRE technique mappings.
    """
    valid_severities = ("low", "medium", "high", "critical")
    if payload.severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {valid_severities}",
        )

    rule_id = f"CUSTOM-{_uuid.uuid4().hex[:8].upper()}"
    rule = Rule(
        rule_id=rule_id,
        name=payload.name,
        description=payload.description or "",
        severity=payload.severity,
        pattern=payload.query,
        condition_logic="custom",
        action="{}",
        is_active=True,
        created_by=current_user.id,
        exceptions=payload.exceptions if payload.exceptions else None,
        is_template=payload.is_template if payload.is_template is not None else False,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    # Optionally create MITRE mappings
    if payload.mitre_techniques:
        for technique_id in payload.mitre_techniques:
            mitre_rule = MitreRule(
                rule_id=rule_id,
                technique_id=technique_id,
                technique_name=technique_id,  # Will be enriched later
                tactic="custom",
                detection_source="correlation",
                query_template=payload.query,
                is_sub_rule=False,
            )
            db.add(mitre_rule)
        db.commit()

    return {
        "id": rule.id,
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "query": rule.pattern,
        "is_active": bool(rule.is_active),
        "is_template": bool(rule.is_template) if rule.is_template is not None else False,
        "exceptions": (_json.loads(rule.exceptions) if rule.exceptions and rule.exceptions.strip().startswith("{") else None),
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "mitre_techniques": payload.mitre_techniques or [],
    }


@router.put("/rules/custom/{rule_id}")
def update_custom_rule(
    rule_id: int,
    payload: CustomRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("soc_analyst")),
):
    """Update a custom detection rule (soc_analyst+)."""
    rule = db.query(Rule).filter(Rule.id == rule_id, (Rule.rule_id.like("CUSTOM-%") | Rule.rule_id.like("TPL-%"))).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom rule not found")

    if payload.name is not None:
        rule.name = payload.name
    if payload.description is not None:
        rule.description = payload.description
    if payload.query is not None:
        rule.pattern = payload.query
        # Also update any MITRE mapping query_templates
        db.query(MitreRule).filter(
            MitreRule.rule_id == rule.rule_id,
        ).update({"query_template": payload.query})
    if payload.severity is not None:
        valid = ("low", "medium", "high", "critical")
        if payload.severity not in valid:
            raise HTTPException(status_code=400, detail=f"Invalid severity. Must be one of: {valid}")
        rule.severity = payload.severity
    if payload.is_active is not None:
        rule.is_active = 1 if payload.is_active else 0
    if payload.exceptions is not None:
        rule.exceptions = payload.exceptions
    if payload.is_template is not None:
        rule.is_template = 1 if payload.is_template else 0
    db.commit()
    db.refresh(rule)

    return {
        "id": rule.id,
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "query": rule.pattern,
        "is_active": bool(rule.is_active),
        "is_template": bool(rule.is_template) if rule.is_template is not None else False,
        "exceptions": (_json.loads(rule.exceptions) if rule.exceptions and rule.exceptions.strip().startswith("{") else None),
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


@router.delete("/rules/custom/{rule_id}")
def delete_custom_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a custom detection rule (admin only)."""
    rule = db.query(Rule).filter(Rule.id == rule_id, (Rule.rule_id.like("CUSTOM-%") | Rule.rule_id.like("TPL-%"))).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom rule not found")
    # Delete associated MITRE mappings first
    db.query(MitreRule).filter(MitreRule.rule_id == rule.rule_id).delete()
    db.delete(rule)
    db.commit()
    return {"detail": "Custom rule deleted", "id": rule_id}
