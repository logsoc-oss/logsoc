"""app/utils/sla_checker.py — SLA breach detection and auto-escalation (Phase 3).

Utility function check_sla_breaches(db) that:
  - For each open alert, computes time since created_at
  - If time > sla_config.resolution_minutes for its severity → set sla_breached=True
  - If severity is critical/high AND time > escalation_minutes AND escalation_level=0
    → escalate (increment escalation_level, log to alert_escalation_log)
  - Returns (breached_count, escalated_count)
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.models import Alert, AlertSlaConfig, AlertEscalationLog


def check_sla_breaches(db: Session) -> dict:
    """Check all open alerts for SLA breaches and auto-escalate where needed.

    Returns dict with keys: breached_count, escalated_count
    """
    now = datetime.now(timezone.utc)

    # Load SLA configs into a dict keyed by severity
    sla_configs = db.query(AlertSlaConfig).all()
    sla_by_severity = {cfg.severity: cfg for cfg in sla_configs}

    if not sla_by_severity:
        return {"breached_count": 0, "escalated_count": 0}

    # Open alerts = status 'new' or 'acknowledged' (not resolved, not false_positive)
    open_alerts = db.query(Alert).filter(
        Alert.status.in_(["new", "acknowledged"])
    ).all()

    breached_count = 0
    escalated_count = 0

    for alert in open_alerts:
        if not alert.created_at:
            continue

        # Make created_at timezone-aware if it's naive (MySQL DATETIME)
        created = alert.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        elapsed = now - created
        elapsed_minutes = elapsed.total_seconds() / 60.0

        cfg = sla_by_severity.get(alert.severity)
        if not cfg:
            continue

        # Check SLA breach: time since creation > resolution_minutes
        if not alert.sla_breached and elapsed_minutes > cfg.resolution_minutes:
            alert.sla_breached = True
            breached_count += 1

        # Check auto-escalation for critical/high severity
        # Only escalate if escalation_level is still 0 and time > escalation_minutes
        if alert.severity in ("critical", "high") and elapsed_minutes > cfg.escalation_minutes:
            if (alert.escalation_level or 0) == 0:
                alert.escalation_level = 1
                alert.escalated_at = now
                # Log to escalation table (escalated_by=NULL means automatic)
                log_entry = AlertEscalationLog(
                    alert_id=alert.id,
                    escalation_level=1,
                    escalated_by=None,  # automatic
                    reason=f"Auto-escalation: {alert.severity} alert exceeded {cfg.escalation_minutes} min SLA",
                )
                db.add(log_entry)
                escalated_count += 1

    db.commit()
    return {"breached_count": breached_count, "escalated_count": escalated_count}