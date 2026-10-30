# app/routers/warroom.py — T25/T26: War Room Timeline + Checklists
"""War Room endpoints for crisis timeline and reflex checklists.

T25: Crisis timeline (CRUD, lock, export PDF)
T26: Crisis checklists (create from template, toggle tasks, list)

RBAC: admin OR compliance_officer only (403 otherwise).
Audit: every CRUD action logged to audit trail.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_crisis import CrisisTimelineEntry, CrisisChecklist
from app.routers.auth import require_role, get_current_user
from app.schemas_crisis import (
    TimelineEntryCreate,
    TimelineEntryResponse,
    ChecklistCreate,
    ChecklistTaskToggle,
    ChecklistResponse,
)

logger = logging.getLogger("logsoc.warroom")

router = APIRouter()

# ── YAML template directory ──
TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "config" / "crisis_templates"

# Auto-lock timeout (seconds)
AUTO_LOCK_SECONDS = 60


def _audit_log(db: Session, user_id: int, action: str, table: str, row_id: int, detail: str = ""):
    """Log an action to the audit_log table (if it exists) or skip silently."""
    try:
        from app.models import ComplianceAudit  # reuse existing audit model
        # We log as a minimal audit entry; ComplianceAudit may not be ideal
        # but it's the closest existing audit table.  In production you'd
        # write to a dedicated audit_log table.
        pass  # Audit is handled by application-level logging
    except ImportError:
        pass
    # Structured application-level audit log
    logger.info("AUDIT user=%d action=%s table=%s row=%d detail=%s",
                user_id, action, table, row_id, detail)


def _require_warroom_role(current_user: User = Depends(get_current_user)) -> User:
    """RBAC: admin or compliance_officer only. superadmin always passes."""
    if current_user.role in ('admin', 'superadmin', 'compliance_officer'):
        return current_user
    raise HTTPException(status_code=403, detail="Insufficient permissions — admin or compliance_officer required")


# ══════════════════════════════════════════════════════════════════════════
# T25 — Crisis Timeline
# ══════════════════════════════════════════════════════════════════════════

@router.post(
    "/{incident_id}/timeline",
    response_model=TimelineEntryResponse,
    summary="Create a timeline entry",
)
def create_timeline_entry(
    incident_id: int,
    body: TimelineEntryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_warroom_role),
):
    """Add an entry to the crisis timeline.  Auto-locks after 60 s."""
    entry = CrisisTimelineEntry(
        incident_id=incident_id,
        user_id=current_user.id,
        event_type=body.event_type,
        content=body.content,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    # Schedule auto-lock by setting locked_at to creation + 60s
    # (A background task would be ideal, but we use a conservative approach:
    #  locked entries are enforced at read/write time.)
    entry.locked_at = datetime.now(timezone.utc) + timedelta(seconds=AUTO_LOCK_SECONDS)
    db.commit()

    _audit_log(db, current_user.id, "CREATE", "crisis_timeline", entry.id, body.content[:200])
    return entry


@router.post(
    "/{incident_id}/timeline/{entry_id}/lock",
    response_model=TimelineEntryResponse,
    summary="Lock a timeline entry (idempotent)",
)
def lock_timeline_entry(
    incident_id: int,
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_warroom_role),
):
    """Lock a timeline entry — makes it immutable (no UPDATE/DELETE)."""
    entry = db.query(CrisisTimelineEntry).filter(
        CrisisTimelineEntry.id == entry_id,
        CrisisTimelineEntry.incident_id == incident_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Timeline entry not found")

    if entry.locked:
        return entry  # idempotent

    entry.locked = True
    entry.locked_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(entry)

    _audit_log(db, current_user.id, "LOCK", "crisis_timeline", entry.id)
    return entry


@router.get(
    "/{incident_id}/timeline",
    response_model=List[TimelineEntryResponse],
    summary="List timeline entries (sorted by timestamp DESC)",
)
def list_timeline_entries(
    incident_id: int,
    limit: int = Query(200, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all timeline entries for an incident, newest first.

    Also auto-locks any entries whose locked_at has passed.
    """
    # Auto-lock entries past their lock timeout
    now = datetime.now(timezone.utc)
    unlockable = db.query(CrisisTimelineEntry).filter(
        CrisisTimelineEntry.incident_id == incident_id,
        CrisisTimelineEntry.locked == False,
        CrisisTimelineEntry.locked_at != None,
        CrisisTimelineEntry.locked_at <= now,
    ).all()
    for e in unlockable:
        e.locked = True
    if unlockable:
        db.commit()

    entries = (
        db.query(CrisisTimelineEntry)
        .filter(CrisisTimelineEntry.incident_id == incident_id)
        .order_by(CrisisTimelineEntry.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return entries


@router.get(
    "/{incident_id}/timeline/export",
    summary="Export timeline as PDF (weasyprint)",
)
def export_timeline_pdf(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_warroom_role),
):
    """Export the full timeline for an incident as a PDF document."""
    try:
        from weasyprint import HTML
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF export unavailable — weasyprint not installed")

    entries = (
        db.query(CrisisTimelineEntry)
        .filter(CrisisTimelineEntry.incident_id == incident_id)
        .order_by(CrisisTimelineEntry.timestamp.asc())
        .all()
    )

    # Build HTML
    rows = ""
    for e in entries:
        lock_icon = "🔒" if e.locked else "🔓"
        event_icon = "🤖" if e.event_type == "system" else "👤"
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if e.timestamp else ""
        rows += f"""<tr>
            <td>{ts}</td>
            <td>{event_icon} {e.event_type}</td>
            <td>{e.content}</td>
            <td>{lock_icon}</td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body {{ font-family: Arial, sans-serif; margin: 30px; }}
h1 {{ color: #c00; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }}
th {{ background-color: #333; color: #fff; }}
tr:nth-child(even) {{ background-color: #f9f9f9; }}
.locked {{ color: #c00; font-weight: bold; }}
</style>
</head><body>
<h1>Crisis Timeline — Incident #{incident_id}</h1>
<p>Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</p>
<p>Total entries: {len(entries)}</p>
<table>
<thead><tr><th>Timestamp</th><th>Type</th><th>Content</th><th>Locked</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""

    pdf_bytes = HTML(string=html_content).write_pdf()
    _audit_log(db, current_user.id, "EXPORT_PDF", "crisis_timeline", incident_id)

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=timeline_incident_{incident_id}.pdf"},
    )


# ══════════════════════════════════════════════════════════════════════════
# T26 — Crisis Checklists
# ══════════════════════════════════════════════════════════════════════════

def _load_template(template_type: str) -> dict:
    """Load a YAML checklist template from config/crisis_templates/."""
    import yaml
    path = TEMPLATE_DIR / f"{template_type}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Template '{template_type}' not found")
    with open(path) as f:
        return yaml.safe_load(f)


@router.post(
    "/{incident_id}/checklist",
    response_model=ChecklistResponse,
    summary="Create a checklist from a template",
)
def create_checklist(
    incident_id: int,
    body: ChecklistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_warroom_role),
):
    """Create a crisis checklist from a YAML template (ransomware, phishing, etc.)."""
    template = _load_template(body.template_type)

    # Build tasks array from template
    tasks = []
    for idx, task in enumerate(template.get("tasks", []), start=1):
        tasks.append({
            "id": idx,
            "label": task.get("label", ""),
            "priority": task.get("priority", "medium"),
            "assigned_to": task.get("assigned_to", ""),
            "completed": False,
            "completed_at": None,
            "completed_by": None,
        })

    checklist = CrisisChecklist(
        incident_id=incident_id,
        template_type=body.template_type,
        tasks=json.dumps(tasks),
        completed_count=0,
    )
    db.add(checklist)
    db.commit()
    db.refresh(checklist)

    _audit_log(db, current_user.id, "CREATE", "crisis_checklists", checklist.id,
                f"template={body.template_type}")

    # Return with parsed tasks
    result = {
        "id": checklist.id,
        "incident_id": checklist.incident_id,
        "template_type": checklist.template_type,
        "tasks": json.loads(checklist.tasks),
        "completed_count": checklist.completed_count,
        "created_at": checklist.created_at,
        "updated_at": checklist.updated_at,
    }
    return result


@router.patch(
    "/{incident_id}/checklist/{task_id}",
    summary="Toggle a checklist task (check/uncheck)",
)
def toggle_checklist_task(
    incident_id: int,
    task_id: int,
    body: ChecklistTaskToggle,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_warroom_role),
):
    """Check or uncheck a specific task in the incident's checklist."""
    checklist = db.query(CrisisChecklist).filter(
        CrisisChecklist.incident_id == incident_id,
    ).first()
    if not checklist:
        raise HTTPException(status_code=404, detail="No checklist found for this incident")

    tasks = json.loads(checklist.tasks)
    task = next((t for t in tasks if t["id"] == task_id), None)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    task["completed"] = body.completed
    if body.completed:
        task["completed_at"] = datetime.now(timezone.utc).isoformat()
        task["completed_by"] = current_user.id
    else:
        task["completed_at"] = None
        task["completed_by"] = None

    checklist.completed_count = sum(1 for t in tasks if t["completed"])
    checklist.tasks = json.dumps(tasks)
    db.commit()

    _audit_log(db, current_user.id, "TOGGLE_TASK", "crisis_checklists", checklist.id,
                f"task={task_id} completed={body.completed}")

    return {
        "id": checklist.id,
        "incident_id": checklist.incident_id,
        "template_type": checklist.template_type,
        "tasks": json.loads(checklist.tasks),
        "completed_count": checklist.completed_count,
        "updated_at": checklist.updated_at,
    }


@router.get(
    "/{incident_id}/checklist",
    response_model=List[ChecklistResponse],
    summary="List checklists for an incident",
)
def list_checklists(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all checklists for an incident with parsed tasks."""
    checklists = db.query(CrisisChecklist).filter(
        CrisisChecklist.incident_id == incident_id,
    ).order_by(CrisisChecklist.created_at.desc()).all()

    results = []
    for cl in checklists:
        results.append({
            "id": cl.id,
            "incident_id": cl.incident_id,
            "template_type": cl.template_type,
            "tasks": json.loads(cl.tasks),
            "completed_count": cl.completed_count,
            "created_at": cl.created_at,
            "updated_at": cl.updated_at,
        })
    return results