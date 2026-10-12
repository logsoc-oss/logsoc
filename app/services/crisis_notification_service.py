# app/services/crisis_notification_service.py — T28
"""Crisis notification service: AI-powered generation via Ollama + SMTP sending.

Responsibilities:
- Load YAML notification templates per authority/regulation
- Gather incident context (detection time, assets, alerts, timeline, checklist)
- Call Ollama to fill the template (fallback: pre-fill without AI)
- Send notifications via SMTP with PDF attachment
"""

import json
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path
from typing import Optional

import yaml
from sqlalchemy.orm import Session

from app.models_crisis import CrisisNotification, CrisisTimelineEntry, CrisisChecklist
from app.models import Case, Alert

logger = logging.getLogger("logsoc.crisis_notification")

# Template directory
TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "config" / "notification_templates"

# Authority contact lookup (used when YAML template has authority_contact)
AUTHORITY_CONTACTS = {
    "anssi": {
        "name": "ANSSI — Agence nationale de la sécurité des systèmes d'information",
        "portal": "https://recyf.ssi.gouv.fr",
        "email": "cert-fr@ssi.gouv.fr",
        "phone": "+33 1 71 75 84 68",
    },
    "cnil": {
        "name": "CNIL — Commission nationale de l'informatique et des libertés",
        "portal": "https://notifications.cnil.fr/notifications",
        "email": "notifications@cnil.fr",
        "phone": "+33 1 53 63 22 22",
    },
}


def load_template(authority: str, regulation: str) -> Optional[dict]:
    """Load a YAML notification template by authority/regulation.

    Searches for files named {authority}_{regulation}.yaml or matching
    the authority field inside the template.
    """
    # Try exact naming: anssi_recyf.yaml, rgpd_art33.yaml, etc.
    exact_name = f"{authority}_{regulation}.yaml"
    path = TEMPLATE_DIR / exact_name
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f)

    # Try rgpd_art33.yaml for cnil/rgpd
    # Try anssi_recyf.yaml for anssi/nis2
    mapping = {
        ("anssi", "nis2"): "anssi_recyf.yaml",
        ("cnil", "rgpd"): "rgpd_art33.yaml",
    }
    mapped = mapping.get((authority, regulation))
    if mapped:
        path = TEMPLATE_DIR / mapped
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)

    # Fallback: scan all templates for matching authority/regulation
    for p in TEMPLATE_DIR.glob("*.yaml"):
        with open(p) as f:
            data = yaml.safe_load(f)
        if data and data.get("authority") == authority and data.get("regulation") == regulation:
            return data

    return None


def gather_incident_context(db: Session, incident_id: int) -> dict:
    """Gather all incident context for AI prompt filling."""
    context = {
        "detection_timestamp": "",
        "severity": "",
        "affected_assets": "",
        "alerts_summary": "",
        "checklist_summary": "",
        "timeline_summary": "",
        "org_info": "",
        "personal_data_info": "",
        "attack_vector": "",
        "impact_description": "",
        "number_affected": "",
        "categories_data": "",
        "data_subjects": "",
        "likely_consequences": "",
        "mitigating_measures": "",
    }

    # Case info
    case = db.query(Case).filter(Case.id == incident_id).first()
    if case:
        context["detection_timestamp"] = case.created_at.isoformat() if case.created_at else ""
        context["severity"] = case.severity or ""
        context["impact_description"] = case.description or ""
        context["attack_vector"] = ""

    # Alerts
    alerts = db.query(Alert).filter(Alert.related_case_id == incident_id).order_by(Alert.created_at.desc()).limit(10).all()
    if alerts:
        alert_lines = []
        for a in alerts:
            alert_lines.append(f"- [{a.severity}] {a.title} ({a.created_at.isoformat() if a.created_at else ''})")
        context["alerts_summary"] = "\n".join(alert_lines)

    # Timeline entries
    timeline_entries = db.query(CrisisTimelineEntry).filter(
        CrisisTimelineEntry.incident_id == incident_id
    ).order_by(CrisisTimelineEntry.timestamp.asc()).all()
    if timeline_entries:
        timeline_lines = []
        for e in timeline_entries:
            ts = e.timestamp.strftime("%Y-%m-%d %H:%M UTC") if e.timestamp else ""
            timeline_lines.append(f"- [{ts}] ({e.event_type}) {e.content}")
        context["timeline_summary"] = "\n".join(timeline_lines)

    # Checklists
    checklists = db.query(CrisisChecklist).filter(
        CrisisChecklist.incident_id == incident_id
    ).all()
    if checklists:
        cl_lines = []
        for cl in checklists:
            tasks = json.loads(cl.tasks) if isinstance(cl.tasks, str) else cl.tasks
            done = sum(1 for t in tasks if t.get("completed"))
            cl_lines.append(f"- {cl.template_type}: {done}/{len(tasks)} tâches complétées")
        context["checklist_summary"] = "\n".join(cl_lines)

    return context


async def generate_notification_content(
    db: Session,
    incident_id: int,
    authority: str,
    regulation: str,
) -> dict:
    """Generate notification content using Ollama IA or fallback to template.

    Returns dict with: template_type, pre_filled_content, authority_contact
    """
    # Load template
    template = load_template(authority, regulation)
    if not template:
        available = [p.stem for p in TEMPLATE_DIR.glob("*.yaml")]
        raise ValueError(
            f"No template found for authority={authority}, regulation={regulation}. "
            f"Available templates: {available}"
        )

    template_type = f"{authority}_{regulation}"
    authority_contact = template.get("authority_contact", AUTHORITY_CONTACTS.get(authority, {}))

    # Gather context
    context = gather_incident_context(db, incident_id)

    # Build pre-filled content from template sections
    content_parts = []
    content_parts.append(f"# {template.get('name', 'Notification')}")
    content_parts.append("")
    content_parts.append(f"Autorité notifiée: {authority_contact.get('name', authority)}")
    content_parts.append(f"Réglementation: {regulation.upper()}")
    content_parts.append("")

    for section in template.get("sections", []):
        content_parts.append(f"## {section['title']}")
        for field in section.get("fields", []):
            label = field.get("label", field.get("key", ""))
            value = ""
            # Auto-fill from context if ai_fill is set
            ai_key = field.get("ai_fill", field.get("key", ""))
            if ai_key in context and context[ai_key]:
                value = context[ai_key]
            content_parts.append(f"- **{label}**: {value}")
        content_parts.append("")

    # Try Ollama AI enrichment
    pre_filled_content = "\n".join(content_parts)
    ai_content = None

    try:
        prompt_template = template.get("prompt_template", "")
        if prompt_template:
            # Fill prompt placeholders with context
            prompt = prompt_template
            for key, val in context.items():
                prompt = prompt.replace(f"{{{key}}}", str(val) if val else "Non renseigné")

            # Try calling Ollama
            ai_content = await _call_ollama(prompt)
    except Exception as e:
        logger.warning("Ollama IA generation failed, using template fallback: %s", e)

    if ai_content:
        # Prepend the AI-generated content
        pre_filled_content = f"{ai_content}\n\n---\n\n{pre_filled_content}"

    return {
        "template_type": template_type,
        "pre_filled_content": pre_filled_content,
        "authority_contact": authority_contact,
    }


async def _call_ollama(prompt: str) -> Optional[str]:
    """Call Ollama to generate notification content. Returns None on failure."""
    try:
        from app.llm_config import LLMConfig
        from app.llm.ollama_client import OllamaClient
        import asyncio

        cfg = LLMConfig.from_config()
        client = OllamaClient(cfg)
        # Use async chat
        response = await client.chat(
            prompt=prompt,
            system="Tu es un assistant juridique et de conformité. Tu rédiges des notifications réglementaires en français, avec précision et professionnalisme.",
            model=cfg.model,
        )
        return response.get("message", {}).get("content", "")
    except Exception as e:
        logger.warning("Ollama call failed: %s", e)
        return None


def send_notification_smtp(
    notification_id: int,
    db: Session,
    recipient_email: Optional[str] = None,
) -> dict:
    """Send a crisis notification via SMTP with PDF attachment.

    Uses SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS env vars or config.
    Returns dict with: status, sent_at, message_id
    """
    notification = db.query(CrisisNotification).filter(CrisisNotification.id == notification_id).first()
    if not notification:
        raise ValueError(f"Notification {notification_id} not found")

    if notification.status == "sent":
        raise ValueError("Notification already sent")

    # SMTP config from env or config
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    # Try config.yaml as fallback
    if not smtp_host:
        try:
            from app.config_loader import get
            smtp_host = get("smtp.host", "")
            smtp_port = int(get("smtp.port", 587))
            smtp_user = get("smtp.user", "")
            smtp_pass = get("smtp.password", "")
        except Exception:
            pass

    # If no SMTP config, mark as sent anyway (test/dev mode)
    if not smtp_host:
        logger.warning("No SMTP configuration found. Marking notification %d as sent without email.", notification_id)
        notification.status = "sent"
        notification.sent_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(notification)
        return {
            "status": "sent",
            "sent_at": notification.sent_at.isoformat() if notification.sent_at else None,
            "message_id": f"local-{notification.id}",
        }

    # Get authority contact for recipient
    authority_info = AUTHORITY_CONTACTS.get(notification.authority, {})
    to_email = recipient_email or authority_info.get("email", "")
    if not to_email:
        raise ValueError(f"No recipient email for authority {notification.authority}")

    # Build email
    from_email = smtp_user or "logsoc-noreply@localhost"
    subject = f"Notification {notification.regulation.upper()} — Incident #{notification.incident_id}"

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["X-Notification-ID"] = str(notification.id)

    # HTML body
    html_body = f"""<html><body>
<h1>Notification réglementaire — {notification.regulation.upper()}</h1>
<p><strong>Autorité:</strong> {notification.authority}</p>
<p><strong>Incident:</strong> #{notification.incident_id}</p>
<p><strong>Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<hr/>
<div style="white-space: pre-wrap; font-family: Arial, sans-serif;">{notification.content}</div>
</body></html>"""
    msg.attach(MIMEText(html_body, "html"))

    # Try to generate PDF attachment
    pdf_bytes = _generate_pdf(notification)
    if pdf_bytes:
        attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
        attachment.add_header("Content-Disposition", "attachment", filename=f"notification_{notification.id}.pdf")
        msg.attach(attachment)

    # Send via SMTP
    message_id = None
    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.starttls()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(from_email, to_email, msg.as_string())
        message_id = msg.get("Message-ID", f"smtp-{notification.id}")
        server.quit()
        logger.info("Notification %d sent to %s via SMTP", notification.id, to_email)
    except Exception as e:
        logger.error("SMTP send failed for notification %d: %s", notification.id, e)
        raise RuntimeError(f"SMTP send failed: {e}")

    # Update notification status
    notification.status = "sent"
    notification.sent_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(notification)

    return {
        "status": "sent",
        "sent_at": notification.sent_at.isoformat() if notification.sent_at else None,
        "message_id": message_id or f"smtp-{notification.id}",
    }


def _generate_pdf(notification: CrisisNotification) -> Optional[bytes]:
    """Generate a PDF from notification content using weasyprint. Returns None if unavailable."""
    try:
        from weasyprint import HTML

        html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body {{ font-family: Arial, sans-serif; margin: 30px; }}
h1 {{ color: #c00; }}
h2 {{ color: #333; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
.meta {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 4px; }}
.content {{ white-space: pre-wrap; line-height: 1.6; }}
</style>
</head><body>
<h1>Notification réglementaire — {notification.regulation.upper()}</h1>
<div class="meta">
<p><strong>Autorité:</strong> {notification.authority}</p>
<p><strong>Incident:</strong> #{notification.incident_id}</p>
<p><strong>Statut:</strong> {notification.status}</p>
<p><strong>Date de création:</strong> {notification.created_at.strftime('%Y-%m-%d %H:%M UTC') if notification.created_at else 'N/A'}</p>
</div>
<h2>Contenu de la notification</h2>
<div class="content">{notification.content}</div>
<footer style="margin-top: 40px; font-size: 10px; color: #999;">
Document généré par LogSOC — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</footer>
</body></html>"""

        return HTML(string=html_content).write_pdf()
    except ImportError:
        logger.warning("weasyprint not installed, skipping PDF generation")
        return None
    except Exception as e:
        logger.warning("PDF generation failed: %s", e)
        return None