"""Phase 6 — Integrations (Webhooks, SIEM forwarding, ITSM, Notifications).

CRUD endpoints for managing integration configurations.
All endpoints require admin (or superadmin) role.
"""
import datetime
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional, List

from app.database import get_db
from app.models import (
    WebhookEndpoint,
    SiemForwardingConfig,
    ItsmConfig,
    NotificationChannel,
    User,
)
from app.routers.auth import require_role

router = APIRouter()
logger = logging.getLogger("logsoc.integrations")

# ── Pydantic schemas ──────────────────────────────────────────────────

# Webhooks
class WebhookCreate(BaseModel):
    name: str
    url: str
    secret: Optional[str] = None
    events: Optional[list] = None
    is_active: Optional[bool] = True


class WebhookUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    secret: Optional[str] = None
    events: Optional[list] = None
    is_active: Optional[bool] = None


# SIEM
class SiemCreate(BaseModel):
    target_type: str = Field(..., pattern=r'^(splunk|elastic|sentinel|syslog)$')
    endpoint: str
    format: Optional[str] = None
    is_active: Optional[bool] = True


class SiemUpdate(BaseModel):
    target_type: Optional[str] = Field(None, pattern=r'^(splunk|elastic|sentinel|syslog)$')
    endpoint: Optional[str] = None
    format: Optional[str] = None
    is_active: Optional[bool] = None


# ITSM
class ItsmCreate(BaseModel):
    target_type: str = Field(..., pattern=r'^(servicenow|jira|glpi)$')
    base_url: str
    api_key: Optional[str] = None
    auto_create_ticket_on_alert: Optional[bool] = False
    ticket_template: Optional[dict] = None
    is_active: Optional[bool] = True


class ItsmUpdate(BaseModel):
    target_type: Optional[str] = Field(None, pattern=r'^(servicenow|jira|glpi)$')
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    auto_create_ticket_on_alert: Optional[bool] = None
    ticket_template: Optional[dict] = None
    is_active: Optional[bool] = None


# Notifications
class NotificationCreate(BaseModel):
    channel_type: str = Field(..., pattern=r'^(email|teams|slack|discord)$')
    webhook_url: Optional[str] = None
    email_recipients: Optional[list] = None
    events: Optional[list] = None
    template: Optional[str] = None
    is_active: Optional[bool] = True


class NotificationUpdate(BaseModel):
    channel_type: Optional[str] = Field(None, pattern=r'^(email|teams|slack|discord)$')
    webhook_url: Optional[str] = None
    email_recipients: Optional[list] = None
    events: Optional[list] = None
    template: Optional[str] = None
    is_active: Optional[bool] = None


# ── Serializers ──────────────────────────────────────────────────────

def _webhook_to_dict(w: WebhookEndpoint) -> dict:
    return {
        "id": w.id,
        "name": w.name,
        "url": w.url,
        "secret": w.secret,
        "events": w.events,
        "is_active": w.is_active,
        "created_at": w.created_at.isoformat() if w.created_at else None,
        "updated_at": w.updated_at.isoformat() if w.updated_at else None,
    }


def _siem_to_dict(s: SiemForwardingConfig) -> dict:
    return {
        "id": s.id,
        "target_type": s.target_type,
        "endpoint": s.endpoint,
        "format": s.format,
        "is_active": s.is_active,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }


def _itsm_to_dict(i: ItsmConfig) -> dict:
    return {
        "id": i.id,
        "target_type": i.target_type,
        "base_url": i.base_url,
        "api_key": i.api_key,
        "auto_create_ticket_on_alert": i.auto_create_ticket_on_alert,
        "ticket_template": i.ticket_template,
        "is_active": i.is_active,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    }


def _notification_to_dict(n: NotificationChannel) -> dict:
    return {
        "id": n.id,
        "channel_type": n.channel_type,
        "webhook_url": n.webhook_url,
        "email_recipients": n.email_recipients,
        "events": n.events,
        "template": n.template,
        "is_active": n.is_active,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "updated_at": n.updated_at.isoformat() if n.updated_at else None,
    }


# ════════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ════════════════════════════════════════════════════════════════════════

@router.get("/webhooks")
def list_webhooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """List all webhook endpoints."""
    rows = db.query(WebhookEndpoint).order_by(WebhookEndpoint.id).all()
    return [_webhook_to_dict(w) for w in rows]


@router.post("/webhooks", status_code=201)
def create_webhook(
    payload: WebhookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Create a new webhook endpoint."""
    obj = WebhookEndpoint(
        name=payload.name,
        url=payload.url,
        secret=payload.secret,
        events=payload.events,
        is_active=payload.is_active if payload.is_active is not None else True,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _webhook_to_dict(obj)


@router.put("/webhooks/{webhook_id}")
def update_webhook(
    webhook_id: int,
    payload: WebhookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update a webhook endpoint."""
    obj = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == webhook_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(obj, key, value)
    db.commit()
    db.refresh(obj)
    return _webhook_to_dict(obj)


@router.delete("/webhooks/{webhook_id}")
def delete_webhook(
    webhook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a webhook endpoint."""
    obj = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == webhook_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    db.delete(obj)
    db.commit()
    return {"message": "Webhook endpoint deleted"}


@router.post("/webhooks/{webhook_id}/test")
def test_webhook(
    webhook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Send a test POST to the webhook URL and return the status code."""
    obj = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == webhook_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    test_payload = {
        "test": True,
        "webhook_id": obj.id,
        "webhook_name": obj.name,
        "message": "Test webhook from LOGSOC",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(obj.url, json=test_payload)
        return {
            "status_code": resp.status_code,
            "url": obj.url,
            "response_body": resp.text[:2048] if resp.text else None,
        }
    except httpx.ConnectError as exc:
        raise HTTPException(status_code=502, detail=f"Connection failed: {exc}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Webhook request timed out")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Webhook test failed: {exc}")


# ════════════════════════════════════════════════════════════════════════
# SIEM FORWARDING
# ════════════════════════════════════════════════════════════════════════

@router.get("/siem")
def list_siem(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """List all SIEM forwarding configurations."""
    rows = db.query(SiemForwardingConfig).order_by(SiemForwardingConfig.id).all()
    return [_siem_to_dict(s) for s in rows]


@router.post("/siem", status_code=201)
def create_siem(
    payload: SiemCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Create a new SIEM forwarding configuration."""
    obj = SiemForwardingConfig(
        target_type=payload.target_type,
        endpoint=payload.endpoint,
        format=payload.format,
        is_active=payload.is_active if payload.is_active is not None else True,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _siem_to_dict(obj)


@router.put("/siem/{siem_id}")
def update_siem(
    siem_id: int,
    payload: SiemUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update a SIEM forwarding configuration."""
    obj = db.query(SiemForwardingConfig).filter(SiemForwardingConfig.id == siem_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="SIEM forwarding config not found")
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(obj, key, value)
    db.commit()
    db.refresh(obj)
    return _siem_to_dict(obj)


@router.delete("/siem/{siem_id}")
def delete_siem(
    siem_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a SIEM forwarding configuration."""
    obj = db.query(SiemForwardingConfig).filter(SiemForwardingConfig.id == siem_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="SIEM forwarding config not found")
    db.delete(obj)
    db.commit()
    return {"message": "SIEM forwarding config deleted"}


# ════════════════════════════════════════════════════════════════════════
# ITSM
# ════════════════════════════════════════════════════════════════════════

@router.get("/itsm")
def list_itsm(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """List all ITSM configurations."""
    rows = db.query(ItsmConfig).order_by(ItsmConfig.id).all()
    return [_itsm_to_dict(i) for i in rows]


@router.post("/itsm", status_code=201)
def create_itsm(
    payload: ItsmCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Create a new ITSM configuration."""
    obj = ItsmConfig(
        target_type=payload.target_type,
        base_url=payload.base_url,
        api_key=payload.api_key,
        auto_create_ticket_on_alert=payload.auto_create_ticket_on_alert if payload.auto_create_ticket_on_alert is not None else False,
        ticket_template=payload.ticket_template,
        is_active=payload.is_active if payload.is_active is not None else True,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _itsm_to_dict(obj)


@router.put("/itsm/{itsm_id}")
def update_itsm(
    itsm_id: int,
    payload: ItsmUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update an ITSM configuration."""
    obj = db.query(ItsmConfig).filter(ItsmConfig.id == itsm_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="ITSM config not found")
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(obj, key, value)
    db.commit()
    db.refresh(obj)
    return _itsm_to_dict(obj)


@router.delete("/itsm/{itsm_id}")
def delete_itsm(
    itsm_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete an ITSM configuration."""
    obj = db.query(ItsmConfig).filter(ItsmConfig.id == itsm_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="ITSM config not found")
    db.delete(obj)
    db.commit()
    return {"message": "ITSM config deleted"}


# ════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ════════════════════════════════════════════════════════════════════════

@router.get("/notifications")
def list_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """List all notification channels."""
    rows = db.query(NotificationChannel).order_by(NotificationChannel.id).all()
    return [_notification_to_dict(n) for n in rows]


@router.post("/notifications", status_code=201)
def create_notification(
    payload: NotificationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Create a new notification channel."""
    obj = NotificationChannel(
        channel_type=payload.channel_type,
        webhook_url=payload.webhook_url,
        email_recipients=payload.email_recipients,
        events=payload.events,
        template=payload.template,
        is_active=payload.is_active if payload.is_active is not None else True,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _notification_to_dict(obj)


@router.put("/notifications/{notification_id}")
def update_notification(
    notification_id: int,
    payload: NotificationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update a notification channel."""
    obj = db.query(NotificationChannel).filter(NotificationChannel.id == notification_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(obj, key, value)
    db.commit()
    db.refresh(obj)
    return _notification_to_dict(obj)


@router.delete("/notifications/{notification_id}")
def delete_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Delete a notification channel."""
    obj = db.query(NotificationChannel).filter(NotificationChannel.id == notification_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    db.delete(obj)
    db.commit()
    return {"message": "Notification channel deleted"}


@router.post("/notifications/{notification_id}/test")
def test_notification(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Send a test notification through the channel."""
    obj = db.query(NotificationChannel).filter(NotificationChannel.id == notification_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Notification channel not found")

    test_message = {
        "test": True,
        "channel_id": obj.id,
        "channel_type": obj.channel_type,
        "message": "Test notification from LOGSOC",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    if obj.channel_type == "email":
        # Email channels don't have a webhook URL to test via POST;
        # return a placeholder success response.
        return {
            "channel_type": "email",
            "status": "simulated",
            "message": "Email notification test — would send to recipients",
            "email_recipients": obj.email_recipients,
        }

    # For teams/slack/discord, send a test POST to the webhook_url
    if not obj.webhook_url:
        raise HTTPException(status_code=400, detail="No webhook_url configured for this channel")

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(obj.webhook_url, json=test_message)
        return {
            "channel_type": obj.channel_type,
            "status_code": resp.status_code,
            "url": obj.webhook_url,
            "response_body": resp.text[:2048] if resp.text else None,
        }
    except httpx.ConnectError as exc:
        raise HTTPException(status_code=502, detail=f"Connection failed: {exc}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Notification request timed out")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Notification test failed: {exc}")