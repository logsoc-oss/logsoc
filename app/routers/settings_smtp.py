"""Administration des paramètres SMTP (expédition emails validation documents).

- GET  /api/v1/settings/smtp        — config (password JAMAIS renvoyé)
- PUT  /api/v1/settings/smtp        — enregistre dans config.yaml (section smtp:)
- POST /api/v1/settings/smtp/test   — envoi réel à l'admin connecté

Structure config.yaml:
  smtp:
    host: smtp.exemple.fr
    port: 587
    encryption: starttls   # none | starttls | ssl
    user: logsoc@exemple.fr
    password: ****
    from_addr: logsoc@exemple.fr
    from_name: "LogSOC Gouvernance"
"""
import logging
import smtplib
import socket
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.routers.auth import require_role
from app.config_loader import get as cfg_get
import app.config_loader as _cl

logger = logging.getLogger("logsoc.settings.smtp")

router = APIRouter()

CONFIG_PATH = "/opt/logsoc-web/config.yaml"


class SmtpSettings(BaseModel):
    host: str = ""
    port: int = 587
    encryption: str = "starttls"  # none | starttls | ssl
    user: str = ""
    password: Optional[str] = None  # None = inchangé
    from_addr: str = ""
    from_name: str = "LogSOC"


class SmtpTestRequest(BaseModel):
    to: Optional[str] = None  # défaut: email de l'admin connecté


def _smtp_configured() -> bool:
    return bool(cfg_get("smtp.host", "")) and bool(cfg_get("smtp.user", ""))


def send_email(to: str, subject: str, html_body: str, text_body: str = "",
               attachments: Optional[list] = None) -> None:
    """Envoi générique via config.yaml smtp. attachments = [(filename, bytes), ...]"""
    host = cfg_get("smtp.host", "")
    if not host:
        raise HTTPException(status_code=503, detail="SMTP non configuré (Administration → Paramètres → Email)")
    port = int(cfg_get("smtp.port", 587))
    encryption = str(cfg_get("smtp.encryption", "starttls")).lower()
    user = str(cfg_get("smtp.user", ""))
    password = str(cfg_get("smtp.password", ""))
    from_addr = str(cfg_get("smtp.from_addr", user))
    from_name = str(cfg_get("smtp.from_name", "LogSOC"))

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    if attachments:
        from email.mime.application import MIMEApplication
        for filename, content in attachments:
            part = MIMEApplication(content, Name=filename)
            part["Content-Disposition"] = f'attachment; filename="{filename}"'
            msg.attach(part)

    try:
        if encryption == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=20)
            if encryption == "starttls":
                server.starttls(context=ssl.create_default_context())
        if user:
            server.login(user, password)
        server.sendmail(from_addr, [to], msg.as_string())
        server.quit()
    except (smtplib.SMTPException, socket.error) as e:
        logger.error("SMTP send failed to %s: %s", to, e)
        raise HTTPException(status_code=502, detail=f"Erreur SMTP: {e}")
    except TimeoutError:
        logger.error("SMTP send timeout to %s (host=%s)", to, host)
        raise HTTPException(status_code=504, detail=f"Timeout SMTP: hôte {host} injoignable après 20s")


@router.get("/settings/smtp")
def get_smtp_settings(_user: User = Depends(require_role("admin"))):
    """Config SMTP — password jamais renvoyé."""
    return {
        "host": str(cfg_get("smtp.host", "")),
        "port": int(cfg_get("smtp.port", 587)),
        "encryption": str(cfg_get("smtp.encryption", "starttls")),
        "user": str(cfg_get("smtp.user", "")),
        "password_set": bool(cfg_get("smtp.password", "")),
        "from_addr": str(cfg_get("smtp.from_addr", "")),
        "from_name": str(cfg_get("smtp.from_name", "LogSOC")),
        "configured": _smtp_configured(),
    }


@router.put("/settings/smtp")
def update_smtp_settings(body: SmtpSettings, _user: User = Depends(require_role("admin"))):
    """Enregistre la section smtp: de config.yaml (read-modify-write)."""
    with open(CONFIG_PATH) as f:
        raw = yaml.safe_load(f) or {}
    smtp = raw.setdefault("smtp", {})
    smtp["host"] = body.host.strip()
    smtp["port"] = int(body.port)
    smtp["encryption"] = body.encryption
    smtp["user"] = body.user.strip()
    if body.password is not None and body.password != "":
        smtp["password"] = body.password
    smtp["from_addr"] = body.from_addr.strip() or body.user.strip()
    smtp["from_name"] = body.from_name.strip() or "LogSOC"

    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(raw, f, default_flow_style=False, allow_unicode=True, sort_keys=True)

    # Recharger la config en memoire
    _cl.reload()
    return {"message": "Paramètres SMTP enregistrés", "configured": _smtp_configured()}


@router.post("/settings/smtp/test")
def test_smtp(body: SmtpTestRequest, current_user: User = Depends(require_role("admin"))):
    """Envoie un email test (destinataire = admin connecté par défaut)."""
    to = (body.to or current_user.email or "").strip()
    if not to:
        raise HTTPException(status_code=400, detail="Aucune adresse de destination (l'admin n'a pas d'email)")
    if not _smtp_configured():
        raise HTTPException(status_code=503, detail="SMTP non configuré")

    html = f"""<div style="font-family: sans-serif; max-width: 520px; margin: auto;">
<h2 style="color: #10b981;">✓ Test SMTP réussi</h2>
<p>Ceci est un email de test envoyé depuis <strong>LogSOC</strong>.</p>
<p>Si vous lisez ce message, la configuration SMTP est fonctionnelle.
Les demandes de validation de documents arriveront depuis cette adresse.</p>
<p style="font-size: 12px; color: #888;">Envoyé à {to}</p>
</div>"""
    try:
        send_email(to, "[LogSOC] Test SMTP — configuration OK", html)
    except HTTPException:
        raise
    return {"message": f"Email test envoyé à {to}", "sent_to": to}