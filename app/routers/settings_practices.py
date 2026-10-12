"""Paramètres du module Pratiques (13/09): fréquence d'audit par défaut.

Toutes les pratiques non_defini héritent de practices.audit_frequency_default
(config.yaml, défaut annuel — 1 fois par an minimum, décision Fabrice).
Le réglage explicite d'une pratique PRIME sur le défaut global."""
import logging
import yaml

from fastapi import APIRouter, Depends
from pydantic import BaseModel

import app.config_loader as _cl
from app.config_loader import get as cfg_get
from app.models import User
from app.routers.auth import require_role

logger = logging.getLogger("logsoc.settings_practices")
router = APIRouter()

CONFIG_PATH = "/opt/logsoc-web/config.yaml"

VALID = ("annuel", "biennal", "ponctuel")


class PracticesSettings(BaseModel):
    audit_frequency_default: str | None = None


@router.get("/practices")
def get_practices_settings(_user: User = Depends(require_role("admin"))):
    # lit le DISQUE (pas CFG en mémoire): --workers 2 = chaque worker a son
    # cache, un PUT servi par l'un ne recharge pas l'autre
    import yaml as _yaml
    try:
        with open(CONFIG_PATH) as f:
            raw = _yaml.safe_load(f) or {}
        freq = str((raw.get("practices") or {}).get("audit_frequency_default", "annuel"))
    except Exception:
        freq = str(cfg_get("practices.audit_frequency_default", "annuel"))
    return {"audit_frequency_default": freq if freq in VALID else "annuel"}


@router.put("/practices")
def update_practices_settings(
    body: PracticesSettings,
    _user: User = Depends(require_role("admin")),
):
    if body.audit_frequency_default not in VALID:
        return {"error": f"Valeur invalide — annuel | biennal | ponctuel"}, 400
    with open(CONFIG_PATH) as f:
        raw = yaml.safe_load(f) or {}
    practices = raw.setdefault("practices", {})
    practices["audit_frequency_default"] = body.audit_frequency_default
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(raw, f, default_flow_style=False, allow_unicode=True, sort_keys=True)
    _cl.reload()
    logger.info("audit_frequency_default=%s", body.audit_frequency_default)
    return {"audit_frequency_default": body.audit_frequency_default}