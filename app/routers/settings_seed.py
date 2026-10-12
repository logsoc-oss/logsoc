"""Mises a jour du referentiel (seeds) depuis un depot git.

- GET  /api/v1/settings/seed          — URL config + etat des donnees locales
- PUT  /api/v1/settings/seed          — enregistre seed.repo_url dans config.yaml
- POST /api/v1/settings/seed/check    — compare la version locale vs distante
- POST /api/v1/settings/seed/apply    — telecharge et applique les seeds

Version des seeds: fichier VERSION dans sql/seeds/ (contenu = date+hash).
Le depot distant doit exposer les fichiers bruts (raw) via HTTP:
  Gitea  : {repo_url}/raw/branch/master/...
  GitHub : https://raw.githubusercontent.com/{owner}/{repo}/{branche}/...
"""
import hashlib
import logging
import os
import subprocess
from datetime import datetime

import httpx
import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.models import User
from app.routers.auth import require_role
from app.config_loader import get as cfg_get
import app.config_loader as _cl

logger = logging.getLogger("logsoc.settings.seed")

router = APIRouter()

CONFIG_PATH = "/opt/logsoc-web/config.yaml"
SEED_DIR = "/opt/logsoc-web/sql/seeds"
SEED_FILES = [
    "00_reference_documents.sql",
    "02_governance_deliverables.sql",
    "01_reference_requirements.sql",
    "03_capability_dictionary.sql",
    "04_target_resolutions.sql",
    "05_security_practices.sql",
    "06_business_roles.sql",
]


def _seed_version() -> str:
    """Version locale: hash du contenu de tous les fichiers seed."""
    h = hashlib.sha256()
    for f in SEED_FILES:
        p = os.path.join(SEED_DIR, f)
        if os.path.exists(p):
            h.update(open(p, "rb").read())
    return h.hexdigest()[:16]


def _repo_raw_url(repo_url: str, filename: str) -> str:
    """URL raw du fichier, selon l'hébergeur du dépôt.

    GitHub : https://raw.githubusercontent.com/{owner}/{repo}/{branche}/sql/seeds/{f}
      - suffixe .git retiré ; branche explicite dans l'URL (…/tree/{branche})
        honorée, sinon défaut master.
    Gitea  : {base}/raw/branch/master/sql/seeds/{f} (repo dédié
      logsoc-referentiel: fichiers À PLAT {base}/raw/branch/master/{f}).
    """
    base = repo_url.rstrip("/")
    if base.endswith(".git"):
        base = base[:-4]

    if "github.com" in base:
        # https://github.com/{owner}/{repo}[/tree/{branche}]
        # ou git@github.com:{owner}/{repo}
        parts = base.split("github.com", 1)[1].lstrip(":/").split("/")
        owner = parts[0] if parts else ""
        repo = parts[1] if len(parts) > 1 else ""
        branch = "master"
        if len(parts) > 3 and parts[2] == "tree":
            branch = parts[3]
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/sql/seeds/{filename}"

    if "logsoc-referentiel" in base:
        return f"{base}/raw/branch/master/{filename}"
    return f"{base}/raw/branch/master/sql/seeds/{filename}"


def _repo_auth() -> tuple:
    """Auth basic (user, token) depuis config seed.auth_user / seed.auth_token."""
    user = str(cfg_get("seed.auth_user", "")).strip()
    token = str(cfg_get("seed.auth_token", "")).strip()
    if user and token:
        return (user, token)
    return None


class SeedSettings(BaseModel):
    repo_url: Optional[str] = None
    auth_user: Optional[str] = None
    auth_token: Optional[str] = None  # jamais renvoye par le GET


@router.get("/settings/seed")
def get_seed_settings(_user: User = Depends(require_role("admin"))):
    repo_url = str(cfg_get("seed.repo_url", ""))
    return {
        "repo_url": repo_url,
        "auth_user": str(cfg_get("seed.auth_user", "")),
        "auth_token_set": bool(cfg_get("seed.auth_token", "")),
        "local_version": _seed_version(),
        "seed_files": SEED_FILES,
        "seed_dir_exists": os.path.isdir(SEED_DIR),
    }


@router.put("/settings/seed")
def update_seed_settings(body: SeedSettings, _user: User = Depends(require_role("admin"))):
    with open(CONFIG_PATH) as f:
        raw = yaml.safe_load(f) or {}
    seed = raw.setdefault("seed", {})
    seed["repo_url"] = (body.repo_url or "").strip()
    if body.auth_user is not None:
        seed["auth_user"] = body.auth_user.strip()
    if body.auth_token is not None and body.auth_token.strip():
        seed["auth_token"] = body.auth_token.strip()
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(raw, f, default_flow_style=False, allow_unicode=True, sort_keys=True)
    _cl.reload()
    return {"message": "URL du dépôt enregistrée", "repo_url": seed["repo_url"]}


@router.post("/settings/seed/check")
async def check_seed_updates(_user: User = Depends(require_role("admin"))):
    """Compare la version locale avec le depot distant (hash du contenu)."""
    repo_url = str(cfg_get("seed.repo_url", ""))
    if not repo_url:
        raise HTTPException(status_code=400, detail="Aucune URL de dépôt configurée")

    remote_hash = hashlib.sha256()
    files_found = 0
    errors = []
    auth = _repo_auth()
    async with httpx.AsyncClient(timeout=30.0, auth=auth, follow_redirects=True) as client:
        for f in SEED_FILES:
            url = _repo_raw_url(repo_url, f)
            try:
                r = await client.get(url)
                if r.status_code == 200:
                    remote_hash.update(r.content)
                    files_found += 1
                else:
                    errors.append(f"{f}: HTTP {r.status_code}")
            except Exception as e:
                errors.append(f"{f}: {e}")
    if files_found == 0:
        raise HTTPException(status_code=502, detail=f"Dépôt injoignable: {'; '.join(errors[:3])}")

    local_v = _seed_version()
    remote_v = remote_hash.hexdigest()[:16]
    return {
        "up_to_date": local_v == remote_v,
        "local_version": local_v,
        "remote_version": remote_v,
        "files_found": files_found,
        "warnings": errors,
    }


@router.post("/settings/seed/apply")
async def apply_seed_updates(_user: User = Depends(require_role("admin"))):
    """Telecharge les seeds du depot et les applique (idempotent: INSERT
    avec IDs explicites; les donnees client ne sont JAMAIS ecrasees —
    les seeds ne contiennent que les tables de reference)."""
    repo_url = str(cfg_get("seed.repo_url", ""))
    if not repo_url:
        raise HTTPException(status_code=400, detail="Aucune URL de dépôt configurée")

    downloaded = []
    auth = _repo_auth()
    async with httpx.AsyncClient(timeout=120.0, auth=auth, follow_redirects=True) as client:
        for f in SEED_FILES:
            url = _repo_raw_url(repo_url, f)
            r = await client.get(url)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Téléchargement échoué: {f} (HTTP {r.status_code})")
            tmp_path = os.path.join("/tmp", f"seed_update_{f}")
            with open(tmp_path, "wb") as fh:
                fh.write(r.content)
            downloaded.append((f, tmp_path))

    # Sauvegarder les seeds locaux actuels puis remplacer
    import shutil
    os.makedirs(SEED_DIR, exist_ok=True)
    for f, tmp_path in downloaded:
        shutil.copy2(tmp_path, os.path.join(SEED_DIR, f))
        os.remove(tmp_path)

    # Appliquer via mysql (ordre defini)
    db_name = "logsoc"
    applied = []
    for f, _ in downloaded:
        path = os.path.join(SEED_DIR, f)
        # Les seeds 00/01/02 contiennent deja des clauses ON DUPLICATE KEY UPDATE
        # chirurgical (colonnes de reference uniquement): les statuts d'analyse
        # utilisateur (compliance_status, is_not_applicable), les PDFs et les
        # signatures ne sont JAMAIS ecrases. Les seeds 05/06 (pur referentiel)
        # utilisent INSERT ... ON DUPLICATE KEY UPDATE egalement.
        # 03 est INSERT IGNORE, 04 laisse tel quel (asset_id client).
        # Aucune transformation REPLACE: elle detruirait la protection.
        with open(path) as fh:
            content = fh.read()
        tmp_sql = f"/tmp/apply_{f}"
        with open(tmp_sql, "w") as fh:
            fh.write(content)
        res = subprocess.run(
            ["mysql", "-u", "root", db_name], stdin=open(tmp_sql),
            capture_output=True, text=True)
        if res.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Application échouée: {f}: {res.stderr[:300]}")
        applied.append(f)
        os.remove(tmp_sql)

    return {
        "message": "Mises à jour appliquées",
        "applied": applied,
        "new_version": _seed_version(),
    }