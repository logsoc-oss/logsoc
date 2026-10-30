"""IA Prompts — CRUD for configurable AI prompts.

Admin-only endpoints to list, view, create, update, reset, and delete IA prompts.
System prompts (is_system=True) cannot be deleted; only their prompt_text can be edited.
Custom prompts (is_system=False) can be fully managed.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import IaPrompt, User
from app.routers.auth import require_role
from app.config_loader import get as cfg_get
import httpx
import re

logger = logging.getLogger("logsoc.ia_prompts")
router = APIRouter()

# ── Hardcoded defaults for system prompts (used by reset) ──

DEFAULT_PROMPTS = {
    "reference_analysis": {
        "label": "Analyse de référentiel",
        "description": "Prompt utilisé pour analyser les documents de référence importés",
        "prompt_text": (
            "Tu es un expert en sécurité des systèmes d'information et conformité réglementaire.\n\n"
            "Analyse ce document de référence et extrais les informations suivantes de manière structurée :\n\n"
            "1. TITRE : Le titre exact du document\n"
            "2. VERSION : La version et/ou date de publication (ex: v2.0, Janvier 2024)\n"
            "3. OBJET : Résumé de l'objet du document (2-3 lignes max)\n"
            "4. STRUCTURE : Liste TOUTES les étapes, sections ou chapitres du document avec un résumé léger (1 ligne) pour chaque\n"
            "5. POINTS CLES : Liste TOUS les points clés et mesures importantes, un par ligne, concis, avec numéro de référence si existant\n"
            "6. CONFORMITE : Référentiel(s) mentionné(s) (NIS2, ISO27001, RGPD, etc.) ou \"Non spécifié\"\n\n"
            "IMPORTANT : Cette analyse a été générée par une IA et ne se substitue pas à la lecture attentive du document original.\n\n"
            "Réponds en français. Sois exhaustif sur les étapes et points clés mais concis sur chaque point.\n\n"
            "Document:\n{text}"
        ),
        "variables": [{"name": "text", "description": "Texte extrait du document"}],
    },
    "document_analysis": {
        "label": "Analyse de document",
        "description": "Prompt pour analyser les documents de la société",
        "prompt_text": (
            "Tu es un expert en sécurité des systèmes d'information et conformité réglementaire. "
            "Analyse ce document de politique de sécurité et fournis:\n"
            "1. Résumé (3-5 lignes)\n"
            "2. Points forts\n"
            "3. Points faibles / manques\n"
            "4. Recommandations d'amélioration\n"
            "5. Conformité NIS2/ISO27001 (si applicable)\n\n"
            "Document:\n{text}"
        ),
        "variables": [{"name": "text", "description": "Texte extrait du document"}],
    },
    "crisis_chat": {
        "label": "Chat IA de crise",
        "description": "Prompt pour le chat IA dans la gestion de crise",
        "prompt_text": "Tu es un assistant de gestion de crise cybersécurité. {context} Question: {message}",
        "variables": [
            {"name": "context", "description": "Contexte de la crise"},
            {"name": "message", "description": "Question de l'utilisateur"},
        ],
    },
    "wizard_generate": {
        "label": "Génération de politique (wizard)",
        "description": "Prompt pour générer le contenu d'une étape du wizard",
        "prompt_text": (
            "Tu es un expert en sécurité des systèmes d'information et conformité réglementaire.\n"
            "Tu rédiges une section d'un document de politique de sécurité pour une organisation.\n\n"
            "Organisation : {company_info_name}\n"
            "Taille : {company_info_size}\n"
            "Secteur : {company_info_sector}\n"
            "Nombre de sites : {company_info_sites}\n"
            "Systèmes principaux : {company_info_systems}\n"
            "Contraintes réglementaires : {company_info_compliance}\n"
            "Niveau de maturité : {company_info_maturity}\n\n"
            "Type de document : {category}\n"
            "Section à rédiger (étape {step}) : {step_title}\n"
            "Description : {step_description}\n\n"
            "{previous_steps_section}\n\n"
            "{current_content_section}\n\n"
            "Réponds UNIQUEMENT avec le contenu de la section, sans introduction ni conclusion générique. "
            "Utilise des titres et sous-titres si nécessaire. Réponds en français."
        ),
        "variables": [
            {"name": "category", "description": "Catégorie du document"},
            {"name": "step", "description": "Numéro d'étape"},
            {"name": "company_info", "description": "Infos organisation"},
            {"name": "current_content", "description": "Contenu actuel"},
            {"name": "previous_steps", "description": "Étapes précédentes"},
        ],
    },
    "wizard_finalize": {
        "label": "Relecture finale (wizard)",
        "description": "Prompt pour la relecture finale du wizard",
        "prompt_text": "Relis et améliore ce document de politique de sécurité. Corrige la formulation, la cohérence et la structure. {content}",
        "variables": [{"name": "content", "description": "Contenu complet du document"}],
    },
}


# ── Schemas ──

class IaPromptResponse(BaseModel):
    id: int
    prompt_key: str
    label: str
    description: Optional[str] = None
    prompt_text: str
    variables: Optional[list] = None
    is_system: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


class IaPromptUpdate(BaseModel):
    prompt_text: str


class IaPromptCreate(BaseModel):
    prompt_key: str
    label: str
    description: Optional[str] = None
    prompt_text: str
    variables: Optional[list] = None


class IaPromptResetResponse(BaseModel):
    prompt_key: str
    prompt_text: str
    message: str


# ── Helper: get_prompt(key) — used by other routers to retrieve prompt text ──

def get_prompt(key: str) -> str:
    """Return the prompt_text for the given key from the DB.
    Falls back to hardcoded DEFAULT_PROMPTS if the key is not in DB.
    """
    db = SessionLocal()
    try:
        row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
        if row:
            return row.prompt_text
        # Fallback to hardcoded
        if key in DEFAULT_PROMPTS:
            return DEFAULT_PROMPTS[key]["prompt_text"]
        raise ValueError(f"Unknown prompt key: {key}")
    finally:
        db.close()


# ── Schema extraction (hardcoded, never user-editable) ──

SCHEMA_EXTRACTION_PROMPT = """Tu es un extracteur de schéma JSON. Lis le prompt d'analyse ci-dessous et extrais la structure du tableau de sortie attendu.

Retourne UNIQUEMENT un JSON valide, sans texte supplémentaire, sans markdown, au format exact suivant:
{"version": <numero>, "columns": [{"name": "nom_colonne_sans_espaces_avec_underscores", "type": "string|text|enum", "values": ["valeur1", "valeur2", ...]}]}

Règles:
- Le nombre de colonnes correspond au nombre de champs séparés par | dans le format de réponse du prompt.
- Le nom de chaque colonne est déduit du nom du champ dans le prompt (ex: "ID / Référence" -> "ref_id", "Règle / Exigence" -> "rule", etc.).
- Pour les ENUM, liste TOUTES les valeurs exactes proposées dans le prompt (ex: "Gouvernance", "Technique", etc.).
- Pour les champs libres, type = "string" ou "text" (text pour les champs longs comme les règles).
- La version est un entier incrémenté (commence à 1).

Prompt à analyser:
---
{prompt_text}
---
"""


async def _extract_schema_from_prompt(prompt_text: str) -> dict | None:
    """Send the prompt to the AI to extract the JSON schema. Returns None on failure."""
    ollama_url = cfg_get("ollama.url", "http://127.0.0.1:11434")
    ollama_model = cfg_get("ollama.model", "qwen3:4b")
    ollama_timeout = max(int(cfg_get("ollama.timeout", "30")), 120)
    api_key = cfg_get("ollama.api_key", "")

    extraction_prompt = SCHEMA_EXTRACTION_PROMPT.replace("{prompt_text}", prompt_text)

    payload = {
        "model": ollama_model,
        "prompt": extraction_prompt,
        "stream": False,
        "format": "json",
        "options": {
            "num_predict": 2048,
            "temperature": 0.1,
            "num_ctx": int(cfg_get("ollama.context_length", "4096")),
        },
    }

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=float(ollama_timeout + 30)) as client:
            resp = await client.post(
                f"{ollama_url.rstrip('/')}/api/generate",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_response = data.get("response", "").strip()

            # Try to parse as JSON directly
            try:
                schema = json.loads(raw_response)
            except json.JSONDecodeError:
                # Try to extract JSON from the response (in case AI wrapped it in markdown)
                json_match = re.search(r'\{[^{}]*"columns"[^{}]*\}', raw_response, re.DOTALL)
                if json_match:
                    try:
                        schema = json.loads(json_match.group())
                    except json.JSONDecodeError:
                        logger.error("Schema extraction: could not parse JSON from AI response")
                        return None
                else:
                    logger.error("Schema extraction: no JSON found in AI response")
                    return None

            # Validate schema structure
            if not isinstance(schema, dict):
                logger.error("Schema extraction: schema is not a dict")
                return None
            if "columns" not in schema or not isinstance(schema["columns"], list):
                logger.error("Schema extraction: missing 'columns' array")
                return None
            if len(schema["columns"]) == 0:
                logger.error("Schema extraction: empty columns array")
                return None

            # Ensure version is present
            if "version" not in schema:
                schema["version"] = 1

            logger.info("Schema extracted: %d columns, version %d", len(schema["columns"]), schema["version"])
            return schema

    except Exception as e:
        logger.error("Schema extraction failed: %s", repr(e))
        return None


def get_prompt_schema(key: str = "reference_page_analysis") -> dict | None:
    """Return the stored JSON schema for a prompt, or None if not available.
    Reads from ia_prompts.variables column."""
    db = SessionLocal()
    try:
        row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
        if not row or not row.variables:
            return None
        try:
            data = json.loads(row.variables)
            if isinstance(data, dict) and "columns" in data:
                return data
            # Maybe it's stored as the old format (list of variable descriptors)
            return None
        except (json.JSONDecodeError, TypeError):
            return None
    finally:
        db.close()


# ── Endpoints ──

@router.get("/ia-prompts", response_model=list[IaPromptResponse])
def list_prompts(
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """List all IA prompts (admin only)."""
    rows = db.query(IaPrompt).order_by(IaPrompt.id).all()
    result = []
    for r in rows:
        variables = None
        if r.variables:
            try:
                variables = json.loads(r.variables)
            except (json.JSONDecodeError, TypeError):
                variables = None
        result.append(IaPromptResponse(
            id=r.id,
            prompt_key=r.prompt_key,
            label=r.label,
            description=r.description,
            prompt_text=r.prompt_text,
            variables=variables,
            is_system=r.is_system if r.is_system is not None else True,
            created_at=r.created_at.isoformat() if r.created_at else None,
            updated_at=r.updated_at.isoformat() if r.updated_at else None,
        ))
    return result


@router.get("/ia-prompts/{key}", response_model=IaPromptResponse)
def get_prompt_detail(
    key: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """Get a single IA prompt by key (admin only)."""
    row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Prompt '{key}' not found")
    variables = None
    if row.variables:
        try:
            variables = json.loads(row.variables)
        except (json.JSONDecodeError, TypeError):
            variables = None
    return IaPromptResponse(
        id=row.id,
        prompt_key=row.prompt_key,
        label=row.label,
        description=row.description,
        prompt_text=row.prompt_text,
        variables=variables,
        is_system=row.is_system if row.is_system is not None else True,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


@router.put("/ia-prompts/{key}", response_model=IaPromptResponse)
async def update_prompt(
    key: str,
    body: IaPromptUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """Update the prompt_text of an existing prompt (admin only).
    Cannot modify prompt_key, label, variables, or is_system.
    For reference_page_analysis: auto-generates JSON schema and stores it in variables."""
    row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Prompt '{key}' not found")
    row.prompt_text = body.prompt_text
    from datetime import datetime, timezone
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)

    # Auto-generate schema for reference_page_analysis
    # DISABLED: MySQL connection times out during IA call. Schema stored manually.
    if False and key == "reference_page_analysis":
        logger.info("Auto-generating schema for reference_page_analysis...")
        schema = await _extract_schema_from_prompt(body.prompt_text)
        if schema:
            # Increment version if previous schema exists
            old_vars = None
            if row.variables:
                try:
                    old_vars = json.loads(row.variables)
                except (json.JSONDecodeError, TypeError):
                    pass
            if old_vars and isinstance(old_vars, dict) and "version" in old_vars:
                # Only increment if columns changed
                old_cols = old_vars.get("columns", [])
                new_cols = schema.get("columns", [])
                if len(old_cols) != len(new_cols):
                    schema["version"] = old_vars["version"] + 1
                else:
                    schema["version"] = old_vars["version"]
            row.variables = json.dumps(schema, ensure_ascii=False)
            # Reconnect DB if connection was lost during IA call
            try:
                db.commit()
            except Exception:
                db.rollback()
                db.close()
                from app.database import SessionLocal
                db2 = SessionLocal()
                row2 = db2.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
                if row2:
                    row2.variables = json.dumps(schema, ensure_ascii=False)
                    db2.commit()
                db2.close()
            db.refresh(row)
            logger.info("Schema stored: version %d, %d columns", schema.get("version", 1), len(schema.get("columns", [])))
        else:
            logger.warning("Schema extraction failed — keeping old variables")
    variables = None
    if row.variables:
        try:
            variables = json.loads(row.variables)
        except (json.JSONDecodeError, TypeError):
            variables = None
    return IaPromptResponse(
        id=row.id,
        prompt_key=row.prompt_key,
        label=row.label,
        description=row.description,
        prompt_text=row.prompt_text,
        variables=variables,
        is_system=row.is_system if row.is_system is not None else True,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


@router.post("/ia-prompts", response_model=IaPromptResponse, status_code=201)
def create_prompt(
    body: IaPromptCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """Create a new custom IA prompt (admin only). is_system will be set to False."""
    # Check key uniqueness
    existing = db.query(IaPrompt).filter(IaPrompt.prompt_key == body.prompt_key).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Prompt key '{body.prompt_key}' already exists")
    variables_json = json.dumps(body.variables) if body.variables else None
    row = IaPrompt(
        prompt_key=body.prompt_key,
        label=body.label,
        description=body.description,
        prompt_text=body.prompt_text,
        variables=variables_json,
        is_system=False,  # custom prompts are never system
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    variables = None
    if row.variables:
        try:
            variables = json.loads(row.variables)
        except (json.JSONDecodeError, TypeError):
            variables = None
    return IaPromptResponse(
        id=row.id,
        prompt_key=row.prompt_key,
        label=row.label,
        description=row.description,
        prompt_text=row.prompt_text,
        variables=variables,
        is_system=False,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


@router.post("/ia-prompts/{key}/reset", response_model=IaPromptResetResponse)
def reset_prompt(
    key: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """Reset a system prompt to its default value (admin only).
    Only system prompts can be reset. Custom prompts cannot be reset."""
    row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Prompt '{key}' not found")
    if key not in DEFAULT_PROMPTS:
        raise HTTPException(status_code=400, detail=f"No default value for prompt '{key}'")
    row.prompt_text = DEFAULT_PROMPTS[key]["prompt_text"]
    from datetime import datetime, timezone
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)
    return IaPromptResetResponse(
        prompt_key=row.prompt_key,
        prompt_text=row.prompt_text,
        message="Prompt reset to default value",
    )


@router.get("/ia-prompts/{key}/schema")
def get_schema(
    key: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """Get the JSON schema for a prompt (expert mode only). Returns the stored schema or 404."""
    row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Prompt '{key}' not found")
    if not row.variables:
        raise HTTPException(status_code=404, detail="No schema stored for this prompt")
    try:
        schema = json.loads(row.variables)
        return schema
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=500, detail="Invalid schema stored")


@router.delete("/ia-prompts/{key}")
def delete_prompt(
    key: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("admin")),
):
    """Delete a custom IA prompt (admin only). System prompts cannot be deleted."""
    row = db.query(IaPrompt).filter(IaPrompt.prompt_key == key).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Prompt '{key}' not found")
    if row.is_system:
        raise HTTPException(status_code=400, detail="System prompts cannot be deleted. Use reset to restore default value.")
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted": key}