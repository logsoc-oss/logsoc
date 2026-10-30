"""Pydantic v2 schemas for LLM-generated risk suggestions.

T47 deliverable (Ollama-T4: EBIOS-aware prompts).

These schemas define the strict output shape the LLM must respect when
answering each `suggestion_type` prompt. They are used by the router
(`app.routers.risks`) to validate the parsed JSON returned by Ollama
before persisting it in `risk_ai_suggestions.payload`.

Why Pydantic and not just trust the regex-extracted dict?
- Provides clear error messages on schema violations (e.g. missing fields).
- Pydantic's coercion lets us accept int-shaped `confidence` from
  under-trained models (we already clamp to [0.0, 1.0] in the router).
- The same JSON Schema can be inlined in the system prompt to nudge the
  LLM toward valid output (see `prompts._SCHEMA_HINT_*`).

Conventions
-----------
* All three types share a common envelope:
    - `text`       (str, 1-2000 chars, the main drafted content)
    - `rationale`  (str, 1-500 chars, why this content)
    - `confidence` (float, 0.0-1.0)
    - `parse_error` (bool, False on success, True if the LLM returned
                    something unparseable; set by the router, never by
                    the LLM itself)
* Optional `meta` dict carries audit metadata (RGPD compliance, model
  name, prompt version). The router fills it; the LLM never sets it.

If the LLM returns a value that fails validation, the router does NOT
crash — it falls back to a `parse_error=True` payload (raw text + low
confidence) so the operator can still see what came back.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Common envelope
# ---------------------------------------------------------------------------


class SuggestionEnvelope(BaseModel):
    """Common fields every LLM suggestion must contain.

    The three concrete output types (Scenario, Treatment, Vulnerability)
    all extend this — it gives us a single .text/.rationale/.confidence
    access path in the frontend (Risques.tsx extracts these directly).
    """
    text: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="Main drafted content (3-6 sentences typical).",
    )
    rationale: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Why this content was proposed (1-2 sentences).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model's self-assessed confidence, 0.0 (random) to 1.0 (sure).",
    )
    # Set by the router when the LLM response was not parseable.
    # Never written by the LLM itself. Defaults to False.
    parse_error: bool = Field(
        default=False,
        description="True iff the router could not extract a valid JSON object "
                    "from the LLM response. Raw text is then in `text`.",
    )


# ---------------------------------------------------------------------------
# Per-suggestion-type schemas
# ---------------------------------------------------------------------------


class ScenarioOutput(SuggestionEnvelope):
    """EBIOS attack-path scenario draft.

    No additional fields beyond the envelope — the scenario is free text
    in EBIOS style (source de menace, action, impact).
    """
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "text": "Un groupe APT exploite un serveur exposé non patché "
                        "(CVE à rechercher) pour obtenir un premier accès, puis "
                        "bascule latéralement vers le contrôleur de domaine "
                        "via une relation d'approbation technique.",
                "rationale": "Le scénario suit un kill-chain classique compromission "
                             "-> mouvement latéral -> impact métier. La vulnérabilité "
                             "initiale est cohérente avec l'absence de MDM sur les "
                             "postes nomades (cf. vulnérabilité connue).",
                "confidence": 0.72,
                "parse_error": False,
            }
        }
    )


class TreatmentOutput(SuggestionEnvelope):
    """EBIOS treatment plan (reduce / accept / transfer / avoid).

    `text` is a markdown-light list of 2-4 actions, each with a timeframe
    (short <3m / medium 3-12m / long >1y). The model is told NEVER to
    suggest a control that contradicts the environment (e.g. MFA in an
    air-gapped network).
    """
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "text": "1. **Court terme** : durcir la politique de mots de passe "
                        "(longueur >= 14, pas de rotation forcée, MFA sur les "
                        "comptes à privilèges).\n"
                        "2. **Moyen terme** : déployer un EDR sur les 50 postes "
                        "sensibles et le serveur exposé.\n"
                        "3. **Moyen terme** : tester la procédure de restauration "
                        "PCA tous les 6 mois (runbook.proc.pca_restore).",
                "rationale": "Le plan s'aligne sur un traitement de type 'reduce' "
                             "déjà déclaré et tient compte du score inhérent 16 "
                             "(priorité haute). Pas de MFA full org recommandé "
                             "car une partie du SI est air-gapped.",
                "confidence": 0.65,
                "parse_error": False,
            }
        }
    )


class VulnerabilityOutput(SuggestionEnvelope):
    """Underlying technical vulnerability draft.

    `text` describes the weakness (CWE category, exposition, exploitation
    conditions) WITHOUT citing a specific CVE the model isn't sure about.
    The model is told to say "CVE à rechercher" instead of inventing one.
    """
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "text": "La surface d'attaque initiale repose sur un serveur web "
                        "exposé sans correctifs de sécurité récents. La catégorie "
                        "CWE probable est CWE-1104 (Use of Unmaintained Third-Party "
                        "Components) combinée à un risque d'injection (CWE-89) si "
                        "les entrées ne sont pas sanitisées. Un CVE précis est à "
                        "rechercher dans la base NVD selon le stack détecté.",
                "rationale": "La description évite d'inventer un identifiant CVE "
                             "(politique RGPD / factualité). Le contrôle de "
                             "détection suggéré est un WAF + un scanner de "
                             "vulnérabilités hebdomadaire.",
                "confidence": 0.55,
                "parse_error": False,
            }
        }
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


# Map suggestion_type -> Pydantic class. Used by the router to validate
# the parsed JSON dict against the right schema. Mirrors PROMPT_BUILDERS
# in app.llm.prompts.
SCHEMA_BUILDERS: dict[str, type[SuggestionEnvelope]] = {
    "scenario": ScenarioOutput,
    "treatment": TreatmentOutput,
    "vulnerability": VulnerabilityOutput,
}


SUPPORTED_OUTPUT_TYPES: tuple[str, ...] = tuple(SCHEMA_BUILDERS.keys())


def validate_suggestion(suggestion_type: str, parsed: dict) -> Optional[SuggestionEnvelope]:
    """Validate a parsed JSON dict against the right Pydantic schema.

    Returns the validated model instance on success, None on failure.
    On failure, the caller should fall back to a `parse_error=True`
    payload (raw text) so the operator still sees what the LLM said.

    Why not raise? Because the failure mode we want is "best-effort
    storage with a warning", not "500 error to the user". The router
    catches ValidationError separately for logging.
    """
    cls = SCHEMA_BUILDERS.get(suggestion_type)
    if cls is None:
        return None
    try:
        return cls.model_validate(parsed)
    except Exception:
        return None


def get_schema_json(suggestion_type: str) -> Optional[dict]:
    """Return the JSON Schema dict for a suggestion_type, or None.

    Used by the prompt builder to inject a strict schema hint into the
    user prompt (helps smaller models emit valid JSON).
    """
    cls = SCHEMA_BUILDERS.get(suggestion_type)
    if cls is None:
        return None
    return cls.model_json_schema()
