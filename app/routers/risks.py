"""app/routers/risks.py — Risk register (C1 Compliance & Risques).
v0.11.1 - 2026-06-09.

EBIOS-like risk model:
  impact * likelihood = inherent_score (0-25)
  treatment: reduce | accept | transfer | avoid
  lifecycle: draft → assessed → in_treatment → accepted | mitigated | transferred | closed

AI assistance is delivered as a suggestion audit (POST /risks/{id}/ai-suggest).
Suggestions are stored in risk_ai_suggestions with applied=False by default.
A human must explicitly apply them (PATCH /risks/{id} with the suggested values).
"""
from __future__ import annotations

import datetime
import json
import logging
import re
import time
from collections import defaultdict
from threading import Lock
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.database import get_db
from app.llm.ollama_client import OllamaClient, OllamaError
from app.llm.prompts import (
    SYSTEM_PROMPT, PROMPT_VERSION, RGPD_DISCLAIMER, SUPPORTED_TYPES, build_prompt,
)
from app.llm.schemas import SUPPORTED_OUTPUT_TYPES, validate_suggestion
from app.llm.singleton import get_client
from app.models import Risk, RiskAISuggestion, Agent
from app.routers.auth import get_current_user, require_role, require_permission
from app.models import User
from app.schemas import (
    RiskCreate, RiskUpdate, RiskResponse,
    RiskStatsResponse, RiskAISuggestionCreate, RiskAISuggestionResponse,
)

logger = logging.getLogger("logsoc.risks")
router = APIRouter()


def _next_risk_uid(db: Session) -> str:
    """Generate the next risk_uid in the form RSK-YYYY-NNNN."""
    # T54: replace datetime.datetime.utcnow() (deprecated in Python 3.12+,
    # returns naive datetime that implies UTC) with
    # datetime.datetime.now(datetime.timezone.utc) which returns a
    # timezone-aware datetime. The .year attribute is timezone-independent,
    # so this is a safe drop-in. Matches the B17 cleanup pattern (75 sites
    # updated 2026-06-09, this one was added post-B17 and missed).
    year = datetime.datetime.now(datetime.timezone.utc).year
    prefix = f"RSK-{year}-"
    last = (
        db.query(Risk.risk_uid)
        .filter(Risk.risk_uid.like(f"{prefix}%"))
        .order_by(Risk.id.desc())
        .first()
    )
    if not last:
        return f"{prefix}0001"
    try:
        n = int(last[0].split("-")[-1]) + 1
    except (IndexError, ValueError):
        n = 1
    return f"{prefix}{n:04d}"


def _risk_to_response(r: Risk) -> RiskResponse:
    return RiskResponse(
        id=r.id,
        risk_uid=r.risk_uid,
        title=r.title,
        scenario=r.scenario,
        asset_id=r.asset_id,
        threat_source=r.threat_source,
        vulnerability=r.vulnerability,
        impact=r.impact,
        likelihood=r.likelihood,
        inherent_score=r.impact * r.likelihood,
        treatment=r.treatment,
        # v0.11.3 (R9)
        compliance_section=r.compliance_section,
        treatment_plan=r.treatment_plan,
        owner_email=r.owner_email,
        status=r.status,
        target_close_date=r.target_close_date.isoformat() if r.target_close_date else None,
        closed_at=r.closed_at,
        created_at=r.created_at,
        updated_at=r.updated_at,
        created_by=r.created_by,
    )


# ── List & stats ──

@router.get("/", response_model=List[RiskResponse])
def list_risks(
    status: Optional[str] = Query(None, pattern="^(draft|assessed|in_treatment|accepted|mitigated|transferred|closed)$"),
    treatment: Optional[str] = Query(None, pattern="^(reduce|accept|transfer|avoid)$"),
    min_score: Optional[int] = Query(None, ge=1, le=25),
    owner_email: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("risks", "read")),
):
    """List risks. Any authenticated user can read (analyst+)."""
    q = db.query(Risk)
    if status:
        q = q.filter(Risk.status == status)
    if treatment:
        q = q.filter(Risk.treatment == treatment)
    if owner_email:
        q = q.filter(Risk.owner_email == owner_email)
    if min_score is not None:
        # Filter by computed inherent_score (impact * likelihood)
        q = q.filter(Risk.impact * Risk.likelihood >= min_score)
    q = q.order_by((Risk.impact * Risk.likelihood).desc(), Risk.id.desc())
    return [_risk_to_response(r) for r in q.limit(limit).all()]


@router.get("/stats", response_model=RiskStatsResponse)
def get_risk_stats(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Aggregate KPIs for the /risques dashboard."""
    total = db.query(func.count(Risk.id)).scalar() or 0
    by_status_rows = db.query(Risk.status, func.count(Risk.id)).group_by(Risk.status).all()
    by_status = {s: c for s, c in by_status_rows}
    by_treatment_rows = db.query(Risk.treatment, func.count(Risk.id)).group_by(Risk.treatment).all()
    by_treatment = {t: c for t, c in by_treatment_rows}

    # Score bands (computed in Python: small dataset, indexed by id)
    by_score_band = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    all_rows = db.query(Risk.impact, Risk.likelihood, Risk.status, Risk.target_close_date).all()
    today = datetime.date.today()
    overdue = 0
    for impact, likelihood, status_val, target in all_rows:
        score = impact * likelihood
        if score <= 6:
            by_score_band["low"] += 1
        elif score <= 12:
            by_score_band["medium"] += 1
        elif score <= 19:
            by_score_band["high"] += 1
        else:
            by_score_band["critical"] += 1
        if target and target < today and status_val not in ("closed", "mitigated", "transferred"):
            overdue += 1

    top = (
        db.query(Risk)
        .order_by((Risk.impact * Risk.likelihood).desc())
        .limit(5)
        .all()
    )
    return RiskStatsResponse(
        total=total,
        by_status=by_status,
        by_treatment=by_treatment,
        by_score_band=by_score_band,
        top_risks=[_risk_to_response(r) for r in top],
        overdue=overdue,
    )


# ── Single risk CRUD ──

@router.get("/{risk_id}", response_model=RiskResponse)
def get_risk(risk_id: int, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    r = db.query(Risk).filter(Risk.id == risk_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return _risk_to_response(r)


@router.post("/", response_model=RiskResponse, status_code=status.HTTP_201_CREATED)
def create_risk(
    data: RiskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("risks", "write")),
):
    if data.asset_id is not None:
        agent = db.query(Agent).filter(Agent.id == data.asset_id).first()
        if not agent:
            raise HTTPException(status_code=400, detail=f"Asset {data.asset_id} not found")

    target_date = None
    if data.target_close_date:
        try:
            target_date = datetime.date.fromisoformat(data.target_close_date)
        except ValueError:
            raise HTTPException(status_code=422, detail="target_close_date must be YYYY-MM-DD")

    r = Risk(
        risk_uid=_next_risk_uid(db),
        title=data.title,
        scenario=data.scenario,
        asset_id=data.asset_id,
        threat_source=data.threat_source,
        vulnerability=data.vulnerability,
        impact=data.impact,
        likelihood=data.likelihood,
        treatment=data.treatment,
        # v0.11.3 (R9) — link to compliance section
        compliance_section=data.compliance_section,
        treatment_plan=data.treatment_plan,
        owner_email=data.owner_email,
        status=data.status,
        target_close_date=target_date,
        created_by=user.id if user else None,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return _risk_to_response(r)


@router.patch("/{risk_id}", response_model=RiskResponse)
def update_risk(
    risk_id: int,
    data: RiskUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("compliance_officer", "admin")),
):
    r = db.query(Risk).filter(Risk.id == risk_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")

    payload = data.model_dump(exclude_unset=True)
    target_date = payload.pop("target_close_date", None) if "target_close_date" in payload else None
    if target_date is not None:
        try:
            r.target_close_date = datetime.date.fromisoformat(target_date)
        except ValueError:
            raise HTTPException(status_code=422, detail="target_close_date must be YYYY-MM-DD")

    for k, v in payload.items():
        setattr(r, k, v)

    if r.status in ("mitigated", "transferred", "closed") and not r.closed_at:
        r.closed_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()
    db.refresh(r)
    return _risk_to_response(r)


@router.delete("/{risk_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_risk(
    risk_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("risks", "delete")),
):
    r = db.query(Risk).filter(Risk.id == risk_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    db.delete(r)
    db.commit()
    return None


# ── AI suggestions ──

@router.post(
    "/{risk_id}/ai-suggest",
    response_model=RiskAISuggestionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_ai_suggestion(
    risk_id: int,
    data: RiskAISuggestionCreate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role("compliance_officer", "admin")),
):
    """Store an AI suggestion draft for a risk. The IA may also auto-call this endpoint.
    Suggestions are stored with applied=False. A human must PATCH the risk to apply them.
    """
    r = db.query(Risk).filter(Risk.id == risk_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    sug = RiskAISuggestion(
        risk_id=risk_id,
        suggestion_type=data.suggestion_type,
        payload=data.payload,
        confidence=data.confidence,
    )
    db.add(sug)
    db.commit()
    db.refresh(sug)
    return RiskAISuggestionResponse(
        id=sug.id,
        risk_id=sug.risk_id,
        suggestion_type=sug.suggestion_type,
        payload=sug.payload,
        confidence=float(sug.confidence) if sug.confidence is not None else None,
        applied=sug.applied,
        applied_by=sug.applied_by,
        created_at=sug.created_at,
    )


@router.get(
    "/{risk_id}/ai-suggestions",
    response_model=List[RiskAISuggestionResponse],
)
def list_ai_suggestions(
    risk_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    r = db.query(Risk).filter(Risk.id == risk_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    sugs = (
        db.query(RiskAISuggestion)
        .filter(RiskAISuggestion.risk_id == risk_id)
        .order_by(RiskAISuggestion.created_at.desc())
        .all()
    )
    return [
        RiskAISuggestionResponse(
            id=s.id,
            risk_id=s.risk_id,
            suggestion_type=s.suggestion_type,
            payload=s.payload,
            confidence=float(s.confidence) if s.confidence is not None else None,
            applied=s.applied,
            applied_by=s.applied_by,
            created_at=s.created_at,
        )
        for s in sugs
    ]


@router.post(
    "/{risk_id}/ai-suggestions/{suggestion_id}/apply",
    response_model=RiskAISuggestionResponse,
)
def apply_ai_suggestion(
    risk_id: int,
    suggestion_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("compliance_officer", "admin")),
):
    """Mark an AI suggestion as applied. The risk's own fields must be PATCHed
    separately by the operator — this endpoint only flips the applied flag.
    """
    sug = (
        db.query(RiskAISuggestion)
        .filter(RiskAISuggestion.id == suggestion_id, RiskAISuggestion.risk_id == risk_id)
        .first()
    )
    if not sug:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    sug.applied = True
    sug.applied_by = user.id if user else None
    db.commit()
    db.refresh(sug)
    return RiskAISuggestionResponse(
        id=sug.id,
        risk_id=sug.risk_id,
        suggestion_type=sug.suggestion_type,
        payload=sug.payload,
        confidence=float(sug.confidence) if sug.confidence is not None else None,
        applied=sug.applied,
        applied_by=sug.applied_by,
        created_at=sug.created_at,
    )


# ── AI suggestions via LLM (T45 [Ollama-T2]) ───────────────────────────────
#
# Endpoint: POST /risks/{id}/ai-suggest-llm
#   - Builds the prompt via app.llm.prompts
#   - Calls the singleton OllamaClient with format="json"
#   - Parses the response, stores a RiskAISuggestion (applied=False)
#   - Returns RiskAISuggestionResponse + meta (latency, model, parse_error)
#
# Rate limit: 10 requests / minute / user, in-memory.
# The legacy /ai-suggest endpoint (R7 heuristic) is preserved.

class LLMSuggestionRequest(BaseModel):
    suggestion_type: str = Field(..., pattern=f"^({'|'.join(SUPPORTED_TYPES)})$")
    prompt_overrides: Optional[dict] = None
    model_override: Optional[str] = None


class LLMSuggestionMeta(BaseModel):
    latency_ms: int
    model_used: str
    parse_error: bool
    ollama_status: Optional[int] = None


class LLMSuggestionResponse(BaseModel):
    suggestion: RiskAISuggestionResponse
    meta: LLMSuggestionMeta


# In-memory token-bucket-ish rate limiter: 10 calls per user per 60s.
_RATE_LOCK = Lock()
_RATE_BUCKETS: dict = defaultdict(list)  # user_id -> [ts, ts, ...] of recent calls
_RATE_LIMIT_MAX = 10
_RATE_LIMIT_WINDOW = 60  # seconds


def _check_rate_limit(user_id: int) -> None:
    now = time.time()
    with _RATE_LOCK:
        bucket = _RATE_BUCKETS[user_id]
        # Drop entries older than the window
        cutoff = now - _RATE_LIMIT_WINDOW
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= _RATE_LIMIT_MAX:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {_RATE_LIMIT_MAX} LLM suggestions "
                       f"per user per {_RATE_LIMIT_WINDOW}s. Slow down.",
            )
        bucket.append(now)


# Try to extract the first JSON object from a possibly noisy string.
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_JSON_OBJECT_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}")


def _extract_json_object(text: str) -> Optional[dict]:
    """Best-effort JSON-object extraction from an LLM response. Returns None
    if no valid JSON object is found.
    """
    if not text:
        return None
    # 1. Fenced code block ```json { ... } ```
    m = _JSON_FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # 2. Greedy match for the first balanced JSON object
    m2 = _JSON_OBJECT_RE.search(text)
    if m2:
        try:
            return json.loads(m2.group(0))
        except json.JSONDecodeError:
            pass
    # 3. Last resort: try the whole string
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


@router.post(
    "/{risk_id}/ai-suggest-llm",
    response_model=LLMSuggestionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an AI suggestion via the configured Ollama instance",
    description="Builds an EBIOS-aware prompt from the risk context, calls the "
                "Ollama LLM at OLLAMA_URL, parses the JSON response, and stores "
                "the suggestion in risk_ai_suggestions with applied=False. The "
                "operator must PATCH the risk to actually apply the suggestion. "
                "Rate limit: 10 requests / minute / user.",
)
async def create_ai_suggestion_llm(
    risk_id: int,
    data: LLMSuggestionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("compliance_officer", "admin")),
):
    # 1. Rate limit (in-memory, no DB)
    _check_rate_limit(user.id)

    # 2. Read risk fields into a snapshot dict, then CLOSE the session.
    #    The LLM call below can take 5-30s, and MariaDB's wait_timeout
    #    (default 10s on Hestia) would kill an idle session. We snapshot
    #    the fields we need, close the session, do the LLM call, then
    #    open a fresh session for the write.
    risk = db.query(Risk).filter(Risk.id == risk_id).first()
    if not risk:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    risk_snapshot = {
        "id": risk.id,
        "risk_uid": getattr(risk, "risk_uid", ""),
        "title": risk.title,
        "scenario": getattr(risk, "scenario", "") or "",
        "threat_source": getattr(risk, "threat_source", "") or "",
        "vulnerability": getattr(risk, "vulnerability", "") or "",
        "impact": getattr(risk, "impact", None),
        "likelihood": getattr(risk, "likelihood", None),
        "inherent_score": getattr(risk, "inherent_score", None),
        "treatment": getattr(risk, "treatment", "") or "",
        "treatment_plan": getattr(risk, "treatment_plan", "") or "",
        "compliance_section": getattr(risk, "compliance_section", "") or "transverse",
        "status": getattr(risk, "status", "") or "draft",
    }
    db.close()  # release the connection back to the pool BEFORE the LLM call

    # 3. Build prompt
    user_prompt = build_prompt(data.suggestion_type, _SnapshotRisk(risk_snapshot))
    if user_prompt is None:
        raise HTTPException(
            status_code=422,
            detail=f"suggestion_type {data.suggestion_type!r} not supported. "
                   f"Supported: {', '.join(SUPPORTED_TYPES)}",
        )

    # 4. Call the LLM (no DB connection held during this!)
    client = get_client()
    t0 = time.time()
    try:
        llm_resp = await client.chat(
            prompt=user_prompt,
            system=SYSTEM_PROMPT,
            model=data.model_override,
            format="json",
            options={"temperature": 0.3},
        )
    except OllamaError as e:
        latency_ms = int((time.time() - t0) * 1000)
        logger.warning("[ai-suggest-llm] Ollama error for risk %s: %s", risk_id, e)
        if e.status_code is None:
            if "timeout" in str(e).lower():
                raise HTTPException(status_code=504, detail=f"Ollama timeout: {e}")
            raise HTTPException(status_code=503, detail=f"Ollama unreachable: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned {e.status_code}: {(e.body or '')[:200]}",
        )
    latency_ms = int((time.time() - t0) * 1000)

    # 5. Parse the LLM JSON
    raw_content = (llm_resp.get("message") or {}).get("content") or ""
    model_used = llm_resp.get("model") or (data.model_override or client.config.model)
    parsed = _extract_json_object(raw_content)
    parse_error = parsed is None

    # T47: validate the parsed dict against the Pydantic schema for this
    # suggestion_type. If validation fails (e.g. missing field, wrong
    # type, confidence out of [0,1]), we fall back to parse_error=True
    # and store the raw text — same policy as the regex-extract failure.
    schema_validated = None
    if parsed is not None:
        schema_validated = validate_suggestion(data.suggestion_type, parsed)
        if schema_validated is None:
            # Schema mismatch but we did extract a JSON object.
            # This is a SOFT failure (the LLM emitted JSON, just wrong shape).
            # Keep the parsed payload but flag it.
            logger.warning(
                "[ai-suggest-llm] schema validation failed for risk=%d type=%s "
                "model=%s raw_keys=%s",
                risk_id, data.suggestion_type, model_used,
                list(parsed.keys()) if isinstance(parsed, dict) else None,
            )
            text_val = str(parsed.get("text", "")).strip() if isinstance(parsed, dict) else ""
            rationale_val = str(parsed.get("rationale", "")).strip() if isinstance(parsed, dict) else ""
            try:
                confidence = float(parsed.get("confidence", 0.5)) if isinstance(parsed, dict) else 0.5
            except (TypeError, ValueError):
                confidence = 0.5
            confidence = max(0.0, min(1.0, confidence))
            parsed_payload = {
                "text": text_val,
                "rationale": rationale_val,
                "parse_error": True,  # mark as parse_error so the UI shows the badge
                "schema_error": True,  # distinguish from raw-JSON-garbage
            }
        else:
            # Validation OK — use the Pydantic-normalised values
            text_val = schema_validated.text
            rationale_val = schema_validated.rationale
            confidence = schema_validated.confidence
            parsed_payload = {
                "text": text_val,
                "rationale": rationale_val,
                "parse_error": False,
            }
    else:
        # Could not even extract a JSON object
        parsed_payload = {
            "text": raw_content,
            "rationale": "LLM response was not valid JSON; raw text stored.",
            "parse_error": True,
        }
        confidence = 0.0

    # 6. Open a FRESH DB session for the write (the prior one was closed)
    from app.database import SessionLocal
    db2 = SessionLocal()
    try:
        # T47: attach audit metadata to the payload. The frontend doesn't
        # need to display these, but auditors / DPO can read them out
        # of the JSON column to prove the suggestion was generated
        # under RGPD constraints and with a known prompt version.
        payload_with_meta = dict(parsed_payload)
        payload_with_meta["meta"] = {
            "rgpd_compliant": True,  # No PII in the prompt; system prompt forbids invention.
            "prompt_version": PROMPT_VERSION,
            "rgpd_disclaimer": RGPD_DISCLAIMER,
            "ollama_model": model_used,
            "latency_ms": latency_ms,
            # schema_validated is the Pydantic instance, or None if validation failed.
            # Persist the boolean so audits can count "schema-validated" suggestions.
            "schema_validated": schema_validated is not None,
        }
        sug = RiskAISuggestion(
            risk_id=risk_id,
            suggestion_type=data.suggestion_type,
            payload=payload_with_meta,
            confidence=confidence,
        )
        db2.add(sug)
        db2.commit()
        db2.refresh(sug)
        suggestion_resp = RiskAISuggestionResponse(
            id=sug.id,
            risk_id=sug.risk_id,
            suggestion_type=sug.suggestion_type,
            payload=sug.payload,
            confidence=float(sug.confidence) if sug.confidence is not None else None,
            applied=sug.applied,
            applied_by=sug.applied_by,
            created_at=sug.created_at,
        )
    except Exception:
        db2.rollback()
        raise
    finally:
        db2.close()

    meta = LLMSuggestionMeta(
        latency_ms=latency_ms,
        model_used=model_used,
        parse_error=parse_error,
    )
    logger.info(
        "[ai-suggest-llm] risk=%d type=%s model=%s latency=%dms parse_error=%s "
        "schema_validated=%s prompt=%s",
        risk_id, data.suggestion_type, model_used, latency_ms, parse_error,
        schema_validated is not None, PROMPT_VERSION,
    )
    return LLMSuggestionResponse(suggestion=suggestion_resp, meta=meta)


class _SnapshotRisk:
    """Duck-typed stand-in for the Risk model, fed from a dict snapshot.

    Lets the prompt builder see the same attribute API (risk.title, .scenario,
    etc.) without holding a live SQLAlchemy session.
    """
    def __init__(self, data: dict):
        self.__dict__.update(data)
