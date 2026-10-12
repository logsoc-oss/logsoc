"""Policy summary generation service (Ticket #38).

When a policy is submitted for review (status -> 'review'), this service:
1. Retrieves the current version (N) and previous version (N-1) content.
2. Calls Ollama to generate a non-technical bullet-point summary of changes.
3. Stores the result in policy_summaries.

If Ollama is unavailable or times out (30s max), a fallback message is stored
so the workflow is never blocked.
"""
from __future__ import annotations

import logging
import datetime

from sqlalchemy.orm import Session
from app.models import SecurityPolicy, PolicyVersion, PolicySummary
from app.llm.singleton import get_client
from app.llm.ollama_client import OllamaError

logger = logging.getLogger("logsoc.policy_summary")

FALLBACK_SUMMARY = "Resume non disponible (IA indisponible)"

SYSTEM_PROMPT = (
    "Tu es un assistant qui resume les changements entre deux versions "
    "d'une politique de securite. Genere un resume en points clairs, non "
    "techniques, comprehensible par un manager non-IT. Reponds en francais "
    "avec 3 a 7 points maximum, prefixes par '- '."
)

USER_PROMPT_TEMPLATE = (
    "Voici deux versions d'une politique de securite nommee '{title}'.\n\n"
    "--- VERSION PRECEDENTE (v{prev_version}) ---\n{prev_content}\n\n"
    "--- VERSION ACTUELLE (v{curr_version}) ---\n{curr_content}\n\n"
    "Resume les changements principaux entre ces deux versions en points non techniques."
)


async def generate_policy_summary(policy: SecurityPolicy, db: Session) -> str:
    """Generate and store an AI summary of changes between version N-1 and N.

    Returns the summary text (or fallback if Ollama is unavailable).
    """
    policy_id = policy.id
    curr_version = policy.version or "1.0"
    curr_content = policy.content or ""

    # Get previous version from PolicyVersion table
    versions = db.query(PolicyVersion).filter(
        PolicyVersion.policy_id == policy_id
    ).order_by(PolicyVersion.created_at.desc()).all()

    prev_content = ""
    prev_version = "N/A"
    if len(versions) >= 1:
        prev = versions[0]
        prev_content = prev.content or ""
        prev_version = prev.version or "N/A"
    else:
        prev_content = "(Version initiale)"
        prev_version = "N/A"

    user_prompt = USER_PROMPT_TEMPLATE.format(
        title=policy.title or "Politique",
        prev_version=prev_version,
        prev_content=prev_content[:8000],
        curr_version=curr_version,
        curr_content=curr_content[:8000],
    )

    summary_text = FALLBACK_SUMMARY
    try:
        client = get_client()
        resp = await client.chat(
            prompt=user_prompt,
            system=SYSTEM_PROMPT,
            options={"temperature": 0.3},
        )
        raw = (resp.get("message") or {}).get("content") or ""
        if raw.strip():
            summary_text = raw.strip()
    except OllamaError as e:
        logger.warning("[policy-summary] Ollama error for policy %s: %s", policy_id, e)
    except Exception as e:
        logger.warning("[policy-summary] Unexpected error for policy %s: %s", policy_id, e)

    # Store in policy_summaries (upsert on unique key)
    existing = db.query(PolicySummary).filter(
        PolicySummary.policy_id == policy_id,
        PolicySummary.version == curr_version,
    ).first()

    if existing:
        existing.summary = summary_text
        existing.generated_at = datetime.datetime.now(datetime.timezone.utc)
    else:
        record = PolicySummary(
            policy_id=policy_id,
            version=curr_version,
            summary=summary_text,
        )
        db.add(record)

    db.commit()
    return summary_text
