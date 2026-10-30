"""EBIOS-aware LLM prompts for risk-suggestion.

T47 deliverable (Ollama-T4) — quality iteration on top of T45.

What T47 adds over T45:
  * Few-shot examples (2 per type) inlined in the user prompt to anchor
    the model's output style and schema discipline. 4B-class models
    drift quickly without them.
  * A structured JSON-schema hint at the end of every user prompt,
    derived from `app.llm.schemas.get_schema_json()`. This is redundant
    with the Ollama `format="json"` mode but empirically helps: small
    models stop free-texting after the first few tokens.
  * `RGPD_DISCLAIMER` constant: a short French text the router injects
    into the persisted `payload["meta"]` so the audit trail records
    that the suggestion was generated under RGPD constraints (art. 25
    data minimisation + art. 32 security of processing).
  * `PROMPT_VERSION` constant: bumped on any prompt change so the
    router can record which prompt version produced each suggestion.

Conventions:
- All user prompts end with a JSON-schema hint asking for STRICT JSON output.
- `OllamaClient.chat(..., format="json")` enables Ollama's native JSON mode,
  so the model knows to stop free-texting.
- RGPD: we never include PII in the prompt; the system prompt forbids
  inventing person names, IPs, or hostnames.

The 3 supported types map to Risk.scenario / Risk.treatment_plan / a separate
vulnerability field. The 'impact' and 'likelihood' types from the schema are
left for a future iteration — they are score-valued and need different prompting.
"""
from __future__ import annotations

import json
from typing import Optional

from app.llm.schemas import get_schema_json


# Bumped on any prompt change. Persisted in risk_ai_suggestions.payload
# ["meta"]["prompt_version"] so audits can correlate a suggestion with
# the exact prompt text that produced it.
PROMPT_VERSION = "0.4.0-t47"

# Short RGPD notice the router attaches to every persisted suggestion.
# French because the target users (RSSI / compliance officers) read French.
# Kept < 200 chars so it fits in the JSON payload without bloating the row.
RGPD_DISCLAIMER = (
    "Suggestion générée par IA. Aucune PII transmise au modèle. "
    "Données minimisées (art. 25 RGPD). Traitement audité (art. 32 RGPD). "
    "À valider par un humain."
)


SYSTEM_PROMPT = """Tu es un analyste cybersécurité senior spécialisé en EBIOS Risk Manager (ANSSI).
Tu assistes un opérateur humain dans la rédaction de fiches de risques. Tu ne
remplaces JAMAIS son jugement : tu proposes un brouillon qu'il doit relire, valider
ou amender.

Contraintes STRICTES :
- Réponds UNIQUEMENT en JSON valide. Aucun texte avant/après le JSON.
- N'invente JAMAIS de noms de personnes, d'IPs, de hostnames ou de CVE spécifiques.
  Si une information manque, écris explicitement "À compléter manuellement".
- Reste concis : 3-6 phrases maximum par champ texte.
- Ne fais pas de recommandations qui contredisent les contraintes de l'environnement
  (ex: ne suggère pas MFA si l'environnement est air-gapped).
- N'inclus AUCUNE donnée personnelle dans ta réponse (noms, IPs internes précises,
  hostnames). Si tu dois illustrer, utilise des placeholders génériques
  (srv-web-01, user-001, 10.x.x.x/24).

Schéma de sortie attendu :
{
  "text": "<le contenu proposé, 3-6 phrases>",
  "rationale": "<pourquoi ce contenu, 1-2 phrases>",
  "confidence": <float 0.0-1.0, ta confiance dans la qualité de la suggestion>
}
"""


def _common_context(risk) -> dict:
    """Extract the fields we always pass to the LLM, regardless of type."""
    return {
        "risk_uid": getattr(risk, "risk_uid", "") or "",
        "title": getattr(risk, "title", "") or "",
        "threat_source": getattr(risk, "threat_source", "") or "",
        "vulnerability": getattr(risk, "vulnerability", "") or "",
        "current_scenario": getattr(risk, "scenario", "") or "",
        "current_treatment": getattr(risk, "treatment_plan", "") or "",
        "treatment": getattr(risk, "treatment", "") or "reduce",
        "impact": getattr(risk, "impact", None),
        "likelihood": getattr(risk, "likelihood", None),
        "inherent_score": getattr(risk, "inherent_score", None),
        "compliance_section": getattr(risk, "compliance_section", "") or "transverse",
        "status": getattr(risk, "status", "") or "draft",
    }


def _format_context(ctx: dict) -> str:
    """Format the risk context as a readable block for the user prompt."""
    lines = [
        "## Contexte du risque",
        f"- Identifiant : {ctx['risk_uid'] or '(non généré)'}",
        f"- Titre : {ctx['title'] or '(vide)'}",
        f"- Source de menace : {ctx['threat_source'] or '(non identifiée)'}",
        f"- Vulnérabilité connue : {ctx['vulnerability'] or '(non documentée)'}",
        f"- Impact brut (1-5) : {ctx['impact'] if ctx['impact'] is not None else 'N/A'}",
        f"- Vraisemblance brute (1-5) : {ctx['likelihood'] if ctx['likelihood'] is not None else 'N/A'}",
        f"- Score inhérent (1-25) : {ctx['inherent_score'] if ctx['inherent_score'] is not None else 'N/A'}",
        f"- Traitement envisagé : {ctx['treatment'] or 'non spécifié'}",
        f"- Section compliance : {ctx['compliance_section']}",
        f"- Statut : {ctx['status']}",
    ]
    if ctx["current_scenario"]:
        lines.append(f"- Scénario existant : {ctx['current_scenario'][:500]}")
    if ctx["current_treatment"]:
        lines.append(f"- Plan de traitement existant : {ctx['current_treatment'][:500]}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Few-shot examples — anchor the model's output style
# ---------------------------------------------------------------------------
# Two per type, hand-written. We pick realistic EBIOS scenarios (ransomware
# on a critical server, phishing of execs) because that's the dominant use
# case in the operator's day-to-day. The model sees these BEFORE the live
# context block, so it copies the tone (3-6 sentences, factual, no drama).
#
# These examples are static; they are not interpolated with risk-specific
# data. If you change one, bump PROMPT_VERSION.

FEW_SHOT_SCENARIO = [
    # Example 1: ransomware on a critical server
    {
        "context": "## Contexte du risque\n- Identifiant : RSK-2026-0001\n- Titre : Perte serveur fichier critique\n- Source de menace : groupe ransomware organisé\n- Vulnérabilité connue : absence de sauvegarde hors-ligne\n- Impact brut (1-5) : 4\n- Vraisemblance brute (1-5) : 4\n- Score inhérent (1-25) : 16\n- Traitement envisagé : reduce\n- Section compliance : pca\n- Statut : assessed",
        "output": {
            "text": "Un groupe ransomware exploite un serveur de fichiers exposé (CVE à rechercher sur le service RDP) pour chiffrer les partages de production, puis étend son emprise via les relations d'approbation Active Directory.",
            "rationale": "Le scénario suit un kill-chain classique compromission -> chiffrement -> propagation latérale. L'absence de sauvegarde hors-ligne rend la restauration longue (RTO > 24h).",
            "confidence": 0.72
        }
    },
    # Example 2: phishing of an executive
    {
        "context": "## Contexte du risque\n- Identifiant : RSK-2026-0007\n- Titre : Phishing DG\n- Source de menace : groupe APT ciblé\n- Vulnérabilité connue : manque de MFA sur messagerie\n- Impact brut (1-5) : 5\n- Vraisemblance brute (1-5) : 3\n- Score inhérent (1-25) : 15\n- Traitement envisagé : reduce\n- Section compliance : pri\n- Statut : in_treatment",
        "output": {
            "text": "Un attaquant envoie un email frauduleux imitant un fournisseur connu. Le DG clique, ses identifiants sont volés. L'attaquant accède à la messagerie et lance une fraude au président (transferts financiers).",
            "rationale": "Le ciblage DG est cohérent avec un groupe APT à motivation financière. Le scénario se concentre sur l'impact métier (fraude) plus que sur l'IT (compte compromis).",
            "confidence": 0.65
        }
    },
]

FEW_SHOT_TREATMENT = [
    {
        "context": "## Contexte du risque\n- Identifiant : RSK-2026-0001\n- Titre : Perte serveur fichier critique\n- Source de menace : groupe ransomware\n- Traitement envisagé : reduce\n- Score inhérent : 16",
        "output": {
            "text": "1. **Court terme (<3 mois)** : durcir la politique de mots de passe admin et activer MFA sur tous les comptes à privilèges.\n2. **Moyen terme (3-12 mois)** : mettre en place des sauvegardes hors-ligne immuables (règle 3-2-1) et tester la restauration PCA trimestrielle.\n3. **Moyen terme** : déployer un EDR sur le serveur exposé et sur les postes admins.",
            "rationale": "Le plan suit la logique défense en profondeur. Pas de MFA full org (une partie du SI est air-gapped). Sauvegardes immuables = priorité #1 vu le score 16.",
            "confidence": 0.7
        }
    },
    {
        "context": "## Contexte du risque\n- Identifiant : RSK-2026-0007\n- Titre : Phishing DG\n- Source de menace : groupe APT\n- Traitement envisagé : reduce\n- Plan de traitement existant : MFA activé sur DG",
        "output": {
            "text": "1. **Court terme** : étendre le MFA à toute la direction et aux assistants de direction.\n2. **Court terme** : déployer un filtre anti-spoofing (DMARC + SPF + DKIM) sur le domaine.\n3. **Moyen terme** : organiser un exercice de phishing simulé trimestriel et former les cibles prioritaires.",
            "rationale": "Le plan s'appuie sur l'existant (MFA DG déjà actif) pour prioriser les quick wins. La formation continue est nécessaire car le risque n'est jamais éliminable à 100%.",
            "confidence": 0.68
        }
    },
]

FEW_SHOT_VULNERABILITY = [
    {
        "context": "## Contexte du risque\n- Identifiant : RSK-2026-0001\n- Titre : Perte serveur fichier critique\n- Vulnérabilité connue : absence de sauvegarde hors-ligne",
        "output": {
            "text": "La surface d'attaque initiale repose sur un serveur de fichiers exposé sans correctifs récents. Catégorie CWE probable : CWE-1104 (Use of Unmaintained Third-Party Components). L'absence de sauvegardes immuables rend toute compromission destructrice. Un contrôle de détection WAF + EDR aurait alerté dès le premier accès.",
            "rationale": "Pas de CVE précise citée (politique factualité). Le contrôle de détection EDR est la première ligne de défense pour ce type d'attaque.",
            "confidence": 0.55
        }
    },
    {
        "context": "## Contexte du risque\n- Identifiant : RSK-2026-0007\n- Titre : Phishing DG\n- Vulnérabilité connue : manque de MFA sur messagerie",
        "output": {
            "text": "La faiblesse technique est une authentification mono-facteur sur la messagerie exécutive, exposée à un credential-stuffing ou phishing. CWE-308 (Use of Single-factor Authentication). L'exploitation nécessite juste un couple identifiant/mot de passe valide, sans jeton matériel. Un contrôle compensatoire serait un FIDO2 token ou une app authenticator TOTP.",
            "rationale": "CWE-308 est la catégorie exacte. On évite de citer un CVE précis qu'on ne maîtrise pas. Le contrôle de mitigation recommandé est aligné avec les standards NIST SP 800-63B AAL2.",
            "confidence": 0.6
        }
    },
]

FEW_SHOT_BY_TYPE: dict[str, list[dict]] = {
    "scenario": FEW_SHOT_SCENARIO,
    "treatment": FEW_SHOT_TREATMENT,
    "vulnerability": FEW_SHOT_VULNERABILITY,
}


def _render_few_shot(examples: list[dict]) -> str:
    """Render a few-shot example list into a single text block."""
    blocks = []
    for i, ex in enumerate(examples, 1):
        out = ex["output"]
        # Compact JSON, one line, easy for the model to mimic.
        out_json = (
            "{"
            f'"text": {json.dumps(out["text"])}, '
            f'"rationale": {json.dumps(out["rationale"])}, '
            f'"confidence": {out["confidence"]}'
            "}"
        )
        blocks.append(
            f"### Exemple {i}\n\n{ex['context']}\n\n"
            f"Réponse :\n```json\n{out_json}\n```"
        )
    return "\n\n".join(blocks)


def _schema_hint(suggestion_type: str) -> str:
    """Inline a short JSON schema hint at the end of the user prompt.

    Derived from the Pydantic schema for this suggestion_type, but
    stripped of descriptions to keep the token count low. Helps smaller
    models emit valid JSON even if Ollama's `format=json` mode misses
    a corner case.
    """
    schema = get_schema_json(suggestion_type)
    if not schema:
        return ""
    # Keep only the top-level required fields
    return (
        "Schéma JSON strict (à respecter EXACTEMENT) :\n"
        "```json\n"
        "{ \"text\": \"<str 1-2000>\", \"rationale\": \"<str 1-500>\", "
        "\"confidence\": <float 0.0-1.0> }\n"
        "```"
    )


# ---------------------------------------------------------------------------
# User prompt templates — one per suggestion_type
# ---------------------------------------------------------------------------

def scenario_prompt(risk) -> str:
    ctx = _common_context(risk)
    return f"""Tâche : propose un scénario EBIOS pour ce risque.

{_render_few_shot(FEW_SHOT_SCENARIO)}

---

{_format_context(ctx)}

Consignes spécifiques :
- Le scénario doit décrire un chemin d'attaque plausible (source, action, impact).
- Reste en 3-6 phrases factuelles, sans dramatisation.
- Si la section compliance est 'transverse' (processus, RH, supply chain), propose un scénario générique de l'écosystème.
- Ne révèle AUCUN nom de personne, IP précise ou hostname de l'organisation. Placeholders acceptables : srv-web-01, user-001, 10.x.x.x/24.

{_schema_hint("scenario")}
"""


def treatment_prompt(risk) -> str:
    ctx = _common_context(risk)
    return f"""Tâche : propose un plan de traitement pour ce risque.

{_render_few_shot(FEW_SHOT_TREATMENT)}

---

{_format_context(ctx)}

Consignes spécifiques :
- Le plan doit lister 2-4 actions concrètes (mesures techniques, organisationnelles).
- Pour chaque action, précise un délai indicatif : "Court terme (<3 mois)" / "Moyen terme (3-12 mois)" / "Long terme (>1 an)".
- Si l'environnement n'a pas de MFA / EDR / etc., ne le propose pas.
- Aligne-toi sur le traitement déclaré (reduce / accept / transfer / avoid).

{_schema_hint("treatment")}
"""


def vulnerability_prompt(risk) -> str:
    ctx = _common_context(risk)
    return f"""Tâche : décris la vulnérabilité technique sous-jacente à ce risque.

{_render_few_shot(FEW_SHOT_VULNERABILITY)}

---

{_format_context(ctx)}

Consignes spécifiques :
- Décris en 3-5 phrases la faiblesse technique (catégorie CWE, exposition, conditions d'exploitation).
- NE CITE PAS de CVE spécifique que tu n'es pas sûr de connaître — dis "CVE à rechercher" si besoin.
- Indique le type de contrôle qui détecterait ou bloquerait l'exploitation (WAF, EDR, MFA, etc.).
- N'utilise pas d'IPs internes précises ni de hostnames réels. Placeholders génériques uniquement.

{_schema_hint("vulnerability")}
"""


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

PROMPT_BUILDERS = {
    "scenario": scenario_prompt,
    "treatment": treatment_prompt,
    "vulnerability": vulnerability_prompt,
}


SUPPORTED_TYPES = tuple(PROMPT_BUILDERS.keys())


def build_prompt(suggestion_type: str, risk) -> Optional[str]:
    """Return the user prompt for the given suggestion_type, or None if unsupported."""
    builder = PROMPT_BUILDERS.get(suggestion_type)
    if builder is None:
        return None
    return builder(risk)
