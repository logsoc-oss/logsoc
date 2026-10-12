# ADR 0004 — On-prem LLM via Ollama for EBIOS risk suggestions

* Status: **Accepted** (2026-06-10)
* Deciders: Fabrice (RSSI/Product), Hermes (technical recommendation)
* Date: 2026-06-10
* Technical story: T44-T47 (Ollama integration), T48 (E2E validation)

## Context and Problem Statement

LogSOC-AI needs AI assistance to help compliance officers write
EBIOS-style risk register entries (scenarios, treatment plans,
vulnerability descriptions). The data is sensitive: threat sources,
vulnerabilities, asset inventories, sometimes personal data flows
(`asset_compliance.data_category=personal`).

Two questions:
1. Which LLM technology?
2. Where does the model run?

Constraints:
* **No data egress** : risk register data must not leave the customer's
  infrastructure (RGPD art. 25 data minimisation, art. 32 security of
  processing, contract clauses with RSSI clients).
* **Operational** : single-server deployment on Hestia (10.0.0.10),
  32 GB RAM, modest GPU (or no GPU — qwen3:4b runs fine on CPU).
* **Quality** : the LLM must produce structured JSON (text + rationale
  + confidence) in EBIOS style (3-6 sentences, factual, no drama).
* **Cost** : zero marginal cost per call. Fixed cost (server + model
  weights) acceptable.
* **Latency budget** : user clicks a button, expects a spinner + a
  draft within 30-60s acceptable (the operator reviews the draft
  anyway, this is a "first version" tool, not an autocomplete).

## Considered Options

### Option A — OpenAI / Anthropic / Mistral SaaS (rejected)

* **Pro** : best-in-class quality, no infra to manage.
* **Pro** : 5-10s typical latency.
* **Con** : **data egress** — every suggestion call sends the risk
  context to a third party. RGPD blocker for our use case
  (personal data, threat intelligence, security posture).
* **Con** : per-token cost accumulates (~$0.01-0.05 per suggestion).
* **Con** : no audit trail of the model behaviour (OpenAI doesn't
  expose logits / raw outputs).

### Option B — Ollama self-hosted (CHOSEN)

* **Pro** : runs on the customer's hardware (or LAN-attached VM).
  No data egress.
* **Pro** : open weights, can be fine-tuned later.
* **Pro** : zero marginal cost.
* **Pro** : full audit trail (every request/response is in our logs).
* **Pro** : supports local models (qwen3:4b, llama3.1:8b) AND Ollama
  Cloud (for customers who want a hosted experience but still use
  the Ollama protocol).
* **Con** : infra to manage (model weights, server, monitoring).
* **Con** : 4-7B models produce less polished output than GPT-4o.
  Mitigated by prompt engineering (few-shot, schema hint) — T47
  hit 100% JSON schema validation with qwen3:4b.
* **Con** : 30s typical latency on CPU for qwen3:4b. Acceptable per
  the latency budget above.

### Option C — Mistral self-hosted via llama.cpp (deferred)

* **Pro** : same data-locality benefits as Ollama.
* **Pro** : well-tuned instruct models (Mistral-7B-Instruct).
* **Con** : more wiring (llama.cpp HTTP server vs. Ollama's polished
  REST API + model registry).
* **Con** : Ollama's `format="json"` mode and model management UX
  are more mature.
* **Decision** : deferred. If Ollama falls behind (model variety,
  perf, license), we can swap to llama.cpp + a different model
  registry later. The `OllamaClient` abstraction in
  `app/llm/ollama_client.py` is small (~130 lines) — swapping
  is bounded.

### Option D — No LLM, rule-based suggestions only (rejected)

* **Pro** : zero infra, zero risk.
* **Con** : the heuristic v1 (R7) produces shallow suggestions —
  EBIOS-flavored but not actionnable. The operator has to rewrite
  half of it. The whole point of the feature is to save operator
  time.
* **Decision** : R7 stays as a baseline / fallback / comparison
  reference (the 3 purple "Heuristique" buttons on the Risques
  page). The 3 sky/blue "LLM" buttons are the new primary path.

## Decision

**Chosen: Option B — Ollama self-hosted.**

We deploy Ollama on the LAN (127.0.0.1:11434, separate VM) and
the FastAPI backend talks to it via HTTP. The frontend never sees
Ollama directly — all calls go through the backend's
`POST /api/v1/risks/{id}/ai-suggest-llm` endpoint, which:
* Validates the user's role (compliance_officer or admin).
* Rate-limits (10 req/min/user, in-memory).
* Snapshots the risk into a dict, closes the DB session (MariaDB
  `wait_timeout=10s` workaround), then calls Ollama.
* Validates the LLM JSON via Pydantic v2 schemas
  (`app/llm/schemas.py`).
* Persists the suggestion in `risk_ai_suggestions` with a `meta`
  dict carrying `rgpd_compliant`, `prompt_version`, `ollama_model`,
  `latency_ms`, `schema_validated` for audit/DPO.
* The frontend extracts `text`/`rationale` from the payload and
  shows an amber "JSON non parsé" badge if `parse_error=true`.

The operator must click "Appliquer" to copy the suggestion into
the risk's actual fields. **The IA never auto-applies.** R7 +
heuristic v1 + manual edit are all still functional.

## Consequences

### Positive

* **RGPD-clean** : no data leaves the infrastructure. RGPD art. 25
  and 32 are satisfied by design.
* **Auditable** : every suggestion is logged in
  `risk_ai_suggestions` with the model name, prompt version,
  latency, and schema validation status. A DPO can run
  `SELECT JSON_EXTRACT(payload, '$.meta.rgpd_compliant') FROM
  risk_ai_suggestions WHERE ...` for an audit report.
* **Cheap** : one VM, ~5 GB disk for qwen3:4b, no per-call cost.
* **Tunable** : we own the prompts (`app/llm/prompts.py`). When
  the model drifts or a new RSSI use case appears, we change the
  prompts (and bump `PROMPT_VERSION`) without depending on a
  vendor.
* **T47 quality** : 15/15 live test calls hit 100% JSON parse +
  100% Pydantic schema validation with qwen3:4b. Confidence
  0.6-0.85. No hallucinated PII (the system prompt forbids it
  + we run few-shot examples of clean outputs).

### Negative

* **Latency** : 30s typical for qwen3:4b on CPU. Mitigation: spinner
  UX, disable-other-buttons-while-running. We don't aim for
  real-time suggestions.
* **Model quality** : qwen3:4b is good but not GPT-4o. Mitigation:
  few-shot examples anchor the style; Pydantic validation catches
  the few bad outputs.
* **Ops burden** : we own the model weights, the Ollama version,
  the network. Mitigation: simple `docker run ollama/ollama` or
  systemd unit on a separate VM, plus a `GET /api/v1/llm/status`
  admin endpoint to verify health.
* **No multi-tenancy isolation** : all operators share the same
  Ollama instance. Acceptable for our deployment (single
  customer) but a multi-tenant SaaS would need a per-tenant
  rate limit and possibly per-tenant model variants.

### Neutral

* **Format ambiguity** : the prompt asks for JSON in 3 different
  ways (system prompt constraint + few-shot output examples +
  inline schema hint). qwen3:4b still occasionally produces a
  non-JSON response. Mitigation: Pydantic schema validation +
  `parse_error=true` + raw text fallback. Operator sees the
  "JSON non parsé" badge and can copy the raw text.
* **Versioning** : `PROMPT_VERSION` is bumped on every prompt
  change. Persisted in the payload meta. This means historical
  suggestions can be correlated with the exact prompt that
  produced them — useful for debugging regressions and for
  compliance audits.

## Validation

T48 (this ADR's validation) covered:

* **E2E live (T48-b)** : 8/8 steps PASSED.
  1. login compliance_officer → token
  2. GET /risks/1 → risk loaded
  3. POST /ai-suggest-llm scenario → 36.3s, qwen3:4b, parse_error=false, conf=0.72
  4. GET /risks/1/ai-suggestions → 8 suggestions listed
  5. DB verify → `prompt_version=0.4.0-t47`, `rgpd_compliant=true` in JSON column
  6. PATCH /risks/1 → risk.scenario updated
  7. POST /ai-suggestions/{id}/apply → applied=true, applied_by=5
  8. DB verify final → applied=1
* **Resilience (T48-c)** : 4/4 error paths return clean HTTP codes.
  - model not found → 502 (Ollama 404 wrapped)
  - unsupported suggestion_type → 422 (Pydantic pattern_mismatch)
  - nonexistent risk → 404
  - missing suggestion_type → 422 (Pydantic missing field)
* **Throughput (T47-f)** : 15/15 LLM calls OK across 5 risks × 3 types.
  100% JSON, 100% Pydantic, 100% RGPD. Latency 16.8-48.3s avg 30s.

Not covered (deferred to future tasks):
* Ollama unreachable (would require changing OLLAMA_URL via admin
  endpoint or container env — destructive, deferred).
* Ollama timeout under contention (would require a deliberately
  slow stub or load test — deferred to a load testing pass).
* Ollama Cloud (`:cloud` model with `OLLAMA_API_KEY`) — needs a
  paid Ollama Cloud account, not in scope.

## Implementation Pointers

* `app/llm/llm_config.py` — env vars, reload, redact
* `app/llm/ollama_client.py` — async httpx wrapper
* `app/llm/singleton.py` — module-level client
* `app/llm/prompts.py` — system prompt, few-shot, build_prompt
* `app/llm/schemas.py` — Pydantic v2 schemas + validate_suggestion
* `app/routers/risks.py` — `create_ai_suggestion_llm` endpoint
* `app/routers/admin_llm.py` — admin endpoints (status, reload, models)
* Frontend `src/pages/Risques.tsx` — 3 sky/blue LLM buttons + spinner
* Frontend `src/api/index.ts` — `risksApi.llmSuggest()`
* Env: `/etc/logsoc/api.env` — `OLLAMA_URL`, `OLLAMA_MODEL`,
  `OLLAMA_TIMEOUT`, optional `OLLAMA_API_KEY`
* Test: `tests/test_llm_*.py` — 50 tests, all pass in 0.63s
* Live validation: `/tmp/val_t47.py` (T47), `/tmp/e2e_t48.py` (T48-b),
  `/tmp/resilience_t48.py` (T48-c)
* Skill: `~/.hermes/skills/devops/logsoc-ollama/SKILL.md`
* Reference: `~/.hermes/skills/devops/logsoc-ollama/references/pydantic-llm-output-validation.md`

## Related Decisions

* ADR 0001 (TBD) — Stack FastAPI + MariaDB + ClickHouse
* ADR 0002 (TBD) — Frontend React + Vite + TanStack Query
* ADR 0003 (TBD) — YARA HQ central distribution

(Future ADRs will be numbered sequentially as new architectural
choices arise. This file is the first one because the previous
choices were implicit / driven by the migration from PHP.)
