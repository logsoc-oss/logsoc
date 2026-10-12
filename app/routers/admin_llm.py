"""Admin endpoints for LLM (Ollama) runtime config.

Endpoints:
  GET  /api/v1/admin/llm/status   — current config (api_key redacted) + healthcheck
  POST /api/v1/admin/llm/reload   — re-read env vars, swap singleton, return new state
  GET  /api/v1/admin/llm/models   — list available models from the Ollama instance

Auth: superadmin or admin role (require_role('admin')).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.routers.auth import require_role
from app.llm.singleton import get_client, get_config, reload_config

logger = logging.getLogger("logsoc.admin.llm")

router = APIRouter()


class LLMStatusResponse(BaseModel):
    config: dict
    reachable: bool
    version: str | None = None
    error: str | None = None


class LLMReloadResponse(BaseModel):
    config: dict
    reachable: bool
    version: str | None = None
    error: str | None = None


class LLMModelInfo(BaseModel):
    name: str
    size: int
    modified_at: str
    family: str | None = None
    parameter_size: str | None = None
    quantization_level: str | None = None
    is_cloud: bool = False
    context_length: int | None = None


class LLMModelsResponse(BaseModel):
    models: list[LLMModelInfo]


@router.get(
    "/llm/status",
    response_model=LLMStatusResponse,
    summary="LLM runtime config + healthcheck",
    description="Returns the current LLMConfig (api_key redacted) and a quick "
                "healthcheck against the configured Ollama instance. "
                "Requires admin role.",
)
async def llm_status(_user=Depends(require_role("admin"))):
    cfg = get_config()
    client = get_client()
    reachable = False
    version = None
    error = None
    try:
        reachable = await client.healthcheck()
        if reachable:
            version = await client.version()
    except Exception as e:
        error = str(e)[:200]
        logger.warning("[admin.llm] status healthcheck failed: %s", e)
    return LLMStatusResponse(
        config=cfg.to_dict(redacted=True),
        reachable=reachable,
        version=version,
        error=error,
    )


@router.post(
    "/llm/reload",
    response_model=LLMReloadResponse,
    summary="Reload LLM config from environment",
    description="Re-reads OLLAMA_URL, OLLAMA_MODEL, OLLAMA_API_KEY, OLLAMA_TIMEOUT "
                "from the running process environment, rebuilds the singleton "
                "OllamaClient. Does NOT require a container restart. "
                "Use this after editing `/opt/logsoc-web/.env` and reloading "
                "the file (e.g. via `docker exec logsoc-api bash -c 'source .env'`). "
                "Requires admin role.",
)
async def llm_reload(_user=Depends(require_role("admin"))):
    try:
        new_cfg = reload_config()
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid LLM env config: {e}")
    client = get_client()
    reachable = False
    version = None
    error = None
    try:
        reachable = await client.healthcheck()
        if reachable:
            version = await client.version()
    except Exception as e:
        error = str(e)[:200]
        logger.warning("[admin.llm] post-reload healthcheck failed: %s", e)
    return LLMReloadResponse(
        config=new_cfg.to_dict(redacted=True),
        reachable=reachable,
        version=version,
        error=error,
    )


@router.get(
    "/llm/models",
    response_model=LLMModelsResponse,
    summary="List available models from the Ollama instance",
    description="Calls GET <OLLAMA_URL>/api/tags on the configured instance and "
                "returns the model list. The 'is_cloud' flag is True for models "
                "suffixed with ':cloud' (Ollama Cloud). "
                "Requires admin role.",
)
async def llm_models(_user=Depends(require_role("admin"))):
    import httpx
    cfg = get_config()
    url = f"{cfg.url}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(cfg.timeout)) as h:
            r = await h.get(url, headers=cfg.auth_headers())
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach Ollama at {cfg.url}: {e}")
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Ollama returned {r.status_code}: {r.text[:200]}")
    data = r.json()
    out = []
    for m in data.get("models", []):
        details = m.get("details", {}) or {}
        model_name = m.get("name", "")
        out.append(LLMModelInfo(
            name=model_name,
            size=m.get("size", 0),
            modified_at=m.get("modified_at", ""),
            family=details.get("family"),
            parameter_size=details.get("parameter_size"),
            quantization_level=details.get("quantization_level"),
            is_cloud=model_name.endswith(":cloud"),
            context_length=None,
        ))
    return LLMModelsResponse(models=out)


@router.get(
    "/llm/models/{model_name}/info",
    summary="Get model info (context_length) for a single model",
)
async def llm_model_info(
    model_name: str,
    _user=Depends(require_role("admin")),
):
    """Calls /api/show for a specific model and returns its context_length."""
    import httpx
    cfg = get_config()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            resp = await client.post(
                f"{cfg.url}/api/show",
                json={"name": model_name},
                headers=cfg.auth_headers(),
            )
            if resp.status_code != 200:
                return {"model": model_name, "context_length": None, "error": f"HTTP {resp.status_code}"}
            mi = resp.json().get("model_info", {})
            ctx_len = None
            for k, v in mi.items():
                if "context_length" in k:
                    ctx_len = v
                    break
            return {"model": model_name, "context_length": ctx_len}
    except Exception as e:
        logger.warning("api/show failed for %s: %s", model_name, e)
        return {"model": model_name, "context_length": None, "error": str(e)}

# ─── Thinking (raisonnement GLM-5.3 / gpt-oss / kimi) ───

@router.get(
    "/llm/thinking",
    summary="Get current thinking configuration",
)
async def get_thinking(_user=Depends(require_role("admin"))):
    """Retourne la config thinking courante + les niveaux supportes."""
    cfg = get_config()
    return {
        "thinking": bool(getattr(cfg, "thinking", True)),
        "thinking_level": getattr(cfg, "thinking_level", "low"),
        "supported_levels": ["low", "medium", "high", "max"],
        "model": cfg.model,
    }


@router.put(
    "/llm/thinking",
    summary="Enable/disable thinking and set level",
    description="Updates ollama.thinking + ollama.thinking_level in config.yaml "
                "(source de verite), reloads the LLM singleton, and returns the "
                "new state. Niveaux: low | medium | high | max.",
)
async def set_thinking(body: dict, _user=Depends(require_role("admin"))):
    import yaml as _yaml
    CONFIG_PATH = "/opt/logsoc-web/config.yaml"

    thinking = body.get("thinking")
    level = body.get("thinking_level")

    if thinking is None and level is None:
        raise HTTPException(status_code=422, detail="Fournir 'thinking' et/ou 'thinking_level'")

    if level is not None:
        level = str(level).strip().lower()
        if level not in ("low", "medium", "high", "max"):
            raise HTTPException(status_code=422, detail=f"Niveau invalide: {level}. Niveaux: low|medium|high|max")

    # Read-modify-write config.yaml (preserve other keys)
    with open(CONFIG_PATH) as f:
        raw = _yaml.safe_load(f) or {}
    ollama = raw.setdefault("ollama", {})
    if thinking is not None:
        ollama["thinking"] = bool(thinking)
    if level is not None:
        ollama["thinking_level"] = level
    with open(CONFIG_PATH, "w") as f:
        _yaml.safe_dump(raw, f, default_flow_style=False, allow_unicode=True, sort_keys=True)

    # Recharger le YAML depuis le disque PUIS le singleton runtime
    try:
        from app import config_loader as _cl
        _cl.reload()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Impossible de relire config.yaml: {e}")
    try:
        new_cfg = reload_config()
        version = None
        client = get_client()
        try:
            version = await client.version()
        except Exception:
            pass
        return {
            "thinking": new_cfg.thinking,
            "thinking_level": new_cfg.thinking_level,
            "model": new_cfg.model,
            "reachable": version is not None,
            "message": "Configuration thinking mise à jour",
        }
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Config invalide après écriture: {e}")

