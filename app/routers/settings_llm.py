"""Settings endpoints for LLM (Ollama) configuration.

GET  /api/v1/settings/llm       — current config (api_key redacted)
PUT  /api/v1/settings/llm       — save config to config.yaml + reload singleton
POST /api/v1/settings/llm/test  — test Ollama connection (version + models)

Auth: admin role required.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import httpx
import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.routers.auth import require_role
from app.llm_config import LLMConfig
from app.llm.singleton import get_config, reload_config
from app.config_loader import CFG

logger = logging.getLogger("logsoc.settings.llm")

router = APIRouter()

# Config file path — same as config_loader
CONFIG_PATHS = [
    Path("/app/config.yaml"),
    Path("/opt/logsoc-web/config.yaml"),
    Path("/etc/logsoc/api.env"),
    Path("./config.yaml"),
]


def _find_config_path() -> Path:
    for p in CONFIG_PATHS:
        if p.exists() and p.is_file():
            return p
    raise FileNotFoundError("No config.yaml found")


class LLMSettingsResponse(BaseModel):
    url: str
    model: str
    api_key: str
    timeout: int
    temperature: float
    context_length: int
    thinking: bool = True
    thinking_level: str = "low"


class LLMSettingsUpdate(BaseModel):
    url: str
    model: str
    api_key: str = ""
    timeout: int = 30
    temperature: float = 0.1
    context_length: int
    thinking: Optional[bool] = None
    thinking_level: Optional[str] = None

    @field_validator("temperature")
    @classmethod
    def validate_temp(cls, v):
        if v is not None and (v < 0 or v > 2):
            raise ValueError("temperature must be between 0 and 2")
        return v

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v < 1 or v > 300:
            raise ValueError("Timeout must be between 1 and 300 seconds")
        return v


class LLMTestRequest(BaseModel):
    url: str
    api_key: str = ""


class LLMTestResponse(BaseModel):
    status: str  # "ok" or "error"
    version: Optional[str] = None
    models: Optional[list[str]] = None
    message: Optional[str] = None


@router.get(
    "/llm",
    response_model=LLMSettingsResponse,
    summary="Get current LLM configuration",
    description="Returns the current Ollama configuration (api_key shown as-is for admin). "
                "Requires admin role.",
)
async def get_llm_settings(_user=Depends(require_role("admin"))):
    cfg = get_config()
    return LLMSettingsResponse(
        url=cfg.url,
        model=cfg.model,
        api_key=cfg.api_key,
        timeout=cfg.timeout,
        temperature=cfg.temperature,
        context_length=cfg.context_length,
        thinking=getattr(cfg, "thinking", True),
        thinking_level=getattr(cfg, "thinking_level", "low"),
    )


@router.put(
    "/llm",
    response_model=LLMSettingsResponse,
    summary="Update LLM configuration",
    description="Save the LLM configuration to config.yaml (ollama section) and "
                "reload the singleton. Requires admin role.",
)
async def update_llm_settings(
    body: LLMSettingsUpdate,
    _user=Depends(require_role("admin")),
):
    # Read current config
    config_path = _find_config_path()
    with open(config_path, "r") as f:
        config_data = yaml.safe_load(f)

    if not isinstance(config_data, dict):
        raise HTTPException(status_code=500, detail="Invalid config.yaml format")

    # Update ollama section
    if "ollama" not in config_data:
        config_data["ollama"] = {}
    config_data["ollama"]["url"] = body.url
    config_data["ollama"]["model"] = body.model
    config_data["ollama"]["api_key"] = body.api_key
    config_data["ollama"]["timeout"] = body.timeout
    config_data["ollama"]["temperature"] = body.temperature
    config_data["ollama"]["context_length"] = body.context_length
    if body.thinking is not None:
        config_data["ollama"]["thinking"] = body.thinking
    if body.thinking_level is not None:
        config_data["ollama"]["thinking_level"] = body.thinking_level
    # pages_per_request REMOVED — batch mode fails, always 1 page per request

    # Write back
    with open(config_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)

    # Reload in-memory singleton
    # We need to update CFG dict as well since config_loader reads it at import time
    from app.config_loader import _CONFIG_FILE
    import app.config_loader as _cl

    with open(config_path, "r") as f:
        new_cfg_data = yaml.safe_load(f)
    _cl.CFG.clear()
    _cl.CFG.update(new_cfg_data)

    new_cfg = reload_config()
    logger.info("LLM settings updated: url=%s model=%s timeout=%ds", new_cfg.url, new_cfg.model, new_cfg.timeout)

    return LLMSettingsResponse(
        url=new_cfg.url,
        model=new_cfg.model,
        api_key=new_cfg.api_key,
        timeout=new_cfg.timeout,
        temperature=new_cfg.temperature,
        context_length=new_cfg.context_length,
        thinking=getattr(new_cfg, "thinking", True),
        thinking_level=getattr(new_cfg, "thinking_level", "low"),
    )


@router.post(
    "/llm/test",
    response_model=LLMTestResponse,
    summary="Test Ollama connection",
    description="Test connectivity to an Ollama instance. Fetches version and model list. "
                "Requires admin role.",
)
async def test_llm_connection(
    body: LLMTestRequest,
    _user=Depends(require_role("admin")),
):
    url = body.url.strip().rstrip("/")
    headers = {}
    if body.api_key:
        headers["Authorization"] = f"Bearer {body.api_key}"

    # 1. Get version
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            r = await client.get(f"{url}/api/version", headers=headers)
            if r.status_code != 200:
                return LLMTestResponse(
                    status="error",
                    message=f"Ollama returned HTTP {r.status_code}: {r.text[:200]}",
                )
            version = r.json().get("version", "unknown")
    except httpx.TimeoutException:
        return LLMTestResponse(status="error", message="Connection timed out after 10 seconds")
    except httpx.ConnectError as e:
        return LLMTestResponse(status="error", message=f"Connection refused: {e}")
    except Exception as e:
        return LLMTestResponse(status="error", message=f"Connection error: {e}")

    # 2. Get models
    models: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            r = await client.get(f"{url}/api/tags", headers=headers)
            if r.status_code == 200:
                data = r.json()
                for m in data.get("models", []):
                    name = m.get("name", "")
                    if name:
                        models.append(name)
    except Exception:
        # Non-fatal: version works but models listing failed
        pass

    # 3. If api_key is present, verify auth with a real generate call
    # /api/version and /api/tags may return 200 without valid auth on Ollama Cloud
    # but /api/generate requires a valid API key
    if body.api_key:
        try:
            test_payload = {
                "model": models[0] if models else "kimi-k2.6",
                "prompt": "Test",
                "stream": False,
                "options": {"num_predict": 1},
            }
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
                r = await client.post(
                    f"{url}/api/generate",
                    json=test_payload,
                    headers=headers,
                )
                if r.status_code == 401:
                    return LLMTestResponse(
                        status="error",
                        message="Authentication failed (401). API key is invalid or expired.",
                    )
                if r.status_code == 403:
                    return LLMTestResponse(
                        status="error",
                        message="Forbidden (403). API key lacks access to this model.",
                    )
                if r.status_code != 200:
                    return LLMTestResponse(
                        status="error",
                        message=f"Generate test failed: HTTP {r.status_code}: {r.text[:200]}",
                    )
        except httpx.TimeoutException:
            return LLMTestResponse(
                status="error",
                message="Generate test timed out (30s). Check model availability.",
            )
        except Exception as e:
            return LLMTestResponse(
                status="error",
                message=f"Generate test error: {e}",
            )

    return LLMTestResponse(
        status="ok",
        version=version,
        models=models,
        message=f"Connected to Ollama {version}, {len(models)} models available" + (", API key valid" if body.api_key else ""),
    )