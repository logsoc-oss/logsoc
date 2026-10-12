import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth, assets, alerts, system, users, events, yara, compliance, ai, ws, agents, actions, correlation, sigma, cases, gdpr, risks, runbook, compliance_infra, admin_llm, agent_config, regulatory_notifications, crisis, crisis_sessions, nis2, dora, gdpr_ext, iso27001, aiact, soar, threat_intel, reporting, cross_mapping, nis2_countries, frameworks_modular, governance, runbooks, hunting, fp_suppressions, cmdb, cmdb_grc, integrations, infrastructure, onboarding, warroom, retention, crisis_warroom_ext, audit, settings_llm, settings_smtp, practices, settings_seed, policy_documents, public_validate, ia_prompts, action_plans, reference_requirements, grc_bridge, governance_actions, governance_docs, domain_skills, wizard, dpo_registries, homologation, governance_committees, business_roles, service_members, settings_practices, business_questionnaires  # Phase3 + Phase4 + Phase5 + Phase6 + Phase7 + #35 + #9 + Phase 2 GovEngine
from app.routers import network_scan  # Network scan for asset discovery + T27 + #29
from app.plugins import PluginManager, setup_plugins
from app.correlation_engine import correlation_worker
# T58 v3.14.0: YARA content fetch from agent → central
from app.yara_scanner import init_scanner as init_yara_scanner
from app.database import SessionLocal

logger = logging.getLogger("logsoc.main")

# Global task references
_broadcaster_task = None
_correlation_task = None
_correlation_stop = None
_policy_reminder_task = None  # Ticket #24: J+7 policy reminder scheduler
_yara_import_task = None  # Ticket #65: Daily YARA rules import scheduler
_retention_task = None  # Ticket #9: Daily retention purge scheduler

BASE_DIR = Path(__file__).resolve().parent.parent
PLUGIN_DIR = BASE_DIR / "plugins"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background tasks on startup, stop on shutdown."""
    global _broadcaster_task, _correlation_task, _correlation_stop, _policy_reminder_task, _yara_import_task, _retention_task
    _broadcaster_task = asyncio.create_task(ws._broadcaster())
    logger.info("WebSocket broadcaster started")
    # v0.3: correlation engine (eBPF ↔ journald cross-validation analyzer)
    _correlation_stop = asyncio.Event()
    _correlation_task = asyncio.create_task(correlation_worker(_correlation_stop))
    logger.info("Correlation engine started")
    # T58 v3.14.0: initialize the YARA content scanner (libyara + rules from DB)
    # Run synchronously at startup so the global scanner is ready before any
    # /yara/scan request hits. Failure is logged but does NOT crash the app —
    # the endpoint will return 503 if the scanner is unavailable.
    try:
        ok, err = init_yara_scanner(SessionLocal)
        if ok:
            logger.info("YARA content scanner initialized (T58)")
        else:
            logger.warning("YARA content scanner init failed: %s", err)
    except Exception as e:
        logger.exception("YARA content scanner init exception: %s", e)

    # Ticket #24: Policy reminder scheduler — runs daily at 09:00 Paris (07:00 UTC)
    # Disabled by default; enable via POLICY_REMINDER_ENABLED=1 env var.
    if os.getenv("POLICY_REMINDER_ENABLED", "").lower() in ("1", "true", "yes"):
        from app.scheduler_policy_reminders import run_policy_reminder_job

        async def _policy_reminder_loop():
            """Background loop: sleep until 07:00 UTC, run the job, sleep 24h."""
            logger.info("Policy reminder scheduler started (daily at 07:00 UTC)")
            while True:
                now = datetime.now(timezone.utc)
                # Next 07:00 UTC
                target = now.replace(hour=7, minute=0, second=0, microsecond=0)
                if target <= now:
                    target += timedelta(days=1)
                delay = (target - now).total_seconds()
                logger.info("Policy reminder next run in %.0f seconds", delay)
                await asyncio.sleep(delay)
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, run_policy_reminder_job
                    )
                    logger.info("Policy reminder job result: %s", result)
                except Exception as exc:
                    logger.exception("Policy reminder job failed: %s", exc)

        _policy_reminder_task = asyncio.create_task(_policy_reminder_loop())

    # Ticket #65: YARA rules import scheduler — runs daily at 03:00 UTC
    # Disabled by default; enable via YARA_IMPORT_ENABLED=1 env var.
    if os.getenv("YARA_IMPORT_ENABLED", "").lower() in ("1", "true", "yes"):
        from app.scheduler_yara_import import run_yara_import_job

        async def _yara_import_loop():
            """Background loop: sleep until 03:00 UTC, run the import, sleep 24h."""
            logger.info("YARA import scheduler started (daily at 03:00 UTC)")
            while True:
                now = datetime.now(timezone.utc)
                # Next 03:00 UTC
                target = now.replace(hour=3, minute=0, second=0, microsecond=0)
                if target <= now:
                    target += timedelta(days=1)
                delay = (target - now).total_seconds()
                logger.info("YARA import next run in %.0f seconds", delay)
                await asyncio.sleep(delay)
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, run_yara_import_job
                    )
                    logger.info("YARA import job result: %s", result)
                except Exception as exc:
                    logger.exception("YARA import job failed: %s", exc)

        _yara_import_task = asyncio.create_task(_yara_import_loop())

    # Ticket #9: Daily retention purge scheduler — runs at 02:00 UTC
    _retention_task = None

    async def _retention_sweep_loop():
        """Background loop: sleep until 02:00 UTC, run the purge, sleep 24h."""
        logger.info("Retention daily sweep scheduler started (02:00 UTC)")
        from app.database import SessionLocal
        from app.services.retention_service import run_all_enabled_policies
        while True:
            now = datetime.now(timezone.utc)
            target = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if target <= now:
                target += timedelta(days=1)
            delay = (target - now).total_seconds()
            logger.info("Retention sweep next run in %.0f seconds", delay)
            await asyncio.sleep(delay)
            try:
                db = SessionLocal()
                try:
                    result = run_all_enabled_policies(db, dry_run=False)
                    logger.info("Retention daily sweep completed: %s", result)
                finally:
                    db.close()
            except Exception as exc:
                logger.exception("Retention daily sweep failed: %s", exc)

    _retention_task = asyncio.create_task(_retention_sweep_loop())

    # Recover pending policy document analyses interrupted by container restart
    try:
        from app.routers.policy_documents import _recover_pending_analyses_async, _analysis_queue
        # await _recover_pending_analyses_async()  # disabled — manual launch only
        logger.info("Policy document analysis recovery completed. Queue size: %d", len(_analysis_queue))
    except Exception as e:
        logger.error("Policy document analysis recovery failed: %s", repr(e))

    yield
    if _broadcaster_task:
        _broadcaster_task.cancel()
        logger.info("WebSocket broadcaster cancelled")
    if _correlation_stop:
        _correlation_stop.set()
    if _correlation_task:
        try:
            await asyncio.wait_for(_correlation_task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _correlation_task.cancel()
    logger.info("Correlation engine stopped")
    if _policy_reminder_task:
        _policy_reminder_task.cancel()
        logger.info("Policy reminder scheduler cancelled")
    if _yara_import_task:
        _yara_import_task.cancel()
        logger.info("YARA import scheduler cancelled")
    if _retention_task:
        _retention_task.cancel()
        logger.info("Retention daily sweep scheduler cancelled")


app = FastAPI(
    title="LOGSOC API",
    description="LogSOC SIEM — Security Information and Event Management Platform.\n\n"
    "## Authentication\n"
    "All endpoints (except `/auth/login`) require a Bearer JWT token in the `Authorization` header.\n\n"
    "## Roles\n"
    "- **superadmin** — full access\n"
    "- **admin** — management access\n"
    "- **analyst** — read + alert operations\n"
    "- **viewer** — read-only\n\n"
    "## Event Ingestion\n"
    "## Event Ingestion\nAgents push events via `POST /api/v1/events/ingest` with HMAC-SHA256 signature.",
    version="0.6.4",
    lifespan=lifespan,
    contact={"name": "LogSOC Team", "url": "https://logsoc.anytimeadmin.info"},
    license_info={"name": "Proprietary"},
)

# CORS
# NOTE: allow_origins=["*"] + allow_credentials=True is REJECTED by browsers
# (spec violation). Must list origins explicitly when credentials=True.
# Since we use Bearer JWT in Authorization header (not cookies), we don't
# actually need allow_credentials=True, but we keep it for compat with
# the websocket auth flow. Origins are explicit for production.
_cors_origins = [
    "https://logsoc.anytimeadmin.info",
    "http://logsoc.anytimeadmin.info",
    "https://logsoc.anytimeadmin.info:443",
]
# Add local dev origins only when not in production
import os as _os
if _os.getenv("ENV", "production") != "production":
    _cors_origins += [
        "http://localhost:5173",  # Vite dev
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ticket #29 — Auditor expiration middleware
# Block expired auditor access at middleware level (no client-side cache).
from starlette.requests import Request
from starlette.responses import JSONResponse
from app.database import SessionLocal as _SessionLocal
from app.models import User as _User
from datetime import datetime as _dt, timezone as _tz

@app.middleware("http")
async def auditor_expiration_middleware(request: Request, call_next):
    """Block requests from expired auditor accounts (role_expires_at < now)."""
    # Skip non-API paths and login
    path = request.url.path
    if not path.startswith("/api/v1/") or path == "/api/v1/auth/login":
        return await call_next(request)

    # Get the Authorization header
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return await call_next(request)

    token = auth_header[7:]
    try:
        from jose import jwt as _jwt
        from app.config import JWT_SECRET, JWT_ALGORITHM
        payload = _jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            return await call_next(request)
        user_id = int(payload.get("sub", 0))
        role = payload.get("role", "")
    except Exception:
        return await call_next(request)

    # Only check auditors
    if role != "auditor":
        return await call_next(request)

    # Check expiration in DB
    db = _SessionLocal()
    try:
        user = db.query(_User).filter(_User.id == user_id, _User.is_active == True).first()
        if user and user.role_expires_at:
            if user.role_expires_at < _dt.now(_tz.utc):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Auditor access has expired. Contact your administrator."},
                )
    finally:
        db.close()

    return await call_next(request)

# Core routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(business_roles.router, prefix="/api/v1/business-roles", tags=["business-roles"])
app.include_router(service_members.router, prefix="/api/v1/services", tags=["service-members"])
app.include_router(network_scan.router, prefix="/api/v1/assets", tags=["assets", "network-scan"])  # MUST be before assets.router
app.include_router(assets.router, prefix="/api/v1/assets", tags=["assets"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(events.router, prefix="/api/v1/events", tags=["events"])
app.include_router(yara.router, prefix="/api/v1", tags=["yara"])
app.include_router(compliance.router, prefix="/api/v1", tags=["compliance"])
app.include_router(system.router, prefix="/api/v1/system", tags=["system"])
app.include_router(ai.router, prefix="/api/v1", tags=["ai"])
app.include_router(ws.router, tags=["websocket"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(actions.router, prefix="/api/v1/actions", tags=["actions"])  # T28
app.include_router(correlation.router, prefix="/api/v1/correlation", tags=["correlation"])
app.include_router(sigma.router, prefix="/api/v1/sigma", tags=["sigma"])
app.include_router(cases.router, prefix="/api/v1/cases", tags=["cases"])
# v0.11.1 — Risks (C1 Compliance & Risques)
app.include_router(risks.router, prefix="/api/v1/risks", tags=["risks"])
# v0.11.1 — Runbook (C2 Compliance Infra)
app.include_router(runbook.router, prefix="/api/v1/runbook", tags=["runbook"])
# v0.11.2 — Compliance Infra scoring (C2 RSSI V3)
app.include_router(compliance_infra.router, prefix="/api/v1/compliance-infra", tags=["compliance-infra"])
# v0.12.0 — LLM admin (Ollama config + reload + models) — T44
app.include_router(admin_llm.router, prefix="/api/v1/admin", tags=["admin", "llm"])
app.include_router(agent_config.router, prefix="/api/v1", tags=["agent-config"])
# v0.10.0 — GDPR / Retention (issue #4)
# Prefix /api/v1 declared in the router file (gdpr.py uses absolute paths)
app.include_router(gdpr.router, prefix="/api/v1", tags=["gdpr"])
app.include_router(regulatory_notifications.router, prefix="/api/v1/notifications", tags=["notifications", "regulatory"])  # T85
app.include_router(crisis_warroom_ext.router, prefix="/api/v1/crisis", tags=["crisis-warroom"])  # T27 — MUST be before crisis.router
app.include_router(crisis_sessions.router, prefix="/api/v1/crisis", tags=["crisis-sessions"])  # MUST be before crisis.router
app.include_router(crisis_sessions.router, prefix="/api/v1/crisis", tags=["crisis-sessions"])  # MUST be before crisis.router
app.include_router(crisis.router, prefix="/api/v1/crisis", tags=["crisis"])  # T86
app.include_router(nis2.router, prefix="/api/v1/nis2", tags=["nis2", "compliance"])  # T87
app.include_router(dora.router, prefix="/api/v1/dora", tags=["dora", "compliance"])  # T88
app.include_router(gdpr_ext.router, prefix="/api/v1/gdpr-ext", tags=["gdpr-ext", "compliance"])  # T89
app.include_router(iso27001.router, prefix="/api/v1/iso27001", tags=["iso27001", "compliance"])  # T90
app.include_router(aiact.router, prefix="/api/v1/aiact", tags=["ai-act", "compliance"])  # T91
app.include_router(soar.router, prefix="/api/v1/soar", tags=["soar"])  # T92
app.include_router(threat_intel.router, prefix="/api/v1/ti", tags=["threat-intel"])  # T93
app.include_router(reporting.router, prefix="/api/v1/reports", tags=["reporting", "dashboards"])  # T94
app.include_router(cross_mapping.router, prefix="/api/v1/mapping", tags=["mapping", "compliance"])  # T95
app.include_router(nis2_countries.router, prefix="/api/v1/nis2-countries", tags=["nis2-countries", "compliance"])  # T96
app.include_router(frameworks_modular.router, prefix="/api/v1/frameworks", tags=["frameworks", "compliance"])  # T97
app.include_router(governance.router, prefix="/api/v1/governance", tags=["governance", "compliance"])  # Phase 2
app.include_router(policy_documents.router, prefix="/api/v1/policies", tags=["policies"])  # Policy documents library
app.include_router(reference_requirements.router, prefix="/api/v1/policies", tags=["requirements"])  # Phase 2: reference requirements
app.include_router(runbooks.router, prefix="/api/v1/runbooks", tags=["runbooks"])  # Phase 3
# Phase 4 — SOC Operations (hunting, FP suppression)
app.include_router(hunting.router, prefix="/api/v1/hunting", tags=["hunting"])
# FP suppressions registered under correlation prefix (shares /api/v1/correlation/suppressions)
app.include_router(fp_suppressions.router, prefix="/api/v1/correlation", tags=["correlation", "fp-suppressions"])
# Phase 5 — CMDB asset inventory
# Phase 6 — Integrations (webhooks, SIEM forwarding, ITSM, notifications)
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["integrations"])
# Phase 7 — Infrastructure (retention, backups, health)
app.include_router(infrastructure.router, prefix="/api/v1/infrastructure", tags=["infrastructure"])
# Ticket #9 — Retention module (generic purge/archive/registry)
app.include_router(retention.router, prefix="/api/v1", tags=["retention", "gdpr"])
# Ticket #35 — Onboarding wizard
app.include_router(onboarding.router, prefix="/api/v1/onboarding", tags=["onboarding"])
# T25/T26 — War Room (timeline + checklists)
app.include_router(warroom.router, prefix="/api/v1/crisis/warroom", tags=["warroom"])
# Ticket #29 — Audit (auditor role, cross-mapping, export PDF, audit trail)
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])
# Settings — LLM (Ollama) configuration
app.include_router(settings_llm.router, prefix="/api/v1/settings", tags=["settings"])
app.include_router(settings_smtp.router, prefix="/api/v1", tags=["settings-smtp"])
app.include_router(settings_seed.router, prefix="/api/v1", tags=["settings-seed"])
app.include_router(public_validate.router, prefix="/api/v1", tags=["public-validate"])
# Settings — IA Prompts configuration
app.include_router(ia_prompts.router, prefix="/api/v1/settings", tags=["settings", "ia-prompts"])
# Action Plans (Operations)
app.include_router(action_plans.router, prefix="/api/v1/action-plans", tags=["action-plans"])
app.include_router(cmdb_grc.router, prefix="/api/v1/cmdb", tags=["cmdb-grc"])  # MUST be before cmdb.router
app.include_router(grc_bridge.router, prefix="/api/v1/grc", tags=["grc-bridge"])
app.include_router(practices.router)  # prefix interne /api/v1/grc
app.include_router(settings_practices.router, prefix="/api/v1/settings", tags=["settings-practices"])
app.include_router(business_questionnaires.router, prefix="/api/v1/business-questionnaires", tags=["business-questionnaires"])
app.include_router(governance_docs.router, prefix="/api/v1/governance-docs", tags=["governance-docs"])
app.include_router(governance_actions.router, prefix="/api/v1/governance-actions", tags=["governance-actions"])
app.include_router(domain_skills.router, prefix="/api/v1/domain-skills", tags=["domain-skills"])
app.include_router(wizard.router, prefix="/api/v1/wizard", tags=["wizard"])
app.include_router(cmdb.router, prefix="/api/v1/cmdb", tags=["cmdb"])

# Plugin system — discovers from ./plugins/ directory
plugin_manager = setup_plugins(app, plugin_dir=PLUGIN_DIR)


@app.get("/")
async def root():
    return {
        "message": "LOGSOC API",
        "version": "0.6.4",
        "docs": "/docs",
        "plugins": [p.name for p in plugin_manager.plugins],
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}

app.include_router(dpo_registries.router, prefix="/api/v1/dpo", tags=["dpo-registries"])
app.include_router(homologation.router, prefix="/api/v1/homologations", tags=["homologation"])
app.include_router(governance_committees.router, prefix="/api/v1/committees", tags=["governance-committees"])
