# LOGSOC-WEB — SIEM Platform

> **LogSOC** = **L**ibre · **O**pen · **G**ouvernance · **S**écurité · **O**pérations · **C**onformité

> Security Information and Event Management — Full-stack monitoring, detection, and compliance platform.

> **Current backend: v0.7.4** — see [CHANGELOG.md](CHANGELOG.md). **API reference: [docs/API.md](docs/API.md)** (72 endpoints, 12 routers).

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐
│  C++ Agent   │────▶│  FastAPI Backend (Python 3.13)       │
│  (soc_agent) │     │  ├─ Auth JWT (bcrypt)                │
└─────────────┘     │  ├─ Events → ClickHouse (OLAP)        │
                     │  ├─ Alerts / Assets → MySQL (OLTP)    │
┌─────────────┐     │  ├─ YARA Rules / Compliance            │
│  Web UI      │────▶│  ├─ AI Insights (auto-analyze)        │
│  (React+TS)  │     │  ├─ WebSocket real-time (/ws/events)  │
└─────────────┘     │  └─ Plugin system (extensible)          │
                     └──────────────┬────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              ┌──────────┐  ┌──────────┐  ┌──────────────┐
              │  MySQL    │  │  Click   │  │  WS Clients  │
              │  (3306)   │  │  House   │  │  (browser)   │
              └──────────┘  │  (8123)  │  └──────────────┘
                            └──────────┘
```

## Quick Start

### Prerequisites
- Python 3.11+ with venv
- Node.js 20+ with npm
- MySQL 8.0+ (password read from `/tmp/.mysqlpwd`)
- ClickHouse 24.x

### Backend

```bash
cd api/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create MySQL tables
python3 -c "from app.database import engine, Base; from app.models import *; Base.metadata.create_all(bind=engine)"

# Run
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd web/
npm install
npm run dev        # Development on http://localhost:5173
npm run build      # Production build → dist/
```

### Docker

```bash
cp .env.example .env    # Fill in secrets
docker compose up -d
```

API available at `http://localhost:8000/docs` (Swagger UI).

## API Endpoints

The full, **up-to-date** endpoint reference is in **[docs/API.md](docs/API.md)**
(72 endpoints across 12 routers, auto-generated from the FastAPI source and
curated by hand with parameter tables and auth levels).

Short version:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/login` | — | Exchange username/password for JWT (30 min) + refresh (7 d) |
| POST | `/api/v1/auth/logout` | user | Invalidate the current session |
| GET | `/api/v1/agents/` | user | List registered agents (paginated) |
| POST | `/api/v1/agents/heartbeat` | HMAC | Agent → central heartbeat (signed) |
| POST | `/api/v1/agents/register` | — | Self-register a new agent (status = `pending`) |
| PUT | `/api/v1/agents/{id}/approve` | admin | Approve a pending agent |
| GET | `/api/v1/users/me` | user | Get the authenticated user's profile |
| GET | `/api/v1/assets/` | user | List monitored assets |
| GET | `/api/v1/assets/stats/summary` | user | Asset KPIs |
| GET | `/api/v1/events/` | user | Query events from ClickHouse (paginated, filtered) |
| POST | `/api/v1/events/` | HMAC | Ingest events from an agent (signed) |
| GET | `/api/v1/events/stats/summary` | user | Event KPIs |
| GET | `/api/v1/alerts/` | user | List alerts |
| GET | `/api/v1/alerts/summary` | user | Alert KPIs (MTTA, by severity) |
| GET | `/api/v1/yara/rules` | user | List YARA rules (paginated, filtered) |
| POST | `/api/v1/yara/import-sigbase` | user | Clone Neo23x0/signature-base, validate, dedup, insert |
| GET | `/api/v1/yara/stats` | user | YARA KPIs (rules, results, last match) |
| GET | `/api/v1/compliance/controls` | user | List compliance controls (RGPD, NIS2, DORA, ISO 27001) |
| GET | `/api/v1/compliance/scores` | user | Score % by framework |
| PUT | `/api/v1/compliance/controls/{id}` | user | Update a control's status / evidence |
| GET | `/api/v1/insights/` | — | List AI insights (⚠ unauthenticated — see CHANGELOG) |
| POST | `/api/v1/insights/analyze` | — | Trigger auto-analysis over recent events |
| GET | `/api/v1/sigma/` | user | List Sigma rules (paginated, filtered) |
| POST | `/api/v1/sigma/import` | user | Import Sigma rules from the local SigmaHQ clone |
| POST | `/api/v1/sigma/evaluate` | user | Evaluate a Sigma rule against recent events |
| GET | `/api/v1/correlation/alerts` | user | List correlation alerts |
| GET | `/api/v1/correlation/mitre/coverage` | user | MITRE ATT&CK coverage matrix |
| GET | `/api/v1/correlation/mitre/navigator` | user | ATT&CK Navigator layer (v4.2 JSON) |
| GET | `/api/v1/system/health` | — | Liveness probe |
| GET | `/api/v1/system/health/details` | — | DB ping, ClickHouse ping, last heartbeat |
| WS | `/ws/events` | JWT (query) | Real-time event push channel |

Interactive Swagger UI: `https://logsoc.example.com/docs`

## Roles

| Role | Permissions |
|------|------------|
| `superadmin` | Full access: users, rules, settings |
| `admin` | Management: rules, assets, alerts |
| `analyst` | Read + alert operations |
| `viewer` | Read-only |

## Event Ingestion (Agents)

Agents push events via `POST /api/v1/events/` with HMAC-SHA256 signing:

```
X-Agent-ID: <agent_uuid>
X-Timestamp: <unix_timestamp>
X-Signature: hmac-sha256(agent_secret, timestamp + body)
```

Each line in the request body is a JSON event stored in ClickHouse `siem_logs`.

## Plugin System

Plugins are auto-discovered from the `plugins/` directory. Each plugin is a Python file or package with a `Plugin` subclass:

```python
# plugins/my_plugin.py
from fastapi import APIRouter
from app.plugins import Plugin, PluginContext

router = APIRouter(prefix="/api/v1/plugin/my", tags=["plugin:my"])

@router.get("/status")
async def status():
    return {"status": "ok"}

class MyPlugin(Plugin):
    name = "my"
    version = "1.0.0"
    description = "My custom plugin"

    def on_register(self, ctx: PluginContext) -> None:
        ctx.add_router(router)
```

Plugins can also define `on_startup()` and `on_shutdown()` lifecycle hooks.

## WebSocket

Connect to `ws://<host>:8000/ws/events` for real-time event broadcast:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/events');
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // data.type: "event" | "alert" | "heartbeat" | "welcome"
};
```

## Project Structure

```
logsoc-web/
├── api/                      # FastAPI backend
│   ├── app/
│   │   ├── main.py           # App config + plugin setup
│   │   ├── config.py         # Settings (JWT, DB, etc.)
│   │   ├── database.py       # MySQL connection
│   │   ├── clickhouse_client.py  # ClickHouse connection
│   │   ├── models.py         # SQLAlchemy models
│   │   ├── schemas.py        # Pydantic schemas
│   │   ├── plugins/           # Plugin system (extensible)
│   │   └── routers/
│   │       ├── auth.py       # JWT auth
│   │       ├── users.py      # User CRUD
│   │       ├── events.py     # Event ingestion + listing
│   │       ├── alerts.py     # Alert management
│   │       ├── assets.py     # Agent/asset management
│   │       ├── yara.py       # YARA rules
│   │       ├── compliance.py  # Compliance controls
│   │       ├── ai.py         # AI insights + auto-analyze
│   │       ├── ws.py         # WebSocket real-time
│   │       └── system.py     # Health + system info
│   ├── plugins/              # Plugin directory
│   │   └── demo_plugin.py    # Example plugin
│   ├── tests/
│   │   └── test_api.py       # 38 tests
│   └── requirements.txt
├── web/                       # React frontend
│   ├── src/
│   │   ├── App.tsx           # Lazy-loaded routes
│   │   ├── api/              # Axios API clients
│   │   ├── hooks/            # useData, useWebSocket
│   │   ├── pages/            # Dashboard, Events, etc.
│   │   ├── stores/           # Zustand auth store
│   │   ├── types/            # TypeScript interfaces
│   │   └── components/       # Layout, Sidebar, etc.
│   └── package.json
├── Dockerfile                 # Multi-stage build
├── docker-compose.yml         # MySQL + ClickHouse + API
├── .env.example               # Environment template
└── SUIVI-AVANCEMENT.md        # Progress tracking
```

## Tests

```bash
cd api/
source venv/bin/activate
python3 -m pytest tests/test_api.py -v
# 38 tests
```

## License

Proprietary — © 2026 LogSOC Team
## Licence

Ce projet est distribue sous licence GNU AGPL-3.0 - voir [LICENSE](LICENSE).
