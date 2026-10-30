# ── LOGSOC-WEB Backend-only Dockerfile ──
# Single stage: Python 3.13-slim runtime with FastAPI.
#
# IMPORTANT — Frontend is NOT built here.
# The React/Vite frontend is built locally (`npm run build` in `web/`) and
# served by an external Nginx from Hestia's `public_html/`. The backend
# container only exposes the FastAPI API on port 8000.
#
# To rebuild + deploy:
#   1. cd web && npm run build && cd ..       # build the SPA locally
#   2. rsync -av web/dist/ srv-demo-core:/path/to/public_html/  # deploy static assets
#   3. docker build -t logsoc-web-api:vX.Y.Z .
#   4. docker save logsoc-web-api:vX.Y.Z | ssh srv-demo-core docker load
#   5. ssh srv-demo-core 'docker restart logsoc-api'
#
# v0.6.2: removed obsolete frontend-builder stage (was 595 MB → now ~280 MB).
#         Removed COPY of web/dist (served by external Nginx).

# ── Python Runtime ──
FROM python:3.13-slim AS runtime

# System deps: gcc for any wheel compilation, libffi for cryptography,
# git + libyara-dev for the /api/v1/yara/import-sigbase endpoint
# (clones signature-base and validates rules with the yara CLI).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev git libyara-dev yara \
    libpango1.0-dev libharfbuzz-dev libffi-dev libjpeg-dev libopenjp2-7-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code (v3.7.0+: app/ is the real backend, not api/)
COPY app/ ./app/

# Config (T64.1.7: single source of truth)
COPY config.yaml ./config.yaml

# Plugin directory (mounted at runtime in dev/compose, or baked-in in prod)
RUN mkdir -p /app/app/plugins

# Non-root user
RUN useradd -r -s /bin/false logsoc && chown -R logsoc:logsoc /app
USER logsoc

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
