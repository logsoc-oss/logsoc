# Retention Runbook

**Owner:** LogSOC operator (admin role required for write operations)
**Audience:** on-call / FABRICE
**Status:** v0.10.4 (2026-06-09) — B13 S3 abstraction + B14v2 audit table live

This runbook covers day-2 operations for the retention module: the
in-MariaDB `retention_policies` table, the `user_log_index` ClickHouse
table, the daily sweep sidecar, the GDPR erasure endpoint, and the
`tools/retention_admin.py` CLI.

## 1. Architecture (1-paragraph)

`siem_logs` (ClickHouse, 5.2M+ rows, 90d TTL) → per-day ingestion. The
**retention sidecar** `logsoc-retention` runs daily at 02:00 UTC and
reads the `retention_policies` MariaDB table (5 seeded domains) to
decide what to do for each domain. Available actions (per v0.10.0):
**anonymize** (HMAC-SHA256 hash of PII fields, one-way) and **erase**
(ClickHouse `ALTER ... UPDATE` to clear fields). The sidecar is
dry-run by default for v0.10.0 (no destructive ALTERs); production
writes are gated on a per-policy flag (`anonymize_after_days > 0`).

The `user_log_index` ClickHouse table is a pre-aggregated
`(username, source_host) → event_count` index, populated by the
`user_log_index_mv` materialized view, that makes GDPR Art.17 erasure
**O(host_groups)** instead of O(5M+ rows). It also tracks
`anonymized_at` and `erased_at` per user.

## 2. Quick health check

```bash
# 2.1 API health
curl -sf https://logsoc.example.com/api/v1/system/health

# 2.2 Sidecar container status
ssh root@srv-demo-core 'docker ps --filter name=logsoc-retention'

# 2.3 Last sidecar sweep
ssh root@srv-demo-core 'docker logs --tail 5 logsoc-retention'

# 2.4 Policy count in DB
docker run --rm --network host --env-file /opt/logsoc-web/.env \
  -v /opt/logsoc-web:/app -w /app logsoc-web-api:latest \
  python3 /app/tools/retention_admin.py show

# 2.5 user_log_index aggregates count
ssh root@srv-demo-core 'clickhouse-client --database logsoc \
  --query "SELECT count() FROM user_log_index"'
```

Expected:
- API: `{"api":"ok","mysql":"ok","clickhouse":"ok"}`
- Sidecar: `Up X minutes (healthy)`, last log line `next sweep at YYYY-MM-DD 02:00:00 UTC`
- Policies: 5 rows (siem_logs, access_logs, audit_logs, yara_rules, asset_compliance)
- user_log_index: ≥36 (5.2M+ events indexed)

## 3. Common tasks

### 3.1 Trigger a sweep manually (e.g. after a bulk ingest)

```bash
# Restart the sidecar with RUN_ON_START=1 (it sweeps on startup)
ssh root@srv-demo-core 'cd /opt/logsoc-web && \
  docker stop logsoc-retention && docker rm logsoc-retention && \
  docker run -d --name logsoc-retention --restart unless-stopped \
    --network host --env-file ./.env \
    -e LOGSOC_CONFIG=/opt/logsoc-web/config.yaml \
    -e LOGSOC_RETENTION_RUN_ON_START=1 \
    logsoc-retention:latest'

# Watch the sweep
ssh root@srv-demo-core 'docker logs -f logsoc-retention | head -20'
```

### 3.2 Apply a policy change to one domain

Option A — via API (audited via `compliance_audit` if `RETENTION_POLICY_UPDATED` log is captured):

```bash
TOKEN=$(curl -sf https://logsoc.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | jq -r .access_token)

curl -sf -X PUT https://logsoc.example.com/api/v1/retention/policies/siem_logs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"hot_days": 120, "notes": "MANUAL: extended to 120d per DORA gap analysis 2026-06-09"}'
```

Option B — via CLI (works without auth, just needs DB access):

```bash
docker run --rm --network host --env-file /opt/logsoc-web/.env \
  -v /opt/logsoc-web:/app -w /app logsoc-web-api:latest \
  python3 /app/tools/retention_admin.py set \
    --domain siem_logs --field hot_days --value 120 --yes
```

### 3.3 GDPR Art.17 erasure of one user

```bash
# Dry-run first (returns impact estimate)
curl -sf -X POST https://logsoc.example.com/api/v1/gdpr/erasure \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "reason": "GDPR Art.17 request, ticket #1234",
    "dry_run": true
  }' | jq

# If impact looks right, run for real (dry_run=false)
curl -sf -X POST https://logsoc.example.com/api/v1/gdpr/erasure \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "reason": "GDPR Art.17 request, ticket #1234",
    "dry_run": false
  }' | jq

# Verify: user_log_index.erased_at should be set for alice
ssh root@srv-demo-core "clickhouse-client --database logsoc --query \
  \"SELECT username, source_host, event_count, erased_at \
   FROM user_log_index WHERE username = 'alice'\""
```

**Important:** the actual `ALTER ... UPDATE` in `siem_logs` is
gated on `policy.erase_after_days > 0` for the domain. If
`erase_after_days IS NULL` (default for siem_logs), the call
returns success with `rows_erased: 0` — this is by design. To
enable, set the policy:
`PUT /api/v1/retention/policies/siem_logs -d '{"erase_after_days": 730}'`

### 3.4 Bulk-apply `config.yaml` defaults to the DB

```bash
# Dry-run
docker run --rm --network host --env-file /opt/logsoc-web/.env \
  -v /opt/logsoc-web:/app -w /app logsoc-web-api:latest \
  python3 /app/tools/retention_admin.py sync-defaults

# Apply for real (--overwrite-notes only if you want to reset notes too)
docker run --rm --network host --env-file /opt/logsoc-web/.env \
  -v /opt/logsoc-web:/app -w /app logsoc-web-api:latest \
  python3 /app/tools/retention_admin.py sync-defaults --apply

# After applying, the next sweep will use the new values (no restart needed)
```

Rows whose `notes` start with `MANUAL:` (the convention used by `set`)
are **skipped** by default. Use `--manual-prefix ''` to disable that
guard (e.g. if you're resetting the whole policy table from scratch).

## 4. Incident scenarios

### 4.1 Sidecar is not running

Symptoms: `docker ps` shows no `logsoc-retention` container, or it's
restart-looping with `Up 5 seconds (health: starting)` and exiting.

Diagnosis:
```bash
ssh root@srv-demo-core 'docker logs --tail 30 logsoc-retention'
```

Common causes:
- **MySQL connection refused**: `MYSQL_HOST` env not set. Check
  `/opt/logsoc-web/.env` and that `127.0.0.1:3306` is reachable from
  the container (use `--network host`).
- **`config.yaml` not mounted**: pass `-e LOGSOC_CONFIG=/opt/logsoc-web/config.yaml`
  and bind-mount the file/dir.
- **Healthcheck failure**: the healthcheck is `pgrep -f retention_entrypoint`.
  If the process is alive but the healthcheck is failing, check the
  Docker daemon's healthcheck logs.

Fix:
```bash
ssh root@srv-demo-core 'cd /opt/logsoc-web && \
  docker stop logsoc-retention && docker rm logsoc-retention && \
  docker run -d --name logsoc-retention --restart unless-stopped \
    --network host --env-file ./.env \
    -e LOGSOC_CONFIG=/opt/logsoc-web/config.yaml \
    --health-cmd "pgrep -f retention_entrypoint" \
    --health-interval 30s \
    logsoc-retention:latest'
```

### 4.2 Sweep fails with "compile_aborted" or ALTER error

Symptoms: sweep summary contains `errors: ["..."]`, the sidecar logs
`ERROR sweep failed: ...`.

Diagnosis:
```bash
ssh root@srv-demo-core 'docker logs --tail 50 logsoc-retention | grep ERROR'
```

Common causes:
- ClickHouse `ALTER ... UPDATE` is **rejected** on tables that are
  `ReplicatedMergeTree` if replica is down. Check
  `clickhouse-client --query "SYSTEM REPLICATION QUEUES"`.
- MariaDB deadlock on the `retention_policies` table (rare — the
  registry is read-only after the cache is loaded). Re-run the
  sweep; it will retry on the next cron tick.
- A `dry_run=true` policy change that wasn't followed by `--apply`
  on the CLI (no-op, but the sidecar doesn't know about CLI changes
  until `POST /api/v1/retention/refresh` is called).

Fix:
```bash
# Force registry refresh
curl -sf -X POST https://logsoc.example.com/api/v1/retention/refresh \
  -H "Authorization: Bearer $TOKEN"

# Trigger a sweep now
ssh root@srv-demo-core 'docker restart logsoc-retention'  # RUN_ON_START sweeps
```

### 4.3 GDPR erasure request: user not found in `user_log_index`

Symptoms: erasure returns `host_groups: []`, `row_count_estimate: 0`.

Diagnosis: the user has no events in `siem_logs` (e.g. they only
appear in MariaDB `users` or `agents` tables, not in the SIEM
event stream). The erasure is correctly a no-op.

Action: check if the user exists in other tables:
```bash
# siem_logs direct count
ssh root@srv-demo-core "clickhouse-client --database logsoc --query \
  \"SELECT count() FROM siem_logs WHERE username = 'alice'\""

# MariaDB users
ssh root@srv-demo-core "mysql -u root logsoc -e \
  \"SELECT id, username, email, role FROM users WHERE username = 'alice'\""
```

If `siem_logs` has rows but `user_log_index` doesn't, the MV is
lagging or the user wasn't captured by the backfill. Re-run the
backfill (see sql/migrations/2026_06_09_retention_user_log_index_backfill.sql).

### 4.4 user_log_index not populating from new events

Symptoms: `user_log_index` row count is stable; new events added to
`siem_logs` don't increment `event_count`.

Diagnosis:
```bash
# MV status
ssh root@srv-demo-core "clickhouse-client --database logsoc --query \
  'SELECT * FROM system.materialized_views WHERE name = %s' \
  --param=logsoc.user_log_index_mv"

# Background pool
ssh root@srv-demo-core "clickhouse-client --database logsoc --query \
  'SELECT * FROM system.mutations WHERE is_done = 0'"
```

Common causes: the MV is **paused** (`SYSTEM STOP VIEW`) or the
background pool is full. Resume / wait:
```bash
ssh root@srv-demo-core "clickhouse-client --database logsoc --query \
  'SYSTEM START VIEW user_log_index_mv'"
```

## 5. Maintenance windows

### 5.1 Adding a new data domain

1. Add the domain to `config.yaml` under `retention.defaults`:
   ```yaml
   retention:
     defaults:
       my_new_logs:
         hot_days: 30
         warm_days: 90
         cold_days: 365
         anonymize_after_days: 60
         erase_after_days: null
   ```

2. Add the corresponding row to `retention_policies`:
   - Via API: `POST /api/v1/retention/policies` is not implemented
     in v0.10.0 (only `PUT` for existing). Use the CLI seed path
     in step 3 instead.
   - Via SQL: `INSERT INTO retention_policies (data_domain, hot_days, ...)
     VALUES ('my_new_logs', 30, 90, 365, 60, NULL, 'seeded on YYYY-MM-DD')`

3. Or use the CLI sync (auto-creates missing rows):
   ```bash
   docker run --rm --network host --env-file /opt/logsoc-web/.env \
     -v /opt/logsoc-web:/app -w /app logsoc-web-api:latest \
     python3 /app/tools/retention_admin.py sync-defaults --apply
   ```

4. Restart the sidecar (or `POST /api/v1/retention/refresh`) so the
   registry picks up the new row.

### 5.2 Rolling out a `config.yaml` change

1. Edit `config.yaml` (or its template `config.yaml.example` if
   adding new keys). Commit the change to git, push to Gitea.
2. Copy to Hestia: `scp config.yaml root@srv-demo-core:/opt/logsoc-web/config.yaml`
3. `POST /api/v1/retention/refresh` to reload.
4. Sweep will pick up the new values on the next cron tick (no restart
   needed for the values themselves; restart only needed if you add
   **new keys** that aren't already in the loaded config dict).

## 6. S3 cold storage (B13, shipped v0.10.4)

The archive job (`app/retention/archive.py`) ships old rows out of
ClickHouse to an S3-compatible backend. Two flavours are supported
by the same code (`app/retention/s3_backend.py`):

- **`S3LocalBackend`** — MinIO (or any self-hosted S3) on Hestia LAN.
  Uses path-style addressing, no SSL by default.
- **`S3CloudBackend`** — AWS S3, Scaleway, OVH, Wasabi, Backblaze B2,
  DigitalOcean Spaces. Detected by endpoint substring. Uses
  virtual-hosted style, SSL on, AES256 or aws:kms server-side
  encryption.

The choice is driven by the **`S3_LOCAL`** env var. Same parameters
in both cases (the abstraction hides the differences).

### 6.1 Configuration

In `/opt/logsoc-web/.env` (and mirrored in `config.yaml` under
`retention.s3:`):

| Variable | Local (MinIO) | Cloud example | Required |
|----------|---------------|---------------|----------|
| `S3_LOCAL` | `YES` | `NO` | yes |
| `S3_ENDPOINT` | `http://127.0.0.1:9100` | `https://s3.fr-par.scw.cloud` | yes |
| `S3_ACCESS_KEY` | `logsocadmin` | `SCWXXXXXXXX` | yes |
| `S3_SECRET_KEY` | (32-byte secret) | (32-byte secret) | yes |
| `S3_BUCKET_LOGS` | `logsoc-archives` | `logsoc-archives-prod` | yes |
| `S3_BUCKET_YARA` | `logsoc-yara` | `logsoc-yara-prod` | yes |
| `S3_REGION` | `us-east-1` (any) | `eu-west-1` (cloud only) | cloud only |
| `S3_USE_SSL` | `false` | `true` (default cloud) | local only |
| `S3_SSE_ALGORITHM` | (none) | `AES256` (default) or `aws:kms` | cloud only |
| `S3_SSE_KMS_KEY_ID` | (none) | `arn:aws:kms:...` (only if SSE-KMS) | conditional |

After any change: `docker restart logsoc-api && docker restart logsoc-retention`
(env-file is read at container start, not on restart — use stop+rm+run).

### 6.2 Healthcheck

```bash
# MinIO on Hestia
ssh root@srv-demo-core 'curl -sf http://127.0.0.1:9100/minio/health/live'

# From inside the sidecar (full healthcheck with bucket list)
ssh root@srv-demo-core 'docker exec logsoc-retention python3 -c "
import sys; sys.path.insert(0, \"/app\")
from app.retention.s3_backend import get_s3_backend
import json
print(json.dumps(get_s3_backend().healthcheck(), indent=2))
"'
```

Expected output (MinIO on 9100):
```json
{
  "backend": "minio-local",
  "endpoint": "http://127.0.0.1:9100",
  "ok": true,
  "buckets": ["logsoc-archives", "logsoc-yara"],
  "error": null
}
```

For cloud, `backend` will be `aws-s3`, `scaleway`, `ovh`, `wasabi`,
`backblaze-b2`, or `digitalocean-spaces` depending on the endpoint.

### 6.3 Bascule MinIO → cloud (procedure)

1. **Create the cloud buckets** (one-time, via cloud provider console
   or `mc` / `aws s3 mb`):
   ```bash
   mc alias set cloud https://s3.fr-par.scw.cloud SCWXXX... SCWYYY...
   mc mb cloud/logsoc-archives-prod
   mc mb cloud/logsoc-yara-prod
   ```

2. **Generate IAM credentials** with read/write on those buckets only
   (least privilege). For Scaleway, create a project-scoped API key.

3. **Edit `/opt/logsoc-web/.env`** on Hestia — flip the variables:
   ```diff
   -S3_LOCAL=YES
   -S3_ENDPOINT=http://127.0.0.1:9100
   -S3_ACCESS_KEY=logsocadmin
   -S3_SECRET_KEY=***   S3_LOCAL=NO
   +S3_ENDPOINT=https://s3.fr-par.scw.cloud
   +S3_ACCESS_KEY=SCWXXX...
   +S3_SECRET_KEY=***   S3_BUCKET_LOGS=logsoc-archives-prod
   +S3_BUCKET_YARA=logsoc-yara-prod
   +S3_REGION=fr-par
   +S3_USE_SSL=true
   +S3_SSE_ALGORITHM=AES256
   ```

4. **Restart both containers** (env is read at start, not restart):
   ```bash
   ssh root@srv-demo-core 'docker stop logsoc-api logsoc-retention
                     docker rm logsoc-api logsoc-retention
                     cd /opt/logsoc-web
                     docker run -d --name logsoc-api --restart unless-stopped \
                       --network host --env-file ./.env -e LOGSOC_CONFIG=/opt/logsoc-web/config.yaml \
                       logsoc-web-api:v0.10.4
                     docker run -d --name logsoc-retention --restart unless-stopped \
                       --network host --env-file ./.env -e LOGSOC_RETENTION_RUN_ON_START=1 \
                       -e CRON_SCHEDULE=02:00 logsoc-retention:v0.10.4'
   ```

5. **Verify** (see §6.2). `backend` should report `scaleway` (or
   `aws-s3`, etc.), `ok=true`, and the new bucket names in `buckets`.

6. **Migrate historical archives** (one-time, only if you want the
   MinIO archives to follow): `mc mirror minio/logsoc-archives
   cloud/logsoc-archives-prod` then same for yara. Skip if the
   cloud bucket is empty by design.

7. **Decommission MinIO** (after a week of clean cloud operation):
   ```bash
   ssh root@srv-demo-core 'docker stop logsoc-minio && docker rm logsoc-minio
                     rm -rf /opt/minio'
   ```
   Keep `/opt/minio/.root_password` archived offline in case you
   need to read old archives.

### 6.4 Bucket layout

```
s3://<S3_BUCKET_LOGS>/
  <data_domain>/
    YYYY/MM/DD/
      archive_<data_domain>_YYYYMMDDTHHMMSSZ.jsonl
```

Example (proven live 2026-06-09 with `siem_logs` policy set to
`hot_days=1`):
```
s3://logsoc-archives/siem_logs/2026/06/09/archive_siem_logs_20260609T105427Z.jsonl
  → 282 bytes, etag=b2da7f34bc192a7d
  → contents: JSON manifest with {domain, cutoff, rows_to_archive,
    started_at, backend, bucket, note}
```

For v0.10.4 the manifest is **metadata only** — actual row payloads
are not exported yet (the destructive ALTER is gated). v0.10.5
will add Parquet export + ALTER DELETE once the export cost is
measured.

### 6.5 YARA bucket

`S3_BUCKET_YARA` stores YARA rule archives and snapshots. The
archive job picks this bucket automatically for `data_domain` in
`{"yara_rules", "yara_scan_results"}` (see `S3Backend.pick_bucket`
in `app/retention/s3_backend.py:129`).

### 6.6 Rotate MinIO credentials

```bash
# 1. Generate new password
ssh root@srv-demo-core 'NEW=*** head -c 32)
              echo "$NEW" > /opt/minio/.root_password
              chmod 600 /opt/minio/.root_password

# 2. Recreate the container
ssh root@srv-demo-core 'docker stop logsoc-minio && docker rm logsoc-minio
              docker run -d --name logsoc-minio --restart unless-stopped \
                --network host \
                -e MINIO_ROOT_USER=logsocadmin \
                -e MINIO_ROOT_PASSWORD="$NEW" \
                -v /opt/minio/data:/data \
                minio/minio:latest server /data \
                --address :9100 --console-address :9101'

# 3. Update S3_SECRET_KEY in /opt/logsoc-web/.env
ssh root@srv-demo-core "sed -i 's|^S3_SECRET_KEY=.*|S3_SECRET_KEY=$NEW|' /opt/logsoc-web/.env"

# 4. Restart API + sidecar (env read at start)
ssh root@srv-demo-core 'docker stop logsoc-api logsoc-retention
              docker rm logsoc-api logsoc-retention
              cd /opt/logsoc-web
              docker run -d --name logsoc-api --restart unless-stopped \
                --network host --env-file ./.env -e LOGSOC_CONFIG=/opt/logsoc-web/config.yaml \
                logsoc-web-api:v0.10.4
              docker run -d --name logsoc-retention --restart unless-stopped \
                --network host --env-file ./.env -e LOGSOC_RETENTION_RUN_ON_START=1 \
                -e CRON_SCHEDULE=02:00 logsoc-retention:v0.10.4'
```

### 6.7 Retention policy audit (B14v2, shipped v0.10.4)

Every `PUT /api/v1/retention/policies/{domain}` writes an append-only
row to `retention_policy_audit` (MariaDB). Schema:

```
id, timestamp, data_domain, event_type (create|update|delete),
user_id, ip_address, user_agent, old_value (JSON), new_value (JSON),
note
```

View recent entries:
```bash
ssh root@srv-demo-core 'docker exec logsoc-api python3 -c "
import sys; sys.path.insert(0, \"/app\")
from app.database import SessionLocal
from app.models import RetentionPolicyAudit
with SessionLocal() as s:
    for r in s.query(RetentionPolicyAudit).order_by(RetentionPolicyAudit.id.desc()).limit(10).all():
        print(f\"{r.id:3d} {r.timestamp} {r.data_domain:20s} {r.event_type:8s} user={r.user_id} ip={r.ip_address} note={r.note!r}\")
"'
```

Or via the CLI helper:
```bash
ssh root@srv-demo-core 'cd /opt/logsoc-web
                docker run --rm --network host --env-file ./.env \
                  -v /opt/logsoc-web:/app -w /app logsoc-web-api:v0.10.4 \
                  python3 /app/tools/retention_admin.py audit
                # filter by domain:
                docker run --rm --network host --env-file ./.env \
                  -v /opt/logsoc-web:/app -w /app logsoc-web-api:v0.10.4 \
                  python3 /app/tools/retention_admin.py audit --domain siem_logs'
```

Business rules enforced server-side (rejected with HTTP 422):
- `hot_days >= 1`
- `warm_days >= hot_days` (or 0)
- `cold_days >= warm_days` (or 0)
- `anonymize_after_days >= hot_days`
- `erase_after_days IS NULL OR erase_after_days >= anonymize_after_days`


## 7. Capacity planning
  At ~57K rows/day, expect ~1.7M rows/month. SummingMergeTree
  on `user_log_index` keeps it small (~36 aggregates for active
  users + ~50 for historical).
- **Anonymize sweep cost**: a single `ALTER ... UPDATE` on a
  SummingMergeTree part is O(rows-in-part), typically a few
  seconds for 100K rows. The first real sweep after the dry-run
  phase may take a few minutes — keep `SWEEP_TIMEOUT_SEC` ≥ 600s.
- **GDPR erasure cost**: O(host_groups × rows-per-host). Worst
  case: a power user with 5M events across 10 hosts → 10 ALTERs,
  ~10 minutes total. The endpoint is synchronous, so the client
  HTTP request may time out. For large erasures, prefer running
  `erasure.erase_user()` from a maintenance script with
  longer timeouts.

## 8. Open follow-ups (out of scope for v0.10.4)

- **B12-B17, B13, B14v2 already shipped.** Next horizons:
  - **Real anonymize/erase writes** (v0.10.5): the sidecar
    currently runs in dry-run for the destructive ALTERs. Switch
    `jobs.run_anonymize_sweep()` and `run_erase_sweep()` to issue
    real ALTERs once the hash strategy is validated on a sample.
  - **Parquet export + ALTER DELETE** (v0.10.5 follow-up): the
    archive job currently writes a manifest only. Export rows to
    Parquet, upload to S3, then issue `ALTER TABLE ... DELETE`
    gated on a per-domain confirmation.
  - **Per-user erasure scope expansion** (B11 v2): currently only
    `siem_logs` is covered. Add `access_logs`, `audit_logs`, etc.
    once those domains have `erase_after_days > 0` configured.
  - **MinIO TLS** (B18): shipped 2026-06-09 — self-signed certs
    in `/opt/minio/certs/`, `S3_USE_SSL=true`, HTTPS strict on
    :9100/:9101. See CHANGELOG v0.10.5 §"Pièges diagnostiqués".
  - **B19 Archive réelle** (shipped 2026-06-09 v0.10.5) :
    - `RETENTION_ARCHIVE_DRY_RUN=true` (default) pour le sweep
      quotidien. Passer à `false` pour exporter réellement.
    - `RETENTION_ARCHIVE_DELETE_ARMED=false` (default) pour
      bloquer le DELETE. Flipper à `true` quand l'opérateur est
      prêt à confirmer les manifests en attente.
    - Workflow : `POST /archive/sweep?dry_run=false` →
      `GET /archive/manifests/{domain}` (audit, lire les
      manifest_id + parquet_sha256 + row_count) → vérifier
      que les Parquet sont dans S3 → `POST /archive/{domain}/confirm`
      avec `{"manifest_id": "...", "reason": "..."}`.
    - Le `.confirmed.json` est l'audit immuable du DELETE. Ne
      jamais DELETE en BDD tant que `.confirmed.json` n'est pas
      écrit (l'endpoint gère l'ordre).
    - **Bascule cloud S3** (cf §6.3) : le flow reste identique,
      seul `S3_LOCAL=NO` change le backend.
  - **B20 Restore endpoint** (shipped 2026-06-09 v0.11.0) :
    - `GET /retention/restore?data_domain=siem_logs&mode=metadata`
      : analyst+ — liste les Parquet + génère des presigned URLs
      (cap 24h). Aucune donnée fetchée, aucun write CH. Use case :
      "qu'est-ce qu'on a archivé en avril ?".
    - `GET /retention/restore?data_domain=siem_logs&mode=reinject&key=s3://...`
      : admin only — télécharge le Parquet + INSERT en CH. Use case :
      "le DPO demande la restitution des events d'avril pour user X".
    - Filtres `from_date`/`to_date` sur la cutoff date du manifest,
      pas sur les rows elles-mêmes (le nom du fichier encode la
      cutoff).
    - Cap `RETENTION_RESTORE_REINJECT_MAX_ROWS` (default 1M) bloque
      les injections massives. Au-delà, le caller doit batcher.
    - **Dédup NOT implémentée** : re-injecter le même Parquet duplique
      les rows. Si la dédup est nécessaire, utiliser une staging
      table + `SELECT DISTINCT` côté CH (TODO v0.12).
  - **Multi-class buckets** (B19): split `logsoc-archives` into
    `logsoc-archives-hot` / `-warm` / `-cold` based on policy
    `cold_days` and lifecycle-transition objects across classes.
  - **Cloud S3 migration** (see §6.3): when Fabrice approves
    a Scaleway or OVH bucket, run the bascule procedure.

## 9. Contacts

- **On-call:** see LogSOC alerting channel.
- **Schema owner:** see `CHANGELOG.md` v0.10.0.
- **Infra owner (Hestia, MariaDB, ClickHouse, Docker):** see
  `~/.hermes/BOUNDARIES` memory for FABRICE's Hestia conventions.
