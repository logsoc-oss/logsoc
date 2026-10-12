from app.enrichment import enrich_event
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import hmac
import hashlib
import time
import json
import uuid
import re
from datetime import datetime, timezone
from app.database import get_db
from app.models import Agent, LogRaw
from app.schemas import EventIngest, EventResponse, EventLine
from app.routers.auth import require_role, get_current_user, require_permission
from app.models import User
from app.clickhouse_client import get_client as get_ch_client

router = APIRouter(prefix="", tags=["events"])

# Severity string -> UInt8 mapping (ClickHouse stores severity as UInt8)
SEVERITY_MAP = {
    "debug": 0, "info": 1, "notice": 2, "warning": 3,
    "error": 4, "critical": 5, "alert": 6, "emergency": 7,
}
SEVERITY_REVERSE = {v: k for k, v in SEVERITY_MAP.items()}


def _classify_apparmor_event(line: EventLine) -> EventLine:
    """Classify AppArmor events in the ingestion pipeline.

    Detects AppArmor verdict (ALLOWED/DENIED) in the message text and applies:
    - ALLOWED: severity=notice, tags apparmor-allowed + no-alert (+ self-noise if comm=logsoc-agent)
    - DENIED:  severity=warning, tags apparmor-denied + alert
    Non-AppArmor events are returned unchanged.
    """
    msg = line.message or ""
    if "apparmor" not in msg.lower():
        return line

    # Extract comm from the message if not already set (AppArmor messages embed comm=...)
    # e.g. audit: type=1400 audit(...): apparmor="ALLOWED" operation="ptrace" ... comm="logsoc-agent" ...
    if not line.comm:
        m = re.search(r'comm="([^"]+)"', msg)
        if m:
            line.comm = m.group(1)

    existing_tags = list(line.tags) if line.tags else []

    if '"ALLOWED"' in msg or "ALLOWED" in msg.split("apparmor=")[-1][:20].upper():
        # AppArmor ALLOWED — authorized operation, not a violation
        line.severity = "notice"
        for t in ("apparmor-allowed", "no-alert"):
            if t not in existing_tags:
                existing_tags.append(t)
        # Tag self-noise for logsoc-agent's own events
        comm_val = (line.comm or "").lower()
        if comm_val == "logsoc-agent":
            if "self-noise" not in existing_tags:
                existing_tags.append("self-noise")
        line.tags = existing_tags
    elif '"DENIED"' in msg or "DENIED" in msg.split("apparmor=")[-1][:20].upper():
        # AppArmor DENIED — potential incident
        line.severity = "warning"
        for t in ("apparmor-denied", "alert"):
            if t not in existing_tags:
                existing_tags.append(t)
        line.tags = existing_tags

    return line


def _extract_event_type(message: str, tags: list) -> str:
    """Extract the event type from the message JSON or tags.

    The event type can come from:
    1. The 'event' field on the EventLine (if provided directly)
    2. The inner JSON message['message']['event'] field
    3. The first tag (legacy fallback)
    """
    # Try to extract from the inner JSON message
    try:
        outer = json.loads(message)
        inner_raw = outer.get('message', '{}')
        if isinstance(inner_raw, str):
            inner = json.loads(inner_raw)
        else:
            inner = inner_raw if isinstance(inner_raw, dict) else {}
        ev = inner.get('event')
        if ev and isinstance(ev, str):
            return ev
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # Fallback: first tag
    if tags and isinstance(tags, list) and len(tags) > 0:
        return tags[0]

    return ''


def _verify_hmac(agent_id: str, timestamp: str, signature: str, body: bytes, db: Session, nonce: str = None) -> Agent:
    """Verify HMAC-SHA256 signature from agent ingestion request."""
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    if abs(int(time.time()) - ts) > 60:
        raise HTTPException(status_code=401, detail="Request expired")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status != "active":
        raise HTTPException(status_code=403, detail="Agent not active")

    secret = agent.hmac_secret_enc
    body_hash = hashlib.sha256(body).hexdigest()
    if nonce:
        message = f"{timestamp}.{nonce}.{body_hash}"
    else:
        message = f"{timestamp}.{body_hash}"
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")

    return agent


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest events from agents",
    description="Agents push log events with HMAC-SHA256 signature. "
    "Each event line is stored in ClickHouse siem_logs table. "
    "Requires headers: X-Agent-ID, X-Timestamp, X-Signature.",
    responses={201: {"description": "Events ingested successfully"}, 401: {"description": "Invalid HMAC signature"}})
async def ingest_events(
    request: Request,
    x_agent_id: str = Header(...),
    x_timestamp: str = Header(...),
    x_signature: str = Header(...),
    x_nonce: str = Header(None),
    x_partial_success: str = Header(None),
    db: Session = Depends(get_db),
):
    """Ingest events from an agent. Writes to ClickHouse siem_logs."""
    body = await request.body()

    # Verify HMAC signature
    agent = _verify_hmac(x_agent_id, x_timestamp, x_signature, body, db, nonce=x_nonce)

    # Parse JSON payload
    try:
        payload = EventIngest(**json.loads(body))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {str(e)}")

    # Write to ClickHouse siem_logs
    ch = get_ch_client()
    # v3.7: use datetime object (not str) — clickhouse-connect needs a real datetime
    # to serialize into DateTime64(3). Passing a str raises
    # AttributeError: 'str' object has no attribute 'timestamp'
    now = datetime.now(timezone.utc)
    # Host-level context from EventIngest (sent once per batch)
    batch_os_name = payload.os_name or ''
    batch_os_version = payload.os_version or ''
    batch_kernel_version = payload.kernel_version or ''
    batch_agent_version = payload.agent_version or ''
    batch_host_ips = payload.host_ips or ''

    rows = []
    for line in payload.lines:
        # v0.7: Classify AppArmor events (ALLOWED → notice + tags, DENIED → warning + tags)
        line = _classify_apparmor_event(line)
        severity_int = SEVERITY_MAP.get(line.severity, 1)  # default info=1
        # Extract event type: prefer explicit field, then inner JSON, then tags
        event_type = getattr(line, 'event', None) or ''
        if not event_type:
            event_type = _extract_event_type(line.message, line.tags or [])
        # Server-side enrichment (MITRE, sigma, severity_score)
        # If agent already enriched (severity_score > 0 and mitre not empty),
        # use agent values. Otherwise enrich server-side.
        _enriched = enrich_event(line)
        _sigma = _enriched['sigma']
        # Per-line host context overrides batch-level
        line_os_name = line.os_name or batch_os_name
        line_os_version = line.os_version or batch_os_version
        line_kernel_version = line.kernel_version or batch_kernel_version
        line_agent_version = line.agent_version or batch_agent_version
        line_host_ips = getattr(line, 'host_ips', '') or batch_host_ips
        rows.append([
            now,                                           # received_at
            x_agent_id,                                    # agent_id
            line.source_host,                              # source_host
            getattr(line, 'source_ip', '0.0.0.0') or '0.0.0.0',  # source_ip
            line.service or '',                            # service
            severity_int,                                  # severity (UInt8)
            event_type,                                    # event
            line.message,                                  # message
            line.raw_message or line.message,              # raw_message
            line.tags or [],                               # tags (Array(String))
            '',                                            # geo_country
            getattr(line, 'event_id', '') or '',           # event_id
            getattr(line, 'comm', '') or '',               # comm
            getattr(line, 'username', '') or '',           # username
            getattr(line, 'filename', '') or '',            # filename
            getattr(line, 'pid', 0) or 0,                  # pid
            getattr(line, 'uid', 0) or 0,                  # uid
            getattr(line, 'dst_ip', '') or '',             # dst_ip
            getattr(line, 'dst_port', 0) or 0,            # dst_port
            getattr(line, 'inode', 0) or 0,               # inode
            line_os_name,                                   # os_name
            line_os_version,                                # os_version
            line_kernel_version,                            # kernel_version
            line_agent_version,                             # agent_version
            line_host_ips,                                  # host_ips
            # v3.7: eBPF ↔ journald cross-validation
            1 if getattr(line, 'journald_match', None) else 0,  # journald_match (UInt8)
            getattr(line, 'journald_message', '') or '',  # journald_message
            getattr(line, 'journald_unit', '') or '',      # journald_unit
            getattr(line, 'journald_identifier', '') or '',  # journald_identifier
            getattr(line, 'correlation_window_ms', 0) or 0,  # correlation_window_ms
            1 if getattr(line, 'ebpf_match', None) else 0,  # ebpf_match (UInt8)
            getattr(line, 'ebpf_event', '') or '',        # ebpf_event
            getattr(line, 'ebpf_comm', '') or '',         # ebpf_comm
            getattr(line, "ebpf_filename", "") or "",     # ebpf_filename
            # Enrichment (agent or server-side via enrich_event)
            _enriched['severity_score'],                       # severity_score
            _enriched['mitre'],                                # mitre
            _sigma,                                            # sigma
            getattr(line, "action", "") or "",               # action
            getattr(line, "source", "") or "",               # source
            getattr(line, "flags", 0) or 0,                   # flags
            getattr(line, "argv", "") or "",                 # argv
            getattr(line, "sha256", "") or "",               # sha256
            getattr(line, "bytes_size", 0) or 0,              # bytes_size
            getattr(line, "family", "") or "",               # family
            getattr(line, "count", 1) or 1,                    # count
            getattr(line, "pids", []) or [],                   # pids
            # T14.6: forensics fields — raw JSON + truncation metadata
            getattr(line, "raw_event", "") or "",              # raw_event (original JSON)
            1 if getattr(line, "truncated", False) else 0,     # truncated (UInt8)
            getattr(line, "orig_len", 0) or 0,                 # orig_len (bytes before truncation)
        ])

    if rows:
        ch.insert(
            "siem_logs",
            rows,
            column_names=[
                "received_at", "agent_id", "source_host", "source_ip",
                "service", "severity", "event", "message", "raw_message",
                "tags", "geo_country",
                "event_id", "comm", "username", "filename",
                "pid", "uid", "dst_ip", "dst_port", "inode",
                "os_name", "os_version", "kernel_version", "agent_version",
                "host_ips",
                # v3.7: cross-validation columns
                "journald_match", "journald_message", "journald_unit",
                "journald_identifier", "correlation_window_ms",
                "ebpf_match", "ebpf_event", "ebpf_comm", "ebpf_filename",
                # Agent enrichment (T29: severity_score, mitre, sigma, etc.)
                "severity_score", "mitre", "sigma", "action", "source",
                "flags", "argv", "sha256", "bytes_size", "family",
                # T14.0b: coalesced events
                "count", "pids",
                # T14.6: forensics fields — raw JSON + truncation metadata
                "raw_event", "truncated", "orig_len",
            ],
        )

    # Update agent last_seen in MySQL
    agent.last_seen = datetime.now(timezone.utc)
    db.commit()

    # Broadcast each event to connected WebSocket clients
    try:
        from app.routers.ws import broadcast_event
        for line in payload.lines:
            event_type = getattr(line, 'event', None) or ''
            if not event_type:
                event_type = _extract_event_type(line.message, line.tags or [])
            ws_data = {
                "agent_id": x_agent_id,
                "source_host": line.source_host,
                "source_ip": getattr(line, 'source_ip', '') or '',
                "service": line.service or '',
                "severity": line.severity,
                "event": event_type,
                "message": line.message,
                "event_id": getattr(line, 'event_id', '') or '',
                "comm": getattr(line, 'comm', '') or '',
                "username": getattr(line, 'username', '') or '',
                "os_name": line.os_name or batch_os_name,
                "os_version": line.os_version or batch_os_version,
                "agent_version": line.agent_version or batch_agent_version,
                "tags": line.tags or [],
            }
            await broadcast_event({
                "type": "event",
                "data": ws_data,
                "timestamp": now,
            })
    except Exception:
        pass  # Don't block ingestion on WS errors

    return {"status": "ok", "received": len(rows), "agent_id": x_agent_id}


@router.get(
    "/",
    response_model=List[EventResponse],
    summary="List events",
    description="Query events from ClickHouse with filters for severity, host, service, event type, and time range. Supports pagination. Use ?event=execve or ?event=execve,tcp_connect for comma-separated event type filtering.")
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    source_host: Optional[str] = None,
    service: Optional[str] = None,
    event: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("events", "read")),
):
    """List events from ClickHouse siem_logs with optional filters."""
    ch = get_ch_client()

    where_clauses = []
    params = {}

    if severity:
        sev_int = SEVERITY_MAP.get(severity, None)
        if sev_int is not None:
            where_clauses.append("severity = {sev:Int32}")
            params["sev"] = sev_int

    if source_host:
        where_clauses.append("source_host = {host:String}")
        params["host"] = source_host

    if service:
        where_clauses.append("service = {svc:String}")
        params["svc"] = service

    if event:
        # Support comma-separated event types: ?event=execve,tcp_connect
        event_types = [e.strip() for e in event.split(',') if e.strip()]
        if len(event_types) == 1:
            where_clauses.append("event = {evt:String}")
            params["evt"] = event_types[0]
        elif len(event_types) > 1:
            # Use IN clause for multiple event types
            placeholders = []
            for i, evt in enumerate(event_types):
                key = f"evt{i}"
                placeholders.append("{" + key + ":String}")
                params[key] = evt
            where_clauses.append("event IN (" + ", ".join(placeholders) + ")")

    if start_time:
        where_clauses.append("received_at >= {start:DateTime64}")
        params["start"] = start_time

    if end_time:
        where_clauses.append("received_at <= {end:DateTime64}")
        params["end"] = end_time

    where = " AND ".join(where_clauses) if where_clauses else "1=1"

    query = f"""
        SELECT received_at, agent_id, source_host, source_ip,
               service, severity, event, message, raw_message, tags,
               event_id, comm, username, filename, pid, uid,
               dst_ip, dst_port, inode,
               os_name, os_version, kernel_version, agent_version,
               host_ips,
               journald_match, journald_message, journald_unit,
               journald_identifier, correlation_window_ms,
               ebpf_match, ebpf_event, ebpf_comm, ebpf_filename
        FROM logsoc.siem_logs
        WHERE {where}
        ORDER BY received_at DESC
        LIMIT {limit} OFFSET {skip}
    """

    result = ch.query(query, parameters=params if params else None)

    events = []
    for row in result.result_rows:
        sev_str = SEVERITY_REVERSE.get(row[5], "info")
        events.append(EventResponse(
            id=0,
            event_id=row[10] if row[10] else "",
            received_at=str(row[0]),
            agent_id=str(row[1]),
            source_host=row[2] or "",
            source_ip=str(row[3]) if row[3] else "",
            service=row[4] or "",
            severity=sev_str,
            event=row[6] if row[6] else "",
            message=row[7] or "",
            raw_message=row[8] or "",
            comm=row[11] or "",
            username=row[12] or "",
            filename=row[13] or "",
            pid=row[14] if row[14] else None,
            uid=row[15] if row[15] else None,
            dst_ip=row[16] or "",
            dst_port=row[17] if row[17] else None,
            inode=row[18] if row[18] else None,
            os_name=row[19] or "",
            os_version=row[20] or "",
            kernel_version=row[21] or "",
            agent_version=row[22] or "",
            host_ips=row[23] or "",
            # v3.7: cross-validation fields
            journald_match=bool(row[24]) if row[24] is not None else None,
            journald_message=row[25] or "",
            journald_unit=row[26] or "",
            journald_identifier=row[27] or "",
            correlation_window_ms=row[28] if row[28] else 0,
            ebpf_match=bool(row[29]) if row[29] is not None else None,
            ebpf_event=row[30] or "",
            ebpf_comm=row[31] or "",
            ebpf_filename=row[32] or "",
            tags=row[9] if isinstance(row[9], list) else [],
            metadata={},
        ))

    return events


@router.get(
    "/stats/summary",
    summary="Event statistics summary",
    description="Returns aggregated event stats: total count, breakdown by severity/service/host, and events-per-minute rate.")
def events_stats(
    current_user: User = Depends(get_current_user),
):
    """Get event statistics for dashboard from ClickHouse."""
    ch = get_ch_client()

    # Total count
    total = ch.command("SELECT count() FROM logsoc.siem_logs")

    # Count by severity
    sev_result = ch.query(
        "SELECT severity, count() as cnt FROM logsoc.siem_logs GROUP BY severity ORDER BY severity"
    )
    by_severity = {}
    for row in sev_result.result_rows:
        sev_str = SEVERITY_REVERSE.get(row[0], str(row[0]))
        by_severity[sev_str] = row[1]

    # Count by service (top 10)
    svc_result = ch.query(
        "SELECT service, count() as cnt FROM logsoc.siem_logs GROUP BY service ORDER BY cnt DESC LIMIT 10"
    )
    by_service = {}
    for row in svc_result.result_rows:
        by_service[row[0]] = row[1]

    # Count by host (top 10)
    host_result = ch.query(
        "SELECT source_host, count() as cnt FROM logsoc.siem_logs GROUP BY source_host ORDER BY cnt DESC LIMIT 10"
    )
    by_host = {}
    for row in host_result.result_rows:
        by_host[row[0]] = row[1]

    # Events per minute (last hour)
    try:
        epm_result = ch.query(
            "SELECT count() / 60 FROM logsoc.siem_logs WHERE received_at >= now() - INTERVAL 1 HOUR"
        )
        events_per_minute = round(epm_result.result_rows[0][0], 2) if epm_result.result_rows else 0
    except Exception:
        events_per_minute = 0

    return {
        "total": total,
        "by_severity": by_severity,
        "by_service": by_service,
        "by_host": by_host,
        "events_per_minute": events_per_minute,
    }


@router.get(
    "/{event_id}",
    response_model=EventResponse,
    summary="Get single event",
    description="Retrieve a specific event by its UUID from ClickHouse.")
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single event by event_id from ClickHouse."""
    ch = get_ch_client()

    result = ch.query(
        "SELECT received_at, agent_id, source_host, source_ip, "
        "service, severity, event, message, raw_message, tags, "
        "event_id, comm, username, filename, pid, uid, "
        "dst_ip, dst_port, inode, "
        "os_name, os_version, kernel_version, agent_version, "
        "host_ips, "
        "journald_match, journald_message, journald_unit, "
        "journald_identifier, correlation_window_ms, "
        "ebpf_match, ebpf_event, ebpf_comm, ebpf_filename "
        "FROM logsoc.siem_logs "
        "WHERE event_id = {eid:String} "
        "LIMIT 1",
        parameters={"eid": event_id},
    )

    if not result.result_rows:
        # Fallback to MySQL for backward compat
        event = db.query(LogRaw).filter(LogRaw.event_id == event_id).first()
        if event:
            return EventResponse(
                id=event.id,
                event_id=event.event_id,
                received_at=str(event.received_at),
                agent_id="",
                source_host=event.source_host or "",
                service=event.service or "",
                severity=event.severity or "info",
                event="",
                message=event.message or "",
                tags=json.loads(event.tags) if event.tags else [],
                metadata=json.loads(event.meta_data) if event.meta_data else {},
            )
        raise HTTPException(status_code=404, detail="Event not found")

    row = result.result_rows[0]
    return EventResponse(
        id=0,
        event_id=row[10] if row[10] else "",
        received_at=str(row[0]),
        agent_id=str(row[1]),
        source_host=row[2] or "",
        source_ip=str(row[3]) if row[3] else "",
        service=row[4] or "",
        severity=SEVERITY_REVERSE.get(row[5], "info"),
        event=row[6] if row[6] else "",
        message=row[7] or "",
        raw_message=row[8] or "",
        comm=row[11] or "",
        username=row[12] or "",
        filename=row[13] or "",
        pid=row[14] if row[14] else None,
        uid=row[15] if row[15] else None,
        dst_ip=row[16] or "",
        dst_port=row[17] if row[17] else None,
        inode=row[18] if row[18] else None,
        os_name=row[19] or "",
        os_version=row[20] or "",
        kernel_version=row[21] or "",
        agent_version=row[22] or "",
        host_ips=row[23] or "",
        # v3.7: cross-validation fields
        journald_match=bool(row[24]) if row[24] is not None else None,
        journald_message=row[25] or "",
        journald_unit=row[26] or "",
        journald_identifier=row[27] or "",
        correlation_window_ms=row[28] if row[28] else 0,
        ebpf_match=bool(row[29]) if row[29] is not None else None,
        ebpf_event=row[30] or "",
        ebpf_comm=row[31] or "",
        ebpf_filename=row[32] or "",
        tags=row[9] if isinstance(row[9], list) else [],
        metadata={},
    )
