"""Network scan endpoints for asset discovery using nmap.

Endpoints:
  POST /api/v1/assets/scan             — start a network scan (async)
  GET  /api/v1/assets/scan/{job_id}/status — poll scan progress
  POST /api/v1/assets/scan/{job_id}/import  — import selected hosts as assets
  GET  /api/v1/assets/scan/network-info    — auto-detect local network
  GET  /api/v1/settings/nmap-path           — get nmap path
  PUT  /api/v1/settings/nmap-path           — set nmap path
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import Agent, AssetGroup
from app.routers.auth import require_role, User

logger = logging.getLogger("logsoc.network_scan")

router = APIRouter()

# ── In-memory job store (same pattern as YARA import) ──
_scan_jobs: Dict[str, Dict[str, Any]] = {}
_scan_jobs_lock = threading.Lock()

# ── Settings store (simple DB-backed) ──
# We store nmap_path in the DB as a key-value pair in a generic way.
# For simplicity, use a tiny helper that reads/writes from the `agents` DB.
# Actually, let's create a proper settings approach using a simple dict table.


# ── OUI lookup table (most common prefixes) ──
OUI_TABLE: Dict[str, str] = {
    # Virtual machines
    "52:54:00": "QEMU Virtual NIC (VM)",
    "00:0c:29": "VMware (VM)",
    "00:50:56": "VMware (VM)",
    "00:05:69": "VMware (VM)",
    "08:00:27": "VirtualBox (VM)",
    "0a:00:27": "VirtualBox (VM)",
    # Network vendors
    "00:1a:2b": "Dell",
    "00:1e:c9": "Dell",
    "f8:db:88": "Dell",
    "00:14:22": "Dell",
    "b8:ac:6f": "Dell iDRAC",
    "00:1a:a0": "Dell",
    # HP / HPE
    "00:17:a4": "HP",
    "00:1e:0b": "HP",
    "3c:a8:2a": "HPE",
    "2c:44:fd": "HPE",
    "70:10:6f": "HPE",
    # Cisco
    "00:1b:54": "Cisco",
    "00:1b:d4": "Cisco",
    "00:25:45": "Cisco",
    "f8:c2:88": "Cisco",
    "00:26:0b": "Cisco",
    "70:81:05": "Cisco",
    "a4:6c:2a": "Cisco Meraki",
    # Intel
    "00:1e:67": "Intel",
    "00:22:68": "Intel",
    "00:1a:64": "Intel",
    "f4:6d:04": "Intel",
    "70:85:c2": "Intel",
    "3c:fd:fe": "Intel",
    # Realtek
    "00:e0:4c": "Realtek",
    "52:54:4e": "Realtek (VM)",
    # Broadcom
    "00:10:18": "Broadcom",
    "00:0e:0c": "Broadcom",
    "b4:b5:fe": "Broadcom",
    # Apple
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0a:27": "Apple",
    "00:0a:95": "Apple",
    "ac:de:48": "Apple",
    "a4:83:e7": "Apple",
    "3c:22:fb": "Apple",
    # Samsung
    "00:12:fb": "Samsung",
    "a0:cb:fd": "Samsung",
    "9c:b6:d0": "Samsung",
    # MikroTik
    "00:0c:42": "MikroTik",
    "4c:5e:0c": "MikroTik",
    "d4:ca:6d": "MikroTik",
    # Ubiquiti
    "00:15:6d": "Ubiquiti",
    "04:18:d6": "Ubiquiti",
    "24:5a:4c": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    # Juniper
    "00:05:85": "Juniper",
    "00:12:1e": "Juniper",
    "2c:6b:f5": "Juniper",
    # Arista
    "00:1c:73": "Arista",
    "08:00:27": "Arista",
    # Netgear
    "00:09:5b": "Netgear",
    "60:38:e0": "Netgear",
    "a0:21:b7": "Netgear",
    # TP-Link
    "50:c7:bf": "TP-Link",
    "60:32:b1": "TP-Link",
    "b0:a7:b9": "TP-Link",
    # D-Link
    "00:05:5d": "D-Link",
    "00:0d:88": "D-Link",
    "00:11:d1": "D-Link",
    "00:17:9a": "D-Link",
    # Fortinet
    "00:09:0f": "Fortinet",
    "70:4c:a5": "Fortinet",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    # Supermicro
    "00:25:90": "Supermicro",
    "0c:c4:7a": "Supermicro",
    # Lenovo
    "00:21:cc": "Lenovo",
    "3c:95:09": "Lenovo",
    "f0:de:f1": "Lenovo",
    # Microsoft Hyper-V
    "00:15:5d": "Hyper-V (VM)",
    "00:1d:d8": "Microsoft",
    # Proxmox/KVM
    "52:54:00": "KVM/QEMU (VM)",
    # Generic
    "ff:ff:ff": "Broadcast",
}


def _lookup_oui(mac: str) -> str:
    """Look up device type from MAC OUI prefix."""
    if not mac:
        return "Unknown"
    prefix = ":".join(mac.lower().split(":")[:3])
    return OUI_TABLE.get(prefix, "Unknown")


def _get_nmap_path() -> str:
    """Get nmap path from DB settings or default."""
    try:
        db = SessionLocal()
        from sqlalchemy import text
        result = db.execute(text("SELECT value FROM settings WHERE key = 'nmap_path'")).scalar()
        db.close()
        if result:
            return str(result)
    except Exception:
        pass
    return "/usr/bin/nmap"


def _set_nmap_path(path: str) -> None:
    """Set nmap path in DB settings."""
    try:
        db = SessionLocal()
        from sqlalchemy import text
        # Try update first
        result = db.execute(
            text("UPDATE settings SET value = :value WHERE key = 'nmap_path'"),
            {"value": path}
        )
        if result.rowcount == 0:
            db.execute(
                text("INSERT INTO settings (key, value) VALUES ('nmap_path', :value)"),
                {"value": path}
            )
        db.commit()
        db.close()
    except Exception as e:
        logger.warning("Failed to set nmap_path: %s", e)


def _run_nmap_scan(ip_range: str, job_id: str) -> None:
    """Background thread: run nmap ping scan and parse results."""
    try:
        _update_job(job_id, status="running", progress=10, step="scan")

        nmap_path = _get_nmap_path()

        # Try running nmap directly (if in container and nmap installed)
        # or via SSH to host if that fails
        cmd = [nmap_path, "-sn", "-oG", "-", ip_range]
        logger.info("Running nmap scan: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0 and "not found" in result.stderr.lower():
                # nmap not in container, try SSH to host
                raise FileNotFoundError("nmap not found locally")
        except FileNotFoundError:
            # Try via SSH to the host
            logger.info("nmap not found locally, trying via SSH to host")
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                "root@backend",
                f"{nmap_path} -sn -oG - {ip_range}"
            ]
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

        if result.returncode != 0:
            _update_job(job_id, status="failed", error=f"nmap error: {result.stderr[:500]}", progress=0)
            return

        _update_job(job_id, progress=50, step="parse")
        output = result.stdout

        # Parse nmap grepable output
        hosts: List[Dict[str, Any]] = []
        for line in output.splitlines():
            if line.startswith("Host:"):
                # Format: Host: 192.168.1.1 (gateway)	Ports: ...	Ignored State: ...	Seq Index: ...	IP ID Seq: ...
                parts = line.split("\t")
                host_part = parts[0]  # "Host: 192.168.1.1 (gateway)"
                ip_match = re.match(r"Host:\s+(\d+\.\d+\.\d+\.\d+)\s*(?:\(([^)]*)\))?", host_part)
                if not ip_match:
                    continue
                ip = ip_match.group(1)
                hostname_from_scan = ip_match.group(2) or ""

                # Look for MAC in the same line or nearby lines
                mac = ""
                device_type = "Unknown"

                # Check if there's a MAC line nearby - nmap -oG puts MAC after Status line
                # Actually with -oG, MAC is on the same line after Status
                for part in parts:
                    if "MAC" in part:
                        mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', part)
                        if mac_match:
                            mac = mac_match.group(1)
                            device_type = _lookup_oui(mac)

                # Also parse standard output (-sn without -oG produces different format)
                # Let's also parse the standard output format as fallback
                hosts.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname_from_scan if hostname_from_scan and hostname_from_scan != ip else "",
                    "device_type": device_type,
                    "status": "new",
                })

        # If grepable format didn't work well, try parsing standard nmap -sn output
        # Read MAC addresses from /proc/net/arp (works without root)
        _update_job(job_id, progress=60, step="scan_mac")
        arp_table = {}
        try:
            with open("/proc/net/arp", "r") as arp_file:
                for line in arp_file:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != "IP":
                        ip_addr = parts[0]
                        mac_addr = parts[3]
                        if mac_addr != "00:00:00:00:00:00" and mac_addr != "*":
                            arp_table[ip_addr] = mac_addr
            logger.info("ARP table: %d entries", len(arp_table))
        except Exception as e:
            logger.warning("Could not read /proc/net/arp: %s", e)

        # Update hosts with MAC from ARP table
        for h in hosts:
            if not h["mac"] and h["ip"] in arp_table:
                h["mac"] = arp_table[h["ip"]]
            if h["mac"]:
                h["device_type"] = _lookup_oui(h["mac"])

        _update_job(job_id, progress=80, step="dedup")

        # Deduplication: exclude hosts already in DB (by IP or MAC)
        db = SessionLocal()
        try:
            existing_agents = db.query(Agent).all()
            existing_ips = set()
            existing_macs = set()
            for a in existing_agents:
                if a.host_ips:
                    for ip in a.host_ips.split(","):
                        existing_ips.add(ip.strip())
                if a.mac:
                    existing_macs.add(a.mac.lower())

            new_hosts = []
            for h in hosts:
                # Skip if IP already known
                if h["ip"] in existing_ips:
                    continue
                # Skip if MAC already known (case-insensitive)
                if h["mac"] and h["mac"].lower() in existing_macs:
                    continue
                new_hosts.append(h)

            hosts = new_hosts
        finally:
            db.close()

        _update_job(job_id, status="completed", progress=100, step="done",
                     hosts_found=hosts, hosts_count=len(hosts))

    except Exception as exc:
        logger.exception("Network scan job %s failed: %s", job_id, exc)
        _update_job(job_id, status="failed", error=str(exc), progress=0)


def _create_job() -> str:
    """Create a new scan job, return the job_id."""
    job_id = str(uuid.uuid4())[:12]
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "job_id": job_id,
            "status": "pending",
            "progress": 0,
            "step": "",
            "hosts_found": [],
            "hosts_count": 0,
            "error": None,
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        }
    return job_id


def _update_job(job_id: str, **kwargs) -> None:
    with _scan_jobs_lock:
        if job_id in _scan_jobs:
            _scan_jobs[job_id].update(kwargs)


# ── Pydantic models ──

class ScanRequest(BaseModel):
    ip_range: str  # e.g., "192.168.1.0/24"

class ScanImportRequest(BaseModel):
    hosts: List[Dict[str, Any]]  # [{ip, mac, hostname, device_type}]

class NetworkInfoResponse(BaseModel):
    interface: Optional[str] = None
    network: Optional[str] = None
    gateway: Optional[str] = None
    error: Optional[str] = None

class NmapPathResponse(BaseModel):
    nmap_path: str


class NmapPathUpdate(BaseModel):
    nmap_path: str


# ── Endpoints ──

@router.post("/scan")
def start_scan(
    request: ScanRequest,
    current_user: User = Depends(require_role("admin")),
):
    """Start a network scan. Returns job_id immediately (async)."""
    job_id = _create_job()

    def _run_async():
        _run_nmap_scan(request.ip_range, job_id)

    t = threading.Thread(target=_run_async, daemon=False)
    t.start()

    return {"job_id": job_id, "status": "running"}


@router.get("/scan/{job_id}/status")
def get_scan_status(job_id: str):
    """Get scan job status and results."""
    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job {job_id} not found")

    result = {
        "job_id": job["job_id"],
        "status": job["status"],
        "progress": job.get("progress", 0),
        "step": job.get("step", ""),
        "hosts_found": job.get("hosts_found", []),
        "hosts_count": job.get("hosts_count", 0),
        "error": job.get("error"),
    }
    return result


@router.post("/scan/{job_id}/import")
def import_scan_results(
    job_id: str,
    request: ScanImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Import selected hosts from scan results as manual assets."""
    imported = 0
    errors = []

    for host in request.hosts:
        ip = host.get("ip", "")
        mac = host.get("mac", "")
        hostname = host.get("hostname", "")
        device_type = host.get("device_type", "")

        if not ip and not hostname:
            errors.append(f"Host missing IP and hostname: {host}")
            continue

        # Use hostname or IP as hostname
        asset_hostname = hostname or ip
        # Determine platform from device_type
        platform = "unknown"
        if "VM" in device_type:
            platform = "linux"
        elif "Router" in device_type or "Switch" in device_type or "Cisco" in device_type:
            platform = "network-device"

        # Check if asset already exists (by IP or MAC)
        existing = None
        if ip:
            existing = db.query(Agent).filter(Agent.host_ips == ip).first()
        if not existing and mac:
            existing = db.query(Agent).filter(Agent.mac == mac.lower()).first()
        if not existing and hostname:
            existing = db.query(Agent).filter(Agent.hostname == hostname).first()

        if existing:
            errors.append(f"Host {ip or hostname} already exists in DB (id={existing.id})")
            continue

        import hashlib
        agent_id = str(uuid.uuid4())
        token_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:60]
        hmac_secret = uuid.uuid4().hex

        agent = Agent(
            agent_id=agent_id,
            hostname=asset_hostname,
            platform=platform,
            mac=mac or None,
            host_ips=ip or None,
            os_name=host.get("os_name") or None,
            os_version=host.get("os_version") or None,
            arch=host.get("arch") or None,
            status="active",
            token_hash=token_hash,
            hmac_secret_enc=hmac_secret,
            source='scan',
        )
        db.add(agent)
        imported += 1

    db.commit()
    return {"imported": imported, "errors": errors}


@router.get("/scan/network-info")
def get_network_info(
    current_user: User = Depends(require_role("user")),
):
    """Auto-detect local network info."""
    interface = None
    gateway = None
    network = None

    try:
        # Get default gateway and interface
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            # default via 192.168.1.1 dev eth0
            parts = result.stdout.strip().split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
            if "dev" in parts:
                interface = parts[parts.index("dev") + 1]
    except FileNotFoundError:
        # Try SSH to host
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "root@backend", "ip route show default"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if "via" in parts:
                    gateway = parts[parts.index("via") + 1]
                if "dev" in parts:
                    interface = parts[parts.index("dev") + 1]
        except Exception:
            pass
    except Exception as e:
        logger.warning("Failed to detect gateway: %s", e)

    try:
        # Get IP/prefix for the interface
        cmd = ["ip", "-o", "addr", "show"]
        if interface:
            cmd.append(interface)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "inet " in line:
                    # inet 192.168.1.5/24 ...
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if match:
                        ip_addr = match.group(1)
                        prefix_len = int(match.group(2))
                        # Convert to network address
                        if prefix_len == 24:
                            network = f"{'.'.join(ip_addr.split('.')[:3])}.0/{prefix_len}"
                        elif prefix_len == 16:
                            network = f"{'.'.join(ip_addr.split('.')[:2])}.0.0/{prefix_len}"
                        else:
                            network = f"{ip_addr}/{prefix_len}"
                        break
    except FileNotFoundError:
        try:
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                   "root@backend", "ip -o addr show"]
            if interface:
                cmd[-1] += f" {interface}"
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "inet " in line:
                        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                        if match:
                            ip_addr = match.group(1)
                            prefix_len = int(match.group(2))
                            if prefix_len == 24:
                                network = f"{'.'.join(ip_addr.split('.')[:3])}.0/{prefix_len}"
                            elif prefix_len == 16:
                                network = f"{'.'.join(ip_addr.split('.')[:2])}.0.0/{prefix_len}"
                            else:
                                network = f"{ip_addr}/{prefix_len}"
                            break
        except Exception:
            pass
    except Exception as e:
        logger.warning("Failed to detect network: %s", e)

    if not network and gateway:
        # Fallback: guess /24 from gateway
        parts = gateway.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    return NetworkInfoResponse(
        interface=interface,
        network=network,
        gateway=gateway,
    )


@router.get("/settings/nmap-path", response_model=NmapPathResponse)
def get_nmap_path(current_user: User = Depends(require_role("admin"))):
    """Get nmap path setting."""
    return NmapPathResponse(nmap_path=_get_nmap_path())


@router.put("/settings/nmap-path", response_model=NmapPathResponse)
def update_nmap_path(
    request: NmapPathUpdate,
    current_user: User = Depends(require_role("admin")),
):
    """Update nmap path setting."""
    _set_nmap_path(request.nmap_path)
    return NmapPathResponse(nmap_path=request.nmap_path)