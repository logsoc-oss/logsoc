"""
WebSocket endpoint for real-time event streaming.

Clients connect to /ws/events and receive live events as JSON.
Also supports a broadcast mechanism for the backend to push events
when they are ingested via the REST API.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

# Connected clients
_connected_clients: Set[WebSocket] = set()
_broadcast_queue: asyncio.Queue | None = None


async def get_broadcast_queue() -> asyncio.Queue:
    global _broadcast_queue
    if _broadcast_queue is None:
        _broadcast_queue = asyncio.Queue(maxsize=1000)
    return _broadcast_queue


async def broadcast_event(event: dict):
    """Push an event to all connected WebSocket clients. Called from REST ingest."""
    queue = await get_broadcast_queue()
    try:
        await queue.put(event)
    except asyncio.QueueFull:
        logger.warning("WebSocket broadcast queue full, dropping event")


async def _broadcaster():
    """Background task: read from queue and fan-out to all clients."""
    queue = await get_broadcast_queue()
    while True:
        event = await queue.get()
        dead = set()
        for ws in _connected_clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        for ws in dead:
            _connected_clients.discard(ws)
            try:
                await ws.close()
            except Exception:
                pass


@router.websocket("/events")
async def ws_events(
    websocket: WebSocket,
    token: str = Query(default=""),
):
    """
    WebSocket endpoint for real-time events.
    Optional ?token=<jwt> for authentication.
    Sends events as JSON:
    {
      "type": "event" | "alert" | "insight" | "heartbeat",
      "data": { ... },
      "timestamp": "..."
    }
    """
    await websocket.accept()
    _connected_clients.add(websocket)
    logger.info(f"WS client connected. Total: {len(_connected_clients)}")

    try:
        # Send a welcome message
        await websocket.send_json({
            "type": "connected",
            "data": {"message": "LogSOC WebSocket connected", "clients": len(_connected_clients)},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Keep connection alive — listen for client messages (pings, commands)
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Client can send pings
                if msg == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "data": {"clients": len(_connected_clients)},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                elif msg.startswith("subscribe:"):
                    # Client subscribes to specific event types
                    # e.g. "subscribe:events,alerts"
                    await websocket.send_json({
                        "type": "subscribed",
                        "data": {"channels": msg.split(":", 1)[1]},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
            except asyncio.TimeoutError:
                # Send heartbeat
                try:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "data": {"clients": len(_connected_clients)},
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    break
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WS error: {e}")
    finally:
        _connected_clients.discard(websocket)
        logger.info(f"WS client disconnected. Total: {len(_connected_clients)}")
        try:
            await websocket.close()
        except Exception:
            pass