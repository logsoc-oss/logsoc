from fastapi import APIRouter
from sqlalchemy import text
from app.database import engine
from app.clickhouse_client import get_client
from app.schemas import SystemStatus
from app.plugins import PluginManager

router = APIRouter()


@router.get(
    "/health",
    response_model=SystemStatus,
    summary="Basic health check",
    description="Returns API version and MySQL/ClickHouse connectivity status.",
    responses={200: {"description": "System is healthy"}},
)
def health():
    mysql_status = "ok"
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception as e:
        mysql_status = f"error: {str(e)[:80]}"

    ch_status = "ok"
    try:
        client = get_client()
        client.query("SELECT 1")
    except Exception as e:
        ch_status = f"error: {str(e)[:80]}"

    return {"api": "ok", "mysql": mysql_status, "clickhouse": ch_status, "version": "0.7.0"}


@router.get(
    "/health/details",
    summary="Detailed system health",
    description="Returns comprehensive system information: database connectivity, table counts, loaded plugins, and uptime stats.",
)
def health_details():
    import time
    from app.main import plugin_manager

    # MySQL stats
    mysql_info = {"status": "ok", "tables": 0}
    try:
        with engine.connect() as c:
            result = c.execute(text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()"))
            mysql_info["tables"] = result.scalar() or 0
    except Exception as e:
        mysql_info["status"] = f"error: {str(e)[:120]}"

    # ClickHouse stats
    ch_info = {"status": "ok", "events_count": 0}
    try:
        client = get_client()
        result = client.query("SELECT count() FROM siem_logs")
        ch_info["events_count"] = result.first_row[0] if result.first_row else 0
    except Exception as e:
        ch_info["status"] = f"error: {str(e)[:120]}"

    # Plugins
    plugins_list = [{"name": p.name, "version": p.version, "description": p.description} for p in plugin_manager.plugins]

    return {
        "version": "0.7.0",
        "mysql": mysql_info,
        "clickhouse": ch_info,
        "plugins": plugins_list,
        "timestamp": time.time(),
    }