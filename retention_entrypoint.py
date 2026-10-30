"""retention_entrypoint.py — Sidecar entrypoint for the daily retention sweep.

Runs `jobs.run_daily_sweep()` on a cron schedule, in a single Python
process. No external cron daemon needed (which keeps Hestia simple).

Why Python-native scheduling (vs system cron or Celery beat):
  - System cron: would need a separate install + crontab management
    in the container. Adds attack surface and complexity for one job.
  - Celery beat: overkill for one daily job. We don't have a worker
    pool, and the API already does the heavy lifting on demand.
  - APScheduler: nice but adds a dependency.
  - Custom loop with datetime + sleep: minimal, predictable, easy to
    read in logs. This file.

Configuration (env vars):
  CRON_SCHEDULE     : "HH:MM" 24h UTC (default "02:00")
  RUN_ON_START      : "1" to run a sweep immediately on startup
                      (default "0")
  SWEEP_TIMEOUT_SEC : kill the sweep if it runs longer than N seconds
                      (default 3600 = 1h)
  LOG_LEVEL         : DEBUG, INFO, WARNING, ERROR (default INFO)

Restart on failure:
  The Docker container is configured with `restart: unless-stopped`,
  so if the process dies, Docker restarts it. The loop catches
  exceptions so the process stays alive across job failures (one bad
  sweep does not kill the sidecar).

Logging:
  All output goes to stdout (Docker captures it). The format includes
  ISO timestamp + level + module, matching the API's format for
  consistent log shipping.
"""

import datetime
import logging
import os
import signal
import sys
import time
import traceback


def _utcnow() -> datetime.datetime:
    """Timezone-aware UTC now. Replaces datetime.utcnow() (deprecated in 3.12+)."""
    return datetime.datetime.now(datetime.timezone.utc)


def _setup_logging():
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s.%(msecs)03d [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    return logging.getLogger("logsoc.retention.sidecar")


logger = _setup_logging()

# Configuration — priority: env (CRON_SCHEDULE etc) > config.yaml > defaults.
# Using a thin try/except so the sidecar still boots even if PyYAML is
# missing or config.yaml is malformed (in which case we fall back to env).
def _load_config():
    try:
        from app.retention_config import get_retention_config
        cfg = get_retention_config()
        return {
            "cron": cfg["sweep_cron"],
            "run_on_start": cfg["run_on_start"],
            "timeout_sec": cfg["sweep_timeout_sec"],
            "log_level": cfg["log_level"],
        }
    except Exception as e:
        logger.warning("could not load retention_config: %s; using env defaults", e)
        return {
            "cron": os.environ.get("CRON_SCHEDULE", "02:00"),
            "run_on_start": os.environ.get("RUN_ON_START", "0") == "1",
            "timeout_sec": int(os.environ.get("SWEEP_TIMEOUT_SEC", "300")),
            "log_level": os.environ.get("LOG_LEVEL", "INFO").upper(),
        }


_config = _load_config()
CRON_SCHEDULE = _config["cron"]
RUN_ON_START = _config["run_on_start"]
SWEEP_TIMEOUT_SEC = _config["timeout_sec"]
LOG_LEVEL = _config["log_level"]

# Re-apply logging with final level
logging.getLogger().setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.info("retention sidecar config: %s", _config)

# Signals: handle SIGTERM/SIGINT gracefully (Docker sends SIGTERM
# on `docker stop`; we want to log the shutdown, not die silently).
_shutdown_requested = False


def _on_signal(signum, _frame):
    global _shutdown_requested
    _shutdown_requested = True
    logger.info("signal %d received, requesting shutdown after current job", signum)


signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT, _on_signal)


def _parse_hhmm(s: str) -> tuple[int, int]:
    """Parse 'HH:MM' into (hour, minute). Raises ValueError on bad format."""
    parts = s.split(":")
    if len(parts) != 2:
        raise ValueError(f"CRON_SCHEDULE must be HH:MM, got {s!r}")
    h, m = int(parts[0]), int(parts[1])
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"CRON_SCHEDULE hour/minute out of range: {s!r}")
    return h, m


def _seconds_until_next(hour: int, minute: int) -> float:
    """Return number of seconds to sleep until the next HH:MM UTC."""
    now = _utcnow()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        # Today's slot already passed; aim for tomorrow
        target += datetime.timedelta(days=1)
    return (target - now).total_seconds()


def _run_sweep_with_timeout() -> dict:
    """Run jobs.run_daily_sweep() with a timeout.

    We use a daemon thread + join-with-timeout because the sweep
    itself is synchronous and can take a long time on large
    datasets. The timeout protects against runaway mutations
    (e.g. an ALTER that hangs on a CH lock).
    """
    import threading
    from app.retention import jobs

    result_box: dict = {}

    def runner():
        try:
            result_box["summary"] = jobs.run_daily_sweep()
            result_box["error"] = None
        except Exception as e:
            result_box["summary"] = None
            result_box["error"] = e
            result_box["traceback"] = traceback.format_exc()

    t = threading.Thread(target=runner, name="retention-sweep", daemon=True)
    t.start()
    t.join(timeout=SWEEP_TIMEOUT_SEC)
    if t.is_alive():
        logger.error(
            "sweep exceeded SWEEP_TIMEOUT_SEC=%d, abandoning (thread is daemon, "
            "will die with this process). Next sweep will retry.",
            SWEEP_TIMEOUT_SEC,
        )
        return {
            "ok": False,
            "timed_out": True,
            "summary": None,
            "error": f"timeout after {SWEEP_TIMEOUT_SEC}s",
        }
    if result_box.get("error") is not None:
        logger.error("sweep failed:\n%s", result_box.get("traceback", ""))
        return {
            "ok": False,
            "timed_out": False,
            "summary": None,
            "error": str(result_box["error"]),
        }
    return {
        "ok": True,
        "timed_out": False,
        "summary": result_box["summary"],
        "error": None,
    }


def main():
    logger.info(
        "retention sidecar starting: CRON_SCHEDULE=%s RUN_ON_START=%s "
        "SWEEP_TIMEOUT_SEC=%d LOG_LEVEL=%s",
        CRON_SCHEDULE, RUN_ON_START, SWEEP_TIMEOUT_SEC, LOG_LEVEL,
    )
    try:
        hour, minute = _parse_hhmm(CRON_SCHEDULE)
    except ValueError as e:
        logger.error("invalid CRON_SCHEDULE: %s. Falling back to 02:00", e)
        hour, minute = 2, 0

    # Run on startup if requested
    if RUN_ON_START:
        logger.info("RUN_ON_START=1, running initial sweep")
        result = _run_sweep_with_timeout()
        logger.info("initial sweep result: ok=%s error=%s", result["ok"], result.get("error"))

    # Main loop
    while not _shutdown_requested:
        sleep_sec = _seconds_until_next(hour, minute)
        next_run = _utcnow() + datetime.timedelta(seconds=sleep_sec)
        logger.info(
            "next sweep at %s UTC (in %.0f seconds = %.1f hours)",
            next_run.strftime("%Y-%m-%d %H:%M:%S"),
            sleep_sec, sleep_sec / 3600,
        )

        # Sleep in small chunks so SIGTERM is responsive (max 60s chunks)
        slept = 0.0
        while slept < sleep_sec and not _shutdown_requested:
            chunk = min(60.0, sleep_sec - slept)
            time.sleep(chunk)
            slept += chunk

        if _shutdown_requested:
            break

        # Run the sweep
        logger.info("running scheduled sweep")
        result = _run_sweep_with_timeout()
        if result["ok"]:
            logger.info("sweep done: %s", result["summary"])
        else:
            logger.error("sweep failed: %s", result.get("error"))

    logger.info("retention sidecar shutting down cleanly")


if __name__ == "__main__":
    main()
