"""app/scheduler_yara_import.py — Ticket #65

Daily scheduled task (03:00 UTC) that:
1. Clones https://github.com/yara-rules/rules (shallow)
2. Walks .yar/.yara files recursively
3. Filters out helper/meta files (index.yar, README, etc.)
4. Parses rule blocks, validates with yara CLI, filters YARA 5.x incompatibles
5. Deduplicates by sha256 against existing DB rules
6. Inserts new rules with inferred severity
7. Logs summary (imported, duplicates skipped, invalid skipped, duration)
8. On failure: logs the error, retries next cycle (no crash)

Reuses import logic from app/routers/yara.py:
  _parse_rule_blocks, _compile_test_yara_cli, _infer_severity,
  _YARA5_HINTS_RE, SKIP_FILENAMES

Integration: called from app/main.py lifespan, enabled via
YARA_IMPORT_ENABLED=1 env var.
"""

import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import YaraRule
from app.routers.yara import (
    _parse_rule_blocks,
    _compile_test_yara_cli,
    _infer_severity,
    _YARA5_HINTS_RE,
    SKIP_FILENAMES,
)

logger = logging.getLogger("logsoc.yara_import")

YARA_RULES_GIT_URL = "https://github.com/yara-rules/rules.git"
CLONE_DIR = "/tmp/yara-rules-import"


def run_yara_import_job() -> dict:
    """Execute the daily YARA rules import job.

    Returns a summary dict with counts for logging/monitoring.
    """
    start_ts = time.time()
    db: Session = SessionLocal()
    summary = {
        "files_scanned": 0,
        "rules_parsed": 0,
        "rules_imported": 0,
        "rules_skipped_duplicate": 0,
        "rules_skipped_invalid": 0,
        "rules_skipped_yara5": 0,
        "rules_skipped_noise": 0,
        "errors": [],
        "duration_seconds": 0.0,
    }

    try:
        # ── 1. Clone the repo (shallow) ──
        # Remove old clone dir if it exists
        if os.path.isdir(CLONE_DIR):
            try:
                shutil.rmtree(CLONE_DIR)
            except Exception as e:
                logger.warning("Could not remove old clone dir %s: %s", CLONE_DIR, e)

        try:
            clone = subprocess.run(
                ["git", "clone", "--depth=1", "--quiet", YARA_RULES_GIT_URL, CLONE_DIR],
                capture_output=True, text=True, timeout=180,
            )
            if clone.returncode != 0:
                msg = f"git clone failed: {clone.stderr[:300]}"
                summary["errors"].append(msg)
                logger.error(msg)
                return summary
        except subprocess.TimeoutExpired:
            msg = "git clone timed out after 180s"
            summary["errors"].append(msg)
            logger.error(msg)
            return summary
        except Exception as e:
            msg = f"git clone exception: {e}"
            summary["errors"].append(msg)
            logger.exception(msg)
            return summary

        logger.info("Cloned %s → %s", YARA_RULES_GIT_URL, CLONE_DIR)

        # ── 2. Walk .yar/.yara files ──
        files = []
        for root, _, names in os.walk(CLONE_DIR):
            for n in names:
                if n.endswith((".yar", ".yara")):
                    files.append(os.path.join(root, n))

        # Filter out helper/meta files
        files = [f for f in files if os.path.basename(f) not in SKIP_FILENAMES]
        summary["files_scanned"] = len(files)
        logger.info("Found %d YARA files to scan", len(files))

        # ── 3. Parse rule blocks from each file ──
        candidates = []  # (rel_path, name, rule_text)
        for fp in files:
            try:
                text = open(fp, errors="ignore").read()
            except Exception as e:
                summary["errors"].append(f"read {fp}: {e}")
                continue
            rel = os.path.relpath(fp, CLONE_DIR)
            for name, rtext in _parse_rule_blocks(text):
                candidates.append((rel, name, rtext))

        summary["rules_parsed"] = len(candidates)
        logger.info("Parsed %d rule blocks from %d files", len(candidates), len(files))

        if not candidates:
            logger.info("No rule blocks found, nothing to import")
            return summary

        # ── 4. Filter noise and YARA 5.x rules ──
        filtered = []
        for rel, name, rtext in candidates:
            nl = name.lower()
            if any(x in nl for x in (
                "malware_test", "_generic_", "generic_",
                "anyrun", "av_for_testing", "_test_",
            )):
                summary["rules_skipped_noise"] += 1
                continue
            if _YARA5_HINTS_RE.search(rtext):
                summary["rules_skipped_yara5"] += 1
                continue
            filtered.append((rel, name, rtext))

        logger.info(
            "After noise/yara5 filter: %d candidates (skipped noise=%d yara5=%d)",
            len(filtered),
            summary["rules_skipped_noise"],
            summary["rules_skipped_yara5"],
        )

        # ── 5. Compile-test in parallel (8 workers) ──
        valid_rules = []
        if filtered:
            with ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(
                    lambda c: (c, _compile_test_yara_cli(c[2])),
                    filtered,
                    chunksize=20,
                ))
            for (rel, name, rtext), ok in results:
                if ok:
                    valid_rules.append((rel, name, rtext))
                else:
                    summary["rules_skipped_invalid"] += 1

        logger.info(
            "Compile test passed: %d / %d (invalid=%d)",
            len(valid_rules), len(filtered), summary["rules_skipped_invalid"],
        )

        # ── 6. Dedup and insert ──
        # Keep DB connection alive during long-running import
        import threading
        from sqlalchemy import text as _text

        _stop_ping = threading.Event()

        def _keepalive():
            while not _stop_ping.is_set():
                _stop_ping.wait(3.0)
                if _stop_ping.is_set():
                    break
                try:
                    db.execute(_text("SELECT 1"))
                except Exception:
                    pass

        ping_thread = threading.Thread(target=_keepalive, daemon=True)
        ping_thread.start()

        try:
            for rel, name, rtext in valid_rules:
                h = hashlib.sha256(rtext.encode()).hexdigest()

                # Dedup by hash and name
                try:
                    if db.query(YaraRule.id).filter(YaraRule.rule_hash == h).first():
                        summary["rules_skipped_duplicate"] += 1
                        continue
                    if db.query(YaraRule.id).filter(YaraRule.name == name).first():
                        summary["rules_skipped_duplicate"] += 1
                        continue
                except Exception as e:
                    summary["errors"].append(f"dedup check: {e}")
                    break

                try:
                    rule = YaraRule(
                        rule_id=str(uuid.uuid4())[:8],
                        name=name,
                        description=f"From yara-rules/rules: {rel}",
                        rule_text=rtext,
                        severity=_infer_severity(name),
                        is_active=True,
                        scan_flags=1,  # file scan by default
                        tags=f"yara-rules,{os.path.dirname(rel)}",
                        rule_hash=h,
                        created_by=None,  # automated import, no user
                    )
                    db.add(rule)
                    summary["rules_imported"] += 1
                except Exception as e:
                    summary["errors"].append(f"add rule {name}: {e}")
                    continue

                # Commit in batches of 25
                if summary["rules_imported"] % 25 == 0:
                    try:
                        db.commit()
                    except Exception as e:
                        db.rollback()
                        summary["errors"].append(f"commit batch: {e}")

            # Final commit
            try:
                db.commit()
            except Exception as e:
                db.rollback()
                summary["errors"].append(f"final commit: {e}")
        finally:
            _stop_ping.set()
            ping_thread.join(timeout=2.0)

    except Exception as e:
        db.rollback()
        summary["errors"].append(f"fatal: {e}")
        logger.exception("YARA import job failed: %s", e)
    finally:
        db.close()
        # Clean up clone dir
        try:
            shutil.rmtree(CLONE_DIR, ignore_errors=True)
        except Exception:
            pass

    summary["duration_seconds"] = round(time.time() - start_ts, 2)

    logger.info(
        "YARA import job complete: files=%d parsed=%d imported=%d "
        "duplicates=%d invalid=%d yara5=%d noise=%d errors=%d "
        "duration=%.1fs",
        summary["files_scanned"],
        summary["rules_parsed"],
        summary["rules_imported"],
        summary["rules_skipped_duplicate"],
        summary["rules_skipped_invalid"],
        summary["rules_skipped_yara5"],
        summary["rules_skipped_noise"],
        len(summary["errors"]),
        summary["duration_seconds"],
    )
    if summary["errors"]:
        for err in summary["errors"][:10]:
            logger.warning("  YARA import error: %s", err)

    return summary


def run_yara_import_standalone():
    """Standalone entry point for the YARA import scheduler.

    Runs the job once and exits. Intended to be called from a cron
    sidecar or external scheduler at 03:00 UTC.

    Usage:
        python -m app.scheduler_yara_import
    """
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s.%(msecs)03d [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    result = run_yara_import_job()
    if result["errors"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    run_yara_import_standalone()