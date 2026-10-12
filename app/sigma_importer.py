"""sigma_importer.py — v0.6.5 SigmaHQ rule importer.

Imports Sigma rules from the SigmaHQ/sigma GitHub repository (Linux rules
only — logsource.product == "linux") into the MariaDB `sigma_rules` table.

Each rule is parsed and:
  1. Stored as raw YAML metadata (title, level, status, logsource, etc.)
  2. Parsed into a Sigma AST (structured detection tree)
  3. Compiled to a ClickHouse WHERE clause fragment (`query_compiled`)
     ready to be plugged into the same template engine that MITRE rules use.

The AST stays in the DB so that future schema migrations can rebind the
SQL without re-parsing YAML (one AST->SQL mapper in the codebase, not
a hard-coded mapping per schema version).

Usage (from container or Hestia):
    docker exec logsoc-api python -m app.sigma_importer \\
        --source https://github.com/SigmaHQ/sigma.git --ref master --limit 5

    # Or against the local clone for offline runs:
    docker exec logsoc-api python -m app.sigma_importer --source /opt/sigma --limit 50

The script is idempotent: re-runs only INSERT rules whose UUID isn't yet
in `sigma_rules` (skips UPDATE for the moment — full re-import is a T4+1
phase when we wire the dashboard "Update Sigma" button).
"""

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from sqlalchemy.orm import Session

from app.clickhouse_client import get_client
from app.database import Base, SessionLocal, engine
from app.models import SigmaRule
from app.sigma_converter import (
    SigmaAST,
    SigmaCompileError,
    parse_detection,
    bind_to_clickhouse,
    SigmaUnsupportedFeature,
)

logger = logging.getLogger("logsoc.sigma_importer")

# Whitelist of Sigma logsource products we care about.
# v0.6.5: only Linux. T4+1 may extend to auditd/sysmon/other.
SUPPORTED_PRODUCTS = {"linux"}

# Sigma levels map to our severity enum directly.
SIGMA_LEVEL_TO_SEVERITY = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _stable_rule_hash(yaml_path: Path) -> str:
    """Generate a stable hash for a rule file (relative path + content)."""
    h = hashlib.sha256()
    h.update(str(yaml_path).encode())
    h.update(yaml_path.read_bytes())
    return h.hexdigest()[:32]


def _extract_mitre_techniques(tags: List[str]) -> List[str]:
    """Parse MITRE technique IDs from Sigma tags (attack.t1234 format)."""
    out: List[str] = []
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        # Tags look like "attack.t1059.004" or "attack.t1059"
        if tag.startswith("attack.t"):
            tech = tag.split(".", 1)[1]  # "t1059.004" -> "1059.004"
            if tech.startswith("t"):
                tech = tech[1:]
            if tech:
                out.append(f"T{tech}")
    return sorted(set(out))


def _git_clone_or_update(repo_url: str, ref: str, workdir: Path) -> Path:
    """Clone a git repo (shallow) or refresh an existing one.

    Returns the path to the repo on disk. For the public SigmaHQ repo, the
    clone is fast (< 5s) thanks to the partial clone.
    """
    target = workdir / "sigma"
    if (target / ".git").is_dir():
        logger.info("Refreshing existing Sigma clone at %s", target)
        try:
            subprocess.run(
                ["git", "-C", str(target), "fetch", "--depth=1", "origin", ref],
                check=True, capture_output=True, timeout=120,
            )
            subprocess.run(
                ["git", "-C", str(target), "reset", "--hard", f"origin/{ref}"],
                check=True, capture_output=True, timeout=30,
            )
        except subprocess.CalledProcessError as e:
            logger.warning("git fetch failed (%s), re-cloning", e.stderr)
            subprocess.run(["rm", "-rf", str(target)], check=False)
    if not (target / ".git").is_dir():
        logger.info("Cloning SigmaHQ/sigma (%s) into %s", ref, target)
        subprocess.run(
            ["git", "clone", "--depth=1", "--branch", ref, repo_url, str(target)],
            check=True, capture_output=True, timeout=300,
        )
    return target


def _iter_linux_rules(repo_root: Path) -> List[Path]:
    """Yield all .yml files under rules/linux/. Recursive."""
    base = repo_root / "rules" / "linux"
    if not base.is_dir():
        logger.warning("Sigma rules/linux directory not found at %s", base)
        return []
    return sorted(base.rglob("*.yml"))


def _parse_rule_file(path: Path) -> Optional[Dict[str, Any]]:
    """Load a Sigma YAML file, return None if invalid/empty."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("Cannot read %s: %s", path, e)
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        logger.warning("YAML parse error in %s: %s", path, e)
        return None
    if not isinstance(data, dict):
        return None
    return data


def _persist_rule(db: Session, row: Dict[str, Any]) -> Tuple[bool, str]:
    """INSERT a rule row. Returns (inserted, reason)."""
    existing = db.query(SigmaRule).filter(SigmaRule.uuid == row["uuid"]).first()
    if existing:
        return False, "duplicate"
    rule = SigmaRule(
        uuid=row["uuid"],
        title=row["title"],
        description=row.get("description", ""),
        status=row.get("status", "test"),
        level=row.get("level", "medium"),
        severity=row["severity"],
        logsource=json.dumps(row["logsource"]),
        logsource_product=row["logsource"].get("product", ""),
        logsource_category=row["logsource"].get("category", ""),
        logsource_service=row["logsource"].get("service", ""),
        detection=json.dumps(row["detection"]),
        detection_ast=json.dumps(row["detection_ast"]),
        query_compiled=row.get("query_compiled", ""),
        query_supported=1 if row.get("query_compiled") else 0,
        query_unsupported_reason=row.get("query_unsupported_reason", ""),
        author=row.get("author", ""),
        date_modified=row.get("date_modified"),
        references=json.dumps(row.get("references", [])),
        falsepositives=json.dumps(row.get("falsepositives", [])),
        tags=json.dumps(row.get("tags", [])),
        mitre_techniques=json.dumps(row.get("mitre_techniques", [])),
        is_active=1 if row.get("status", "test") != "experimental" else 0,
        source_file=row["source_file"],
        rule_hash=row["rule_hash"],
        imported_at=datetime.now(timezone.utc),
    )
    db.add(rule)
    db.flush()  # raise IntegrityError early if duplicate
    return True, "ok"


def import_rules(
    source: str,
    ref: str = "master",
    limit: Optional[int] = None,
    workdir: Optional[Path] = None,
    product_filter: Optional[set] = None,
) -> Dict[str, int]:
    """Main entry point. Returns counters for the import run."""
    if product_filter is None:
        product_filter = SUPPORTED_PRODUCTS
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="logsoc_sigma_"))

    if source.startswith("http://") or source.startswith("https://") or source.endswith(".git"):
        repo_root = _git_clone_or_update(source, ref, workdir)
    else:
        repo_root = Path(source)
        if not (repo_root / "rules" / "linux").is_dir():
            raise SystemExit(f"Source {source} does not look like a Sigma repo (no rules/linux/)")

    rule_files = _iter_linux_rules(repo_root)
    logger.info("Found %d rule files under rules/linux/", len(rule_files))
    if limit:
        rule_files = rule_files[:limit]
        logger.info("Limiting import to first %d files", limit)

    # Ensure the SigmaRule table exists (idempotent CREATE IF NOT EXISTS).
    Base.metadata.create_all(bind=engine, tables=[SigmaRule.__table__])

    db = SessionLocal()
    stats = {
        "scanned": 0,
        "parsed": 0,
        "unsupported": 0,
        "inserted": 0,
        "duplicates": 0,
        "errors": 0,
        "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "by_category": {},
        "mitre_coverage": set(),
    }
    try:
        for path in rule_files:
            stats["scanned"] += 1
            data = _parse_rule_file(path)
            if not data:
                stats["errors"] += 1
                continue
            logsource = data.get("logsource") or {}
            if not isinstance(logsource, dict):
                stats["errors"] += 1
                continue
            if logsource.get("product") not in product_filter:
                continue  # silently skip non-linux rules

            stats["parsed"] += 1

            # Initialize per-rule state (used both on success and unsupported paths)
            query_compiled = ""
            query_unsupported_reason = ""
            detection_ast: Dict[str, Any] = {}
            ast = None

            # Build the AST (may raise SigmaUnsupportedFeature)
            try:
                detection_raw = data.get("detection") or {}
                ast = parse_detection(detection_raw, condition=data.get("condition", ""))
            except SigmaUnsupportedFeature as e:
                stats["unsupported"] += 1
                detection_ast = {"type": "unsupported", "reason": str(e)}
                query_unsupported_reason = str(e)
            except Exception as e:
                logger.debug("AST parse failed for %s: %s", path, e)
                stats["errors"] += 1
                continue

            # Bind AST -> ClickHouse SQL (only if AST was parseable)
            if ast is not None:
                try:
                    query_compiled = bind_to_clickhouse(ast)
                    detection_ast = ast.to_dict()
                except (SigmaCompileError, SigmaUnsupportedFeature) as e:
                    logger.debug("Bind failed for %s: %s", path, e)
                    query_compiled = ""
                    query_unsupported_reason = f"{type(e).__name__}: {e}"
                    stats["unsupported"] += 1
                except Exception as e:
                    logger.warning("Unexpected bind error for %s: %s", path, e)
                    query_compiled = ""
                    query_unsupported_reason = f"unexpected: {e}"
                    stats["unsupported"] += 1

            uuid_val = data.get("id")
            if not uuid_val:
                stats["errors"] += 1
                continue

            severity = SIGMA_LEVEL_TO_SEVERITY.get(
                (data.get("level") or "medium").lower(), "medium"
            )
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            cat = logsource.get("category", "uncategorized")
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
            tags = data.get("tags") or []
            mitre_techs = _extract_mitre_techniques(tags)
            stats["mitre_coverage"].update(mitre_techs)

            row = {
                "uuid": uuid_val,
                "title": data.get("title", path.stem),
                "description": data.get("description", ""),
                "status": data.get("status", "test"),
                "level": data.get("level", "medium"),
                "severity": severity,
                "logsource": logsource,
                "logsource_product": logsource.get("product", ""),
                "logsource_category": logsource.get("category", ""),
                "logsource_service": logsource.get("service", ""),
                "detection": detection_raw,
                "detection_ast": ast.to_dict() if ast is not None and hasattr(ast, "to_dict") else detection_ast,
                "query_compiled": query_compiled or "",
                "query_supported": bool(query_compiled and not query_unsupported_reason),
                "query_unsupported_reason": query_unsupported_reason or "",
                "author": data.get("author", ""),
                "date_modified": data.get("modified") or data.get("date"),
                "references": data.get("references", []),
                "falsepositives": data.get("falsepositives", []),
                "tags": tags,
                "mitre_techniques": mitre_techs,
                "source_file": str(path.relative_to(repo_root)),
                "rule_hash": _stable_rule_hash(path),
            }
            try:
                inserted, reason = _persist_rule(db, row)
                if inserted:
                    stats["inserted"] += 1
                else:
                    stats["duplicates"] += 1
            except Exception as e:
                logger.warning("Insert failed for %s: %s", path, e)
                db.rollback()
                stats["errors"] += 1
        db.commit()
    finally:
        db.close()

    # Convert set to list for JSON-serializable output
    stats["mitre_coverage"] = sorted(stats["mitre_coverage"])
    return stats


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Import SigmaHQ rules into LogSOC")
    p.add_argument(
        "--source",
        default="https://github.com/SigmaHQ/sigma.git",
        help="Git URL or local path to a SigmaHQ clone (default: %(default)s)",
    )
    p.add_argument("--ref", default="master", help="Git ref / branch (default: master)")
    p.add_argument("--limit", type=int, default=None, help="Limit import to first N files (debug)")
    p.add_argument(
        "--workdir",
        default="/tmp/sigma-import",
        help="Working directory for the Sigma clone (default: %(default)s)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    stats = import_rules(
        source=args.source,
        ref=args.ref,
        limit=args.limit,
        workdir=Path(args.workdir),
    )
    print(json.dumps(stats, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
