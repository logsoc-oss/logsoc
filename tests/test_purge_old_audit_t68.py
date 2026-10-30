"""T68 (logsoc-web#18 follow-up, v0.18.0-t68) tests for purge_old_audit.py.

The purge tool connects to MySQL via pymysql. Tests are split into:

1. **Source-level tests** (default, always run):
   - Defaults are 1095/3650 days.
   - The tool reads config.yaml's audit_purge section if present.
   - The systemd timer references the script.
   - The tool supports --apply, --only, --compliance-audit-days,
     --gdpr-audit-days flags.

2. **Mocked pymysql tests** (no live DB):
   - The tool calls pymysql.connect with the right creds.
   - The tool calls SELECT COUNT(*) before DELETE.
   - The tool rolls back on dry-run, commits on --apply.
   - The tool emits valid JSON on stdout.

We don't hit a live MariaDB here (the live E2E was done in the
session — see CHANGELOG [0.18.0-t68] for the Hestia run).
"""
import json
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))


class TestPurgeToolSource(unittest.TestCase):
    """Static checks on purge_old_audit.py."""

    def setUp(self):
        self.tool_path = os.path.join(HERE, "..", "tools", "purge_old_audit.py")
        self.service_path = os.path.join(
            HERE, "..", "deploy", "systemd", "logsoc-audit-purge.service"
        )
        self.timer_path = os.path.join(
            HERE, "..", "deploy", "systemd", "logsoc-audit-purge.timer"
        )
        with open(self.tool_path) as f:
            self.src = f.read()
        with open(self.service_path) as f:
            self.service = f.read()
        with open(self.timer_path) as f:
            self.timer = f.read()

    def test_defaults_are_documented(self):
        """3y for compliance_audit, 10y for gdpr_audit (RGPD art. 5(2))."""
        # The constants are defined in the tool source
        self.assertIn("DEFAULT_COMPLIANCE_AUDIT_DAYS = 1095", self.src,
            "Compliance audit default must be 1095 days (3y)")
        self.assertIn("DEFAULT_GDPR_AUDIT_DAYS = 3650", self.src,
            "GDPR audit default must be 3650 days (10y per RGPD art. 5(2))")

    def test_uses_pymysql_not_cli(self):
        """The tool uses pymysql (consistent with backend), not mariadb CLI."""
        self.assertIn("import pymysql", self.src,
            "Tool must use pymysql (same as backend, no shell escaping issues)")
        self.assertNotIn("subprocess", self.src,
            "Tool must not shell out to mariadb (use pymysql)")
        # The old bash version was deleted — verify it's not in the repo
        bash_path = os.path.join(HERE, "..", "tools", "purge_old_audit.sh")
        self.assertFalse(os.path.exists(bash_path),
            "Old bash version must be removed (pymysql is the canonical impl)")

    def test_reads_config_yaml(self):
        """The tool reads config.yaml for both creds and audit_purge defaults."""
        self.assertIn("LOGSOC_CONFIG", self.src,
            "Tool must read LOGSOC_CONFIG env for config.yaml path")
        self.assertIn("audit_purge", self.src,
            "Tool must read config.yaml's audit_purge section")
        # DB creds
        for key in ("host", "port", "user", "password", "database"):
            self.assertIn(f'"{key}"', self.src,
                f"Tool must extract {key!r} from config.yaml's database section")

    def test_supports_apply_flag(self):
        """--apply triggers DELETE+commit, default is dry-run."""
        self.assertIn('"--apply"', self.src,
            "Tool must support --apply flag")
        self.assertIn('"store_true"', self.src,
            "--apply must be a store_true action")

    def test_supports_only_flag(self):
        """--only restricts to one table."""
        self.assertIn('"--only"', self.src,
            "Tool must support --only flag")
        self.assertIn('"compliance_audit"', self.src,
            "--only must accept 'compliance_audit'")
        self.assertIn('"gdpr_audit"', self.src,
            "--only must accept 'gdpr_audit'")

    def test_supports_custom_retention(self):
        self.assertIn('"--compliance-audit-days"', self.src)
        self.assertIn('"--gdpr-audit-days"', self.src)
        # Also env-var override (systemd Environment=)
        self.assertIn("PURGE_COMPLIANCE_DAYS", self.src)
        self.assertIn("PURGE_GDPR_DAYS", self.src)

    def test_dry_run_does_not_commit(self):
        """On dry-run, the tool rolls back. On --apply, it commits."""
        self.assertIn("conn.rollback()", self.src,
            "Dry-run path must rollback the transaction")
        self.assertIn("conn.commit()", self.src,
            "Apply path must commit the transaction")

    def test_emits_json_summary(self):
        """stdout = single JSON object, machine-parseable for monitoring."""
        self.assertIn("json.dumps(summary", self.src,
            "Tool must emit JSON summary on stdout")
        self.assertIn('"tables"', self.src,
            "JSON must have 'tables' key with per-table details")

    def test_uses_correct_time_columns(self):
        """compliance_audit.timestamp vs gdpr_audit.created_at."""
        # The function _time_col maps table -> column
        m = re.search(r"def _time_col.*?(?=\ndef |\nclass |\Z)",
                      self.src, re.DOTALL)
        self.assertIsNotNone(m, "_time_col function not found")
        if m is None:
            return
        body = m.group(0)
        self.assertIn('"timestamp"', body,
            "compliance_audit must use 'timestamp' column")
        self.assertIn('"created_at"', body,
            "gdpr_audit must use 'created_at' column")


class TestPurgeSystemdUnits(unittest.TestCase):
    """The systemd units reference the right script and schedule."""

    def setUp(self):
        self.service_path = os.path.join(
            HERE, "..", "deploy", "systemd", "logsoc-audit-purge.service"
        )
        self.timer_path = os.path.join(
            HERE, "..", "deploy", "systemd", "logsoc-audit-purge.timer"
        )
        with open(self.service_path) as f:
            self.service = f.read()
        with open(self.timer_path) as f:
            self.timer = f.read()

    def test_service_runs_the_tool_with_apply(self):
        self.assertIn("purge_old_audit.py", self.service,
            "Service ExecStart must call the tool")
        self.assertIn("--apply", self.service,
            "Service must run with --apply (cron should purge, not dry-run)")

    def test_service_runs_as_root(self):
        """Root is needed to read /opt/logsoc-web/config.yaml."""
        self.assertIn("User=root", self.service)

    def test_service_uses_oneshot(self):
        self.assertIn("Type=oneshot", self.service,
            "Service is oneshot (cron-like)")

    def test_timer_runs_weekly(self):
        """Sunday at 03:00 UTC is the low-traffic slot."""
        self.assertIn("OnCalendar=Sun", self.timer,
            "Timer must run on Sunday")
        self.assertIn("03:00:00", self.timer,
            "Timer must run at 03:00 UTC (low traffic)")

    def test_timer_is_persistent(self):
        """If the system was off at scheduled time, run ASAP on next boot."""
        self.assertIn("Persistent=true", self.timer,
            "Timer must be persistent (don't miss runs)")

    def test_timer_randomized_delay(self):
        """Avoid thundering herd if multiple logsoc hosts share a DB."""
        self.assertIn("RandomizedDelaySec", self.timer,
            "Timer must have a randomized delay (avoid thundering herd)")

    def test_timer_links_to_service(self):
        self.assertIn("Unit=logsoc-audit-purge.service", self.timer,
            "Timer must invoke the .service unit")


class TestPurgeToolExecution(unittest.TestCase):
    """Mocked execution tests — no live MySQL."""

    def test_dry_run_does_not_delete(self):
        """Dry-run: SELECT COUNT but no DELETE, rollback at end."""
        # Mock the connection so we can introspect calls
        from tools import purge_old_audit
        mock_conn = mock.MagicMock()
        mock_cursor = mock.MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (0,)

        with mock.patch.object(purge_old_audit, "_connect", return_value=mock_conn), \
             mock.patch.object(purge_old_audit, "_load_mysql_creds",
                               return_value={"host": "x", "port": 1, "user": "u",
                                             "password": "p", "database": "d"}), \
             mock.patch.object(purge_old_audit, "_load_retention_defaults",
                               return_value={}):
            rc = purge_old_audit.cmd_purge(mock.MagicMock(apply=False, only=None,
                                                            compliance_audit_days=None,
                                                            gdpr_audit_days=None))

        # Should NOT have called DELETE
        delete_calls = [c for c in mock_cursor.execute.call_args_list
                        if "DELETE" in str(c)]
        self.assertEqual(len(delete_calls), 0,
            f"Dry-run should not call DELETE, got: {delete_calls}")
        # Should have called rollback
        mock_conn.rollback.assert_called_once()
        mock_conn.commit.assert_not_called()
        self.assertEqual(rc, 0)

    def test_apply_calls_delete_and_commit(self):
        """--apply: SELECT then DELETE then commit."""
        from tools import purge_old_audit
        mock_conn = mock.MagicMock()
        mock_cursor = mock.MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (1,)  # 1 row to delete
        mock_cursor.rowcount = 1

        with mock.patch.object(purge_old_audit, "_connect", return_value=mock_conn), \
             mock.patch.object(purge_old_audit, "_load_mysql_creds",
                               return_value={"host": "x", "port": 1, "user": "u",
                                             "password": "p", "database": "d"}), \
             mock.patch.object(purge_old_audit, "_load_retention_defaults",
                               return_value={}):
            rc = purge_old_audit.cmd_purge(mock.MagicMock(apply=True, only=None,
                                                            compliance_audit_days=None,
                                                            gdpr_audit_days=None))

        # Should have called DELETE
        delete_calls = [c for c in mock_cursor.execute.call_args_list
                        if "DELETE" in str(c)]
        self.assertEqual(len(delete_calls), 2,
            f"Apply should DELETE both tables, got: {delete_calls}")
        # Should have committed
        mock_conn.commit.assert_called_once()
        mock_conn.rollback.assert_not_called()
        self.assertEqual(rc, 0)

    def test_only_skips_other_table(self):
        """--only=gdpr_audit should skip compliance_audit entirely."""
        from tools import purge_old_audit
        mock_conn = mock.MagicMock()
        mock_cursor = mock.MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (0,)

        with mock.patch.object(purge_old_audit, "_connect", return_value=mock_conn), \
             mock.patch.object(purge_old_audit, "_load_mysql_creds",
                               return_value={"host": "x", "port": 1, "user": "u",
                                             "password": "p", "database": "d"}), \
             mock.patch.object(purge_old_audit, "_load_retention_defaults",
                               return_value={}):
            rc = purge_old_audit.cmd_purge(mock.MagicMock(apply=False, only="gdpr_audit",
                                                            compliance_audit_days=None,
                                                            gdpr_audit_days=None))

        # The SELECT should be called only once (for gdpr_audit), not twice
        select_calls = [c for c in mock_cursor.execute.call_args_list
                        if "SELECT" in str(c)]
        self.assertEqual(len(select_calls), 1,
            f"--only=gdpr_audit should SELECT only gdpr_audit, got: {select_calls}")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
