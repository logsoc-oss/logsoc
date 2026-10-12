"""Unit tests for tools/retention_admin.py.

Tests the pure-logic helpers (no DB connection required).
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "tools"))


def _mock_session():
    """Build a mock sessionmaker + session context manager."""
    mock_session = mock.MagicMock()
    # The 'with SessionCls() as session' pattern enters the context
    # and gives us the session.
    mock_session_cls = mock.MagicMock()
    mock_session_cls.return_value.__enter__.return_value = mock_session
    mock_session_cls.return_value.__exit__.return_value = False
    return mock_session, mock_session_cls


class TestRetentionAdminSyncLogic(unittest.TestCase):

    def test_dry_run_inserts_missing_domains(self):
        from tools import retention_admin
        mock_session, mock_session_cls = _mock_session()
        mock_query = mock_session.query.return_value
        mock_query.all.return_value = []  # DB empty

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())), \
             mock.patch.object(retention_admin, "_load_defaults_from_config",
                               return_value={
                                   "siem_logs": {"hot_days": 90, "warm_days": 365,
                                                 "cold_days": 2555,
                                                 "anonymize_after_days": 180,
                                                 "erase_after_days": None},
                                   "access_logs": {"hot_days": 30, "warm_days": 90,
                                                   "cold_days": 365,
                                                   "anonymize_after_days": 60,
                                                   "erase_after_days": 365},
                               }):
            args = mock.MagicMock(apply=False, overwrite_notes=False, manual_prefix="MANUAL:")
            rc = retention_admin.cmd_sync_defaults(args)
            self.assertEqual(rc, 0)
            # In dry-run, no commit
            mock_session.commit.assert_not_called()
            mock_session.add.assert_not_called()

    def test_apply_inserts_new_domains(self):
        from tools import retention_admin
        mock_session, mock_session_cls = _mock_session()
        mock_query = mock_session.query.return_value
        mock_query.all.return_value = []

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())), \
             mock.patch.object(retention_admin, "_load_defaults_from_config",
                               return_value={
                                   "siem_logs": {"hot_days": 90, "warm_days": 365,
                                                 "cold_days": 2555,
                                                 "anonymize_after_days": 180,
                                                 "erase_after_days": None},
                               }):
            args = mock.MagicMock(apply=True, overwrite_notes=False, manual_prefix="MANUAL:")
            rc = retention_admin.cmd_sync_defaults(args)
            self.assertEqual(rc, 0)
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()

    def test_manual_prefix_skips_row(self):
        from tools import retention_admin
        existing_row = mock.MagicMock()
        existing_row.data_domain = "siem_logs"
        existing_row.notes = "MANUAL: tested manually on 2026-06-08"
        existing_row.hot_days = 60  # different from config
        existing_row.warm_days = 365
        existing_row.cold_days = 2555
        existing_row.anonymize_after_days = 180
        existing_row.erase_after_days = None

        mock_session, mock_session_cls = _mock_session()
        mock_query = mock_session.query.return_value
        mock_query.all.return_value = [existing_row]

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())), \
             mock.patch.object(retention_admin, "_load_defaults_from_config",
                               return_value={
                                   "siem_logs": {"hot_days": 90, "warm_days": 365,
                                                 "cold_days": 2555,
                                                 "anonymize_after_days": 180,
                                                 "erase_after_days": None},
                               }):
            args = mock.MagicMock(apply=True, overwrite_notes=False, manual_prefix="MANUAL:")
            rc = retention_admin.cmd_sync_defaults(args)
            self.assertEqual(rc, 0)
            # The manual row should NOT be touched
            self.assertEqual(existing_row.hot_days, 60)
            # No commit (no changes)
            mock_session.commit.assert_not_called()


class TestRetentionAdminSetLogic(unittest.TestCase):

    def test_invalid_field_rejected(self):
        from tools import retention_admin
        args = mock.MagicMock(domain="siem_logs", field="invalid_field",
                              value="100", yes=True)
        rc = retention_admin.cmd_set(args)
        self.assertEqual(rc, 2)

    def test_domain_not_found(self):
        from tools import retention_admin
        mock_session, mock_session_cls = _mock_session()
        mock_session.query.return_value.filter_by.return_value.first.return_value = None

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())):
            args = mock.MagicMock(domain="unknown", field="hot_days",
                                  value="100", yes=True)
            rc = retention_admin.cmd_set(args)
            self.assertEqual(rc, 1)

    def test_dry_run_no_commit(self):
        from tools import retention_admin
        row = mock.MagicMock()
        row.data_domain = "siem_logs"
        row.hot_days = 60
        row.notes = None
        mock_session, mock_session_cls = _mock_session()
        mock_session.query.return_value.filter_by.return_value.first.return_value = row

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())):
            args = mock.MagicMock(domain="siem_logs", field="hot_days",
                                  value="120", yes=False)
            rc = retention_admin.cmd_set(args)
            self.assertEqual(rc, 0)
            mock_session.commit.assert_not_called()
            # hot_days NOT changed
            self.assertEqual(row.hot_days, 60)

    def test_apply_with_manual_sentinel(self):
        from tools import retention_admin
        row = mock.MagicMock()
        row.data_domain = "siem_logs"
        row.hot_days = 60
        row.notes = ""
        mock_session, mock_session_cls = _mock_session()
        mock_session.query.return_value.filter_by.return_value.first.return_value = row

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())):
            args = mock.MagicMock(domain="siem_logs", field="hot_days",
                                  value="120", yes=True)
            rc = retention_admin.cmd_set(args)
            self.assertEqual(rc, 0)
            mock_session.commit.assert_called_once()
            self.assertEqual(row.hot_days, 120)
            self.assertTrue(row.notes.startswith("MANUAL:"))

    def test_erase_after_days_null(self):
        from tools import retention_admin
        row = mock.MagicMock()
        row.data_domain = "siem_logs"
        row.erase_after_days = 365
        row.notes = "MANUAL: existing"
        mock_session, mock_session_cls = _mock_session()
        mock_session.query.return_value.filter_by.return_value.first.return_value = row

        with mock.patch.object(retention_admin, "_session",
                               return_value=(mock_session_cls, mock.MagicMock())):
            args = mock.MagicMock(domain="siem_logs", field="erase_after_days",
                                  value="null", yes=True)
            rc = retention_admin.cmd_set(args)
            self.assertEqual(rc, 0)
            self.assertIsNone(row.erase_after_days)
            # notes already had MANUAL:, so unchanged
            self.assertEqual(row.notes, "MANUAL: existing")


if __name__ == "__main__":
    unittest.main()
