-- Compliance officer role (v0.9.0) - Issue #3 logsoc-web
-- 2026-06-08
--
-- Adds the `compliance_officer` role to the User.role ENUM.
-- Decision Fabrice 2026-06-08: new role with full read/write on compliance
-- tables, read on assets, separate from admin (no full system access).
--
-- Role matrix (validated by Fabrice in issue #3):
--   admin               : full system access (legacy)
--   superadmin          : full system access + user mgmt (legacy)
--   analyst             : read on assets + compliance (legacy)
--   viewer              : no access to compliance (legacy)
--   compliance_officer  : NEW - read/write on compliance tables,
--                                  read on assets, no system access
--
-- The application layer (app/routers/auth.py, schemas, deps) must
-- enforce the matrix. This migration only updates the database enum.

-- 1) Modify the User.role ENUM to add compliance_officer
-- MariaDB / MySQL ENUMs can be extended without rewriting the table.
-- We use ALTER TABLE ... MODIFY COLUMN which is the safe operation
-- for ENUM extension (no data rewrite in modern MariaDB 10.0+).

ALTER TABLE users MODIFY COLUMN role
    ENUM('superadmin','admin','analyst','viewer','compliance_officer')
    NOT NULL DEFAULT 'viewer';

-- 2) Rollback (for reference, not executed)
-- ALTER TABLE users MODIFY COLUMN role
--     ENUM('superadmin','admin','analyst','viewer')
--     NOT NULL DEFAULT 'viewer';
