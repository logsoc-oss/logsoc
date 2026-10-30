-- Modules RBAC audit + crisis : comblent le gap des sections Audit et Gestion de crise
-- ( invisibles pour tous les rôles car les clés nav n'étaient mappées sur aucun module )
-- Idempotent : rejouable.

-- Module audit (lecture) : le backend practices.py accepte déjà ces rôles en lecture
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export)
SELECT r.role, 'audit', 1, 0, 0, 0
FROM (SELECT 'rssi' AS role UNION SELECT 'dpo' UNION SELECT 'analyst' UNION SELECT 'viewer'
      UNION SELECT 'auditor' UNION SELECT 'compliance_officer' UNION SELECT 'soc_analyst'
      UNION SELECT 'admin' UNION SELECT 'superadmin') r
WHERE NOT EXISTS (
    SELECT 1 FROM role_permissions rp WHERE rp.role = r.role AND rp.module = 'audit'
);

-- Module crisis : section minRole rssi (gestion de crise = coeur du rôle RSSI)
INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export)
SELECT r.role, 'crisis', 1, 1, 0, 0
FROM (SELECT 'rssi' AS role UNION SELECT 'soc_analyst' UNION SELECT 'admin' UNION SELECT 'superadmin') r
WHERE NOT EXISTS (
    SELECT 1 FROM role_permissions rp WHERE rp.role = r.role AND rp.module = 'crisis'
);