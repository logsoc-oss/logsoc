-- Module RBAC dpo : la section Protection des Données doit être réservée au DPO
-- ( aligné sur le backend : dpo_registries.py EDIT_ROLES = admin/superadmin/dpo )
-- Fixe aussi l'incohérence : les items DPO étaient mappés sur le module governance
-- partagé, donc visibles par le RSSI (403 backend) et les registres cachés au DPO lui-même.
-- Idempotent : rejouable.

INSERT INTO role_permissions (role, module, can_read, can_write, can_delete, can_export)
SELECT r.role, 'dpo', 1, 1, 1, 1
FROM (SELECT 'dpo' AS role UNION SELECT 'admin' UNION SELECT 'superadmin') r
WHERE NOT EXISTS (
    SELECT 1 FROM role_permissions rp WHERE rp.role = r.role AND rp.module = 'dpo'
);