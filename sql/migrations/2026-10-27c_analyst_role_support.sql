-- Support complet du role analyst (existant cote frontend, absent de la DB)
-- 1. users.role enum : ajouter analyst
ALTER TABLE users MODIFY role ENUM('superadmin','admin','soc_analyst','analyst','auditor','dpo','rssi','compliance_officer','viewer') DEFAULT 'viewer';
-- 2. matrice RBAC analyst : modules investigation en lecture
INSERT IGNORE INTO role_permissions (role, module, can_read, can_write, can_delete, can_export) VALUES
('analyst','events',1,0,0,0),('analyst','alerts',1,0,0,0),('analyst','cases',1,0,0,0),
('analyst','assets',1,0,0,0),('analyst','correlation',1,0,0,0),('analyst','reporting',1,0,0,0),
('analyst','risks',1,0,0,0),('analyst','threat_intel',1,0,0,0);
