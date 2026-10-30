-- Migration 2026-09-13: business_role multi-casquettes + référentiel administrable
-- Design validé Fabrice: un user peut cumuler plusieurs casquettes métier
-- séparées par ' / ' (ex. 'dsi / rssi'). Les gardes matchent par intersection.
-- Ajout: table business_roles_ref (liste fermée administrable, soft-delete).

-- 1) Margelle pour les casquettes multiples (4-5 casquettes max)
ALTER TABLE users MODIFY COLUMN business_role VARCHAR(255) NULL;

-- 2) Référentiel des casquettes métier (liste fermée, administrable en UI admin)
CREATE TABLE IF NOT EXISTS business_roles_ref (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    label VARCHAR(128) NOT NULL,
    is_seeded TINYINT(1) NOT NULL DEFAULT 0,   -- 1 = code verrouillé (gardes en dur)
    active TINYINT(1) NOT NULL DEFAULT 1,      -- soft-delete
    sort_order INT NOT NULL DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3) Seed: 8 casquettes canoniques (codes VERROUILLÉS: utilisés en dur
--    par les gardes signature/validation et les verification_role livrables)
--    + 6 casquettes issues du select historique Users.tsx (administrables)
INSERT INTO business_roles_ref (code, label, is_seeded, sort_order) VALUES
    ('rssi',       'RSSI — Responsable Sécurité SI',    1, 10),
    ('dpo',        'DPO — Délégué Protection Données',  1, 20),
    ('dsi',        'DSI — Direction des Services SI',   1, 30),
    ('gerant',     'Gérant / DG',                       1, 40),
    ('president',  'Président',                         1, 50),
    ('compliance', 'Responsable conformité',            1, 60),
    ('juriste',    'Juriste',                            1, 70),
    ('auditeur',   'Auditeur',                           1, 80),
    ('responsable_metier', 'Responsable métier',        0, 90),
    ('expert',     'Expert sécurité',                    0, 100),
    ('risk_manager', 'Risk Manager',                    0, 110),
    ('moe',        'MOA / MOE',                          0, 120),
    ('membre',     'Membre',                             0, 130),
    ('rapporteur', 'Rapporteur',                         0, 140)
ON DUPLICATE KEY UPDATE label = VALUES(label);

-- 4) Migration des données existantes
--    pixies (id=9): dsi -> 'dsi / rssi' → débloque les 18 livrables RSSI
UPDATE users SET business_role = 'dsi / rssi'
WHERE id = 9 AND business_role = 'dsi';
-- admin (id=1): 'gerant' matche déjà toutes les gardes direction — inchangé.

-- 5) Normalisation défensive des valeurs existantes éventuelles en MAJUSCULES
UPDATE users SET business_role = LOWER(business_role)
WHERE business_role REGEXP BINARY '[A-Z]';