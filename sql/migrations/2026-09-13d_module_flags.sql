-- Migration 2026-09-13d: activation/désactivation des modules (option B)
-- Pas de ligne = module ACTIVÉ. is_active=0 = désactivé pour tous (503)
-- sauf superadmin + menu masqué. Administrable page Rôles & Accès.
CREATE TABLE IF NOT EXISTS module_flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    module VARCHAR(64) NOT NULL UNIQUE,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Aucun seed: tout est activé par défaut.