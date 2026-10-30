-- Migration 2026-09-13h: déclaration terrain pratique×asset (BP v2 Ops)
-- Le technicien/équipe déclare l'état d'une pratique sur un asset —
-- saisie rapide (1 par paire) sans éditer les exigences une à une.
CREATE TABLE IF NOT EXISTS practice_asset_status (
    id INT AUTO_INCREMENT PRIMARY KEY,
    practice_id INT NOT NULL,
    asset_id INT NOT NULL,
    status ENUM('conforme', 'non_conforme', 'non_applicable') NOT NULL DEFAULT 'conforme',
    updated_by VARCHAR(50) NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_practice_asset (practice_id, asset_id),
    INDEX idx_pas_asset (asset_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Aucun seed: les déclarations se font par l'équipe dans Opérations.