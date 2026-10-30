-- Compliance Infra scoring snapshots (C2 RSSI V3, v0.11.2) - 2026-06-09
--
-- Une ligne par (section, computed_at) = un snapshot dans le temps.
-- Permet d'afficher l'évolution du score et de garder une trace d'audit
-- (qui a calculé quoi, quand, avec quels inputs).
--
-- Note : le score est aussi calculé en temps réel par GET /compliance-infra/section/{key}.
-- Cette table est l'historique. Pas d'index unique : plusieurs snapshots
-- par section sont autorisés (append-only log).

CREATE TABLE IF NOT EXISTS compliance_section_scores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    section VARCHAR(16) NOT NULL,                    -- pra, pca, pri, sc, fore, test
    coverage_pct DECIMAL(5,2) NOT NULL,              -- 0-100
    freshness_pct DECIMAL(5,2) NOT NULL,             -- 0-100
    risks_closed_pct DECIMAL(5,2) NOT NULL,          -- 0-100
    global_score DECIMAL(5,2) NOT NULL,              -- 0-100 (moyenne pondérée)
    procedure_count INT NOT NULL DEFAULT 0,
    subtheme_count INT NOT NULL DEFAULT 0,           -- nombre de sous-thèmes couverts
    subtheme_total INT NOT NULL DEFAULT 0,           -- nombre de sous-thèmes dans le référentiel
    risk_open INT NOT NULL DEFAULT 0,
    risk_total INT NOT NULL DEFAULT 0,
    computed_at DATETIME NOT NULL,
    computed_by INT NULL,                            -- user.id ou NULL (system)
    INDEX idx_section_computed (section, computed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
