-- T95: Cross-framework mapping — NIS2 ↔ DORA ↔ RGPD ↔ AI Act ↔ ISO 27001 ↔ NIST CSF ↔ CIS ↔ ANSSI ↔ PCI-DSS ↔ SOC 2 ↔ EBIOS
-- 2026-06-18

CREATE TABLE IF NOT EXISTS framework_controls (
    id INT AUTO_INCREMENT PRIMARY KEY,
    framework VARCHAR(50) NOT NULL,
    control_id VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) DEFAULT '',
    -- Mapping to ISO 27001 (as pivot framework)
    iso27001_ref VARCHAR(20) DEFAULT '',
    -- Mapping to NIS2
    nis2_ref VARCHAR(20) DEFAULT '',
    -- Mapping to NIST CSF
    nist_csf_ref VARCHAR(20) DEFAULT '',
    -- Display
    display_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_fw_ctrl (framework, control_id),
    INDEX idx_framework (framework),
    INDEX idx_iso (iso27001_ref),
    INDEX idx_nis2 (nis2_ref),
    INDEX idx_nist (nist_csf_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS framework_mapping (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_framework VARCHAR(50) NOT NULL,
    source_control_id VARCHAR(20) NOT NULL,
    target_framework VARCHAR(50) NOT NULL,
    target_control_id VARCHAR(20) NOT NULL,
    -- Match quality
    match_quality ENUM('exact','partial','related') NOT NULL DEFAULT 'related',
    -- Notes
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_mapping (source_framework, source_control_id, target_framework, target_control_id),
    INDEX idx_source (source_framework, source_control_id),
    INDEX idx_target (target_framework, target_control_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed framework controls (key controls from each framework, mapped to ISO 27001 as pivot)
-- NIS2 10 measures (Art. 21)
INSERT INTO framework_controls (framework, control_id, title, description, category, iso27001_ref, nis2_ref, nist_csf_ref, display_order) VALUES
('nis2', 'a', 'Politiques d''analyse des risques', 'Art. 21 §2a — Politiques de sécurité SI', 'governance', 'A.5.1', 'a', 'ID.RA', 1),
('nis2', 'b', 'Gestion des incidents', 'Art. 21 §2b — Gestion des incidents', 'incident', 'A.5.24', 'b', 'RS', 2),
('nis2', 'c', 'Continuité des activités', 'Art. 21 §2c — Continuité et gestion des crises', 'continuity', 'A.5.29', 'c', 'RC', 3),
('nis2', 'd', 'Chaîne d''approvisionnement', 'Art. 21 §2d — Sécurité chaîne d''approvisionnement', 'supplier', 'A.5.19', 'd', 'ID.SC', 4),
('nis2', 'e', 'Acquisition et développement', 'Art. 21 §2e — Sécurité acquisition/dev/maintenance', 'development', 'A.8.25', 'e', 'PR.IP', 5),
('nis2', 'f', 'Évaluation efficacité', 'Art. 21 §2f — Évaluation des mesures', 'assessment', 'Clause 9', 'f', 'DE', 6),
('nis2', 'g', 'Cyberhygiène et formation', 'Art. 21 §2g — Cyberhygiène et formation', 'training', 'A.6.3', 'g', 'PR.AT', 7),
('nis2', 'h', 'Cryptographie', 'Art. 21 §2h — Cryptographie et chiffrement', 'crypto', 'A.8.24', 'h', 'PR.DS', 8),
('nis2', 'i', 'RH, accès, actifs', 'Art. 21 §2i — Sécurité RH, contrôle d''accès, actifs', 'access', 'A.5.15', 'i', 'PR.AC', 9),
('nis2', 'j', 'MFA et communications', 'Art. 21 §2j — MFA et communications sécurisées', 'auth', 'A.5.17', 'j', 'PR.AC', 10),
-- DORA 5 pillars
('dora', 'p1', 'Gestion des risques TIC', 'Pilier 1 — Cadre de gestion des risques TIC', 'risk', 'A.5.1', 'a', 'ID.RA', 1),
('dora', 'p2', 'Notification d''incidents', 'Pilier 2 — Notification incidents majeurs 4h/72h/1 mois', 'incident', 'A.5.24', 'b', 'RS', 2),
('dora', 'p3', 'Tests de résilience', 'Pilier 3 — Tests de résilience et TLPT', 'testing', 'A.5.35', 'f', 'DE', 3),
('dora', 'p4', 'Gestion tiers TIC', 'Pilier 4 — Gestion des risques tiers TIC', 'supplier', 'A.5.19', 'd', 'ID.SC', 4),
('dora', 'p5', 'Partage d''informations', 'Pilier 5 — Partage cybermenaces', 'ti', 'A.5.7', 'b', 'DE.CM', 5),
-- RGPD key articles
('rgpd', 'art30', 'Registre des traitements', 'Art. 30 — Registre des activités de traitement', 'governance', 'A.5.31', 'a', 'ID', 1),
('rgpd', 'art33', 'Notification violation CNIL', 'Art. 33 — Notification 72h CNIL', 'incident', 'A.5.24', 'b', 'RS', 2),
('rgpd', 'art34', 'Notification personnes', 'Art. 34 — Information des personnes (risque élevé)', 'incident', 'A.5.24', 'b', 'RS', 3),
('rgpd', 'art35', 'DPIA', 'Art. 35 — Analyse d''impact (AIPD)', 'assessment', 'Clause 6.1', 'f', 'ID.RA', 4),
('rgpd', 'art28', 'Sous-traitants', 'Art. 28 — Sous-traitants (DPA)', 'supplier', 'A.5.19', 'd', 'ID.SC', 5),
('rgpd', 'art32', 'Sécurité du traitement', 'Art. 32 — Sécurité du traitement', 'security', 'A.8.24', 'h', 'PR.DS', 6),
-- AI Act key articles
('ai_act', 'art5', 'Pratiques interdites', 'Art. 5 — Pratiques interdites (risque inacceptable)', 'governance', 'A.5.1', 'a', 'GV', 1),
('ai_act', 'art9', 'Gestion des risques', 'Art. 9 — Système de gestion des risques IA', 'risk', 'Clause 6.1', 'a', 'ID.RA', 2),
('ai_act', 'art14', 'Supervision humaine', 'Art. 14 — Supervision humaine', 'governance', 'A.5.2', 'a', 'PR', 3),
('ai_act', 'art15', 'Précision et cybersécurité', 'Art. 15 — Précision, robustesse, cybersécurité', 'security', 'A.8.8', 'e', 'PR.IP', 4),
('ai_act', 'art26', 'Obligations déployeur', 'Art. 26 — Obligations du déployeur', 'governance', 'A.5.1', 'a', 'GV', 5),
('ai_act', 'art50', 'Transparence', 'Art. 50 — Exigences de transparence', 'governance', 'A.5.1', 'a', 'GV', 6),
-- NIST CSF 2.0 (6 functions)
('nist_csf', 'GV', 'Govern', 'Fonction Govern — Gouvernance', 'governance', 'Clause 5', 'a', 'GV', 1),
('nist_csf', 'ID', 'Identify', 'Fonction Identify — Actifs, risques', 'risk', 'Clause 6.1', 'a', 'ID', 2),
('nist_csf', 'PR', 'Protect', 'Fonction Protect — Contrôles d''accès, données', 'security', 'A.5.15', 'i', 'PR', 3),
('nist_csf', 'DE', 'Detect', 'Fonction Detect — Surveillance, détection', 'monitoring', 'A.8.16', 'f', 'DE', 4),
('nist_csf', 'RS', 'Respond', 'Fonction Respond — Réponse aux incidents', 'incident', 'A.5.24', 'b', 'RS', 5),
('nist_csf', 'RC', 'Recover', 'Fonction Recover — Continuité, restauration', 'continuity', 'A.5.29', 'c', 'RC', 6),
-- CIS Controls v8 (18 controls, key ones)
('cis', 'C1', 'Inventaire des actifs', 'CIS 1 — Identifier et gérer les actifs', 'assets', 'A.5.9', 'i', 'ID', 1),
('cis', 'C5', 'Gestion des comptes', 'CIS 5 — Inventaire des comptes', 'access', 'A.5.16', 'i', 'PR.AC', 5),
('cis', 'C7', 'Vulnérabilités', 'CIS 7 — Évaluation continue des vulnérabilités', 'vuln', 'A.8.8', 'e', 'ID.RA', 7),
('cis', 'C8', 'Logs', 'CIS 8 — Gestion des logs', 'logging', 'A.8.15', 'f', 'DE.CM', 8),
('cis', 'C10', 'Malware', 'CIS 10 — Protection contre les maliciels', 'malware', 'A.8.7', 'e', 'PR.IP', 10),
('cis', 'C11', 'Sauvegardes', 'CIS 11 — Récupération des données', 'backup', 'A.8.13', 'c', 'RC', 11),
('cis', 'C16', 'Response plan', 'CIS 16 — Plan de réponse aux incidents', 'incident', 'A.5.24', 'b', 'RS', 16),
-- ANSSI 42 measures (4 families, key ones)
('anssi', 'M1-15', 'Protection', 'ANSSI mesures 1-15 — MFA, mots de passe, segmentation', 'security', 'A.8.5', 'j', 'PR', 1),
('anssi', 'M16-25', 'Détection', 'ANSSI mesures 16-25 — Logs, SIEM, supervision', 'monitoring', 'A.8.16', 'f', 'DE', 2),
('anssi', 'M26-35', 'Réaction', 'ANSSI mesures 26-35 — Gestion d''incidents, forensics', 'incident', 'A.5.24', 'b', 'RS', 3),
('anssi', 'M36-42', 'Gouvernance', 'ANSSI mesures 36-42 — Politique, organisation, formation', 'governance', 'A.5.1', 'a', 'GV', 4),
-- PCI-DSS v4 (12 requirements)
('pci_dss', 'R1', 'Pare-feu', 'PCI 1 — Protection des réseaux', 'network', 'A.8.20', 'e', 'PR.AC', 1),
('pci_dss', 'R3', 'Protection données stockées', 'PCI 3 — Chiffrement des données', 'crypto', 'A.8.24', 'h', 'PR.DS', 3),
('pci_dss', 'R8', 'Authentification', 'PCI 8 — MFA et gestion identités', 'auth', 'A.5.17', 'j', 'PR.AC', 8),
('pci_dss', 'R10', 'Journalisation', 'PCI 10 — Logs et monitoring', 'logging', 'A.8.15', 'f', 'DE.CM', 10),
('pci_dss', 'R11', 'Tests réguliers', 'PCI 11 — Scans et pen tests', 'testing', 'A.5.35', 'f', 'DE', 11),
('pci_dss', 'R12', 'Politique de sécurité', 'PCI 12 — Gouvernance et formation', 'governance', 'A.5.1', 'a', 'GV', 12),
-- SOC 2 (5 criteria)
('soc2', 'Security', 'Security', 'SOC 2 — Sécurité (protection accès non autorisé)', 'security', 'A.5.15', 'i', 'PR', 1),
('soc2', 'Availability', 'Availability', 'SOC 2 — Disponibilité', 'continuity', 'A.5.29', 'c', 'RC', 2),
('soc2', 'Processing', 'Processing Integrity', 'SOC 2 — Intégrité du traitement', 'integrity', 'A.8.9', 'e', 'PR.IP', 3),
('soc2', 'Confidentiality', 'Confidentiality', 'SOC 2 — Confidentialité', 'crypto', 'A.8.24', 'h', 'PR.DS', 4),
('soc2', 'Privacy', 'Privacy', 'SOC 2 — Confidentialité des données personnelles', 'privacy', 'A.5.34', 'i', 'PR', 5),
-- EBIOS RM (5 phases)
('ebios', 'P1', 'Cadrage', 'EBIOS Phase 1 — Cadrage du périmètre', 'governance', 'Clause 4', 'a', 'GV', 1),
('ebios', 'P2', 'Scénarios', 'EBIOS Phase 2 — Scénarios de risques', 'risk', 'Clause 6.1', 'a', 'ID.RA', 2),
('ebios', 'P3', 'Analyse', 'EBIOS Phase 3 — Analyse des risques', 'risk', 'Clause 6.1', 'a', 'ID.RA', 3),
('ebios', 'P4', 'Traitement', 'EBIOS Phase 4 — Traitement du risque', 'treatment', 'Clause 8', 'a', 'PR', 4),
('ebios', 'P5', 'Validation', 'EBIOS Phase 5 — Validation et indicateurs', 'assessment', 'Clause 9', 'f', 'DE', 5)
ON DUPLICATE KEY UPDATE title = VALUES(title), description = VALUES(description);

-- Seed cross-mappings (source → target via ISO 27001 pivot)
INSERT INTO framework_mapping (source_framework, source_control_id, target_framework, target_control_id, match_quality) VALUES
-- NIS2 ↔ ISO 27001
('nis2', 'a', 'iso27001', 'A.5.1', 'exact'), ('nis2', 'b', 'iso27001', 'A.5.24', 'exact'),
('nis2', 'c', 'iso27001', 'A.5.29', 'exact'), ('nis2', 'd', 'iso27001', 'A.5.19', 'exact'),
('nis2', 'e', 'iso27001', 'A.8.25', 'exact'), ('nis2', 'f', 'iso27001', 'Clause 9', 'partial'),
('nis2', 'g', 'iso27001', 'A.6.3', 'exact'), ('nis2', 'h', 'iso27001', 'A.8.24', 'exact'),
('nis2', 'i', 'iso27001', 'A.5.15', 'exact'), ('nis2', 'j', 'iso27001', 'A.5.17', 'exact'),
-- NIS2 ↔ NIST CSF
('nis2', 'a', 'nist_csf', 'ID', 'partial'), ('nis2', 'b', 'nist_csf', 'RS', 'exact'),
('nis2', 'c', 'nist_csf', 'RC', 'exact'), ('nis2', 'd', 'nist_csf', 'ID', 'partial'),
('nis2', 'g', 'nist_csf', 'PR', 'partial'), ('nis2', 'h', 'nist_csf', 'PR', 'partial'),
-- DORA ↔ ISO 27001
('dora', 'p1', 'iso27001', 'A.5.1', 'exact'), ('dora', 'p2', 'iso27001', 'A.5.24', 'exact'),
('dora', 'p3', 'iso27001', 'A.5.35', 'exact'), ('dora', 'p4', 'iso27001', 'A.5.19', 'exact'),
-- RGPD ↔ ISO 27001
('rgpd', 'art30', 'iso27001', 'A.5.31', 'exact'), ('rgpd', 'art33', 'iso27001', 'A.5.24', 'exact'),
('rgpd', 'art35', 'iso27001', 'Clause 6.1', 'partial'), ('rgpd', 'art28', 'iso27001', 'A.5.19', 'exact'),
('rgpd', 'art32', 'iso27001', 'A.8.24', 'exact'),
-- AI Act ↔ ISO 27001
('ai_act', 'art5', 'iso27001', 'A.5.1', 'partial'), ('ai_act', 'art9', 'iso27001', 'Clause 6.1', 'partial'),
('ai_act', 'art14', 'iso27001', 'A.5.2', 'partial'), ('ai_act', 'art15', 'iso27001', 'A.8.8', 'exact'),
-- NIS2 ↔ DORA
('nis2', 'b', 'dora', 'p2', 'exact'), ('nis2', 'd', 'dora', 'p4', 'exact'),
('nis2', 'a', 'dora', 'p1', 'partial'), ('nis2', 'f', 'dora', 'p3', 'partial'),
-- NIS2 ↔ RGPD
('nis2', 'b', 'rgpd', 'art33', 'partial'), ('nis2', 'i', 'rgpd', 'art32', 'partial'),
-- NIS2 ↔ CIS
('nis2', 'i', 'cis', 'C1', 'partial'), ('nis2', 'b', 'cis', 'C16', 'exact'),
('nis2', 'h', 'cis', 'C8', 'partial'),
-- ISO 27001 ↔ NIST CSF
('iso27001', 'A.5.1', 'nist_csf', 'GV', 'exact'), ('iso27001', 'A.5.24', 'nist_csf', 'RS', 'exact'),
('iso27001', 'A.5.29', 'nist_csf', 'RC', 'exact'), ('iso27001', 'A.8.24', 'nist_csf', 'PR', 'partial'),
('iso27001', 'A.8.16', 'nist_csf', 'DE', 'exact'),
-- ISO 27001 ↔ CIS
('iso27001', 'A.5.9', 'cis', 'C1', 'exact'), ('iso27001', 'A.8.15', 'cis', 'C8', 'exact'),
('iso27001', 'A.8.7', 'cis', 'C10', 'exact'), ('iso27001', 'A.8.13', 'cis', 'C11', 'exact'),
-- ISO 27001 ↔ PCI-DSS
('iso27001', 'A.8.20', 'pci_dss', 'R1', 'exact'), ('iso27001', 'A.8.24', 'pci_dss', 'R3', 'exact'),
('iso27001', 'A.5.17', 'pci_dss', 'R8', 'exact'), ('iso27001', 'A.8.15', 'pci_dss', 'R10', 'exact'),
-- ISO 27001 ↔ SOC 2
('iso27001', 'A.5.15', 'soc2', 'Security', 'exact'), ('iso27001', 'A.5.29', 'soc2', 'Availability', 'exact'),
('iso27001', 'A.8.24', 'soc2', 'Confidentiality', 'exact'), ('iso27001', 'A.5.34', 'soc2', 'Privacy', 'exact'),
-- ISO 27001 ↔ ANSSI
('iso27001', 'A.8.5', 'anssi', 'M1-15', 'partial'), ('iso27001', 'A.8.16', 'anssi', 'M16-25', 'exact'),
('iso27001', 'A.5.24', 'anssi', 'M26-35', 'exact'), ('iso27001', 'A.5.1', 'anssi', 'M36-42', 'exact'),
-- ISO 27001 ↔ EBIOS
('iso27001', 'Clause 4', 'ebios', 'P1', 'exact'), ('iso27001', 'Clause 6.1', 'ebios', 'P2', 'exact'),
('iso27001', 'Clause 6.1', 'ebios', 'P3', 'exact'), ('iso27001', 'Clause 8', 'ebios', 'P4', 'exact'),
('iso27001', 'Clause 9', 'ebios', 'P5', 'exact')
ON DUPLICATE KEY UPDATE match_quality = VALUES(match_quality);