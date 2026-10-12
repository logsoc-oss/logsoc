-- T97: Frameworks modulaires — NIST CSF 2.0, CIS v8, ANSSI 42, PCI-DSS v4, SOC 2, EBIOS RM
-- 2026-06-18

CREATE TABLE IF NOT EXISTS framework_assessments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    framework VARCHAR(50) NOT NULL,
    control_id VARCHAR(20) NOT NULL,
    -- Assessment
    status ENUM('not_started','in_progress','implemented','verified','gap') NOT NULL DEFAULT 'not_started',
    maturity_level TINYINT DEFAULT 0,
    -- Evidence
    evidence_description TEXT,
    gap_description TEXT,
    remediation_plan TEXT,
    remediation_due_date DATE NULL,
    -- IG for CIS (IG1/IG2/IG3), Tier for NIST CSF (1-4), Type for SOC 2 (I/II)
    target_level VARCHAR(20) DEFAULT '',
    current_level VARCHAR(20) DEFAULT '',
    -- Review
    last_reviewed_at DATETIME NULL,
    next_review_due DATE NULL,
    updated_by INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_fw_ctrl (framework, control_id),
    INDEX idx_framework (framework),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed NIST CSF 2.0 (6 functions)
INSERT INTO framework_assessments (framework, control_id, status, target_level, current_level) VALUES
('nist_csf', 'GV', 'not_started', 'Tier 3', 'Tier 1'),
('nist_csf', 'ID', 'not_started', 'Tier 3', 'Tier 1'),
('nist_csf', 'PR', 'not_started', 'Tier 3', 'Tier 1'),
('nist_csf', 'DE', 'not_started', 'Tier 3', 'Tier 1'),
('nist_csf', 'RS', 'not_started', 'Tier 3', 'Tier 1'),
('nist_csf', 'RC', 'not_started', 'Tier 3', 'Tier 1')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed CIS v8 (18 controls, IG1 baseline)
INSERT INTO framework_assessments (framework, control_id, status, target_level, current_level) VALUES
('cis', 'C1', 'not_started', 'IG1', ''), ('cis', 'C2', 'not_started', 'IG1', ''),
('cis', 'C3', 'not_started', 'IG1', ''), ('cis', 'C4', 'not_started', 'IG1', ''),
('cis', 'C5', 'not_started', 'IG1', ''), ('cis', 'C6', 'not_started', 'IG1', ''),
('cis', 'C7', 'not_started', 'IG1', ''), ('cis', 'C8', 'not_started', 'IG1', ''),
('cis', 'C9', 'not_started', 'IG1', ''), ('cis', 'C10', 'not_started', 'IG1', ''),
('cis', 'C11', 'not_started', 'IG1', ''), ('cis', 'C12', 'not_started', 'IG2', ''),
('cis', 'C13', 'not_started', 'IG2', ''), ('cis', 'C14', 'not_started', 'IG2', ''),
('cis', 'C15', 'not_started', 'IG2', ''), ('cis', 'C16', 'not_started', 'IG2', ''),
('cis', 'C17', 'not_started', 'IG2', ''), ('cis', 'C18', 'not_started', 'IG3', '')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed ANSSI 42 measures (4 families)
INSERT INTO framework_assessments (framework, control_id, status) VALUES
('anssi', 'M1-15', 'not_started'), ('anssi', 'M16-25', 'not_started'),
('anssi', 'M26-35', 'not_started'), ('anssi', 'M36-42', 'not_started')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed PCI-DSS v4 (12 requirements)
INSERT INTO framework_assessments (framework, control_id, status) VALUES
('pci_dss', 'R1', 'not_started'), ('pci_dss', 'R2', 'not_started'),
('pci_dss', 'R3', 'not_started'), ('pci_dss', 'R4', 'not_started'),
('pci_dss', 'R5', 'not_started'), ('pci_dss', 'R6', 'not_started'),
('pci_dss', 'R7', 'not_started'), ('pci_dss', 'R8', 'not_started'),
('pci_dss', 'R9', 'not_started'), ('pci_dss', 'R10', 'not_started'),
('pci_dss', 'R11', 'not_started'), ('pci_dss', 'R12', 'not_started')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed SOC 2 (5 criteria)
INSERT INTO framework_assessments (framework, control_id, status, target_level) VALUES
('soc2', 'Security', 'not_started', 'Type II'),
('soc2', 'Availability', 'not_started', 'Type II'),
('soc2', 'Processing', 'not_started', 'Type II'),
('soc2', 'Confidentiality', 'not_started', 'Type II'),
('soc2', 'Privacy', 'not_started', 'Type II')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;

-- Seed EBIOS RM (5 phases)
INSERT INTO framework_assessments (framework, control_id, status) VALUES
('ebios', 'P1', 'not_started'), ('ebios', 'P2', 'not_started'),
('ebios', 'P3', 'not_started'), ('ebios', 'P4', 'not_started'),
('ebios', 'P5', 'not_started')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;