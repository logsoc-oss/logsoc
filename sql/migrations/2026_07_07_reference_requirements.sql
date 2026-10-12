-- Migration: reference_requirements table
-- Stores parsed requirements from reference document AI analysis (7 columns)
-- Date: 2026-07-07

CREATE TABLE IF NOT EXISTS reference_requirements (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  document_id INT NOT NULL,
  page_number INT NOT NULL,
  ref_id VARCHAR(128),
  rule TEXT NOT NULL,
  target VARCHAR(255),
  control_type VARCHAR(128),
  grc_category ENUM('Gouvernance','Technique','Physique','Resilience','Audit'),
  deliverable_type ENUM('Document_Cadre_PSSI','Charte_&_Contrat','Tache_Operationnelle','Configuration_Securite','Registre_&_Inventaire'),
  actor ENUM('RSSI_Equipe_Cyber','RH_Juridique','Equipe_Infra_Ops','Utilisateur_Final'),
  control_frequency ENUM('Continu','Hebdomadaire','Mensuel','Trimestriel','Annuel','Au_changement') NULL,
  criticality ENUM('Mineure','Majeure','Critique') NULL,
  asset_tag VARCHAR(128) NULL,
  compliance_status ENUM('Non_traitee','En_cours','Conforme','Non_conforme','Non_applicable') DEFAULT 'Non_traitee',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_doc (document_id),
  KEY idx_grc (grc_category),
  KEY idx_deliverable (deliverable_type),
  KEY idx_actor (actor),
  KEY idx_status (compliance_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;