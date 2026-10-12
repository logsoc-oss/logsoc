-- Migration: CMDB + Referentiel fixes (2026-07-10)
-- Description: Colonnes et ENUMs ajoutes pendant la session CMDB/GRC

-- 1. app_version pour les applications
ALTER TABLE assets_cmdb ADD COLUMN IF NOT EXISTS app_version VARCHAR(64) DEFAULT NULL;

-- 2. ip_address etendu pour IPv6
ALTER TABLE assets_cmdb MODIFY COLUMN ip_address VARCHAR(255) DEFAULT NULL;

-- 3. status ENUM + inactive
ALTER TABLE assets_cmdb MODIFY COLUMN status ENUM('active','inactive','archived') DEFAULT 'active';

-- 4. asset_type ENUM etendu (37 types hardware + software + legacy)
ALTER TABLE assets_cmdb MODIFY COLUMN asset_type ENUM(
  'server','server_bare','server_vm','vm','container',
  'network_device','network_switch','network_router','firewall','firewall_cluster',
  'load_balancer','storage_nas','storage_san','wifi_ap',
  'workstation','laptop','tablet','phone_ip','printer','camera',
  'application','app_business','app_web','database','saas',
  'middleware','monitoring','siem','security_suite','backup',
  'identity','collaboration','dev_platform','hypervisor',
  'endpoint','other_hardware','other_software'
) NOT NULL;

-- 5. control_frequency ENUM + "A chaque changement"
ALTER TABLE reference_requirements
  MODIFY COLUMN control_frequency ENUM(
    'Ponctuel','Continu','Hebdomadaire','Mensuel','Trimestriel',
    'Semestriel','Annuel','A chaque changement','Au_changement'
  ) DEFAULT NULL;

-- 6. organism + country sur policy_documents
ALTER TABLE policy_documents
  ADD COLUMN IF NOT EXISTS organism VARCHAR(128) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS country ENUM(
    'FR','DE','UK','ES','IT','BE','NL','LU','PT','IE',
    'DK','SE','NO','FI','PL','AT','CH','CZ','RO','BG',
    'HR','EE','LV','LT','SI','SK','HU','EL','CY','MT'
  ) DEFAULT NULL;

-- 7. Update documents existants avec ANSSI/FR
UPDATE policy_documents SET organism='ANSSI', country='FR' WHERE organism IS NULL;

-- 8. proof_url + waiver sur asset_requirement_links (deja dans 2026-07-09_grc_bridge_phase2.sql)
-- Inclu ici pour compatibilite
ALTER TABLE asset_requirement_links
  ADD COLUMN IF NOT EXISTS proof_url VARCHAR(512) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS waiver_reason TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS waiver_expires_at DATE DEFAULT NULL;