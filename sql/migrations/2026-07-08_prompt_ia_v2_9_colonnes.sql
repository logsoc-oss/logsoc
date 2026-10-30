-- Migration: Prompt IA v2 — 7 → 9 colonnes (Fréquence + Criticité générées par l'IA)
-- Date: 2026-07-08
-- Description: Ajout des colonnes Fréquence et Criticité dans le prompt IA, nouveaux ENUM actor/deliverable_type/control_frequency
-- Prérequis: Aucun (migration additive)

-- 1. Migration des données : RSSI_Equipe_Cyber → RSSI_Gouvernance (avant l'ALTER pour éviter "Data truncated")
-- L'ENUM actuel ne contient pas RSSI_Gouvernance, il faut donc d'abord l'ajouter
ALTER TABLE reference_requirements 
  MODIFY COLUMN actor ENUM('RSSI_Gouvernance','SecOps_CyberTech','Equipe_Infra_Ops','Directions_Metiers','RH_Juridique','Utilisateur_Final','RSSI_Equipe_Cyber') DEFAULT NULL;

-- 2. Migration des données
UPDATE reference_requirements SET actor = 'RSSI_Gouvernance' WHERE actor = 'RSSI_Equipe_Cyber';

-- 3. Retirer l'ancienne valeur de l'ENUM
ALTER TABLE reference_requirements 
  MODIFY COLUMN actor ENUM('RSSI_Gouvernance','SecOps_CyberTech','Equipe_Infra_Ops','Directions_Metiers','RH_Juridique','Utilisateur_Final') DEFAULT NULL;

-- 4. ALTER ENUM deliverable_type : 5 → 6 valeurs (+ Rapport_&_Audit)
ALTER TABLE reference_requirements 
  MODIFY COLUMN deliverable_type ENUM('Document_Cadre_PSSI','Charte_&_Contrat','Registre_&_Inventaire','Rapport_&_Audit','Configuration_Securite','Tache_Operationnelle') DEFAULT NULL;

-- 5. ALTER ENUM control_frequency : 6 → 8 valeurs (+ Ponctuel + Semestriel)
ALTER TABLE reference_requirements 
  MODIFY COLUMN control_frequency ENUM('Ponctuel','Continu','Hebdomadaire','Mensuel','Trimestriel','Semestriel','Annuel','À chaque changement','Au_changement') DEFAULT NULL;

-- criticality : inchangé (Mineure/Majeure/Critique — le prompt IA v2 génère maintenant directement ces valeurs)