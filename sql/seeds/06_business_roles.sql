-- LogSOC seed: référentiel des casquettes métier business_roles_ref (14)
-- Utilisées par les gardes de domaine (DPO/RSSI) et le rôle répondant (membre). rssi_test exclu.
-- UPSERT chirurgical: référentiel pur.
-- Généré depuis la prod le 2026-10-10
SET NAMES utf8mb4;
/*M!999999\- enable the sandbox mode */ 
INSERT INTO `business_roles_ref` (`id`, `code`, `label`, `is_seeded`, `active`, `sort_order`, `created_at`) VALUES
(1,'rssi','RSSI — Responsable Sécurité SI',1,1,10,'2026-09-13 02:48:27'),
(2,'dpo','DPO — Délégué Protection Données',1,1,20,'2026-09-13 02:48:27'),
(3,'dsi','DSI — Direction des Services SI',1,1,30,'2026-09-13 02:48:27'),
(4,'gerant','Gérant / DG',1,1,40,'2026-09-13 02:48:27'),
(5,'president','Président',1,1,50,'2026-09-13 02:48:27'),
(6,'compliance','Responsable conformité',1,1,60,'2026-09-13 02:48:27'),
(7,'juriste','Juriste',1,1,70,'2026-09-13 02:48:27'),
(8,'auditeur','Auditeur',1,1,80,'2026-09-13 02:48:27'),
(9,'responsable_metier','Responsable métier',0,1,90,'2026-09-13 02:48:27'),
(10,'expert','Expert sécurité',0,1,100,'2026-09-13 02:48:27'),
(11,'risk_manager','Risk Manager',0,1,110,'2026-09-13 02:48:27'),
(12,'moe','MOA / MOE',0,1,120,'2026-09-13 02:48:27'),
(13,'membre','Membre',0,1,130,'2026-09-13 02:48:27'),
(14,'rapporteur','Rapporteur',0,1,140,'2026-09-13 02:48:27')
ON DUPLICATE KEY UPDATE `code` = VALUES(`code`), `label` = VALUES(`label`), `is_seeded` = VALUES(`is_seeded`), `active` = VALUES(`active`), `sort_order` = VALUES(`sort_order`), `created_at` = VALUES(`created_at`);
