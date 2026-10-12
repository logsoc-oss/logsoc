-- Runbook wiki (C2 Compliance Infra) - 2026-06-09
-- Markdown-based procedures, versioned, with section grouping
-- The 6 sections mirror ComplianceInfra.tsx (pra, pca, pri, sc, fore, test)

CREATE TABLE IF NOT EXISTS runbook_procedures (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    section ENUM('pra','pca','pri','sc','fore','test','general') NOT NULL,
    slug VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    markdown LONGTEXT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    owner_email VARCHAR(255),
    last_reviewed_at DATE,
    next_review_at DATE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by INT,
    UNIQUE KEY uq_runbook_section_slug (section, slug),
    INDEX idx_runbook_section (section),
    INDEX idx_runbook_next_review (next_review_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Runbook review log (append-only audit)
CREATE TABLE IF NOT EXISTS runbook_reviews (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    procedure_id BIGINT NOT NULL,
    reviewed_by INT,
    review_note TEXT,
    reviewed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reviews_procedure (procedure_id),
    CONSTRAINT fk_reviews_procedure FOREIGN KEY (procedure_id) REFERENCES runbook_procedures(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed demo procedures
INSERT IGNORE INTO runbook_procedures (section, slug, title, markdown, version, owner_email, last_reviewed_at, next_review_at) VALUES
('pra', 'backup-restore-postgres',
 'Sauvegarde et restauration PostgreSQL/MariaDB',
 '## Objectif\nRTO: 4h, RPO: 15min.\n\n## Procédure\n1. Vérifier que les backups MariaDB sont à jour (`/opt/backups/mariadb/`)\n2. Stopper les containers `logsoc-api` et `logsoc-retention`\n3. Restaurer le dump le plus récent\n4. Vérifier la cohérence : `SELECT COUNT(*) FROM users`\n5. Redémarrer les containers\n\n## Tests\n- Dernier test PRA: 2026-03-15 ✅\n- Prochain test: 2026-09-15',
 1, 'infra@anytimeadmin.info', '2026-03-15', '2026-09-15'),

('pca', 'mode-degrade-readonly',
 'Mode dégradé lecture seule',
 '## Déclenchement\nSi le backend FastAPI est down > 15min, basculer en mode read-only via nginx :\n- Rediriger /api/v1/* vers un cache statique des derniers events\n- Garder /login opérationnel\n\n## Rollback\n- Désactiver le mode read-only dans nginx\n- Vérifier que les events sont rejoués depuis le WAL\n\n## Communication\n- Slack #incident: template `MODE_DEGRADE_ACTIVATED`',
 1, 'infra@anytimeadmin.info', '2026-01-20', '2026-07-20'),

('fore', 'acquisition-image-disque',
 'Acquisition d''une image disque (forensique)',
 '## Pré-requis\n- Stockage externe chiffré LUKS\n- `dd` + `sha256sum` + horodatage\n- Chaîne de preuve documentée (template `CHAIN_OF_CUSTODY.md`)\n\n## Procédure\n1. Documenter : hostname, serial, date UTC, opérateur\n2. Calculer le hash de l''image source : `sha256sum /dev/sda > source.sha256`\n3. Cloner : `dd if=/dev/sda of=/mnt/luks/IMAGE.dd bs=4M status=progress`\n4. Vérifier : `sha256sum IMAGE.dd` doit matcher\n5. Signer le manifest (PGP)\n6. Stocker dans /opt/forensics/YYYY-MM-DD/\n\n## E-discovery\n- Indexer avec `ewfexport` puis `libewf-tools`',
 1, 'rssi@anytimeadmin.info', '2026-04-10', '2026-10-10'),

('sc', 'sbom-scan',
 'SBOM + scan vulnérabilités (supply chain)',
 '## Outils\n- `syft` pour générer le SBOM CycloneDX\n- `grype` pour le scan CVE\n\n## Commande\n```\ncd /opt/logsoc-agent\nsyft . -o cyclonedx-json > sbom.json\ngrype sbom:./sbom.json --fail-on high\n```\n\n## Fréquence\n- À chaque release\n- Scan hebdomadaire en CI\n\n## Tier-2\n- Demander le SBOM des fournisseurs via `security@anytimeadmin.info`',
 1, 'rssi@anytimeadmin.info', '2026-05-01', '2026-11-01'),

('test', 'tabletop-ransomware',
 'Exercice tabletop ransomware',
 '## Scénario\nJ+0 02h00 : alertes EDR en masse sur 5 hosts. SIEM down. Criptage partagé NFS.\n\n## Déroulé (4h)\n- 0h00 : détection (EDR)\n- 0h15 : premier appel RSSI (qui ? qui décide ?)\n- 0h30 : confinement (network segmentation, kill switch)\n- 1h00 : communication (DPO, ANSSI, clients)\n- 2h00 : décision paiement (NON par défaut)\n- 4h00 : lessons learned\n\n## Participants\nRSSI, DPO, DG, DAF, IT, COM\n\n## Fréquence\n1x/an minimum. Dernier: 2025-11-20.',
 1, 'rssi@anytimeadmin.info', '2025-11-20', '2026-11-20'),

('pri', 'capacity-planning',
 'Capacity planning trimestriel',
 '## Métriques à suivre\n- Volume SIEM (events/jour, Mo/jour)\n- Latence P95 des requêtes dashboard\n- Taux de désaturation MinIO (cold storage)\n- Coût cloud vs prévision\n\n## Processus\n- Extraction mensuelle via `tools/capacity_report.py`\n- Revue trimestrielle avec DAF\n- Décision scaling si > 80% de la capacité',
 1, 'infra@anytimeadmin.info', '2026-04-01', '2026-07-01');
