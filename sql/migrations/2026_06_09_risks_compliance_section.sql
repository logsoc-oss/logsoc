-- R9 — Link risks to compliance sections (v0.11.3, 2026-06-09)
--
-- Avant R9 : tous les risques étaient comptés globalement, ce qui rendait
-- l'axe "risques fermés" du scoring R8 cosmétique (toutes les sections
-- voyaient le même total).
--
-- Après R9 : chaque risque pointe vers UNE section compliance (pra/pca/pri/sc/fore/test)
-- via la colonne compliance_section. Le scoring devient discriminant.
--
-- NULL est toléré pour les risques "généraux" (ex: gouvernance, RH) qui ne
-- tombent dans aucune des 6 sections RSSI V3. Ces risques n'apparaissent
-- dans le score d'aucune section.

ALTER TABLE risks
    ADD COLUMN compliance_section
        ENUM('pra', 'pca', 'pri', 'sc', 'fore', 'test')
        NULL AFTER treatment,
    ADD INDEX idx_risks_compliance_section (compliance_section);
