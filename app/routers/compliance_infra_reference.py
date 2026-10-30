"""app/routers/compliance_infra_reference.py — Référentiel RSSI V3.

v0.11.2 - 2026-06-09. Définit les 6 sections compliance + sous-thèmes
utilisés par le scoring de couverture (R8).

C'est la SEULE source de vérité pour le nombre de sous-thèmes par section :
si tu ajoutes un sous-thème, la couverture (procédures/sous-thèmes) baisse
mécaniquement, ce qui force à documenter le nouveau thème.

Pondération du score global (voir compute_section_score) :
  - couverture (procédures couvrant des sous-thèmes)  : 60 %
  - fraîcheur (pas en retard de revue)                 : 30 %
  - risques fermés (1 - open/total)                    : 10 %
"""
from __future__ import annotations

from typing import Dict, List, Set

# Les 6 sections RSSI V3 + leurs sous-thèmes.
# Slug = identifiant interne, label = affichage.
SECTIONS: Dict[str, Dict] = {
    "pra": {
        "label": "PRA — Plan de reprise",
        "subthemes": [
            "rto_rpo",            # RTO/RPO contractualisés
            "backups",            # Stratégie de sauvegardes
            "restore_test",       # Tests de restauration documentés
            "offsite_encryption", # Sauvegardes hors-site chiffrées
            "runbook_pra",        # Procédure PRA documentée
        ],
    },
    "pca": {
        "label": "PCA — Plan de continuité",
        "subthemes": [
            "critical_services",  # 3 services critiques identifiés
            "degraded_mode",      # Mode dégradé documenté + testé
            "failover_automation", # Basculements automatisés
            "runbook_pca",        # Procédure PCA documentée
        ],
    },
    "pri": {
        "label": "PRI — Prévention & résilience",
        "subthemes": [
            "dependency_mapping", # Dépendances tierces cartographiées
            "capacity_planning",  # Capacity planning à jour
            "hardening_benchmark", # Hardening (CIS, ANSSI, etc.)
            "runbook_pri",        # Procédure PRI documentée
        ],
    },
    "sc": {
        "label": "Supply chain",
        "subthemes": [
            "supplier_audit",     # Fournisseurs critiques audités
            "sbom",               # SBOM généré à chaque release
            "incident_clause",    # Clause de notification incident
            "runbook_sc",         # Procédure Supply chain documentée
        ],
    },
    "fore": {
        "label": "Forensics",
        "subthemes": [
            "chain_of_custody",   # Chaîne de preuve documentée
            "acquisition_tools",  # Outils d'acquisition validés
            "team_training",      # Équipe formée
            "runbook_fore",       # Procédure Forensics documentée
        ],
    },
    "test": {
        "label": "Tests & exercices",
        "subthemes": [
            "tabletop",           # Tabletop exercice
            "coverage_6sections", # Tests couvrant les 6 sections
            "post_test_actions",  # Plan d'action post-test
            "runbook_test",       # Procédure Tests documentée
        ],
    },
}


def all_subthemes_for_section(section: str) -> List[str]:
    """Retourne la liste des sous-thèmes pour une section donnée."""
    if section not in SECTIONS:
        return []
    return SECTIONS[section]["subthemes"]


def all_section_keys() -> List[str]:
    """Retourne les 6 clés de section (pra, pca, pri, sc, fore, test)."""
    return list(SECTIONS.keys())


def section_label(section: str) -> str:
    """Label humain d'une section."""
    return SECTIONS.get(section, {}).get("label", section)


def total_subthemes() -> int:
    """Nombre total de sous-thèmes dans le référentiel (24 par défaut)."""
    return sum(len(s["subthemes"]) for s in SECTIONS.values())


# Mapping slug de procédure Runbook -> sous-thèmes couverts.
# Une procédure peut couvrir plusieurs sous-thèmes (ex: "backup-restore-postgres"
# couvre "backups" et "restore_test" et "offsite_encryption").
# C'est déclaratif : l'humain qui crée la procédure décide quels sous-thèmes
# elle couvre en l'éditant. Le slug match fait foi.
PROCEDURE_SUBTHEME_MAP: Dict[str, Dict[str, Set[str]]] = {
    # PRA
    "pra": {
        "backup-restore-postgres": {"backups", "restore_test", "offsite_encryption", "rto_rpo"},
    },
    # PCA
    "pca": {
        "mode-degrade-readonly": {"degraded_mode", "critical_services", "failover_automation"},
    },
    # PRI
    "pri": {
        "capacity-planning": {"capacity_planning", "dependency_mapping"},
    },
    # SC
    "sc": {
        "sbom-scan": {"sbom", "supplier_audit"},
    },
    # Forensics
    "fore": {
        "acquisition-image-disque": {"acquisition_tools", "chain_of_custody"},
    },
    # Tests
    "test": {
        "tabletop-ransomware": {"tabletop", "post_test_actions", "coverage_6sections"},
    },
}


def covered_subthemes_for_section(section: str, procedure_slugs: List[str]) -> Set[str]:
    """Calcule l'ensemble des sous-thèmes couverts par les slugs de procédures
    d'une section donnée. Utilise PROCEDURE_SUBTHEME_MAP.

    Args:
        section: clé de section (pra, pca, pri, sc, fore, test).
        procedure_slugs: liste des slugs de procédures de cette section.

    Returns:
        Set des sous-thèmes couverts.
    """
    section_map = PROCEDURE_SUBTHEME_MAP.get(section, {})
    covered: Set[str] = set()
    for slug in procedure_slugs:
        for st in section_map.get(slug, set()):
            covered.add(st)
    return covered
