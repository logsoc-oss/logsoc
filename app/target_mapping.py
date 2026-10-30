"""Target → Assets resolution — CHAINE 100% DETERMINISTE (aucune IA).

Ordre de resolution:
  1. Override manuel (target_asset_mappings.asset_id > 0) — decision explicite
     de l'admin qui PRIME sur tout (page Mappage = vue de controle)
  2. Dictionnaire (capability_dictionary) -> capacite -> TOUS les assets CMDB
     qui portent cette capacite (asset_capabilities) — redondance native:
     les 2 DC partagent domain_controller
  3. Fallback: regles de champs CMDB (type + OS) — ancien moteur bootstrap
  4. Rien => [] (en attente, visible dans la page Mappage)

Le dictionnaire et les capacites sont editables par l'admin (tables SQL).
Les regles de champs restent en code (bootstrap figé, rarement modifiees).
"""
import re
from typing import Optional, List

from sqlalchemy.orm import Session

from app.models import (
    AssetCmdb, TargetAssetMapping, ReferenceRequirement,
    AssetCapability, CapabilityDictionary,
)

# ── Regles de champs (fallback uniquement) ──
_RULES = [
    {
        "name": "active_directory_server",
        "patterns": [
            r"active\s*directory", r"\bntlm\b", r"\bkerberos\b",
            r"contr[ôo]leur\s*de\s*domaine", r"domaine\s*windows",
        ],
        "asset_types": ("server", "server_bare", "server_vm"),
        "os_like": "windows%",
        "exclude_types": ("workstation", "identity"),
    },
    {
        "name": "workstation",
        "patterns": [
            r"postes?\s*d['\"]?administration", r"postes?\s*utilisateurs?",
            r"postes?\s*de\s*travail", r"pare-feu\s*local",
            r"os\s*du\s*poste", r"stations?\s*de\s*travail",
        ],
        "asset_types": ("workstation",),
    },
    {
        "name": "logging_server",
        "patterns": [
            r"journalisation", r"journaux?", r"\blog(s|ging)?\b",
            r"\bsiem\b", r"centralisation\s*des\s*logs",
        ],
        "asset_types": ("middleware",),
    },
    {
        "name": "logging_host_server",
        "patterns": [
            r"journalisation", r"journaux?", r"\blog(s|ging)?\b",
            r"\bsiem\b", r"centralisation\s*des\s*logs",
        ],
        "asset_types": ("server", "server_bare", "server_vm"),
        "exclude_os_like": "windows%",
    },
    {
        "name": "virtualization_host",
        "patterns": [r"virtualisation", r"hyperviseur"],
        "asset_types": ("server", "server_bare", "server_vm"),
        "exclude_os_like": "windows%",
    },
    {
        "name": "bastion",
        "patterns": [r"\bbastion\b", r"\bmba\b", r"administration\s*distante"],
        "asset_types": ("server", "server_bare", "server_vm"),
    },
    {
        "name": "database",
        "patterns": [r"\bbdd\b", r"base\s*de\s*donn[ée]es?", r"\bsgbd\b"],
        "asset_types": ("database",),
    },
    # v2.1 (10/09) — 33 orphelines résolues par RÈGLES DE CHAMPS (pas d'asset unique:
    # la cible désigne une CLASSE d'assets, pas une machine). Multi-assets natif.
    {
        # Cibles "Tier 0" (ressources/protocoles/flux Tier 0, cœur de confiance...)
        # -> TOUS les assets CMDB classés tier_level='Tier_0' (champ GRC existant)
        "name": "tier0_assets",
        "patterns": [
            r"tier\s*0", r"c[œo]ur\s*de\s*confiance",
            # cibles Tier 0 sans le mot dans la cible (regle mentionne le Tier 0)
            r"^windows\s*server\s*core$",
            r"solutions?\s*de\s*protection\s*contre\s*les\s*menaces",
            r"agents?\s*de\s*protection\s*contre\s*les\s*menaces",
        ],
        "tier_level": "Tier_0",
    },
    {
        # Cibles Windows génériques (SMBv1, GPO, tâches planifiées, AppLocker/WDAC,
        # Credential Guard, "Systèmes Windows") -> TOUS les Windows actifs
        "name": "windows_assets",
        "patterns": [
            r"smbv1", r"applocker", r"\bwdac\b", r"credential\s*guard",
            r"t[âa]ches?\s*planifi[ée]es?", r"politiques?\s*de\s*s[ée]curit[ée]\s*/\s*gpo",
            r"syst[èe]mes?\s*windows",
        ],
        "os_like": "windows%",
    },
]

_DEFAULT_IGNORED = [
    r"t[ée]l[ée]phones?\s*mobiles?", r"\bsi\s*d['\"]?administration\b",
    r"flux\s*d['\"]?administration", r"r[ée]seau\s*d['\"]?administration",
    r"syst[èe]me\s*d['\"]?[ée]change\s*externe", r"\bipsec\b",
]

# Catalogue des capacites (pour le frontend et la coherence)
CAPABILITY_CATALOG = {
    "domain_controller": "Contrôleur de domaine / AD",
    "dns_server": "Serveur DNS",
    "vpn_gateway": "Passerelle VPN / accès distant",
    "bastion": "Bastion / administration distante",
    "log_server": "Serveur de journalisation / SIEM",
    "siem": "SIEM",
    "database": "Base de données",
    "hypervisor": "Hyperviseur / virtualisation",
    "web_server": "Serveur web",
    "mail_server": "Serveur de messagerie",
    "file_server": "Serveur de fichiers",
    "backup_server": "Serveur de sauvegarde",
    "admin_workstation": "Poste d'administration",
    "user_workstation": "Poste utilisateur",
    "mobile_device": "Terminal mobile",
    "firewall": "Pare-feu",
    "local_firewall": "Pare-feu local (endpoint)",
    "network_infra": "Infrastructure réseau",
    "identity_provider": "Fournisseur d'identité (SSO/IdP)",
    "app_server": "Serveur applicatif",
    # v2.1 (10/09) — résolution des 313 orphelines (classification CSV validée):
    "remote_access": "Accès distant / prise en main (RDP, assistance, partage d'écran)",
    "management_infra": "Infrastructure de gestion (WSUS, relais, outils d'admin, gestion centralisée)",
    "storage": "Stockage (SAN/NAS, périphériques de stockage)",
}


def _norm(s: str) -> str:
    return (s or "").strip().lower()


# ── Resolution (LA fonction centrale) ──

def resolve_assets_for_target(target_text: str, db: Session) -> List[int]:
    """Resout un target vers une LISTE d'asset_ids (redondance native).
    Ordre: override manuel > dictionnaire+capacites > regles de champs."""
    t = (target_text or "").strip()
    if not t:
        return []

    # 1. Override manuel explicite — PRIME sur tout
    m = db.query(TargetAssetMapping).filter(
        TargetAssetMapping.target_text == t
    ).first()
    if m and m.is_ignored:
        return []
    if m and m.asset_id:
        return [m.asset_id]

    # 2. Dictionnaire: exact match puis contains
    tn = _norm(t)
    entry = db.query(CapabilityDictionary).filter(
        CapabilityDictionary.target_pattern == t
    ).first()
    if not entry:
        # contains match (pattern le plus long d'abord)
        entries = db.query(CapabilityDictionary).filter(
            CapabilityDictionary.target_pattern.like(f"%{t}%")
        ).all()
        if len(entries) == 1:
            entry = entries[0]
        elif entries:
            entry = max(entries, key=lambda e: len(e.target_pattern))
    if entry:
        caps = db.query(AssetCapability).filter(
            AssetCapability.capability == entry.capability
        ).all()
        # v2.1: un asset INACTIF ne porte plus sa capacite (cohérent avec _RULES
        # qui filtre status='active') — sinon on lie des exigences a du materiel
        # decommissionne.
        asset_ids = []
        for c in caps:
            a = db.query(AssetCmdb).filter(
                AssetCmdb.id == c.asset_id, AssetCmdb.status == "active").first()
            if a:
                asset_ids.append(c.asset_id)
        if asset_ids:
            return asset_ids

    # 3. Fallback: regles de champs
    for pat in _DEFAULT_IGNORED:
        if re.search(pat, tn):
            return []
    for rule in _RULES:
        if any(re.search(p, tn) for p in rule["patterns"]):
            # v2.1: regle par CLASSE (tier_level) -> TOUS les assets de la classe
            if rule.get("tier_level"):
                assets = db.query(AssetCmdb).filter(
                    AssetCmdb.tier_level == rule["tier_level"],
                    AssetCmdb.status == "active",
                ).all()
                return [a.id for a in assets]
            q = db.query(AssetCmdb).filter(AssetCmdb.status == "active")
            if rule.get("asset_types"):
                q = q.filter(AssetCmdb.asset_type.in_(rule["asset_types"]))
            if rule.get("exclude_types"):
                q = q.filter(~AssetCmdb.asset_type.in_(rule["exclude_types"]))
            if rule.get("os_like"):
                q = q.filter(AssetCmdb.os_name.like(rule["os_like"]))
            if rule.get("exclude_os_like"):
                q = q.filter(~AssetCmdb.os_name.like(rule["exclude_os_like"]))
            asset = q.order_by(AssetCmdb.criticality.desc()).first()
            return [asset.id] if asset else []

    return []


def resolve_capability_for_target(target_text: str, db: Session) -> Optional[str]:
    """Quelle capacite le dictionnaire associe a ce target (diagnostic UI)."""
    t = (target_text or "").strip()
    if not t:
        return None
    entry = db.query(CapabilityDictionary).filter(
        CapabilityDictionary.target_pattern == t
    ).first()
    if not entry:
        entries = db.query(CapabilityDictionary).filter(
            CapabilityDictionary.target_pattern.like(f"%{t}%")
        ).all()
        if entries:
            entry = max(entries, key=lambda e: len(e.target_pattern))
    return entry.capability if entry else None


def capabilities_for_asset(asset_id: int, db: Session) -> List[str]:
    return [c.capability for c in db.query(AssetCapability).filter(
        AssetCapability.asset_id == asset_id
    ).all()]


def auto_link_assets_for_capability(capability: str, db: Session) -> int:
    """Event-driven: une capacite vient d'etre declaree sur un asset ->
    cree les liens exigences pour TOUS les targets du dictionnaire de cette
    capacite + les regles de champs correspondantes. Idempotent.
    Retourne le nombre de liens crees."""
    from app.models import AssetRequirementLink
    created = 0

    # Targets du dictionnaire pour cette capacite
    patterns = [e.target_pattern for e in db.query(CapabilityDictionary).filter(
        CapabilityDictionary.capability == capability
    ).all()]

    # + targets des regles de champs correspondantes (mapping regle->capacite)
    rule_to_cap = {
        "active_directory_server": "domain_controller",
        "workstation": "admin_workstation",
        "logging_server": "log_server",
        "logging_host_server": "log_server",
        "virtualization_host": "hypervisor",
        "bastion": "bastion",
        "database": "database",
    }
    for r in _RULES:
        if rule_to_cap.get(r["name"]) == capability:
            patterns.extend(r["patterns"])

    # Assets portant cette capacite
    asset_ids = [c.asset_id for c in db.query(AssetCapability).filter(
        AssetCapability.capability == capability
    ).all()]
    if not asset_ids:
        return 0

    # Dedupliquer les paires (requirement, asset) avant insert — le contains-match
    # peut produire la meme exigence via plusieurs patterns du meme target.
    seen = set()
    to_add = []
    for pattern in patterns:
        # exigences dont le target contient le pattern (case-insensitive)
        reqs = db.query(ReferenceRequirement).filter(
            ReferenceRequirement.entry_type == "requirement",
            ReferenceRequirement.target.isnot(None),
        ).filter(
            (ReferenceRequirement.target == pattern)
            | (ReferenceRequirement.target.like(f"%{pattern}%"))
        ).all()
        for r in reqs:
            for aid in asset_ids:
                key = (r.id, aid)
                if key in seen:
                    continue
                seen.add(key)
                exists = db.query(AssetRequirementLink).filter(
                    AssetRequirementLink.requirement_id == r.id,
                    AssetRequirementLink.asset_id == aid,
                ).first()
                if exists:
                    continue
                to_add.append((r.id, aid))
    for rid, aid in to_add:
        db.add(AssetRequirementLink(
            requirement_id=rid, asset_id=aid, link_type="direct",
        ))
        created += 1
    db.commit()
    return created


def bootstrap_mappings(db: Session, force: bool = False) -> dict:
    """Enregistre chaque target distinct des exigences avec son etat de
    resolution (pour la page Mappage). N'ecrase jamais un override."""
    targets = [
        row[0] for row in db.query(ReferenceRequirement.target)
        .filter(
            ReferenceRequirement.entry_type == "requirement",
            ReferenceRequirement.target.isnot(None),
        )
        .distinct()
        .all()
    ]
    stats = {"created": 0, "existing": 0, "resolved": 0, "ignored": 0}
    for target in targets:
        existing = db.query(TargetAssetMapping).filter(
            TargetAssetMapping.target_text == target
        ).first()
        if existing:
            stats["existing"] += 1
            continue
        resolved = resolve_assets_for_target(target, db)
        m = TargetAssetMapping(
            target_text=target,
            asset_id=resolved[0] if resolved else None,
            match_rule="auto_resolver" if resolved else None,
        )
        db.add(m)
        stats["created"] += 1
        if resolved:
            stats["resolved"] += 1
        else:
            for pat in _DEFAULT_IGNORED:
                if re.search(pat, _norm(target)):
                    m.is_ignored = True
                    stats["ignored"] += 1
                    break
    db.commit()
    return stats


def requirements_for_target(target_text: str, db: Session) -> List[ReferenceRequirement]:
    return db.query(ReferenceRequirement).filter(
        ReferenceRequirement.entry_type == "requirement",
        ReferenceRequirement.target == target_text,
    ).all()