"""Utilitaires multi-casquettes business_role (2026-09-13).

Design validé Fabrice: users.business_role peut contenir PLUSIEURS
casquettes métier séparées par ' / ' (ex. 'dsi / rssi'). Un user fait
partie d'un service (dsi) sans forcément en être le responsable (rssi),
et peut cumuler les casquettes.

Toutes les gardes (signature livrables, contre-signature direction,
validation emails, rapport d'audit, désignation auditeur) doivent matcher
par INTERSECTION sur les casquettes splittées — jamais par égalité
stricte sur la chaîne brute.

NB: users.role (axe ACCÈS technique) est indépendant et reste en
égalité stricte (superadmin, admin, rssi, dpo, auditor, ...).
"""
from typing import Iterable, Optional, Set


def split_business_roles(raw: Optional[str]) -> Set[str]:
    """Splitte 'DSI / RSSI' -> {'dsi', 'rssi'} (insensible à la casse)."""
    if not raw:
        return set()
    return {p.strip().lower() for p in str(raw).split("/") if p.strip()}


def user_business_roles(user) -> Set[str]:
    """Les casquettes métier d'un objet User (ou SimpleNamespace en tests)."""
    return split_business_roles(getattr(user, "business_role", None))


def match_any(user, wanted: Iterable[str]) -> bool:
    """True si l'utilisateur porte AU MOINS UNE des casquettes voulues.

    wanted peut être une liste/set brute ('rssi') ou déjà splittée.
    """
    wanted_set = {str(w).strip().lower() for w in wanted if str(w).strip()}
    return bool(user_business_roles(user) & wanted_set)


def first_match(user, wanted: Iterable[str], default: Optional[str] = None) -> Optional[str]:
    """La première casquette de wanted portée par l'utilisateur (pour
    l'affichage du cachet/audit-trail: signer en tant que 'rssi', pas
    'dsi / rssi')."""
    roles = user_business_roles(user)
    for w in wanted:
        w = str(w).strip().lower()
        if w and w in roles:
            return w
    return default


def join_business_roles(roles: Iterable[str]) -> str:
    """Reconstruit la chaîne canonique 'dsi / rssi' depuis une liste."""
    seen = []
    for r in roles:
        r = str(r).strip().lower()
        if r and r not in seen:
            seen.append(r)
    return " / ".join(seen)