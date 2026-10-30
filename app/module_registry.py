"""Activation/désactivation des modules — LogSOC 13/09 (option B validée).

Un module DÉSACTIVÉ refuse tout le monde (503 "Module désactivé par
l'administrateur") sauf superadmin, et se masque du menu. Activé =
comportement normal (matrice par rôle via require_permission).

Le flag vit dans module_flags (pas de ligne = activé, soft-flag is_active).
La garde combinée `module_and_permission` est le point d'entrée unique:
d'abord le flag, puis la permission granulaire du rôle.
"""
from fastapi import HTTPException

from app.models import ModuleFlag

# Les 15 modules du référentiel RBAC (labels dans RolesPermissionsAdmin.tsx)
KNOWN_MODULES = (
    'events', 'alerts', 'cases', 'agents', 'yara', 'sigma', 'correlation',
    'threat_intel', 'assets', 'users', 'compliance', 'governance', 'risks',
    'reporting', 'soar',
)


def get_module_flags(db) -> dict:
    """{module: is_active} — modules explicitement flaggés."""
    rows = db.query(ModuleFlag).all()
    return {r.module: bool(r.is_active) for r in rows}


def get_disabled_modules(db) -> set:
    """L'ensemble des modules désactivés."""
    return {m for m, active in get_module_flags(db).items() if not active}


def is_module_enabled(db, module: str) -> bool:
    """True sauf si une ligne is_active=0 existe pour ce module."""
    flags = get_module_flags(db)
    return flags.get(module, True)


def set_module_active(db, module: str, active: bool) -> None:
    """Upsert du flag (soft)."""
    row = db.query(ModuleFlag).filter(ModuleFlag.module == module).first()
    if not row:
        row = ModuleFlag(module=module, is_active=active)
        db.add(row)
    else:
        row.is_active = active
    db.commit()


def check_module_enabled(db, user, module: str) -> None:
    """Lève 503 si le module est désactivé (superadmin passe toujours).
    À appeler AVANT la garde de permission."""
    if (getattr(user, "role", None) or "") == "superadmin":
        return
    if not is_module_enabled(db, module):
        raise HTTPException(
            status_code=503,
            detail=f"Module '{module}' désactivé par l'administrateur",
        )