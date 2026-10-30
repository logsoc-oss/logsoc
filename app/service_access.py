"""Accès par service (appartenance) — LogSOC 2026-09-13.

Design validé Fabrice:
- user_service_links(user_id, service_id, is_owner) = appartenance aux
  services (référentiel business_services, partagé avec le CMDB).
- Un MEMBRE d'un service VOIT les livrables rattachés à son service
  (governance_deliverables.service_id) + leurs exigences (par deliverable_id),
  QUEL QUE SOIT son users.role — lecture seule.
- Nuance tâches: les actions du plan d'action (governance_actions) liées à un
  livrable de son service restent ACTIONNABLES par les membres (statut/
  progression), pas les autres champs.
- Rôles forts (vue globale inchangée): superadmin, admin, rssi, dpo,
  compliance_officer, auditor (lecteur global par nature).
- L'appartenance ne donne JAMAIS d'écriture sur les livrables/documents —
  seuls les rôles d'accès classiques (require_role) décident.
"""
from typing import Set

STRONG_ROLES = {"superadmin", "admin", "rssi", "dpo", "compliance_officer", "auditor"}


def is_strong_role(user) -> bool:
    return (getattr(user, "role", None) or "") in STRONG_ROLES


def get_user_service_ids(db, user) -> Set[int]:
    """Les ids des services dont l'utilisateur est membre (ou owner)."""
    from app.models import UserServiceLink
    links = db.query(UserServiceLink).filter(
        UserServiceLink.user_id == user.id
    ).all()
    return {l.service_id for l in links}


def get_user_services(db, user) -> list:
    """Les objets services du user, avec le flag owner."""
    from app.models import UserServiceLink, BusinessService
    links = db.query(UserServiceLink).filter(
        UserServiceLink.user_id == user.id
    ).all()
    if not links:
        return []
    svc = {s.id: s for s in db.query(BusinessService).filter(
        BusinessService.id.in_([l.service_id for l in links])).all()}
    out = []
    for l in links:
        s = svc.get(l.service_id)
        if s:
            out.append({"service_id": s.id, "name": s.name, "is_owner": bool(l.is_owner)})
    return out


def can_read_deliverable(db, user, deliverable_id: int) -> bool:
    """Lecture du livrable (et de ses exigences par transitivité):
    rôle fort -> toujours; sinon membre du service du livrable."""
    if is_strong_role(user):
        return True
    from app.models import GovernanceDeliverable
    d = db.query(GovernanceDeliverable).filter(
        GovernanceDeliverable.id == deliverable_id
    ).first()
    if not d:
        return False
    sid = getattr(d, "service_id", None)
    if not sid:
        return False
    return sid in get_user_service_ids(db, user)


def can_update_action_status(db, user, action_id: int) -> bool:
    """Nuance tâches: un membre d'un service peut MAJ statut/progression des
    actions assignées à SON service (action_plans.service_id).
    Rôles forts: toujours."""
    if is_strong_role(user):
        return True
    from app.models import ActionPlan
    a = db.query(ActionPlan).filter(ActionPlan.id == action_id).first()
    if not a:
        return False
    sid = getattr(a, "service_id", None)
    if not sid:
        return False
    return sid in get_user_service_ids(db, user)


def scoped_deliverable_ids(db, user):
    """None = vue globale (rôle fort); sinon ensemble des ids livrables des
    services du user (sert de filtre aux listes)."""
    if is_strong_role(user):
        return None
    from app.models import GovernanceDeliverable
    sids = get_user_service_ids(db, user)
    if not sids:
        return set()
    rows = db.query(GovernanceDeliverable.id).filter(
        GovernanceDeliverable.service_id.in_(sids)
    ).all()
    return {r.id for r in rows}