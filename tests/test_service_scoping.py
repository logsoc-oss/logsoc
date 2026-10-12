"""Garde-fou appartenance services + accès lecture (2026-09-13).

Design validé Fabrice:
- Un user membre d'un service (user_service_links) VOIT les livrables de son
  service + leurs exigences (lecture seule), QUEL QUE SOIT son users.role.
- Nuance: les ACTIONS (tâches) du plan d'action rattachées à son service
  restent ACTIONNABLES par ses membres (statut/progression).
- Rôles forts (admin/rssi/dpo/compliance_officer) = vue globale inchangée.

ROUGE attendu avant patch: aucun filtrage par service n'existe.
VERT attendu après app/service_access.py + filtres routers.
"""
import sys
import types

sys.path.insert(0, "/home/hermes/log-soc-ai/logsoc-web")


def make_user(role="viewer", user_id=99, business_role=None):
    u = types.SimpleNamespace()
    u.id = user_id
    u.role = role
    u.business_role = business_role
    u.is_active = True
    u.is_signatory = False
    return u


def test_service_access_module():
    from app.service_access import get_user_service_ids, can_read_deliverable, can_update_action_status
    # duck-typing: db factice fournie par les closures ci-dessous
    db = _FakeDb()
    # membre du SSI (service 10)
    assert get_user_service_ids(db, make_user(user_id=9)) == {10}
    # lecture livrable SSI -> OK pour membre
    assert can_read_deliverable(db, make_user(user_id=9), deliverable_id=101) is True
    # lecture livrable d'un autre service -> refuse pour un viewer membre SSI
    assert can_read_deliverable(db, make_user(user_id=9), deliverable_id=999) is False
    # role fort (rssi) -> vue globale
    assert can_read_deliverable(db, make_user(role="rssi", user_id=9), deliverable_id=999) is True
    # admin -> vue globale
    assert can_read_deliverable(db, make_user(role="admin", user_id=9), deliverable_id=999) is True
    # user sans aucun service -> ne voit que... rien (hors roles forts)
    assert can_read_deliverable(db, make_user(user_id=77), deliverable_id=101) is False
    # nuance taches: membre SSI peut MAJ le statut d'une action de son service
    assert can_update_action_status(db, make_user(user_id=9), action_id=55) is True
    # action d'un autre service -> refuse
    assert can_update_action_status(db, make_user(user_id=9), action_id=66) is False


class _FakeQ:
    def __init__(self, result):
        self.result = result
    def filter(self, *a, **k):
        return self
    def all(self):
        return self.result
    def first(self):
        r = self.result
        return r[0] if r else None


class _FakeDb:
    """Rows factices: links user 9->service 10; deliverable 101->service 10,
    999->service 20; action 55->deliverable 101, 66->deliverable 999."""

    def query(self, model):
        name = getattr(model, "__name__", str(model))
        if name == "UserServiceLink":
            def filtu(*a, **k):
                wanted = None
                for crit in a:
                    try:
                        wanted = int(crit.right.value)
                    except Exception:
                        pass
                if wanted == 9:
                    return _FakeQ([types.SimpleNamespace(user_id=9, service_id=10, is_owner=False)])
                return _FakeQ([])
            q0 = _FakeQ([])
            q0.filter = filtu
            return q0
        if name == "GovernanceDeliverable":
            def filt(*a, **k):
                wanted = None
                for crit in a:
                    try:
                        wanted = int(crit.right.value)
                    except Exception:
                        pass
                rows = []
                if wanted == 101:
                    rows = [types.SimpleNamespace(id=101, service_id=10)]
                elif wanted == 999:
                    rows = [types.SimpleNamespace(id=999, service_id=20)]
                return _FakeQ(rows)
            q = _FakeQ([])
            q.filter = filt
            return q
        if name == "ActionPlan":
            def filt2(*a, **k):
                wanted = None
                for crit in a:
                    try:
                        wanted = int(crit.right.value)
                    except Exception:
                        pass
                rows = []
                if wanted == 55:
                    rows = [types.SimpleNamespace(id=55, service_id=10)]
                elif wanted == 66:
                    rows = [types.SimpleNamespace(id=66, service_id=20)]
                return _FakeQ(rows)
            q2 = _FakeQ([])
            q2.filter = filt2
            return q2
        return _FakeQ([])


if __name__ == "__main__":
    results = {}
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                results[name] = "PASS"
            except Exception as e:
                results[name] = f"FAIL: {e}"
    for k, v in results.items():
        print(f"{k:40s} {v}")
    n_fail = sum(1 for v in results.values() if v.startswith("FAIL"))
    sys.exit(1 if n_fail else 0)