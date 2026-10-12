"""Garde-fou multi-casquettes business_role (2026-09-13).

Principe Fabrice: un user peut porter PLUSIEURS casquettes métier séparées
par ' / ' (ex. 'dsi / rssi'). Toutes les gardes doivent matcher par
INTERSECTION sur les casquettes splittées, pas par égalité stricte.

ROUGE attendu avant patch: les gardes actuelles comparent business_role
en égalité stricte -> un user 'dsi / rssi' ne matche pas 'rssi'.
VERT attendu après patch app/roles.py + gardes.
"""
import sys, types

sys.path.insert(0, "/home/hermes/log-soc-ai/logsoc-web")


def make_user(business_role, role="", is_signatory=True):
    u = types.SimpleNamespace()
    u.business_role = business_role
    u.role = role
    u.is_signatory = is_signatory
    u.email = "x@y.z"
    u.is_active = True
    return u


def test_split():
    from app.roles import user_business_roles, match_any
    assert user_business_roles(make_user("dsi / rssi")) == {"dsi", "rssi"}, "split ' / '"
    assert user_business_roles(make_user("DSI / RSSI")) == {"dsi", "rssi"}, "insensible casse"
    assert user_business_roles(make_user(None)) == set(), "None -> vide"
    assert user_business_roles(make_user("")) == set(), "vide -> vide"
    assert match_any(make_user("dsi / rssi"), {"rssi"}) is True, "intersection rssi"
    assert match_any(make_user("dsi / rssi"), {"dpo"}) is False, "pas d'intersection"
    assert match_any(make_user("gerant"), {"gerant", "president", "dg", "direction"}) is True


def test_normalize():
    from app.routers.users import normalize_business_role
    assert normalize_business_role("RSSI /  DSI") == "rssi / dsi"
    assert normalize_business_role("dsi/rssi") == "dsi / rssi"
    assert normalize_business_role("dsi / rssi / dsi") == "dsi / rssi", "dédoublonne"
    assert normalize_business_role(None) is None
    assert normalize_business_role("") is None


def test_doc_signing():
    from app.doc_signing import _required_business_role, check_sign_permission
    # _required_business_role doit continuer a splitter cote livrable
    d = types.SimpleNamespace(verification_role="RSSI")
    assert "rssi" in _required_business_role(d)
    d2 = types.SimpleNamespace(verification_role="DSI / Juriste / DPO")
    req = _required_business_role(d2)
    assert {"dsi", "juriste", "dpo"} <= set(req)
    # garde: user 'dsi / rssi' peut signer un livrable verification_role=rssi
    user = make_user("dsi / rssi")
    doc = types.SimpleNamespace(deliverable_id=1)
    ok, err = check_sign_permission(user, doc, _fake_db(), "signatory")
    assert ok, f"signatory rssi refuse pour 'dsi / rssi': {err}"
    # contre-signature direction: user 'gerant / president' accepte
    user2 = make_user("gerant / president")
    ok2, err2 = check_sign_permission(user2, doc, _fake_db(), "direction")
    assert ok2, f"direction refuse pour 'gerant / president': {err2}"
    # user 'dsi' seul ne peut PAS signer rssi
    ok3, _ = check_sign_permission(make_user("dsi"), doc, _fake_db(), "signatory")
    assert not ok3, "dsi seul ne doit pas signer un livrable rssi"


class _FakeQ:
    def __init__(self, result):
        self.result = result
    def filter(self, *a, **k):
        return self
    def first(self):
        return self.result


class _FakeDb:
    def query(self, *a, **k):
        return _FakeQ(types.SimpleNamespace(verification_role="RSSI"))


def _fake_db():
    return _FakeDb()


def test_doc_validation():
    from app.roles import match_any
    # fallback direction: user 'dsi / gerant' matche le fallback gerant
    users = [make_user("dsi / gerant"), make_user("dsi")]
    matched = [u for u in users if match_any(u, ("gerant", "president", "dg", "direction"))]
    assert len(matched) == 1, "fallback direction doit matcher 'dsi / gerant'"
    # resolve_direction_validators repose sur match_any pour les 2 branches
    from app.doc_validation import resolve_direction_validators
    import inspect
    src = inspect.getsource(resolve_direction_validators)
    assert "match_any" in src, "resolve_direction_validators doit utiliser match_any"


def test_audit_report_signing():
    from app.routers.practices import _can_sign_audit_report
    user = make_user("dsi / rssi", role="auditor")
    ok, err = _can_sign_audit_report(user)
    assert ok, f"rapport audit: 'dsi / rssi' doit signer (err: {err})"
    # user sans casquette rssi et role non rssi -> refuse
    ok2, _ = _can_sign_audit_report(make_user("dsi", role="auditor"))
    assert not ok2


if __name__ == "__main__":
    import traceback
    results = {}
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                results[name] = "PASS"
            except Exception as e:
                results[name] = f"FAIL: {e}"
    for k, v in results.items():
        print(f"{k:35s} {v}")
    n_fail = sum(1 for v in results.values() if v.startswith("FAIL"))
    sys.exit(1 if n_fail else 0)