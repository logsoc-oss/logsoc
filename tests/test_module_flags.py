"""Garde-fou activation/désactivation des modules (2026-09-13).

Design validé Fabrice (option B): un module désactivé par l'admin refuse
TOUT le monde (503) sauf superadmin; le menu se masque dynamiquement.
Activé = comportement normal (matrice par rôle via require_permission).

ROUGE attendu avant patch: aucune notion de module désactivé n'existe.
"""
import sys
import types

sys.path.insert(0, "/home/hermes/log-soc-ai/logsoc-web")


def test_module_flags():
    from app.module_registry import is_module_enabled, get_disabled_modules
    db = _FakeDb()
    # yara actif par défaut (pas de ligne = activé)
    assert is_module_enabled(db, "yara") is True, "module sans ligne = activé"
    # soar désactivé (ligne is_active=0)
    assert is_module_enabled(db, "soar") is False, "ligne active=0 -> désactivé"
    # liste des désactivés
    disabled = get_disabled_modules(db)
    assert "soar" in disabled, "soar dans les désactivés"
    assert "yara" not in disabled


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
    def query(self, model):
        name = getattr(model, "__name__", str(model))
        if name == "ModuleFlag":
            return _FakeQ([types.SimpleNamespace(module="soar", is_active=False)])
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
        print(f"{k:35s} {v}")
    sys.exit(1 if any(v.startswith("FAIL") for v in results.values()) else 0)