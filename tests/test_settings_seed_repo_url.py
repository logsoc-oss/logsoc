"""Tests unitaires de _repo_raw_url (settings_seed) — support GitHub + Gitea.

Run: PYTHONPATH=. python3 tests/test_settings_seed_repo_url.py
ou:  python3 -m pytest tests/test_settings_seed_repo_url.py -v

Couverture (cahier des charges, mission SRV-NOVA 2026-10-10):
  1. GitHub avec suffixe .git
  2. GitHub sans suffixe .git
  3. Gitea (format raw historique)
 + branche explicite /tree/{branche} dans l'URL GitHub
 + repo dédié logsoc-referentiel (fichiers À PLAT, format Gitea)
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from app.routers.settings_seed import _repo_raw_url


class TestRepoRawUrl(unittest.TestCase):

    def test_github_avec_suffixe_git(self):
        url = _repo_raw_url(
            "https://github.com/logsoc-oss/logsoc.git", "00_reference_documents.sql")
        self.assertEqual(
            url,
            "https://raw.githubusercontent.com/logsoc-oss/logsoc/master/sql/seeds/00_reference_documents.sql")

    def test_github_sans_suffixe_git(self):
        url = _repo_raw_url(
            "https://github.com/logsoc-oss/logsoc", "05_security_practices.sql")
        self.assertEqual(
            url,
            "https://raw.githubusercontent.com/logsoc-oss/logsoc/master/sql/seeds/05_security_practices.sql")

    def test_gitea(self):
        url = _repo_raw_url(
            "https://git.example.com/pixies/logsoc-web.git", "01_reference_requirements.sql")
        self.assertEqual(
            url,
            "https://git.example.com/pixies/logsoc-web/raw/branch/master/sql/seeds/01_reference_requirements.sql")

    def test_github_branche_explicite(self):
        url = _repo_raw_url(
            "https://github.com/logsoc-oss/logsoc/tree/main", "VERSION")
        self.assertEqual(
            url,
            "https://raw.githubusercontent.com/logsoc-oss/logsoc/main/sql/seeds/VERSION")

    def test_gitea_referentiel_plat(self):
        """Repo dédié logsoc-referentiel: fichiers À PLAT (pas de sql/seeds/)."""
        url = _repo_raw_url(
            "https://git.example.com/pixies/logsoc-referentiel", "00_reference_documents.sql")
        self.assertEqual(
            url,
            "https://git.example.com/pixies/logsoc-referentiel/raw/branch/master/00_reference_documents.sql")


if __name__ == "__main__":
    unittest.main(verbosity=2)