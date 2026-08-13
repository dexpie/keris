"""Tes untuk modul hidden endpoint discovery (tanpa jaringan luar)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from keris.modules.hidden import _classify, HIDDEN_ENDPOINTS, INTERESTING_CLASS


class TestHiddenClassify:
    def test_admin_high(self):
        name, sev = _classify("/admin")
        assert name == "Admin panel"
        assert sev == "HIGH"

    def test_env_critical(self):
        name, sev = _classify("/.env")
        assert sev == "CRITICAL"

    def test_git_critical(self):
        name, sev = _classify("/.git/config")
        assert sev == "CRITICAL"

    def test_swagger_medium(self):
        name, sev = _classify("/swagger-ui/")
        assert sev == "MEDIUM"

    def test_backup_high(self):
        name, sev = _classify("/backup.zip")
        assert sev == "HIGH"

    def test_unknown_path(self):
        name, sev = _classify("/whatever")
        assert name is None and sev is None


class TestHiddenWordlist:
    def test_has_core_endpoints(self):
        for p in ("/admin", "/.env", "/.git/config", "/actuator", "/backup.zip",
                  "/swagger.json", "/graphql", "/.htpasswd"):
            assert p in HIDDEN_ENDPOINTS

    def test_classification_rules_complete(self):
        # setiap rule punya 3 elemen
        for rule in INTERESTING_CLASS:
            assert len(rule) == 3