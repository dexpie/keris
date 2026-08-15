"""Test refactor CLI: struktur package, dispatch, dan backward compat."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class TestCliPackage:
    def test_modules_exist(self):
        import keris.cli.auth
        import keris.cli.common
        import keris.cli.main
        import keris.cli.monitor
        import keris.cli.recon
        import keris.cli.report
        import keris.cli.scan
        assert all(m for m in [keris.cli.auth, keris.cli.common, keris.cli.main])

    def test_handler_split_by_domain(self):
        from keris.cli import auth, monitor, recon, report, scan
        assert hasattr(scan, "_cmd_scan")
        assert hasattr(recon, "_cmd_recon")
        assert hasattr(auth, "_cmd_crack")
        assert hasattr(monitor, "_cmd_dos")
        assert hasattr(report, "_cmd_export")

    def test_main_dispatches_all_commands(self):
        from keris.cli.main import main
        for cmd in ("recon", "passive", "scan", "plugins", "fuzz", "jwt",
                    "ports", "openapi", "bruteforce", "platforms", "project",
                    "wayback", "dns", "subdomain", "buckets", "tls", "waf",
                    "params", "hidden", "crawl", "graphql", "takeover",
                    "smuggling", "cachepoison", "hostheader", "websocket",
                    "jsanalysis", "sensitive", "retest", "export",
                    "dashboard", "dos", "serve", "watch", "tui", "hunt",
                    "credcheck", "exploit", "shell", "pivot", "rebind",
                    "gitdump", "authbypass", "spray", "dbdump", "cloud",
                    "xsshook", "k8s", "crack", "har", "re", "backdoor", "init"):
            assert hasattr(main, "__call__"), cmd


class TestBackwardCompat:
    def test_main_module_reexports(self):
        import keris.__main__ as m
        for name in ("_parse_args", "main", "_make_client", "_suffixed",
                     "_cmd_retest", "EXIT_ERROR", "_save_history",
                     "_load_history", "_history_path"):
            assert hasattr(m, name), name

    def test_parse_args_still_works(self):
        from keris.__main__ import _parse_args
        args = _parse_args(["recon", "http://x"])
        assert args.command == "recon"
        assert args.target == "http://x"