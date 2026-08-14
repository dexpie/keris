import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import keris.__main__ as m


class TestSubcommandFlags:
    """Setiap handler yang memakai args.json_output harus punya flag tersebut."""

    def test_scan_has_json_output(self):
        a = m._parse_args(["scan", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_discover_has_json_output(self):
        a = m._parse_args(["discover", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_recon_has_json_output(self):
        a = m._parse_args(["recon", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_hunt_has_json_output(self):
        a = m._parse_args(["hunt", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_credcheck_has_json_output(self):
        a = m._parse_args(["credcheck", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_waf_has_json_output(self):
        a = m._parse_args(["waf", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_openapi_has_json_output(self):
        a = m._parse_args(["openapi", "http://x", "--json-output", "o.json"])
        assert a.json_output == "o.json"

    def test_ports_has_json_output(self):
        a = m._parse_args(["ports", "127.0.0.1", "--json-output", "o.json"])
        assert a.json_output == "o.json"