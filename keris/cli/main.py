"""Keris CLI dispatcher: main() yang memilih handler berdasarkan command."""

import os
import sys
from typing import List, Optional

from keris.core.logger import error, ok, set_quiet

from keris.cli.auth import (
    _cmd_authbypass, _cmd_cloud, _cmd_crack, _cmd_credcheck, _cmd_dbdump,
    _cmd_exploit, _cmd_gitdump, _cmd_hunt, _cmd_k8s, _cmd_pivot,
    _cmd_rebind, _cmd_shell, _cmd_spray, _cmd_xsshook,
)
from keris.cli.common import EXIT_ERROR, EXIT_OK, _merge_config, _parse_args
from keris.cli.monitor import _cmd_dos, _cmd_serve, _cmd_tui, _cmd_watch
from keris.cli.recon import (
    _cmd_buckets, _cmd_dns, _cmd_jwt, _cmd_passive, _cmd_platforms, _cmd_ports,
    _cmd_project, _cmd_recon, _cmd_subdomain, _cmd_tls, _cmd_waf,
    _cmd_wayback,
)
from keris.cli.report import _cmd_dashboard, _cmd_export
from keris.cli.scan import (
    _cmd_backdoor, _cmd_bruteforce, _cmd_cachepoison, _cmd_crawl, _cmd_discover,
    _cmd_fuzz, _cmd_graphql, _cmd_har, _cmd_hidden, _cmd_hostheader,
    _cmd_jsanalysis, _cmd_openapi, _cmd_params, _cmd_plugins, _cmd_re,
    _cmd_retest, _cmd_scan, _cmd_sensitive, _cmd_smuggling, _cmd_takeover,
    _cmd_websocket,
)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    cfg, overrides = _merge_config(args)

    if getattr(args, "no_color", False):
        from keris.core import logger as logger_mod

        logger_mod.disable_color()
    set_quiet(getattr(args, "quiet", False) or overrides.get("quiet", False))

    from keris.core.logger import brutal_warning

    # --- MODE OVERPOWERED: --pwn mengaktifkan seluruh modul serangan ---
    if args.command == "scan" and getattr(args, "pwn", False):
        if not getattr(args, "authorized", False):
            from keris.core.logger import error as _err

            _err("--pwn membutuhkan --authorized (konfirmasi izin tertulis).")
            return 2
        for _flag in ("hunt", "chain", "triage", "browser", "exploit",
                      "brute_extended", "exploit_cve", "cache_poisoning",
                      "host_header", "username_enum", "ssrf", "waf",
                      "ssrf_exploit", "jwt_attack", "race", "js_deps",
                      "favicon", "server_cve", "wayback", "exploit_kit"):
            if not hasattr(args, _flag):
                setattr(args, _flag, False)
            setattr(args, _flag, True)
        brutal_warning("PWN")

    # output-dir: semua laporan ditulis ke direktori tersebut
    if getattr(args, "output_dir", None):
        os.makedirs(args.output_dir, exist_ok=True)
        _join_output = lambda p: os.path.join(args.output_dir, os.path.basename(p))
        for attr in ("output", "json_output", "html_output", "pdf_output"):
            val = getattr(args, attr, None)
            if val:
                setattr(args, attr, _join_output(val))

    try:
        if args.command == "recon":
            return _cmd_recon(args, cfg, overrides)
        if args.command == "passive":
            return _cmd_passive(args, cfg, overrides)
        if args.command == "discover":
            return _cmd_discover(args, cfg, overrides)
        if args.command == "scan":
            return _cmd_scan(args, cfg, overrides)
        if args.command == "plugins":
            return _cmd_plugins(args, cfg, overrides)
        if args.command == "fuzz":
            return _cmd_fuzz(args, cfg, overrides)
        if args.command == "jwt":
            return _cmd_jwt(args, cfg, overrides)
        if args.command == "ports":
            return _cmd_ports(args, cfg, overrides)
        if args.command == "openapi":
            return _cmd_openapi(args, cfg, overrides)
        if args.command == "bruteforce":
            return _cmd_bruteforce(args, cfg, overrides)
        if args.command == "platforms":
            return _cmd_platforms(args, cfg, overrides)
        if args.command == "project":
            return _cmd_project(args, cfg, overrides)
        if args.command == "wayback":
            return _cmd_wayback(args, cfg, overrides)
        if args.command == "dns":
            return _cmd_dns(args, cfg, overrides)
        if args.command == "subdomain":
            return _cmd_subdomain(args, cfg, overrides)
        if args.command == "buckets":
            return _cmd_buckets(args, cfg, overrides)
        if args.command == "tls":
            return _cmd_tls(args, cfg, overrides)
        if args.command == "waf":
            return _cmd_waf(args, cfg, overrides)
        if args.command == "params":
            return _cmd_params(args, cfg, overrides)
        if args.command == "hidden":
            return _cmd_hidden(args, cfg, overrides)
        if args.command == "crawl":
            return _cmd_crawl(args, cfg, overrides)
        if args.command == "graphql":
            return _cmd_graphql(args, cfg, overrides)
        if args.command == "takeover":
            return _cmd_takeover(args, cfg, overrides)
        if args.command == "smuggling":
            return _cmd_smuggling(args, cfg, overrides)
        if args.command == "cachepoison":
            return _cmd_cachepoison(args, cfg, overrides)
        if args.command == "hostheader":
            return _cmd_hostheader(args, cfg, overrides)
        if args.command == "websocket":
            return _cmd_websocket(args, cfg, overrides)
        if args.command == "jsanalysis":
            return _cmd_jsanalysis(args, cfg, overrides)
        if args.command == "sensitive":
            return _cmd_sensitive(args, cfg, overrides)
        if args.command == "retest":
            return _cmd_retest(args, cfg, overrides)
        if args.command == "export":
            return _cmd_export(args, cfg, overrides)
        if args.command == "dashboard":
            return _cmd_dashboard(args, cfg, overrides)
        if args.command == "dos":
            return _cmd_dos(args, cfg, overrides)
        if args.command == "serve":
            return _cmd_serve(args, cfg, overrides)
        if args.command == "watch":
            return _cmd_watch(args, cfg, overrides)
        if args.command == "tui":
            return _cmd_tui(args, cfg, overrides)
        if args.command == "hunt":
            return _cmd_hunt(args, cfg, overrides)
        if args.command == "credcheck":
            return _cmd_credcheck(args, cfg, overrides)
        if args.command == "exploit":
            return _cmd_exploit(args, cfg, overrides)
        if args.command == "shell":
            return _cmd_shell(args, cfg, overrides)
        if args.command == "pivot":
            return _cmd_pivot(args, cfg, overrides)
        if args.command == "rebind":
            return _cmd_rebind(args, cfg, overrides)
        if args.command == "gitdump":
            return _cmd_gitdump(args, cfg, overrides)
        if args.command == "authbypass":
            return _cmd_authbypass(args, cfg, overrides)
        if args.command == "spray":
            return _cmd_spray(args, cfg, overrides)
        if args.command == "dbdump":
            return _cmd_dbdump(args, cfg, overrides)
        if args.command == "cloud":
            return _cmd_cloud(args, cfg, overrides)
        if args.command == "xsshook":
            return _cmd_xsshook(args, cfg, overrides)
        if args.command == "k8s":
            return _cmd_k8s(args, cfg, overrides)
        if args.command == "crack":
            return _cmd_crack(args, cfg, overrides)
        if args.command == "har":
            return _cmd_har(args, cfg, overrides)
        if args.command == "re":
            return _cmd_re(args, cfg, overrides)
        if args.command == "backdoor":
            return _cmd_backdoor(args, cfg, overrides)
        if args.command == "init":
            from keris.core.config import save_example_config

            path = save_example_config(args.output)
            ok(f"Contoh konfigurasi ditulis: {path}")
            return EXIT_OK
    except SystemExit:
        raise
    except Exception as e:
        error(f"Error: {e}")
        return EXIT_ERROR
    return EXIT_ERROR