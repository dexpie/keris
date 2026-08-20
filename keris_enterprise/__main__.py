"""CLI keris-enterprise: setup / start / status / stop / worker / scheduler.

Contoh:
    python -m keris_enterprise setup --admin-email admin@company.com
    python -m keris_enterprise start --port 9000
    python -m keris_enterprise worker --port 9000
    python -m keris_enterprise scheduler --port 9000
    python -m keris_enterprise status
    python -m keris_enterprise stop
"""

import argparse
import sys

from keris.core.logger import info, ok, warn


def _setup(args) -> int:
    from keris_enterprise import EnterpriseServer

    srv = EnterpriseServer(host="127.0.0.1", port=0, db_path=args.db)
    admin = args.admin_user or "admin"
    srv.users.create_user(admin, args.admin_password, role="admin",
                          email=args.admin_email)
    srv.db.close()
    ok(f"Setup selesai. Admin: {admin} (role=admin). DB: {args.db}")
    return 0


def _start(args) -> int:
    from keris_enterprise import EnterpriseServer

    srv = EnterpriseServer(host=args.host, port=args.port, db_path=args.db,
                           authorized=args.authorized)
    if args.admin_user and args.admin_password:
        try:
            srv.users.create_user(args.admin_user, args.admin_password,
                                  role="admin", email=args.admin_email or "")
        except Exception:
            warn("Admin sudah ada; lewati pembuatan user.")
    srv.scheduler.start()
    srv.worker.start()
    ok("Scheduler + worker aktif.")
    srv.run_forever()
    return 0


def _worker(args) -> int:
    """Jalankan worker scan saja (dipakai docker-compose service worker)."""
    from keris_enterprise import EnterpriseServer

    srv = EnterpriseServer(host=args.host, port=args.port, db_path=args.db,
                           authorized=args.authorized)
    srv.worker.start()
    ok("Worker scan aktif (Ctrl+C untuk berhenti).")
    try:
        while True:
            srv._shutdown.wait(1.0)
    except KeyboardInterrupt:
        pass
    srv.worker.stop()
    srv.db.close()
    ok("Worker dihentikan")
    return 0


def _scheduler(args) -> int:
    """Jalankan scheduler scan terjadwal saja (docker-compose service)."""
    from keris_enterprise import EnterpriseServer

    srv = EnterpriseServer(host=args.host, port=args.port, db_path=args.db,
                           authorized=args.authorized)
    srv.scheduler.start()
    ok("Scheduler scan terjadwal aktif (Ctrl+C untuk berhenti).")
    try:
        while True:
            srv._shutdown.wait(1.0)
    except KeyboardInterrupt:
        pass
    srv.scheduler.stop()
    srv.db.close()
    ok("Scheduler dihentikan")
    return 0


def _status(args) -> int:
    import json

    from keris_enterprise import EnterpriseServer

    srv = EnterpriseServer(host="127.0.0.1", port=0, db_path=args.db)
    dash = srv.dashboard()
    dash["queue"] = srv.worker.queue_length()
    srv.db.close()
    if args.json:
        print(json.dumps(dash, indent=2, default=str))
    else:
        ok(f"Project: {dash['projects']} | Hasil: {dash['recent_results']} | "
           f"Temuan: {dash['total_findings']} | Remediasi open: "
           f"{dash['remediations_open']} | Queue worker: {dash['queue']}")
    return 0


def _stop(args) -> int:
    warn("keris-enterprise adalah server foreground; hentikan dengan Ctrl+C "
         "di terminal tempat server berjalan, atau kirim SIGTERM.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="keris-enterprise")
    sub = p.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("setup", help="Inisialisasi admin & DB")
    ps.add_argument("--admin-email", default="")
    ps.add_argument("--admin-user", default="admin")
    ps.add_argument("--admin-password", default="admin123")
    ps.add_argument("--db", default="")
    ps.set_defaults(fn=_setup)
    ps2 = sub.add_parser("start", help="Jalankan server + scheduler + worker")
    ps2.add_argument("--host", default="0.0.0.0")
    ps2.add_argument("--port", type=int, default=9000)
    ps2.add_argument("--db", default="")
    ps2.add_argument("--authorized", action="store_true")
    ps2.add_argument("--admin-user", default="")
    ps2.add_argument("--admin-password", default="")
    ps2.add_argument("--admin-email", default="")
    ps2.set_defaults(fn=_start)
    pwk = sub.add_parser("worker", help="Jalankan worker scan saja")
    pwk.add_argument("--host", default="0.0.0.0")
    pwk.add_argument("--port", type=int, default=9000)
    pwk.add_argument("--db", default="")
    pwk.add_argument("--authorized", action="store_true")
    pwk.set_defaults(fn=_worker)
    psch = sub.add_parser("scheduler", help="Jalankan scheduler scan terjadwal")
    psch.add_argument("--host", default="0.0.0.0")
    psch.add_argument("--port", type=int, default=9000)
    psch.add_argument("--db", default="")
    psch.add_argument("--authorized", action="store_true")
    psch.set_defaults(fn=_scheduler)
    ps3 = sub.add_parser("status", help="Ringkasan dashboard")
    ps3.add_argument("--db", default="")
    ps3.add_argument("--json", action="store_true")
    ps3.set_defaults(fn=_status)
    ps4 = sub.add_parser("stop", help="Hentikan server")
    ps4.set_defaults(fn=_stop)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())