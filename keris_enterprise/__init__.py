"""keris-enterprise: paket enterprise yang mengintegrasikan fitur keris.

Komponen:
- `auth`  : autentikasi & RBAC (admin, pentester, viewer)
- `db`    : storage SQLite (dev) / PostgreSQL-ready
- `projects` : manajemen project/client + penjadwalan scan per project
- `scheduler` : cron-based scanning (loop background, `keris watch` terintegrasi)
- `alerts` : alerting email/Slack/Teams/webhook + escalation policy
- `integrations` : DefectDojo, Slack/Teams, GitHub/GitLab auto-ticket, Splunk/ELK
- `api`   : REST API untuk semua fungsi (scan, report, config, users)
- `webui` : dashboard web (risk trend, attack paths, remediation tracking)

Zero-dependency runtime: stdlib `http.server`, `sqlite3`, `smtplib`.
Depend pada `keris` core untuk menjalankan scan & report.
"""

from keris_enterprise.api import EnterpriseServer
from keris_enterprise.auth import (Role, UserStore, hash_password,
                                   verify_password)
from keris_enterprise.projects import ProjectStore

__version__ = "0.1.0"

__all__ = [
    "EnterpriseServer", "UserStore", "ProjectStore",
    "Role", "hash_password", "verify_password", "__version__",
]