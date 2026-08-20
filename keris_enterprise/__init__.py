"""keris-enterprise: paket enterprise yang mengintegrasikan fitur keris.

Komponen:
- `auth`  : autentikasi & RBAC (admin, pentester, viewer)
- `orgs`  : multi-tenant organizations + RBAC matrix (permissions)
- `db`    : storage SQLite (dev) / PostgreSQL-ready
- `projects` : manajemen project/client + hasil scan + remediasi
- `scheduler` : cron-based scanning (loop background, `keris watch` terintegrasi)
- `worker` : worker & queue scan async (subprocess keris)
- `alerts` : alerting email/Slack/Teams/webhook + escalation policy
- `integrations` : DefectDojo, Slack/Teams, GitHub/GitLab auto-ticket, Splunk/ELK
- `api`   : REST API untuk semua fungsi (auth, orgs, scan, report, config, users)
- `webui` : dashboard web (risk trend, attack paths, remediation tracking)

Zero-dependency runtime: stdlib `http.server`, `sqlite3`, `smtplib`.
Depend pada `keris` core untuk menjalankan scan & report.
"""

from keris_enterprise.api import EnterpriseServer
from keris_enterprise.auth import (Role, UserStore, hash_password,
                                   verify_password)
from keris_enterprise.orgs import OrgStore, has_permission, rbac_matrix
from keris_enterprise.projects import ProjectStore
from keris_enterprise.worker import ScanWorker

__version__ = "0.1.0"

__all__ = [
    "EnterpriseServer", "UserStore", "ProjectStore", "OrgStore", "ScanWorker",
    "Role", "hash_password", "verify_password", "has_permission",
    "rbac_matrix", "__version__",
]