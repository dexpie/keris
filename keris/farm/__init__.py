"""Distributed scanning cluster (v0.16.0): master-worker farm.

Paket `keris.farm` menyediakan:
- `master.py` : master node (REST API + SQLite + aggregasi)
- `worker.py` : worker node (register, claim job, jalankan scan, kirim hasil)
- `client.py` : klien API untuk submit/status/stop
- `auth.py`   : JWT sederhana berbasis HMAC (zero-dep)

Komunikasi HTTP REST dengan JWT. Load balancing: worker meng-claim job
berdasarkan kapasitasnya; job yang ditinggalkan worker mati akan di-reassign.
Storage metadata SQLite; report disimpan lokal (mirip S3 object store).

CLI:
    keris farm master --port 8080
    keris farm worker --master http://localhost:8080 --capacity 3
    keris farm submit --targets targets.txt
    keris farm status
    keris farm stop
"""

from keris.farm.auth import (create_token, read_secret, verify_token)
from keris.farm.client import (FarmClient, submit_jobs, farm_status, farm_stop)
from keris.farm.master import MasterServer
from keris.farm.worker import WorkerLoop

__all__ = [
    "MasterServer", "WorkerLoop", "FarmClient",
    "submit_jobs", "farm_status", "farm_stop",
    "create_token", "verify_token", "read_secret",
]