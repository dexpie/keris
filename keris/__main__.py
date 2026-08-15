"""Entry point CLI untuk Keris (bootstrap).

Seluruh implementasi dipisah ke package `keris.cli`:
- parser & helper bersama:  keris.cli.common
- command handler per domain: keris.cli.{scan,recon,auth,report,monitor}
- dispatcher:               keris.cli.main

Modul ini hanya re-export nama-nama yang dipakai oleh test/consumer lama
sehingga tetap backward compatible.
"""

import sys
from typing import List, Optional

from keris import __version__  # noqa: F401
from keris.cli.common import (  # noqa: F401
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    _exit_code,
    _history_path,
    _load_history,
    _make_client,
    _parse_args,
    _save_history,
    _suffixed,
)
from keris.cli.main import main  # noqa: F401
from keris.cli.scan import _cmd_retest  # noqa: F401

if __name__ == "__main__":
    sys.exit(main())