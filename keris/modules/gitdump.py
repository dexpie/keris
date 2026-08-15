"""Full .git dump & source recovery.

Ketika /.git terbaca publik, modul ini mengunduh seluruh repository:
- HEAD, config, index
- object blobs/trees/commits (sha1) — via /.git/objects/xx/rest
- paket objects (/.git/objects/pack/*.idx + *.pack) bila ada
- rekonstruksi isi file dari blob (compress zlib) + parse tree untuk
  menemukan nama path file

Hasil ditulis ke direktori `outdir` (default ./.gitdump-<host>) sehingga
tester bisa memeriksa source code dan secret yang pernah di-commit.

GUARD: memerlukan `authorized=True`; tanpa itu modul menolak beroperasi.
"""

import os
import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from keris.core.http import KerisHTTP
from keris.core.logger import debug, info, ok, warn
from keris.modules.scanner import Finding

GIT_OBJECTS = "/.git/objects/"
HEAD_RE = re.compile(rb"ref: refs/heads/([^\n]+)")


def _parse_index_entries(data: bytes) -> List[Tuple[str, str]]:
    """Parse git index -> [(path, sha20hex), ...].

    Entry index v2: 10 uint32 (40 byte) + sha1(20) + flags(2) = 62 byte,
    lalu path NUL-terminated dan dipad ke kelipatan 8.
    """
    if not data.startswith(b"DIRC") or len(data) < 12:
        return []
    try:
        count = struct.unpack(">I", data[8:12])[0]
    except Exception:
        return []
    entries = []
    pos = 12
    for _ in range(count):
        if pos + 62 > len(data):
            break
        entry_start = pos
        sha = data[pos + 40:pos + 60]
        name_len = struct.unpack(">H", data[pos + 60:pos + 62])[0] & 0x0FFF
        null = data.find(b"\x00", pos + 62, pos + 62 + name_len + 8)
        if null == -1:
            break
        path = data[pos + 62:null].decode("utf-8", "replace")
        if path:
            entries.append((path, sha.hex()))
        # pad ke kelipatan 8 relatif terhadap AWAL entry (62 + path + nul)
        entry_total = 62 + (null - entry_start - 62) + 1
        pad = (8 - entry_total % 8) % 8
        pos = null + 1 + pad
    return entries


def _decompress(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except Exception:
        return b""


def _fetch(client: KerisHTTP, url: str) -> Optional[Tuple[int, bytes]]:
    try:
        r = client.get(url, timeout=15)
        return r.status_code, r.content or b""
    except Exception:
        return None


def dump_git(base: str, client: KerisHTTP, outdir: str = "",
             max_objects: int = 300, authorized: bool = False) -> List[Finding]:
    """Unduh & rekonstruksi repo .git publik ke direktori."""
    if not authorized:
        warn("Git dump memerlukan --authorized.")
        return []
    base = base.rstrip("/")
    if not outdir:
        host = (base.split("//")[-1].split("/")[0] or "target").replace(":", "_")
        outdir = f".gitdump-{host}"
    os.makedirs(outdir, exist_ok=True)
    findings: List[Finding] = []

    # 1. index -> daftar (file, sha)
    code, idx = _fetch(client, base + "/.git/index")
    entries = _parse_index_entries(idx) if code == 200 else []
    info(f"Index .git: {len(entries)} file terdaftar")

    # 2. download object per blob sha
    recovered = 0
    if entries:
        for path, sha_hex in entries:
            if recovered >= max_objects:
                break
            obj_url = base + GIT_OBJECTS + sha_hex[:2] + "/" + sha_hex[2:]
            c2, body = _fetch(client, obj_url)
            raw = _decompress(body) if c2 == 200 else b""
            if raw and raw.startswith(b"blob "):
                content = raw.split(b"\x00", 1)[1] if b"\x00" in raw else b""
                dest = os.path.join(outdir, "source", path)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    with open(dest, "wb") as f:
                        f.write(content)
                    recovered += 1
                except Exception:
                    pass

    # 3. coba tarik packfile bila ada
    packs = 0
    code, listing = _fetch(client, base + "/.git/objects/pack/")
    if code == 200 and listing:
        for m in re.finditer(rb"[0-9a-f]{40}\.idx", listing):
            pack_id = m.group(0)[:-4].decode()
            pack_url = base + "/.git/objects/pack/" + pack_id + ".pack"
            c3, pbody = _fetch(client, pack_url)
            if c3 == 200 and pbody:
                dest = os.path.join(outdir, "pack", pack_id + ".pack")
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(pbody)
                packs += 1
                if packs >= 3:
                    break

    # 4. branch name dari HEAD
    code, head = _fetch(client, base + "/.git/HEAD")
    branch = ""
    if code == 200:
        m = HEAD_RE.search(head or b"")
        branch = m.group(1).decode("utf-8", "replace") if m else ""

    if recovered or packs:
        findings.append(Finding(
            "CRITICAL", "Source code direkonstruksi dari .git dump",
            base + "/.git/",
            f"Berhasil mengunduh {recovered} blob + {packs} pack dari "
            f"repository. Source code tersimpan di `{outdir}`; periksa "
            "secret yang pernah di-commit.",
            f"blobs={recovered}, packs={packs}, branch={branch}",
            cwe="CWE-540",
            references="https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
        ))
        ok(f"Git dump: {recovered} file direkonstruksi ke {outdir}")
    else:
        info("Index terbaca tapi object blob tidak dapat diunduh "
             "(filter mungkin memblokir /objects/)")
    return findings
