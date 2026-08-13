"""Contoh plugin Python Keris.

Fungsi `run(client, base, ctx)` dipanggil untuk setiap target.
Mengembalikan list objek Finding dari keris.modules.scanner.
"""

from keris.modules.scanner import Finding


def run(client, base, ctx):
    findings = []
    # cek server header yang tidak biasa / server info leak
    server = ctx.get("recon", {}).get("server_header", "")
    if server and "Server:" in server:
        findings.append(Finding(
            severity="INFO",
            title="Informasi server terekspos",
            endpoint=base,
            detail=f"Header Server mengungkap detail: {server}",
            evidence=server,
        ))
    # cek respon OPTIONS yang mengizinkan semua method berbahaya
    try:
        r = client.options(base, timeout=10)
        allow = r.headers.get("Allow", "")
        if allow and {"DELETE", "PUT"} & set(allow.split(",")):
            findings.append(Finding(
                severity="LOW",
                title="HTTP method berbahaya diizinkan",
                endpoint=base,
                detail=f"OPTIONS mengizinkan: {allow}",
                evidence=allow,
            ))
    except Exception:
        pass
    return findings
