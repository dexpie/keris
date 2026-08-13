"""Analisis sertifikat TLS/SSL: masa berlaku, issuer, SAN, protokol lemah.

Non-destruktif: melakukan handshake TLS ke host target (default port 443).
"""

import datetime
import socket
import ssl
from typing import Dict, List, Optional

from keris.core.logger import debug, info, ok, warn

WEAK_PROTOCOLS = ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]


def _get_cert(host: str, port: int = 443, timeout: float = 8.0) -> Optional[dict]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                version = ssock.version()
                if not der:
                    return None
                try:
                    import certifi

                    _ = certifi.where()
                except ImportError:
                    pass
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_der_x509_certificate(der, default_backend())
                san = set()
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san = set(ext.value.get_values_for_type(x509.DNSName))
                except x509.ExtensionNotFound:
                    pass
                return {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": cert.not_valid_before_utc.isoformat(),
                    "not_after": cert.not_valid_after_utc.isoformat(),
                    "san": sorted(san),
                    "serial": hex(cert.serial_number),
                    "tls_version": version or "unknown",
                }
    except (socket.timeout, OSError, ssl.SSLError) as e:
        debug(f"TLS handshake gagal {host}:{port}: {e}")
        return None


def check_tls_cert(host: str, port: int = 443, timeout: float = 8.0) -> Dict:
    """Analisis sertifikat dan protokol TLS dari host."""
    info(f"TLS certificate check: {host}:{port}")
    result = {"host": host, "port": port, "cert": None, "issues": [], "weak_protocols": []}

    cert = _get_cert(host, port, timeout)
    if not cert:
        result["issues"].append(("MEDIUM", "Tidak dapat mengambil sertifikat TLS (koneksi gagal)."))
        warn("Tidak dapat mengambil sertifikat TLS")
        return result

    result["cert"] = cert
    ok(f"Sertifikat: issuer={cert['issuer']}, expires={cert['not_after']}")

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        not_after = datetime.datetime.fromisoformat(cert["not_after"])
        not_before = datetime.datetime.fromisoformat(cert["not_before"])
        if not_after < now:
            result["issues"].append(("HIGH", "Sertifikat TLS sudah kedaluwarsa."))
        elif (not_after - now).days < 30:
            result["issues"].append(("MEDIUM", f"Sertifikat hampir kedaluwarsa "
                                               f"({(not_after - now).days} hari lagi)."))
        if not_before > now:
            result["issues"].append(("MEDIUM", "Sertifikat belum berlaku (notBefore di masa depan)."))
    except ValueError:
        pass

    # periksa protokol lemah
    for proto in WEAK_PROTOCOLS:
        if _protocol_supported(host, port, proto):
            result["weak_protocols"].append(proto)
            result["issues"].append(("MEDIUM", f"Protokol lemah didukung: {proto}"))

    if "self-signed" in cert["issuer"].lower() or cert["issuer"] == cert["subject"]:
        result["issues"].append(("LOW", "Sertifikat tampak self-signed."))

    return result


def _protocol_supported(host: str, port: int, proto: str, timeout: float = 6.0) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        min_ver = {"TLSv1.2": ssl.TLSVersion.TLSv1_2,
                   "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                   "TLSv1": ssl.TLSVersion.TLSv1,
                   "SSLv3": ssl.TLSVersion.SSLv3}.get(proto)
        if min_ver is not None:
            ctx.minimum_version = min_ver
        ctx.maximum_version = min_ver  # batasi ke protokol tersebut saja
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False
