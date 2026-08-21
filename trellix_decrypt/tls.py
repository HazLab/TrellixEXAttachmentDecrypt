"""Optional native HTTPS: manage the TLS certificate/key the app serves with.

If a cert + key are present — via ``TLS_CERT_FILE`` / ``TLS_KEY_FILE``, or imported
through the admin UI into ``DATA_DIR/tls/`` — the server starts with TLS; otherwise it
serves plain HTTP and a reverse proxy is expected to terminate HTTPS (still recommended
for automatic renewal in production, but now optional).

Imported material (PEM cert+key, or a PKCS#12 / .pfx bundle) is normalised to PEM — the
certificate chain and an unencrypted PKCS#8 key — and written ``0600`` under
``DATA_DIR/tls/``, which Uvicorn reads at startup.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key, pkcs12)

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"


def data_dir_for(settings) -> Path:
    return Path(settings.data_dir) if settings.data_dir else Path.cwd()


def tls_dir(settings) -> Path:
    return data_dir_for(settings) / "tls"


def active_paths(settings) -> tuple[str | None, str | None]:
    """Cert/key the server should serve with: explicit env paths win, else the files
    imported under ``DATA_DIR/tls``, else ``(None, None)`` → plain HTTP."""
    if (settings.tls_cert_file and settings.tls_key_file
            and Path(settings.tls_cert_file).exists() and Path(settings.tls_key_file).exists()):
        return settings.tls_cert_file, settings.tls_key_file
    d = tls_dir(settings)
    cert, key = d / CERT_NAME, d / KEY_NAME
    if cert.exists() and key.exists():
        return str(cert), str(key)
    return None, None


def _write(settings, cert_pem: bytes, key_pem: bytes) -> None:
    d = tls_dir(settings)
    d.mkdir(parents=True, exist_ok=True)
    (d / CERT_NAME).write_bytes(cert_pem)
    (d / KEY_NAME).write_bytes(key_pem)
    for f in (d / CERT_NAME, d / KEY_NAME):
        try:
            os.chmod(f, 0o600)
        except OSError:  # best-effort on platforms without POSIX perms
            pass


def _spki(pub) -> bytes:
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _describe(cert: x509.Certificate) -> dict:
    def s(name):
        try:
            return name.rfc4514_string()
        except Exception:  # noqa: BLE001
            return str(name)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {"subject": s(cert.subject), "issuer": s(cert.issuer), "not_after": na.isoformat()}


def install_pem(settings, cert_bytes: bytes, key_bytes: bytes, key_password: str = "") -> dict:
    """Validate and store a PEM certificate (+ optional chain) and private key."""
    key = load_pem_private_key(key_bytes, password=(key_password.encode() if key_password else None))
    cert = x509.load_pem_x509_certificate(cert_bytes)  # validates the leaf parses
    if _spki(cert.public_key()) != _spki(key.public_key()):
        raise ValueError("the certificate and private key do not match")
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    _write(settings, cert_bytes, key_pem)  # keep original cert bytes to preserve any chain
    return _describe(cert)


def install_pkcs12(settings, data: bytes, password: str = "") -> dict:
    """Validate and store a PKCS#12 (.p12 / .pfx) bundle, converting it to PEM."""
    key, cert, extra = pkcs12.load_key_and_certificates(data, password.encode() if password else None)
    if key is None or cert is None:
        raise ValueError("the PKCS#12 file must contain a certificate and a private key")
    chain = cert.public_bytes(Encoding.PEM)
    for c in (extra or []):
        chain += c.public_bytes(Encoding.PEM)
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    _write(settings, chain, key_pem)
    return _describe(cert)


def remove(settings) -> None:
    d = tls_dir(settings)
    for n in (CERT_NAME, KEY_NAME):
        try:
            (d / n).unlink()
        except FileNotFoundError:
            pass


def status(settings) -> dict:
    """UI status: whether HTTPS is active and, if so, the cert's subject/issuer/expiry."""
    cert_path, _ = active_paths(settings)
    if not cert_path:
        return {"active": False}
    out = {"active": True, "source": "environment" if settings.tls_cert_file else "uploaded"}
    try:
        out.update(_describe(x509.load_pem_x509_certificate(Path(cert_path).read_bytes())))
    except Exception:  # noqa: BLE001 — status is best-effort
        pass
    return out
