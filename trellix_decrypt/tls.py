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

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key, pkcs12)
from cryptography.x509.oid import NameOID

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


def serving(settings) -> tuple[str, int, dict]:
    """How the server should bind: (scheme, port, uvicorn-ssl-kwargs).

    HTTPS when ``https_enabled`` and a cert is available → ``https_port``; otherwise plain
    HTTP on ``web_port`` (also the fallback if HTTPS is requested without a cert)."""
    if settings.https_enabled:
        cert, key = active_paths(settings)
        if cert and key:
            ssl = {"ssl_certfile": cert, "ssl_keyfile": key}
            if settings.tls_key_password:
                ssl["ssl_keyfile_password"] = settings.tls_key_password
            return "https", settings.https_port, ssl
    return "http", settings.web_port, {}


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


def generate_self_signed(settings, hostnames, days: int = 825) -> dict:
    """Create a self-signed certificate + key for the given hostnames/IPs and store it.

    Convenience for a standalone/internal host or testing — the traffic is encrypted, but
    the certificate is **untrusted** (browsers warn recipients; EX rejects the webhook if
    its notification 'SSL Verify' is on). Opt-in only; never auto-enabled by default."""
    hosts = [h.strip() for h in hostnames if h and h.strip()] or ["localhost"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    san = []
    for h in hosts:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            san.append(x509.DNSName(h))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    _write(settings, cert.public_bytes(Encoding.PEM),
           key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
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
