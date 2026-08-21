"""Native-HTTPS cert/key import (PEM + PKCS#12) and status."""

from __future__ import annotations

import datetime
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat, pkcs12)
from cryptography.x509.oid import NameOID

from trellix_decrypt import tls


class _Settings:
    def __init__(self, data_dir):
        self.data_dir = str(data_dir)
        self.tls_cert_file = ""
        self.tls_key_file = ""
        self.tls_key_password = ""


def _self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "decrypt.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2100, 1, 1))
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return cert_pem, key_pem, key, cert


def test_install_pem_activates_https_then_remove(tmp_path):
    s = _Settings(tmp_path)
    assert tls.active_paths(s) == (None, None)      # HTTP by default
    cert_pem, key_pem, _, _ = _self_signed()
    info = tls.install_pem(s, cert_pem, key_pem)
    assert "decrypt.test" in info["subject"]
    cert, key = tls.active_paths(s)
    assert cert and key and os.path.exists(cert) and os.path.exists(key)
    st = tls.status(s)
    assert st["active"] is True and st["source"] == "uploaded"
    tls.remove(s)
    assert tls.active_paths(s) == (None, None)      # reverted to HTTP


def test_install_pem_rejects_mismatched_key(tmp_path):
    s = _Settings(tmp_path)
    cert_pem, _, _, _ = _self_signed()
    _, other_key_pem, _, _ = _self_signed()          # a different key
    with pytest.raises(ValueError):
        tls.install_pem(s, cert_pem, other_key_pem)


def test_install_pkcs12(tmp_path):
    s = _Settings(tmp_path)
    _, _, key, cert = _self_signed()
    p12 = pkcs12.serialize_key_and_certificates(b"friendly", key, cert, None,
                                                BestAvailableEncryption(b"pw"))
    info = tls.install_pkcs12(s, p12, "pw")
    assert "decrypt.test" in info["subject"]
    assert tls.status(s)["active"] is True


def test_tls_import_endpoint(tmp_path):
    from starlette.testclient import TestClient

    from trellix_decrypt.web import create_app

    from .conftest import make_context
    ctx = make_context(ui_password="", data_dir=str(tmp_path))   # setup mode → TLS API open
    client = TestClient(create_app(ctx))
    assert client.get("/api/tls").json()["active"] is False
    cert_pem, key_pem, _, _ = _self_signed()
    r = client.post("/api/tls", data={"mode": "pem"},
                    files={"cert": ("c.pem", cert_pem), "key": ("k.pem", key_pem)})
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["restart_required"] is True
    assert client.get("/api/tls").json()["active"] is True
    assert client.post("/api/tls/remove").json()["ok"] is True
    assert client.get("/api/tls").json()["active"] is False


def test_generate_self_signed(tmp_path):
    s = _Settings(tmp_path)
    info = tls.generate_self_signed(s, ["decrypt.example.com", "127.0.0.1"])
    assert "decrypt.example.com" in info["subject"]
    cert_path, key_path = tls.active_paths(s)
    assert cert_path and key_path
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "decrypt.example.com" in san.get_values_for_type(x509.DNSName)
    assert tls.status(s)["active"] is True


def test_generate_self_signed_defaults_to_localhost(tmp_path):
    s = _Settings(tmp_path)
    info = tls.generate_self_signed(s, [])   # empty -> localhost
    assert "localhost" in info["subject"]


class _Serve(_Settings):
    def __init__(self, data_dir, **kw):
        super().__init__(data_dir)
        self.web_port = 8080
        self.https_port = 8443
        self.https_enabled = False
        for k, v in kw.items():
            setattr(self, k, v)


def test_serving_http_by_default(tmp_path):
    s = _Serve(tmp_path)
    scheme, port, ssl = tls.serving(s)
    assert scheme == "http" and port == 8080 and ssl == {}


def test_serving_https_when_enabled_with_cert(tmp_path):
    s = _Serve(tmp_path, https_enabled=True)
    cert_pem, key_pem, _, _ = _self_signed()
    tls.install_pem(s, cert_pem, key_pem)
    scheme, port, ssl = tls.serving(s)
    assert scheme == "https" and port == 8443 and "ssl_certfile" in ssl


def test_serving_falls_back_to_http_when_https_enabled_without_cert(tmp_path):
    s = _Serve(tmp_path, https_enabled=True)
    scheme, port, ssl = tls.serving(s)
    assert scheme == "http" and port == 8080 and ssl == {}


def test_env_paths_take_precedence(tmp_path):
    # explicit TLS_CERT_FILE/TLS_KEY_FILE win over the DATA_DIR/tls upload location
    cert_pem, key_pem, _, _ = _self_signed()
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(cert_pem); kf.write_bytes(key_pem)
    s = _Settings(tmp_path)
    s.tls_cert_file, s.tls_key_file = str(cf), str(kf)
    assert tls.active_paths(s) == (str(cf), str(kf))
    assert tls.status(s)["source"] == "environment"
