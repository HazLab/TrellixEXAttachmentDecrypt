"""Settings parsing from environment variables (the real deployment path)."""

from __future__ import annotations

import pytest

from trellix_decrypt.config import Settings

REQUIRED = {
    "EX_BASE_URL": "https://ex.test",
    "EX_USERNAME": "u",
    "EX_PASSWORD": "p",
    "SMTP_HOST": "smtp.test",
}


@pytest.fixture
def env(monkeypatch):
    # Ensure no stray .env / real env vars leak in, then set the required ones.
    for key in ("TRIGGER_MALWARE_NAMES", "WEBHOOK_IP_ALLOWLIST"):
        monkeypatch.delenv(key, raising=False)
    for key, val in REQUIRED.items():
        monkeypatch.setenv(key, val)
    return monkeypatch


def test_comma_separated_malware_names_from_env(env):
    env.setenv("TRIGGER_MALWARE_NAMES", "CustomPolicy.MVX.pdf,CustomPolicy.MVX.zip,CustomPolicy.MVX.65066.PassExtractFailed")
    s = Settings(_env_file=None)
    assert s.trigger_malware_names == [
        "CustomPolicy.MVX.pdf", "CustomPolicy.MVX.zip", "CustomPolicy.MVX.65066.PassExtractFailed"]


def test_ip_allowlist_from_env(env):
    env.setenv("WEBHOOK_IP_ALLOWLIST", "10.0.0.1, 10.0.0.2")
    s = Settings(_env_file=None)
    assert s.webhook_ip_allowlist == ["10.0.0.1", "10.0.0.2"]


def test_list_defaults_when_env_absent(env):
    s = Settings(_env_file=None)
    assert "CustomPolicy.MVX.pdf" in s.trigger_malware_names
    assert s.webhook_ip_allowlist == []
