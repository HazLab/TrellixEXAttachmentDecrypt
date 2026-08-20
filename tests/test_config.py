"""Settings parsing from environment variables (the real deployment path)."""

from __future__ import annotations

import pytest

from trellix_decrypt.config import Settings, resolve_secret_key

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


# --- SECRET_KEY resolution -------------------------------------------------

def test_explicit_env_secret_key_wins(tmp_path):
    key_file = tmp_path / "secret.key"
    assert resolve_secret_key("a-real-explicit-key", key_file) == "a-real-explicit-key"
    assert not key_file.exists()  # never persisted when supplied explicitly


def test_placeholder_key_is_generated_and_persisted(tmp_path):
    key_file = tmp_path / "secret.key"
    first = resolve_secret_key("change-me", key_file)      # the shipped placeholder
    assert first and first != "change-me"
    assert key_file.exists()
    # A restart (blank env) reads the SAME persisted key so sessions/tokens survive.
    assert resolve_secret_key("", key_file) == first


# --- required-config / setup gating ----------------------------------------

def _full(**over):
    base = dict(ex_base_url="https://ex", ex_username="u", ex_password="p", smtp_host="smtp",
                smtp_from="a@b", public_base_url="https://x", ui_password="pw",
                webhook_username="w", webhook_password="wp")
    base.update(over)
    return Settings(_env_file=None, **base)


def test_is_configured_true_when_complete():
    assert _full().is_configured() is True


def test_missing_required_flags_gaps():
    s = _full(ui_password="", ex_base_url="")
    missing = s.missing_required()
    assert "ui_password" in missing and "ex_base_url" in missing
    assert s.is_configured() is False


def test_webhook_auth_can_be_ip_allowlist_only():
    s = _full(webhook_username="", webhook_password="", webhook_ip_allowlist=["10.0.0.1"])
    assert "webhook_auth" not in s.missing_required()


def test_webhook_auth_missing_when_neither_creds_nor_allowlist():
    s = _full(webhook_username="", webhook_password="", webhook_ip_allowlist=[])
    assert "webhook_auth" in s.missing_required()
