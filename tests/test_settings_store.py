"""SettingsStore: env defaults, DB overrides, secret encryption, masking."""

from __future__ import annotations

from trellix_decrypt.settings_store import SettingsStore
from trellix_decrypt.storage import Setting, build_session_factory

from .conftest import make_settings


def _store():
    settings = make_settings()
    sf = build_session_factory(settings.db_url)
    return SettingsStore(settings, sf), sf


def test_overrides_take_precedence_over_env():
    store, _ = _store()
    assert store.effective_settings().max_password_attempts == 3  # env default
    store.update({"max_password_attempts": 5})
    assert store.effective_settings().max_password_attempts == 5


def test_secret_is_encrypted_at_rest_and_roundtrips():
    store, sf = _store()
    store.update({"ex_password": "s3cr3t"})
    with sf() as s:
        row = s.get(Setting, "ex_password")
    assert row.is_secret and row.value != "s3cr3t"          # stored ciphertext
    assert store.effective_settings().ex_password == "s3cr3t"  # decrypts back


def test_masked_hides_secrets_but_shows_plain_fields():
    store, _ = _store()
    store.update({"ex_password": "s3cr3t", "ex_base_url": "https://ex.box"})
    masked = store.masked()
    assert masked["ex_password"] == "********"
    assert masked["ex_base_url"] == "https://ex.box"


def test_blank_secret_keeps_existing():
    store, _ = _store()
    store.update({"ex_password": "first"})
    store.update({"ex_password": ""})        # blank -> unchanged
    store.update({"smtp_password": "********"})  # masked placeholder -> unchanged
    assert store.effective_settings().ex_password == "first"


def test_list_field_roundtrips_as_csv():
    store, _ = _store()
    store.update({"trigger_malware_names": ["A.pdf", "B.zip"]})
    assert store.effective_settings().trigger_malware_names == ["A.pdf", "B.zip"]
