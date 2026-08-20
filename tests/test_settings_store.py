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


def test_clear_removes_an_optional_secret():
    store, _ = _store()
    store.update({"ex_client_token": "tok-123"})
    assert store.effective_settings().ex_client_token == "tok-123"
    # A blank alone keeps it; an explicit clear removes it.
    store.update({"ex_client_token": ""})
    assert store.effective_settings().ex_client_token == "tok-123"
    store.update({}, clear=["ex_client_token"])
    assert store.effective_settings().ex_client_token == ""
    assert store.masked()["ex_client_token"] == ""   # shows as unset in the UI


def test_saving_env_equal_value_does_not_shadow_env():
    # Regression: a UI Save must not persist a value identical to the env one, or it
    # would shadow later env changes (e.g. LOG_LEVEL). make_settings sets log_level=INFO.
    settings = make_settings(log_level="INFO")
    sf = build_session_factory(settings.db_url)
    store = SettingsStore(settings, sf)
    store.update({"log_level": "INFO"})                 # same as env -> no override row
    with sf() as s:
        assert s.get(Setting, "log_level") is None
    store.update({"log_level": "DEBUG"})                # a real change -> override
    assert store.effective_settings().log_level == "DEBUG"


def test_saving_env_equal_value_drops_existing_override():
    settings = make_settings(log_level="INFO")
    sf = build_session_factory(settings.db_url)
    store = SettingsStore(settings, sf)
    store.update({"log_level": "DEBUG"})                # create an override
    assert store.effective_settings().log_level == "DEBUG"
    store.update({"log_level": "INFO"})                 # back to env value -> override removed
    with sf() as s:
        assert s.get(Setting, "log_level") is None
    assert store.effective_settings().log_level == "INFO"


def test_clear_masks_an_env_provided_value():
    # A value supplied via env (not the DB) can also be blanked from the UI.
    settings = make_settings(imap_password="from-env")
    sf = build_session_factory(settings.db_url)
    store = SettingsStore(settings, sf)
    assert store.effective_settings().imap_password == "from-env"
    store.update({}, clear=["imap_password"])
    assert store.effective_settings().imap_password == ""
