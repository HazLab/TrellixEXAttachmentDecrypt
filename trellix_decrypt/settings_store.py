"""UI-editable settings: env defaults overlaid with DB overrides.

Secrets are encrypted at rest with Fernet, keyed by the deployment SECRET_KEY.
``effective_settings()`` returns a fully-validated Settings object the rest of
the app uses; the AppContext rebuilds the EX client/mailer from it on save.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet
from sqlalchemy import select

from .config import Settings
from .storage import Setting

# Fields the settings UI may change (everything else is infra: db_url, web_*,
# secret_key, ui_password — set via environment only).
EDITABLE = (
    "ex_base_url", "ex_username", "ex_password", "ex_verify_tls", "ex_client_token",
    "smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from", "smtp_tls_mode",
    "smtp_helo_hostname",
    "trigger_alert_name", "trigger_malware_names",
    "max_password_attempts", "recheck_delay", "recheck_interval", "recheck_max_attempts",
    "notify_max_retries", "notify_retry_interval",
    "imap_host", "imap_port", "imap_username", "imap_password", "imap_ssl", "imap_mailbox",
    "bounce_poll_interval",
    "public_base_url", "webhook_username", "webhook_password", "token_ttl",
)
SECRET_KEYS = frozenset({"ex_password", "smtp_password", "ex_client_token", "webhook_password", "imap_password"})
LIST_KEYS = frozenset({"trigger_malware_names"})


def _fernet(secret_key: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest()))


class SettingsStore:
    def __init__(self, env: Settings, session_factory):
        self._env = env
        self._sf = session_factory
        self._fernet = _fernet(env.secret_key)

    def _overrides(self) -> dict:
        out: dict = {}
        with self._sf() as s:
            for row in s.scalars(select(Setting)).all():
                value = row.value
                if row.is_secret and value:
                    value = self._fernet.decrypt(value.encode()).decode()
                if row.key in LIST_KEYS and isinstance(value, str):
                    value = [p.strip() for p in value.split(",") if p.strip()]
                out[row.key] = value
        return out

    def effective_settings(self) -> Settings:
        data = self._env.model_dump()
        data.update(self._overrides())
        return Settings(**data)

    def masked(self) -> dict:
        """Current editable values for the settings form; secrets shown only as set/unset."""
        eff = self.effective_settings()
        out = {}
        for key in EDITABLE:
            value = getattr(eff, key)
            if key in SECRET_KEYS:
                out[key] = "********" if value else ""
            elif key in LIST_KEYS:
                out[key] = ", ".join(value)
            else:
                out[key] = value
        return out

    def update(self, changes: dict) -> None:
        with self._sf() as s:
            for key, value in changes.items():
                if key not in EDITABLE:
                    continue
                if key in SECRET_KEYS:
                    if value in (None, "", "********"):  # blank / unchanged -> keep existing
                        continue
                    value = self._fernet.encrypt(str(value).encode()).decode()
                elif isinstance(value, list):
                    value = ",".join(str(v) for v in value)
                else:
                    value = str(value)
                row = s.get(Setting, key)
                if row is None:
                    s.add(Setting(key=key, value=value, is_secret=key in SECRET_KEYS))
                else:
                    row.value = value
            s.commit()
