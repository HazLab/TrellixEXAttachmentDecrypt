"""Application settings, loaded from environment variables (or a `.env` the operator creates)."""

from __future__ import annotations

from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Trellix EX appliance ---
    ex_base_url: str
    ex_username: str
    ex_password: str
    ex_verify_tls: bool = True
    ex_client_token: str = ""  # optional X-FeClient-Token, provided by Trellix

    # An alert triggers the flow only when its top-level "name" equals
    # trigger_alert_name AND one of its malware names exactly equals one of
    # trigger_malware_names (case-insensitive). The encrypted-attachment custom
    # policy emits CustomPolicy.MVX.<ext>. An empty list disables triggering
    # (prevents firing on unrelated riskware objects).
    trigger_alert_name: str = "RISKWARE_OBJECT"
    # NoDecode: take the env value as a raw string so the CSV validator handles it
    # (pydantic-settings otherwise tries to JSON-decode list fields from env).
    trigger_malware_names: Annotated[list[str], NoDecode] = [
        "CustomPolicy.MVX.pdf", "CustomPolicy.MVX.zip", "CustomPolicy.MVX.docx",
        "CustomPolicy.MVX.65066.PassExtractFailed",
    ]

    # --- Outbound mail ---
    smtp_host: str
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "attachment-help@example.com"
    smtp_starttls: bool = True
    # HELO/EHLO name announced to the server. Some servers require a FQDN here
    # and reject the OS hostname (504 5.5.2). Set to a fully-qualified name.
    smtp_helo_hostname: str = ""

    # --- Web / links ---
    public_base_url: str = "http://localhost:8080"
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    secret_key: str = "change-me"
    token_ttl: int = 86400  # seconds
    ui_password: str = ""  # admin password gating the dashboard/settings UI (UI_PASSWORD)

    # --- Webhook auth (EX HTTP notification posts here using Basic auth) ---
    webhook_username: str = ""
    webhook_password: str = ""
    webhook_ip_allowlist: Annotated[list[str], NoDecode] = []

    # --- Flow tuning ---
    max_password_attempts: int = 3
    recheck_delay: int = 120
    recheck_interval: int = 60
    recheck_max_attempts: int = 10
    # Auto-retry of failed recipient emails (SMTP errors).
    notify_max_retries: int = 5
    notify_retry_interval: int = 300  # seconds between background retry sweeps

    # --- Bounce monitoring (IMAP poll of the sender mailbox for DSNs) ---
    # Leave imap_host blank to disable. Detects "accepted then bounced" mail and
    # flips the case to BOUNCED.
    imap_host: str = ""
    imap_port: int = 993
    imap_username: str = ""
    imap_password: str = ""
    imap_ssl: bool = True
    imap_mailbox: str = "INBOX"
    bounce_poll_interval: int = 120  # seconds

    # --- Storage ---
    db_url: str = "sqlite:///trellix_decrypt.sqlite3"

    # --- Logging ---
    log_level: str = "INFO"  # DEBUG for verbose troubleshooting

    @field_validator("trigger_malware_names", "webhook_ip_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v):
        """Accept comma-separated strings from env vars as lists."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v
