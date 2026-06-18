"""Application settings, loaded from environment variables (or a `.env` the operator creates)."""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Trellix EX appliance ---
    ex_base_url: str
    ex_username: str
    ex_password: str
    ex_verify_tls: bool = True

    # An alert triggers the flow if its rule ID is in trigger_rule_ids OR any of
    # its malware names contains one of trigger_malware_names (case-insensitive).
    trigger_rule_ids: list[int] = []
    trigger_malware_names: list[str] = []

    # --- Outbound mail ---
    smtp_host: str
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "attachment-help@example.com"
    smtp_starttls: bool = True

    # --- Web / links ---
    public_base_url: str = "http://localhost:8080"
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    secret_key: str = "change-me"
    token_ttl: int = 86400  # seconds

    # --- Webhook auth ---
    webhook_secret: str = "change-me"
    webhook_ip_allowlist: list[str] = []

    # --- Flow tuning ---
    max_password_attempts: int = 3
    recheck_delay: int = 120
    recheck_interval: int = 60
    recheck_max_attempts: int = 10

    # --- Storage ---
    db_url: str = "sqlite:///trellix_decrypt.sqlite3"

    @field_validator("trigger_rule_ids", "trigger_malware_names", "webhook_ip_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v):
        """Accept comma-separated strings from env vars as lists."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v
