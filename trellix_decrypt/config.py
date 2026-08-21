"""Application settings, loaded from environment variables (or a `.env` the operator creates)."""

from __future__ import annotations

from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Trellix EX appliance ---
    # These are operationally required (enforced by missing_required / setup mode) but
    # default to empty so the service can boot into setup mode and be configured via UI.
    ex_base_url: str = ""
    ex_username: str = ""
    ex_password: str = ""
    ex_verify_tls: bool = False  # default off — EX appliances commonly use self-signed certs
    ex_client_token: str = ""  # optional X-FeClient-Token, provided by Trellix
    ex_timeout: int = 60  # HTTP timeout (s) for EX API calls — EX can be slow

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
    smtp_host: str = ""  # required in practice (see missing_required); empty enables setup mode
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "attachment-help@example.com"
    # TLS mode: opportunistic (STARTTLS if offered, else plaintext), starttls
    # (require STARTTLS), none (never), ssl (implicit TLS / SMTPS, e.g. port 465).
    smtp_tls_mode: str = "opportunistic"
    # Verify the SMTP server's TLS certificate. Default off for self-signed / lab CAs
    # (e.g. "basic constraints ... not marked critical"); enable in production.
    smtp_verify_tls: bool = False
    # HELO/EHLO name announced to the server. Some servers require a FQDN here
    # and reject the OS hostname (504 5.5.2). Set to a fully-qualified name.
    smtp_helo_hostname: str = ""

    # --- Web / links ---
    public_base_url: str = "http://localhost:8080"
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    # Blank by default: on first run a strong random key is generated and persisted
    # (see resolve_secret_key). NEVER ship a shared literal default — that would be
    # identical on every install and so no secret at all.
    secret_key: str = ""
    token_ttl: int = 86400  # seconds
    ui_password: str = ""  # admin password gating the dashboard/settings UI (UI_PASSWORD)

    # --- Native HTTPS (optional; else a reverse proxy terminates TLS) ---
    # Explicit PEM paths win; otherwise the app uses a cert/key imported via the admin UI
    # into DATA_DIR/tls/. With neither, it serves plain HTTP. Applied at startup (restart).
    tls_cert_file: str = ""       # PEM certificate (chain ok)
    tls_key_file: str = ""        # PEM private key
    tls_key_password: str = ""    # password if TLS_KEY_FILE is encrypted
    # Opt-in: if true and no cert is present, generate a SELF-SIGNED one on startup (for a
    # standalone/internal host or testing). Untrusted — browsers warn; enable EX's SSL
    # Verify off for the webhook, or use a real cert/proxy. Off by default.
    tls_self_signed: bool = False
    # Serve HTTPS (needs a cert — imported or self-signed) on https_port; otherwise serve
    # plain HTTP on web_port. Restart to apply.
    https_enabled: bool = False
    https_port: int = 8443

    # --- Webhook auth (EX HTTP notification posts here using Basic auth) ---
    webhook_username: str = ""
    webhook_password: str = ""
    webhook_ip_allowlist: Annotated[list[str], NoDecode] = []

    # --- Rate limiting (public POST endpoints; self-healing, per-IP) ---
    # Windowed limits: N attempts per window, then HTTP 429 until the window rolls
    # off. In-memory, so a restart also clears them — there is no permanent lockout.
    login_rate_limit: int = 10          # failed admin sign-ins per IP per window
    login_rate_window: int = 900        # seconds (15 min)
    form_rate_limit: int = 10           # password submissions per (IP+token) per window
    form_rate_window: int = 300         # seconds (5 min)
    # Trust the reverse proxy's X-Forwarded-For for the client IP (enable only when
    # actually behind a trusted proxy; the header is otherwise spoofable).
    trust_forwarded_for: bool = False
    # Reject webhook / password bodies larger than this many bytes (cheap DoS guard).
    max_request_bytes: int = 1_048_576  # 1 MiB

    # --- Flow tuning ---
    max_password_attempts: int = 3
    # Recheck polling. A released/clean email sends no push, so it's found only by the
    # poll — kept eager so it doesn't sit in "rechecking". recheck_delay is the wait
    # before the FIRST poll; after a short eager ramp the poll settles to
    # recheck_interval, for recheck_max_attempts polls total.
    recheck_delay: int = 10
    recheck_interval: int = 30
    recheck_max_attempts: int = 12

    # --- Reconciliation (backfill trigger alerts missed while the app was down) ---
    # On startup (and, if reconcile_interval > 0, periodically) query EX for recent
    # alerts and start the flow for any matching email we have no case for. Idempotent
    # (dedup by queue id; skips _RA re-detections), so it's safe to run repeatedly and
    # alongside EX's own notification retries — it won't create duplicates or re-email.
    reconcile_lookback: str = "48_hours"   # EX alerts-query duration to scan
    reconcile_interval: int = 1800         # seconds between periodic sweeps (0 = startup only)
    # Auto-retry of failed recipient emails (SMTP errors).
    notify_max_retries: int = 5
    notify_retry_interval: int = 300  # seconds between background retry sweeps
    # Auto-retry of failed EX resubmissions (rescan errors / EX briefly down).
    resubmit_max_retries: int = 5
    resubmit_retry_interval: int = 120  # seconds between background rescan-retry sweeps

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
    # Directory for persistent state that must survive restarts — the auto-generated
    # secret.key and (when DB_URL is left at its default) the SQLite file. Point this
    # at a mounted volume for Docker or a writable path for the packaged executable.
    # Empty = the current working directory (unchanged legacy behaviour).
    data_dir: str = ""
    db_url: str = "sqlite:///trellix_decrypt.sqlite3"

    # --- Logging ---
    log_level: str = "INFO"  # DEBUG for verbose troubleshooting
    log_file: str = "trellix_decrypt.log"  # also write all logs (incl. every HTTP request) here; "" = console only
    log_file_max_bytes: int = 10_000_000   # rotate at ~10 MB
    log_file_backups: int = 5              # keep this many rotated files

    @field_validator("trigger_malware_names", "webhook_ip_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v):
        """Accept comma-separated strings from env vars as lists."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    def webhook_auth_configured(self) -> bool:
        """The webhook is safe to serve only with Basic-auth creds and/or an IP allowlist."""
        return bool(self.webhook_username or self.webhook_password or self.webhook_ip_allowlist)

    def missing_required(self) -> list[str]:
        """Settings that must be provided before the service is operational. The admin
        password is required so the UI can't be left open; SECRET_KEY is intentionally
        NOT here (auto-generated). Used to drive first-run setup mode."""
        required = {
            "ex_base_url": self.ex_base_url,
            "ex_username": self.ex_username,
            "ex_password": self.ex_password,
            "smtp_host": self.smtp_host,
            "smtp_from": self.smtp_from,
            "public_base_url": self.public_base_url,
            "ui_password": self.ui_password,
        }
        missing = [k for k, v in required.items() if not str(v or "").strip()]
        if not self.webhook_auth_configured():
            missing.append("webhook_auth")  # username+password and/or ip allowlist
        return missing

    def is_configured(self) -> bool:
        return not self.missing_required()


#: Placeholder still found in old .env files; treated as "unset" so a real key is generated.
INSECURE_SECRET_KEYS = frozenset({"", "change-me", "changeme", "secret", "please-change-me"})


def resolve_secret_key(env_value: str, key_path: str) -> str:
    """Return a stable, strong SECRET_KEY.

    Precedence: an explicit, non-placeholder ``SECRET_KEY`` env value wins. Otherwise
    read a previously-generated key from ``key_path``; if absent, generate a strong one
    and persist it there (0600) so tokens, sessions, and encrypted secrets survive
    restarts. This removes the shipped ``change-me`` default without forcing the
    operator to invent a key. Rotating the key invalidates held passwords/sessions.
    """
    import os
    import secrets
    from pathlib import Path

    if str(env_value or "").strip().lower() not in INSECURE_SECRET_KEYS:
        return env_value
    path = Path(key_path)
    if path.exists():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    generated = secrets.token_urlsafe(48)
    path.write_text(generated, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # best-effort on platforms without POSIX perms
        pass
    return generated
