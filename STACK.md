# Tech stack

The technologies used by the Trellix EX encrypted-attachment recovery service.
See `documentation/documentation.md` for architecture and module layout, and
`pyproject.toml` for exact version pins.

## Language & runtime

- **Python ≥ 3.11** — async throughout (`asyncio`).
- Packaged with **setuptools** via `pyproject.toml`; console entry point
  `trellix-decrypt` (`python -m trellix_decrypt`).

## Web / API framework

- **FastAPI** (≥ 0.110) — webhook consumer, public password form, admin dashboard,
  and JSON API.
- **Uvicorn** (`[standard]`, ≥ 0.29) — ASGI server.
- **Starlette** (via FastAPI) — routing; `TestClient` in tests.
- **python-multipart** (≥ 0.0.9) — form parsing for the password submission.

## HTTP client (to the EX appliance)

- **httpx** (≥ 0.27) — async client for the Trellix WSAPI: auth, alerts,
  quarantine list/rescan/release/delete, alert-by-uuid.

## Data / persistence

- **SQLAlchemy 2.0** (ORM) — `AttachmentCase`, `PasswordAttempt`, `EventLog`,
  `Setting`.
- **SQLite** — default database (`DB_URL`).

## Config & validation

- **pydantic-settings** (≥ 2.2) — `Settings` from environment / `.env`, with
  UI-editable overrides persisted in the `Setting` table.

## Security / crypto

- **cryptography** (≥ 42.0) — **Fernet** symmetric encryption for the attachment
  password at rest and stored settings secrets, keyed by `SECRET_KEY`.
- **itsdangerous** (≥ 2.1) — signed, TTL-expiring one-time links and the signed
  session cookie.
- Webhook auth: **HTTP Basic** + source-IP allowlist. Password form is
  rate-limited. HTTPS is expected to be terminated by a reverse proxy.

## Email

- **aiosmtplib** (≥ 3.0) — async SMTP send (recipient notifications).
- **Jinja2** (≥ 3.1) — email and web-page templating.
- **IMAP** (`imaplib`, stdlib) + DSN parsing — bounce monitor (`bounce.py`).

## Frontend (no build step, no framework)

- Vanilla **HTML / CSS / JavaScript** — `static/app.js`, `static/settings.js`,
  `static/style.css` (light/dark themes), served through Jinja2 templates.

## Testing & tooling

- **pytest** (≥ 8.0) + **pytest-asyncio** (auto mode).
- **respx** (≥ 0.21) — mocks the EX HTTP API in tests.
- **Ruff** (≥ 0.4) — linter.

## External system integrated

- **Trellix Email Security (EX)** WSAPI **v2.0.0** (Reference Release 2025.1) —
  alerts, quarantine management, rescan, and alert-by-uuid. Token auth via
  `X-FeApi-Token` (+ optional `X-FeClient-Token`), with automatic re-auth.
