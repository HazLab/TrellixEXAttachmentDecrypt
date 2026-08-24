# Trellix EX Attachment Decrypt

A small, modular Python service that recovers **password-protected attachments**
quarantined by **Trellix Email Security (EX)**.

When EX can't extract an encrypted attachment (PDF, Office doc, or archive) it
raises a *riskware* alert and quarantines the mail. This service asks the
recipient for the password over a one-time link, resubmits the mail to EX for
re-analysis, and tracks the outcome — retrying on wrong passwords, concluding on
clean or malicious results.

## Flow

1. EX posts an alert to the webhook (`POST /webhook/ex-alert`).
2. If it matches the configured trigger (encrypted-attachment rule), the
   recipient is emailed a randomized one-time link.
3. The recipient submits the password.
4. The service resubmits to EX with the password (rescan API).
5. A background poll checks the re-detection (`<queue_id>_RA`): wrong password →
   ask again (up to the retry cap); quarantined → held; not quarantined → clean,
   delivered.

Full architecture and module layout: `documentation/documentation.md`.
Deployment details: `DEPLOY.md`. Tech stack: `docs/STACK.md`.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # or: pip install -r requirements.txt

cp env.example .env              # edit, OR skip and configure in the UI later
python -m trellix_decrypt        # start (also available as: trellix-decrypt)
```

The app boots even with no config — it starts in **setup mode**, so you can fill
everything in from the **Settings** UI instead of `.env`. To sanity-check EX
connectivity without starting the server (exit 0 = OK):

```bash
python -m trellix_decrypt --check
```

## Configuration

Read from environment variables or a `.env` you create (**never committed**).
The full annotated list is in `env.example`; the essentials:

```bash
# Trellix EX appliance
EX_BASE_URL=https://ex.example.com
EX_USERNAME=admin                # account with the Admin role
EX_PASSWORD=...
EX_VERIFY_TLS=false              # off by default (EX often uses self-signed certs)

# Trigger: alert name == TRIGGER_ALERT_NAME AND a malware name exactly matches
# one of TRIGGER_MALWARE_NAMES (the encrypted-attachment policy emits
# CustomPolicy.MVX.<ext>). Empty TRIGGER_MALWARE_NAMES disables triggering.
TRIGGER_ALERT_NAME=RISKWARE_OBJECT
TRIGGER_MALWARE_NAMES=CustomPolicy.MVX.pdf,CustomPolicy.MVX.zip,CustomPolicy.MVX.docx

# Outbound mail (the recipient link)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_FROM=attachment-help@example.com

# Web + admin UI
PUBLIC_BASE_URL=https://decrypt.example.com   # builds the one-time link
UI_PASSWORD=...                               # gates the dashboard/settings
SECRET_KEY=                                   # blank → auto-generated secret.key

# Webhook auth — set the SAME creds on EX's HTTP notification consumer
WEBHOOK_USERNAME=ex-webhook
WEBHOOK_PASSWORD=...
```

Retry/recheck cadence (`RECHECK_DELAY`, `RECHECK_RAMP`, `RECHECK_INTERVAL`,
`RECHECK_MAX_ATTEMPTS`) and `MAX_PASSWORD_ATTEMPTS` have sensible defaults — see
`env.example`. Anything set here is just the default; **Settings** overrides it
live (secrets encrypted at rest, no restart).

## Run in production

All three modes persist two things across restarts — `secret.key` and the
database — under **`DATA_DIR`** (default: the working directory).

- **Docker (recommended):** `docker compose up -d --build` — mounts a `data`
  volume at `DATA_DIR=/data`. Configure via `.env` or the Settings UI.
- **Prebuilt binary (no Python):** download the Linux/macOS/Windows executable
  from GitHub **Releases**, then
  `DATA_DIR=/var/lib/trellix-decrypt ./trellix-decrypt`.
- **From source:** `pip install -r requirements.txt && python -m trellix_decrypt`.

HTTPS is expected to be terminated by a reverse proxy (or set the built-in TLS
vars in `env.example`).

## Admin UI

Open the host root and sign in with `UI_PASSWORD`:

- **Dashboard** (`/`) — live searchable case list with status badges and a detail
  drawer (lifecycle stepper + event timeline). Auto-refreshes; dark/light.
- **Settings** (`/settings`) — EX/SMTP/trigger/retry config, applied live.

Public (no login): `/p/<token>`, `/webhook/ex-alert`, `/healthz`.

## Test

```bash
pytest
```

## Notes

- EX endpoints/auth/rescan follow the Trellix API Reference 2025.1 (PDFs in
  `docs/`) and live in `trellix_decrypt/ex_client.py`. Rescan is
  `POST /emailmgmt/quarantine/rescan/<queue_id>` with
  `{"rescan_properties": {"pwd_list": [...]}}`.
- Attachment passwords are encrypted at rest, used for the rescan, then purged —
  never stored in plaintext.

## License

MIT
