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

Alerts missed while the service was down are picked up automatically: on startup
(and on demand from the dashboard) it **reconciles** against what EX is actually
holding in quarantine and opens any case it is missing, without duplicates.

Full architecture and module layout: `documentation/documentation.md`.
Deployment details: `DEPLOY.md`. Tech stack: `STACK.md`.

## Prerequisites

**On the Trellix EX appliance:**

- **EX 11.0.0+** with an **MVX engine** available and the **MTA in block mode**.
- **Riskware policy 65066** (`PassExtractFailed`) enabled and set to **quarantine**.
- An **EX API account** with the **Admin** role.
- This service registered as an **HTTP notification server** pointing at the webhook.

**On the app host:**

- A runtime for your chosen install: **Python 3.11+** (from source) · **Docker**
  (container) · **nothing** (prebuilt binary). Linux/macOS/Windows; SQLite is
  built in — no separate DB.
- Network reach to the **EX WSAPI** and an **SMTP** relay.
- A public **HTTPS** hostname (`PUBLIC_BASE_URL`) that EX can POST to at
  `/webhook/ex-alert` — via a reverse proxy or the built-in TLS.

See `DEPLOY.md` §1 for the full checklist.

## Quick start

**Linux / macOS:**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # or: pip install -r requirements.txt

cp env.example .env              # edit, OR skip and configure in the UI later
python -m trellix_decrypt        # start (also available as: trellix-decrypt)
```

**Windows (PowerShell):**

```powershell
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"          # or: pip install -r requirements.txt

copy env.example .env            # edit, OR skip and configure in the UI later
python -m trellix_decrypt        # start (also available as: trellix-decrypt)
```

The app boots even with no config — it starts in **setup mode**, so you can fill
everything in from the **Settings** UI instead of `.env`. Until an admin password
exists, Settings opens only through the **one-time setup link** printed in the
startup log (`…/settings?setup=<token>`), so nobody else on the network can claim
the install first. To sanity-check EX
connectivity without starting the server (exit 0 = OK):

```bash
python -m trellix_decrypt --check
```

## Configuration

> **`.env` is optional.** The app boots with no config into **setup mode** —
> **every setting can be entered and changed from the Settings UI** (`/settings`),
> stored in the DB (secrets encrypted) and applied live, no restart. Use `.env`
> (or real environment variables) only if you prefer file-based config; the UI
> always overrides it.

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
TRIGGER_MALWARE_NAMES=CustomPolicy.MVX.pdf,CustomPolicy.MVX.zip,CustomPolicy.MVX.docx,CustomPolicy.MVX.65066.PassExtractFailed

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
live (secrets encrypted at rest, no restart). A value that doesn't validate (for
example text in a numeric field) is rejected and nothing is saved.

## Run in production

All three modes persist two things across restarts — `secret.key` and the
database — under **`DATA_DIR`** (default: the working directory).

- **Docker (recommended):** `docker compose up -d --build` — mounts a `data`
  volume at `DATA_DIR=/data`. Configure via `.env` or the Settings UI. The image
  is built locally from this folder, so rebuild after pulling an update. First-run
  setup link: `docker compose logs attachment-decrypt | grep "SETUP MODE"`.
- **Prebuilt binary (no Python):** download the Linux/macOS/Windows executable
  from the latest GitHub **Release** (v0.1.2 or newer) and run it — see below.
- **From source:** `pip install -r requirements.txt && python -m trellix_decrypt`.

### Running the executable

It needs **no arguments** — just run it. It serves on port 8080 and keeps its
database and `secret.key` in the folder you run it from.

```powershell
.\trellix-decrypt-windows.exe                 # Windows
```
```bash
chmod +x trellix-decrypt-linux && ./trellix-decrypt-linux     # Linux (macOS: trellix-decrypt-macos)
```

- **`DATA_DIR`** (an environment variable, not an argument) keeps the data in a
  fixed folder instead of the current one — recommended for a real install:
  - Windows (PowerShell): `$env:DATA_DIR="C:\ProgramData\trellix-decrypt"; .\trellix-decrypt-windows.exe`
  - Linux/macOS: `DATA_DIR=/var/lib/trellix-decrypt ./trellix-decrypt-linux`
- **`--check`** is the only argument it accepts: it tests the connection to EX
  and exits without starting the server.
- **Keeping an existing setup:** point `DATA_DIR` at the folder that already
  holds `trellix_decrypt.sqlite3` and `secret.key` (or run the executable from
  it). Stop any other copy first — two can't share one database.

**HTTPS:** either import a certificate so the app serves TLS itself (Settings →
HTTPS/TLS, or the `TLS_*` variables in `env.example`), or terminate TLS at a
reverse proxy. Behind a proxy, set `TRUST_FORWARDED_FOR=true` so rate limits see
the real client address.

## Admin UI

Open the host root and sign in with `UI_PASSWORD`:

- **Dashboard** (`/`) — live searchable case list with status badges and a detail
  drawer (lifecycle stepper, event timeline, EX alert details). Resend an email,
  retry a rescan, or run **Reconcile** from here. Auto-refreshes; dark/light.
- **Settings** (`/settings`) — EX/SMTP/trigger/retry/HTTPS config, applied live.

Public (no login): `/p/<token>`, `/webhook/ex-alert`, `/healthz`.

## Security

- **First run:** with no admin password, Settings opens only through the one-time
  setup link in the startup log. The admin password can be changed, not removed.
- **Sessions:** signed cookie (`Secure` over HTTPS); logging out revokes it, and
  changing the admin password signs everyone out.
- **Webhook:** requires HTTP Basic auth and/or a source-IP allowlist; request size
  is capped.
- **Rate limits** on admin sign-in and on the recipient password form.
- **Secrets:** stored settings secrets and the held attachment password are
  encrypted at rest; the password is purged once the rescan succeeds.
- **Hardening:** security headers on every response; no public API explorer.
- TLS verification towards EX and SMTP is **off by default** (self-signed
  appliances are common) — turn it on in Settings when they have trusted certs.

## Test

```bash
pytest
```

## Notes

- EX endpoints/auth/rescan follow the Trellix API Reference 2025.1 (vendor
  document, not included in this repository) and live in
  `trellix_decrypt/ex_client.py`. Rescan is
  `POST /emailmgmt/quarantine/rescan/<queue_id>` with
  `{"rescan_properties": {"pwd_list": [...]}}`.
- Attachment passwords are encrypted at rest, used for the rescan, then purged —
  never stored in plaintext.
