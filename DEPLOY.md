# Deployment Guide

How to install, run, and persist **Trellix EX Attachment Decrypt** in production —
from source, with Docker, or as a prebuilt executable — plus what the `SECRET_KEY`
and database require. For the full architecture and operations reference see
`documentation/documentation.md` (rendered: `documentation/documentation.html`).

## At a glance

| Method | Best for | Needs on the host |
|--------|----------|-------------------|
| From source | Dev, or servers that already run Python | Python ≥ 3.11 + pip |
| Docker | Most production installs | Docker (+ Compose) |
| Executable | Hosts without Python | Nothing — a single binary |

All three run the same app and share the same configuration and persistence rules
(below). For HTTPS you have two options — **import a certificate** so the app serves TLS
natively (Settings → HTTPS/TLS, or `TLS_CERT_FILE`/`TLS_KEY_FILE`), **or** terminate TLS
at a **reverse proxy** (now optional). Behind a trusted proxy, set
`TRUST_FORWARDED_FOR=true` so rate limits key on the real client IP.

## 1. Before you start

### On the Trellix EX appliance

- **EX version 11.0.0 or later** (latest recommended, for the newest rescan improvements).
- An **MVX engine available** — integrated mode (built-in), sensor mode (enrolled in a
  separate IVX cluster), or hybrid.
- The **MTA in block mode**.
- **Riskware policy 65066** (`PassExtractFailed`) **enabled and set to quarantine**.
- This service registered as an **HTTP notification server** on EX, pointing at the
  webhook (see the "Point EX at the webhook" section of the main guide).
- An **EX API account** with the **API Analyst** role.

### On the app host

- A host that can reach the **EX WSAPI** and an **SMTP** relay.
- A public hostname for the recipient links (`PUBLIC_BASE_URL`), reachable over **HTTPS** —
  either by **importing a certificate** (native TLS; Settings → HTTPS/TLS or
  `TLS_CERT_FILE`/`TLS_KEY_FILE`) or via a **reverse proxy** that terminates TLS (optional;
  default app port 8080).
- The EX appliance must be able to POST to `https://<host>/webhook/ex-alert`.

> **Native HTTPS:** to serve TLS without a proxy, import a **PEM** cert+key or a
> **PKCS#12 / `.pfx`** bundle under **Settings → HTTPS/TLS** (or set `TLS_CERT_FILE` /
> `TLS_KEY_FILE` / `TLS_KEY_PASSWORD`). For an internal host/testing you can **generate a
> self-signed** cert (button, or `TLS_SELF_SIGNED=true`) — untrusted, so browsers warn and
> EX rejects the webhook if its SSL Verify is on. Material is stored `0600` under
> `DATA_DIR/tls/`; **restart to apply**, and set `PUBLIC_BASE_URL` to `https://…`. A proxy
> is still nice for automatic cert renewal.

## 2. Persistent state — `DATA_DIR` (read first)

Two things **must survive restarts**, or sign-in sessions break and stored encrypted
settings become unreadable:

- **`secret.key`** — signs sessions and one-time links; encrypts stored secrets.
- **the database** — case history and settings.

Both live under **`DATA_DIR`** (default: the current working directory). For anything
beyond a quick local test, point `DATA_DIR` at a **dedicated, writable, persistent,
backed-up** folder the service owns. **Back up `DATA_DIR` as a unit** — the database is
partly unreadable without its `secret.key`.

**What should `DATA_DIR` be?** A durable location (not a container's ephemeral layer or
a tmpfs), writable by the user the service runs as, and included in your backups:

| Environment | Recommended `DATA_DIR` |
|-------------|------------------------|
| Docker | `/data` — a mounted volume (the compose default) |
| Linux (service) | `/var/lib/trellix-decrypt` (owned by the service user) |
| macOS | `/usr/local/var/trellix-decrypt` |
| Windows | `C:\ProgramData\trellix-decrypt` |
| Quick local test | leave unset → uses the working directory |

Set it the way your shell expects:

```bash
export DATA_DIR=/var/lib/trellix-decrypt        # Linux / macOS (bash/zsh)
```
```powershell
$env:DATA_DIR = "C:\ProgramData\trellix-decrypt"  # Windows PowerShell
```
```bat
set DATA_DIR=C:\ProgramData\trellix-decrypt       :: Windows cmd.exe
```

## 3. SECRET_KEY — how to set it

Precedence: an explicit **`SECRET_KEY`** environment variable wins; otherwise the app
**generates a strong key on first run** and writes it to `DATA_DIR/secret.key` (file
mode `600`). Two supported options:

- **Auto-generate (simplest).** Do nothing; just keep `DATA_DIR` persistent so the
  generated key is reused on restart.
- **Manage it yourself.** Generate one and set `SECRET_KEY`:

  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(48))"
  ```

`SECRET_KEY` is intentionally **not** editable from the Settings UI (it protects the
database the UI writes to). **Rotating it invalidates** every active session and makes
any held password and stored settings-secrets unreadable — rotate deliberately, then
re-enter settings secrets.

## 4. Database — what's required

- **Default (SQLite): nothing to set up.** The app **creates the database file
  automatically** on first run at `DATA_DIR/trellix_decrypt.sqlite3` — no server, no
  schema/migration step. Just keep the file (it's inside `DATA_DIR`).
- **A different database (optional).** Set `DB_URL` to any SQLAlchemy URL, e.g.
  `postgresql+psycopg://user:pass@host/dbname`. The **driver is not bundled** — install
  it yourself (e.g. `pip install "psycopg[binary]"`) in your source or Docker build.
  `DB_URL` is environment-only (it can't be stored in the database it points at).
  Tables are created automatically.

## 5. Option A — From source

Needs Python ≥ 3.11 and pip. Pick the block for your OS (set `DATA_DIR` to a path
from §2).

**Linux / macOS:**

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt                        # or: pip install .
export DATA_DIR=/var/lib/trellix-decrypt               # macOS: /usr/local/var/trellix-decrypt
python -m trellix_decrypt --check                      # optional: validate EX connectivity
python -m trellix_decrypt                              # or the console script: trellix-decrypt
```

**Windows (PowerShell):**

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt                        # or: pip install .
$env:DATA_DIR = "C:\ProgramData\trellix-decrypt"
python -m trellix_decrypt --check                      # optional
python -m trellix_decrypt
```

For a service manager (systemd, supervisor, Windows Service via NSSM, …), run
`python -m trellix_decrypt` with `DATA_DIR` and any config set in the service's
environment. Configuration can come from the environment, a `.env` file, or entirely
from the Settings UI.

## 6. Option B — Docker

**Compose** (persists `DATA_DIR` in a named volume automatically):

```bash
docker compose up -d --build
```

`docker-compose.yml` sets `DATA_DIR=/data` and mounts the `data` volume there, so
`secret.key` and the SQLite DB persist across restarts and rebuilds. Provide config via
a local `.env` (optional — the app boots into setup mode and can be configured from the
UI), or pass `SECRET_KEY` as an environment secret. The image runs as a non-root user,
exposes port 8080, and has a `/healthz` healthcheck.

**Changing the port:** set `WEB_PORT` (the container port — the app and the healthcheck
both follow it) and `HOST_PORT` (the published host port) in `.env`; compose maps
`HOST_PORT:WEB_PORT`. For example `HOST_PORT=9000` and `WEB_PORT=9000`, then
`docker compose up -d`, reachable at `http://host:9000`. In Docker set the port this way
rather than in the Settings UI, so the port mapping and healthcheck stay in sync.

**HTTPS in Docker:** set `HTTPS_ENABLED=true` and set `HTTPS_PORT` **equal to** `WEB_PORT`
(and to `HOST_PORT`) so the single compose mapping and the healthcheck line up — the
healthcheck follows the scheme automatically. Or, more commonly, keep the container on
HTTP and terminate TLS at your ingress/reverse proxy.

**Plain `docker run`** (bring your own volume):

```bash
docker build -t trellix-attachment-decrypt .
docker run -d --name attachment-decrypt \
  -p 8080:8080 \
  -e DATA_DIR=/data \
  -e SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
  -v trellix_data:/data \
  --restart unless-stopped \
  trellix-attachment-decrypt
```

Omit `-e SECRET_KEY=...` to auto-generate into the volume; add `--env-file .env` to
pass operator config.

## 7. Option C — Prebuilt executable

Standalone **Windows / Linux / macOS** binaries come from the **Build binaries** GitHub
Actions workflow — built when a version tag (`v*`) is pushed (attached to the GitHub
**Release**) or on demand via the workflow's **Run workflow** button (downloadable as
run artifacts). It does **not** build on ordinary commits. The binary bundles Python,
all dependencies, and the templates/static assets; it only needs a writable `DATA_DIR`.

**Linux / macOS:**

```bash
chmod +x ./trellix-decrypt
DATA_DIR=/var/lib/trellix-decrypt ./trellix-decrypt        # add --check first to test EX
```

**Windows (PowerShell):**

```powershell
$env:DATA_DIR = "C:\ProgramData\trellix-decrypt"
.\trellix-decrypt-windows.exe
```

The Windows binary is unsigned, so SmartScreen may warn on first run — choose
*More info → Run anyway*, or code-sign it in your own pipeline.

## 8. Minimum configuration to go live

Whichever method you use, the service stays in **setup mode** (the webhook returns
`503`) until these are set — via environment/`.env` or the Settings UI:

- **EX**: `EX_BASE_URL`, `EX_USERNAME`, `EX_PASSWORD`
- **SMTP**: `SMTP_HOST`, `SMTP_FROM`
- **Web**: `PUBLIC_BASE_URL`, `UI_PASSWORD` (the admin password)
- **Webhook auth**: `WEBHOOK_USERNAME` + `WEBHOOK_PASSWORD` and/or `WEBHOOK_IP_ALLOWLIST`

`SECRET_KEY` and `DB_URL` are **not** required — they default as described above. On
first run with no admin password, open the app and it drops you on the Settings page to
bootstrap; once the admin password is saved, normal sign-in is enforced.

## 9. First-run flow

1. Start the service (any method) with `DATA_DIR` set.
2. Open `http://<host>:8080/` — you are redirected to **Settings** (setup mode).
3. Fill in the **admin password** plus the required fields above; **Save**.
4. Sign in with the admin password. Register this service as an EX **HTTP
   notification** destination (main guide, "Point EX at the webhook").
5. Confirm a `POST /webhook/ex-alert` reaches the log and a case appears.

## 10. Upgrades

- **From source:** pull, `pip install -r requirements.txt` (in case pins changed),
  restart. `DATA_DIR` is untouched.
- **Docker:** `docker compose pull` / `docker compose up -d --build`. The `data`
  volume persists across image rebuilds.
- **Executable:** replace the binary; keep the same `DATA_DIR`.

Schema changes are applied automatically (tables are created on start); there is no
separate migration command.

## 11. Backups & restore

Back up **`DATA_DIR` as a whole** — it holds both `secret.key` and the database, and
one is useless without the other. To restore, put the same `DATA_DIR` contents in place
and start the service (or restore the Docker `data` volume). If you manage `SECRET_KEY`
via the environment, back that value up too (separately and securely).

## 12. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Webhook returns **405** | The EX Server URL is the base host (EX POSTs to `/`). Set it to `https://<host>/webhook/ex-alert`; a GET to that URL returns `200 {"status":"ready"}` when correct. |
| Webhook returns **413** | Payload over `MAX_REQUEST_BYTES` (default 1 MiB) — usually EX **Extended** format or a **Daily Digest**. Use **Normal** + **Per Event**, or raise `MAX_REQUEST_BYTES`. |
| No alerts arrive / flow never starts | EX HTTP-notification **Notification** set to **Malware Object** excludes `RISKWARE_OBJECT` (the encrypted-attachment trigger). Set it to **All Events** (or include **riskware object**). |
| Missed alerts after downtime | The app auto-**reconciles** on startup — queries EX for recent trigger alerts and backfills any missing case (idempotent). Trigger it on demand with the **Reconcile** button; tune `RECONCILE_LOOKBACK` / `RECONCILE_INTERVAL`. |
| Webhook returns **503** | Setup mode — finish the required config (§8). |
| **Missing dependencies** at start (source) | You skipped install — `pip install -r requirements.txt` (or use Docker/exe). |
| Sessions drop / stored secrets unreadable after redeploy | `DATA_DIR` (or `SECRET_KEY`) wasn't persisted — mount a volume / set a stable folder. |
| Rescan says "queue id not found" | Check the **EX appliance clock**; fix it and retry. |
| Windows exe blocked | Unsigned binary — *More info → Run anyway*, or sign it. |

## Configuration reference (appendix)

Configuration can come from environment variables / a `.env` file or the Settings UI
(each field there also has a **?** tooltip). Two groups point in **opposite directions**
— the usual source of confusion:

- **EX API** (`EX_*`) — how *this service* reaches *your EX appliance* (outbound: list
  quarantine, rescan, fetch alerts).
- **Webhook** (`WEBHOOK_*`) — how *EX* reaches *this service* (inbound: EX POSTs alert
  notifications to us).

† **Webhook auth** is conditionally required: you need the Basic-auth pair *and/or* the
IP allowlist — at least one, or the webhook refuses to run.

### Trellix EX API — this service → the appliance

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `EX_BASE_URL` | HTTPS address of your EX appliance. This service calls the EX API here to list quarantine, rescan an email with a password, and fetch alert detail. | Yes | `—` |
| `EX_USERNAME` | Username of an EX **API account** (needs the *API Analyst* role); this service logs in with it. | Yes | `—` |
| `EX_PASSWORD` | Password for the EX API account. | Yes | `—` |
| `EX_VERIFY_TLS` | Validate the appliance's TLS certificate. Off by default (EX boxes usually present a self-signed cert). | — | `false` |
| `EX_CLIENT_TOKEN` | Optional extra `X-FeClient-Token` some appliances require alongside the login token. | — | `—` |
| `EX_TIMEOUT` | Seconds to wait for an EX API call before giving up. | — | `60` |

### Webhook — the appliance → this service

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| *Webhook URL* (derived) | The endpoint EX POSTs to: `https://<PUBLIC_BASE_URL>/webhook/ex-alert`. Paste it into EX's HTTP-notification **Server URL**; derived from `PUBLIC_BASE_URL`. | — | `…/webhook/ex-alert` |
| `WEBHOOK_USERNAME` | HTTP **Basic-auth** username EX must send when it POSTs. Set the same value here *and* on the EX notification consumer. | Cond.† | `—` |
| `WEBHOOK_PASSWORD` | HTTP **Basic-auth** password EX must send (paired with the username above). | Cond.† | `—` |
| `WEBHOOK_IP_ALLOWLIST` | Comma-separated source IPs allowed to POST the webhook. Use instead of, or with, Basic auth. | Cond.† | `—` |

### Email delivery — SMTP

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `SMTP_HOST` | Outbound mail relay host used to send the recipient email. | Yes | `—` |
| `SMTP_PORT` | Relay port (587 STARTTLS, 465 implicit TLS, 25 plain). | — | `587` |
| `SMTP_USERNAME` | Relay auth username, if required. | — | `—` |
| `SMTP_PASSWORD` | Relay auth password, if required. | — | `—` |
| `SMTP_FROM` | From address recipients see on the email. | Yes | `attachment-help@example.com` |
| `SMTP_TLS_MODE` | How TLS is negotiated: `opportunistic`, `starttls`, `none`, or `ssl` (implicit, 465). | — | `opportunistic` |
| `SMTP_VERIFY_TLS` | Validate the relay's TLS certificate. Off by default for lab/self-signed CAs. | — | `false` |
| `SMTP_HELO_HOSTNAME` | HELO/EHLO name announced to the relay. Set an FQDN if the relay rejects the OS hostname. | — | `—` |

### Recipient links & the admin site

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `PUBLIC_BASE_URL` | Externally-reachable URL of **this service**. Builds the one-time recipient link *and* the webhook URL. Must match how recipients/EX reach you. | Yes | `http://localhost:8080` |
| `UI_PASSWORD` | Password for the admin dashboard. Setting it the first time ends setup mode. | Yes | `—` |
| `TOKEN_TTL` | Seconds a one-time recipient link stays valid before expiring. | — | `86400` |
| `WEB_HOST` | Interface this service binds to (`0.0.0.0` = all). *Restart to apply.* | — | `0.0.0.0` |
| `WEB_PORT` | Plain-**HTTP** port this service listens on (when HTTPS is off). In Docker set `WEB_PORT`/`HOST_PORT` (§6). *Restart to apply.* | — | `8080` |
| `HTTPS_ENABLED` | Serve **HTTPS** (needs a cert — imported or self-signed) on `HTTPS_PORT`; otherwise plain HTTP on `WEB_PORT`. *Restart to apply.* | — | `false` |
| `HTTPS_PORT` | Port to bind when HTTPS is enabled. *Restart to apply.* | — | `8443` |
| `SECRET_KEY` | Signs links/sessions and encrypts stored secrets. Auto-generated if unset; environment-only (not in the UI). | — | `auto-generated` |
| `DATA_DIR` | Directory for persistent state — `secret.key` and the default SQLite DB (§2). | — | `working dir` |
| `DB_URL` | Database URL (§4). Environment-only. | — | `sqlite:///trellix_decrypt.sqlite3` |
| `TLS_CERT_FILE` | PEM certificate (chain OK) to serve **HTTPS natively**; blank uses a cert imported in Settings → HTTPS/TLS, else plain HTTP. *Restart to apply.* | — | `—` |
| `TLS_KEY_FILE` | PEM private key paired with `TLS_CERT_FILE`. *Restart to apply.* | — | `—` |
| `TLS_KEY_PASSWORD` | Password if `TLS_KEY_FILE` is encrypted. | — | `—` |

### What triggers the flow

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `TRIGGER_ALERT_NAME` | The EX alert top-level **name** that starts the flow (the encrypted-attachment policy raises `RISKWARE_OBJECT`). | — | `RISKWARE_OBJECT` |
| `TRIGGER_MALWARE_NAMES` | Comma-separated signature names that must also be present (`CustomPolicy.MVX.<ext>` or `...65066.PassExtractFailed`). Alert name **and** one signature name must match. Empty disables triggering. | — | `CustomPolicy.MVX.pdf, CustomPolicy.MVX.zip, CustomPolicy.MVX.docx, CustomPolicy.MVX.65066.PassExtractFailed` |

### Bounce detection — optional, IMAP

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `IMAP_HOST` | Mailbox host polled to detect **bounces** (DSNs). Blank disables bounce monitoring. | — | `—` |
| `IMAP_PORT` | IMAP port (993 for IMAPS). | — | `993` |
| `IMAP_USERNAME` | IMAP account username for the bounce mailbox. | — | `—` |
| `IMAP_PASSWORD` | IMAP account password. | — | `—` |
| `IMAP_MAILBOX` | Mailbox scanned for bounces (e.g. `INBOX`). | — | `INBOX` |
| `IMAP_SSL` | Connect to IMAP over SSL (IMAPS). | — | `true` |
| `BOUNCE_POLL_INTERVAL` | Seconds between bounce polls. | — | `120` |

### Security & rate limiting

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `LOGIN_RATE_LIMIT` | Failed admin sign-ins allowed per IP within the window before `429`. Self-healing. *Restart to apply.* | — | `10` |
| `LOGIN_RATE_WINDOW` | Window (seconds) for the login rate limit. *Restart to apply.* | — | `900` |
| `FORM_RATE_LIMIT` | Password-form submissions allowed per IP+link within the window. *Restart to apply.* | — | `10` |
| `FORM_RATE_WINDOW` | Window (seconds) for the password-form rate limit. *Restart to apply.* | — | `300` |
| `TRUST_FORWARDED_FOR` | Trust `X-Forwarded-For` for the client IP. Enable only behind a trusted reverse proxy. | — | `false` |
| `MAX_REQUEST_BYTES` | Reject webhook/form bodies larger than this (DoS guard; also large EX *Extended* alerts). | — | `1048576` |

### Retry, recheck & reconcile

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `MAX_PASSWORD_ATTEMPTS` | Wrong-password rounds allowed before giving up. | — | `3` |
| `RECHECK_DELAY` | Seconds before the first recheck poll after a resubmission. | — | `10` |
| `RECHECK_INTERVAL` | Steady-state seconds between later recheck polls. | — | `30` |
| `RECHECK_MAX_ATTEMPTS` | Number of recheck polls before concluding from the list. | — | `12` |
| `NOTIFY_MAX_RETRIES` | How many times to retry a failed recipient email. | — | `5` |
| `NOTIFY_RETRY_INTERVAL` | Seconds between email retry sweeps. | — | `300` |
| `RESUBMIT_MAX_RETRIES` | How many times to retry a failed EX rescan. | — | `5` |
| `RESUBMIT_RETRY_INTERVAL` | Seconds between rescan retry sweeps. | — | `120` |
| `RECONCILE_LOOKBACK` | EX alerts-query window scanned to backfill missed alerts. | — | `48_hours` |
| `RECONCILE_INTERVAL` | Seconds between periodic reconcile sweeps (0 = startup only). | — | `1800` |

### Logging

| Setting | What it is / what it's for | Req. | Default |
|---------|--------------------------|:----:|---------|
| `LOG_LEVEL` | Verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. *Restart to apply.* | — | `INFO` |
| `LOG_FILE` | File to write logs to (blank = console only). *Restart to apply.* | — | `trellix_decrypt.log` |
| `LOG_FILE_MAX_BYTES` | Rotate the log file at this size (bytes). *Restart to apply.* | — | `10000000` |
| `LOG_FILE_BACKUPS` | How many rotated log files to keep. *Restart to apply.* | — | `5` |