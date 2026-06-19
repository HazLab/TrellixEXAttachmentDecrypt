# CLAUDE.md

Guidance for Claude Code (and humans) working in this repo.

## What this is

A small, modular Python service that recovers password-protected attachments
quarantined by **Trellix Email Security (EX)**.

Pipeline:

1. EX posts alerts (HTTP webhook, JSON) under an `Alerts` array (see
   `docs/sample_alert.json`). One email yields several alert objects sharing one
   `smtpMessage.queueId`. The flow triggers only when an alert's top-level
   **name** == `TRIGGER_ALERT_NAME` (e.g. `RISKWARE_OBJECT`) AND one of its
   malware **names** exactly matches one of `TRIGGER_MALWARE_NAMES`. Note: there
   is no malware-level `type` field. The encrypted-attachment custom policy emits
   `CustomPolicy.MVX.pdf` / `.zip` / `.docx` (other CustomPolicy.MVX rules like
   `...qrCodePresent` are unrelated and must not match — hence exact-name match).
   Empty `TRIGGER_MALWARE_NAMES` disables triggering.
2. We look up the recipient and email them a **one-time randomized link**.
3. The recipient submits the attachment password on that link.
4. We call the EX **rescan** API (`POST /emailmgmt/quarantine/rescan/<queue_id>`
   with `{"rescan_properties": {"pwd_list": [...]}}`) to re-analyze with the
   password. (The doc names the path param `email_uuid`, but it is the queue id.)
5. EX re-analyzes the resubmission and re-detects it under the **same queue id +
   `_RA` suffix**, then **pushes** that re-detection to our webhook (the same HTTP
   notification consumer as the original). We classify it straight from the pushed
   alert in `domain.FlowEngine._classify_resubmission` — **no API lookup**: the
   `/alerts` query returns no `uuid` to join the quarantine record's `alert_uuids`
   on, and there is no GET-by-uuid we can rely on, so pulling alert details is
   unworkable. From the pushed alert:
   - `MALWARE_OBJECT` / `malicious: yes` → decrypted & malicious → stop
     (`DONE_MALICIOUS`); this is final and always wins (ingest sorts malicious
     alerts first within a single push so they beat a same-batch riskware retry);
   - still a riskware trigger (`RISKWARE_OBJECT` + `CustomPolicy.MVX.<ext>`) →
     wrong password → email the user again, up to `max_password_attempts`
     (default 3, cap 5).
   The `_RA` alert is **correlated** to the original case by stripping the `_RA`
   suffix(es) and matching the queue id (`repo.find_case_by_queue_id`) — it is
   never added as a new case. `recheck` is now only a **fail-closed timeout
   backstop** (`ex_client.has_resubmission_quarantine`): if no verdict was pushed,
   it concludes `DONE_CLEAN` *only* when the email is genuinely no longer
   (re-)quarantined; if it is still re-quarantined it treats it as a wrong password
   rather than release a held email.
6. Every recipient / email / attempt / state transition is tracked.

A web UI may be layered on later — keep layers cleanly separable.

## Conventions

- **Modular but minimal.** One file per layer (below). Group related classes in a
  file; don't over-split into tiny files, and don't write a monolith. No dead
  code, no speculative abstractions.
- Pure business logic (`domain.py`) has **zero I/O** and is unit-testable without
  network, DB, or SMTP. All transport is isolated behind it.
- Async throughout (FastAPI + httpx + aiosmtplib; rechecks run as asyncio tasks).
- Type-hint public functions. Keep functions short.

## Layout

```
trellix_decrypt/
  __main__.py     Entrypoint (python -m trellix_decrypt).
  app.py          Composition root: build Settings + AppContext, return the app.
  context.py      AppContext: owns the live FlowEngine; reload() re-wires the EX
                  client/mailer/rules/tokens from current settings (no restart).
  config.py       Settings (pydantic-settings; env vars / real .env created by user).
  settings_store.py  UI-editable config: env defaults + DB overrides, secrets
                  encrypted (Fernet keyed by SECRET_KEY). effective_settings()/masked()/update().
  domain.py       AlertEvent, FlowState enum, RiskwareRules, one-time tokens,
                  FlowEngine (the state machine / orchestrator) + the pure alert
                  parser (parse_alert / iter_alerts). NO I/O.
  ex_client.py    EXClient: auth (X-FeApi-Token + optional X-FeClient-Token, auto
                  re-auth), get_alerts, quarantine list/release/delete,
                  rescan_target (picks the path-bearing rescannable entry),
                  rescan(target_id, passwords), has_resubmission_quarantine (recheck
                  backstop). EXApiError carries status_code/body (+ .not_found).
                  Verified against docs/*.pdf (Release 2025.1).
                  *** ALL wsapis paths live at the top — the single place to adjust. ***
  ingest.py       AlertSource base + EX-alert JSON parser + FastAPI webhook router.
  mailer.py       SMTPMailer + Jinja2 email rendering.
  storage.py      SQLAlchemy engine/session, ORM models (AttachmentCase carries the
                  recipient; PasswordAttempt, EventLog, Setting), CaseRepository
                  (+ list_cases/case_detail read models).
  web/            FastAPI package: server.py (app factory), auth.py (shared-password
                  session), routes_password.py (public form), routes_dashboard.py
                  (dashboard/settings/login pages), routes_api.py (auth JSON API).
  recheck.py      Scheduler wrapper + recheck job + notify-retry/bounce loops.
  bounce.py       parse_bounce() DSN parser + BounceMonitor (IMAP poll of sender
                  mailbox); flips accepted-then-bounced mail to BOUNCED.
  templates/      Jinja2: recipient email + form/result; base/dashboard/settings/login.
  static/         style.css (light/dark), app.js (dashboard), settings.js.
tests/            pytest; respx mocks the EX API.
```

## Admin UI

Auth-gated (shared `UI_PASSWORD`, signed session cookie) dashboard at `/`: live
searchable case list + detail drawer (lifecycle stepper + EventLog timeline),
dark/light. `/settings` edits EX/SMTP/trigger/retry config via `/api/settings`;
saving persists to the `Setting` table (secrets encrypted) and calls
`AppContext.reload()` to apply live. Public, ungated: `/p/<token>`, the webhook,
`/healthz`.

## Flow states (`domain.py`)

`RECEIVED → AWAITING_PASSWORD → PASSWORD_SUBMITTED → RESUBMITTED → RECHECKING →`
one of `{DONE_CLEAN, DONE_MALICIOUS, FAILED_MAX_RETRIES, EXPIRED}`.
Wrong password loops `RECHECKING → AWAITING_PASSWORD` with `attempt += 1`.
Email problems: `NOTIFY_FAILED` (SMTP error handing off — auto-retried + resendable)
and `BOUNCED` (accepted then DSN'd back — detected by `bounce.py`, resendable).

## Security

- The attachment password is held **encrypted at rest** (Fernet via `SECRET_KEY`,
  `AttachmentCase.pwd_enc`) only until the EX rescan succeeds, then purged — this
  is what lets the rescan auto-retry without re-asking the recipient. Never stored
  in plaintext; `PasswordAttempt` keeps a hash for audit. Changing `SECRET_KEY`
  makes any held password (and stored settings secrets) unreadable.
- One-time links: signed (`itsdangerous`), TTL-expiring; opening an expired link
  auto-reissues a fresh one. Single use is enforced by case state, not the token.
- Webhook requires HTTP Basic auth (EX's notification creds) and/or a source-IP
  allowlist — at least one must be configured or it rejects. The password
  form is rate-limited. HTTPS is expected to be terminated by a reverse proxy.
- `.claude/settings.json` denies reading/writing `.env*` and `*.sqlite3` — never
  commit secrets or the DB.

## Configuration

Read from environment variables (and an optional `.env` the operator creates;
Claude must not write `.env*`). See `README.md` for the full list. Key groups:
EX (`EX_BASE_URL`, `EX_USERNAME`, `EX_PASSWORD`, `EX_VERIFY_TLS`),
`TRIGGER_ALERT_NAME` + `TRIGGER_MALWARE_NAMES`, SMTP (`SMTP_*`), web (`PUBLIC_BASE_URL`, `SECRET_KEY`,
`TOKEN_TTL`), webhook (`WEBHOOK_USERNAME`/`WEBHOOK_PASSWORD`, `WEBHOOK_IP_ALLOWLIST`),
flow (`MAX_PASSWORD_ATTEMPTS`, `RECHECK_DELAY`, `RECHECK_INTERVAL`,
`RECHECK_MAX_ATTEMPTS`), `DB_URL`.

## Run & test

```bash
pip install -e ".[dev]"        # deps from pyproject.toml
python -m trellix_decrypt      # start service (uvicorn + scheduler)
pytest                         # unit + respx-mocked EX client tests
```

## Caveats

- Endpoints/auth/rescan are verified against `docs/*.pdf` (Trellix API Reference
  Release 2025.1). Appliance-specific points to confirm on a live box:
  - The re-quarantine of a resubmitted email appears under the original
    `queue_id` plus a suffix EX appends (e.g. `_RA`). We only ever **read** that
    by prefix-match and never construct the suffix ourselves (correlation in
    `domain.handle_alert`; backstop in `ex_client.has_resubmission_quarantine`).
  - Classification relies on EX **pushing** the `_RA` re-detection to the webhook
    (confirmed for both riskware and malware on the lab box). If a deployment's
    notification policy does NOT push malware re-detections, the
    `has_resubmission_quarantine` backstop still fails closed (keeps the mail
    quarantined / re-asks) but won't label it `DONE_MALICIOUS`.
```
