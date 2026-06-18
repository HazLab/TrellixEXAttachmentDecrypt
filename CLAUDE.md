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
4. We resolve the email's `email_uuid` from the quarantine list and call the EX
   **rescan** API (`POST /emailmgmt/quarantine/rescan/<email_uuid>` with
   `{"rescan_properties": {"pwd_list": [...]}}`) to re-analyze with the password.
5. EX re-detects a failed resubmission under the **same queue id + `_RA`
   suffix**. A background recheck queries the **alerts API** for `<queueId>_RA`
   (`ex_client.classify_resubmission`) and decides:
   - still a riskware trigger (`RISKWARE_OBJECT` + `CustomPolicy.MVX.<ext>`) →
     wrong password → email the user again, up to `max_password_attempts`
     (default 3, cap 5);
   - a `MALWARE_OBJECT` / `malicious: yes` alert, or no `_RA` alert at all → stop.
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
  app.py          Composition root: build Settings, wire deps, start web+scheduler.
  config.py       Settings (pydantic-settings; env vars / real .env created by user).
  domain.py       AlertEvent, FlowState enum, RiskwareRules, one-time tokens,
                  FlowEngine (the state machine / orchestrator) + the pure alert
                  parser (parse_alert / iter_alerts). NO I/O.
  ex_client.py    EXClient: auth (X-FeApi-Token + optional X-FeClient-Token, auto
                  re-auth), get_alerts, quarantine list/release/delete,
                  resolve_email_uuid, rescan(email_uuid, passwords),
                  classify_resubmission. Verified against docs/*.pdf (Release 2025.1).
                  *** ALL wsapis paths live at the top — the single place to adjust. ***
  ingest.py       AlertSource base + EX-alert JSON parser + FastAPI webhook router.
  mailer.py       SMTPMailer + Jinja2 email rendering.
  storage.py      SQLAlchemy engine/session, ORM models (AttachmentCase carries the
                  recipient; PasswordAttempt, EventLog), CaseRepository.
  web.py          FastAPI app factory + password form routes + health.
  recheck.py      Scheduler wrapper + recheck job (poll for {queue_id}_RA, classify).
  templates/      Jinja2: password-request email + web form/result pages.
tests/            pytest; respx mocks the EX API.
```

## Flow states (`domain.py`)

`RECEIVED → AWAITING_PASSWORD → PASSWORD_SUBMITTED → RESUBMITTED → RECHECKING →`
one of `{DONE_CLEAN, DONE_MALICIOUS, FAILED_MAX_RETRIES, EXPIRED}`.
Wrong password loops `RECHECKING → AWAITING_PASSWORD` with `attempt += 1`.

## Security

- Passwords are used immediately for resubmission and **never stored in
  plaintext**; `PasswordAttempt` keeps only a hash (dedupes wrong tries + counts).
- One-time tokens (`secrets`/`itsdangerous`): single-use, TTL-expiring, stored
  hashed.
- Webhook requires a shared secret (+ optional source-IP allowlist); the password
  form is rate-limited. HTTPS is expected to be terminated by a reverse proxy.
- `.claude/settings.json` denies reading/writing `.env*` and `*.sqlite3` — never
  commit secrets or the DB.

## Configuration

Read from environment variables (and an optional `.env` the operator creates;
Claude must not write `.env*`). See `README.md` for the full list. Key groups:
EX (`EX_BASE_URL`, `EX_USERNAME`, `EX_PASSWORD`, `EX_VERIFY_TLS`),
`TRIGGER_ALERT_NAME` + `TRIGGER_MALWARE_NAMES`, SMTP (`SMTP_*`), web (`PUBLIC_BASE_URL`, `SECRET_KEY`,
`TOKEN_TTL`), webhook (`WEBHOOK_SECRET`, `WEBHOOK_IP_ALLOWLIST`),
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
  Release 2025.1). Two appliance-specific points to confirm on a live box:
  - The rescan path param is documented as `email_uuid` (we resolve it from the
    quarantine list by `queue_id`); the doc's example value is queue-id-shaped.
  - The re-quarantine of a resubmitted email appears under the original
    `queue_id` plus a suffix EX appends (e.g. `_RA`). We **read** that back from
    quarantine/alerts by prefix-match and never construct the suffix ourselves
    (`ex_client.classify_resubmission`).
```
