# Trellix EX Attachment Decrypt — Engineering & Operations Documentation

> Single-document build (Markdown + HTML). Regenerate with the docs build script; the
> Word (`.docx`) export is kept local and is not committed.

## Contents

- [Overview](#doc-01_overview)
- [Architecture](#doc-02_architecture)
- [Flow & States](#doc-03_flow_and_states)
- [Code Reference](#doc-04_code_reference)
- [Data Model](#doc-05_data_model)
- [Security](#doc-06_security)
- [User Guide](#doc-07_user_guide)
- [Tech Stack](#doc-08_tech_stack)
- [Configuration reference](#doc-09_config_reference)

# 1. Overview

## The problem

Trellix Email Security (EX) inspects inbound email and detonates attachments in a
sandbox (MVX). When an attachment is **password-protected** — an encrypted PDF, a
password-locked Office document, or an encrypted ZIP — EX cannot open it, cannot
prove it is safe, and therefore **quarantines the email** and raises a *riskware*
alert (`RISKWARE_OBJECT`).

This behaviour depends on the EX configuration: the appliance must be in **block
mode**, and the **riskware policy 65066** (*password extraction failed*) must be
**enabled and set to quarantine**. The alert's **signature name** is then either the
`CustomPolicy.MVX.<ext>` form (e.g. `CustomPolicy.MVX.pdf` / `.zip` / `.docx`) or
`CustomPolicy.MVX.65066.PassExtractFailed` — this service's trigger matches any of the
names you list (see the trigger configuration).

Legitimate senders routinely encrypt attachments and send the password separately.
Without automation, every such email becomes a manual help-desk ticket: find the
recipient, ask them for the password, log in to the EX console, resubmit the email
for re-analysis, and watch the result. This service automates that entire loop.

## What the service does

```mermaid
flowchart LR
    EX[Trellix EX] -->|1. quarantine alert| SVC[Attachment Decrypt]
    SVC -->|2. one-time link| R[Recipient]
    R -->|3. submits password| SVC
    SVC -->|4. rescan w/ password| EX
    EX -->|5. re-detection push| SVC
    SVC -->|6. verdict| DASH[Admin dashboard]
```

1. **Receive** — EX posts a quarantine alert to the service's webhook.
2. **Ask** — if the alert matches the configured encrypted-attachment trigger, the
   service emails every recipient a randomized, single-use, expiring link.
3. **Collect** — a recipient opens the link and submits the attachment password.
4. **Resubmit** — the service calls the EX *rescan* API, handing EX the password so
   it can open and re-analyze the attachment.
5. **Re-detect** — EX re-analyzes and pushes the re-detection back to the webhook
   (under the original queue id with an `_RA` suffix).
6. **Conclude** — the service determines the outcome and records it:
   - **Wrong password** → the attachment is still encrypted → email the recipient
     again, up to a retry cap.
   - **Clean** → EX released and delivered the email → `Released`.
   - **Malicious / still held** → EX re-quarantined it → `Quarantined`.

Every recipient, email, password attempt, and state change is tracked and visible
in a password-gated web dashboard.

## What it is *not*

- It never sees or stores the attachment itself — only the password, transiently.
- It never makes the malware verdict; **EX** does. The service only orchestrates
  the resubmission and reads EX's answer.
- It stores the password only long enough to complete the rescan, encrypted at
  rest, then purges it.

## Key properties

| Property | How it's achieved |
|----------|-------------------|
| **Fully automated** | Webhook in, email out, rescan, verdict — no human step except the recipient typing the password. |
| **Resilient** | Wrong passwords retry; failed emails and failed rescans are swept and retried; a recheck timer backstops missed pushes; and **reconciliation** backfills any trigger alerts that arrived while the app was down. |
| **Safe with the password** | Held encrypted (Fernet) only until the rescan succeeds, then deleted; only a hash is kept for audit. |
| **Operable** | Live dashboard, live-editable settings, health check, connectivity self-test (`--check`). |
| **Self-contained** | One Python process, SQLite by default, no external services beyond EX and an SMTP relay. |

## A one-screen tour

- **Entry points:** `POST /webhook/ex-alert` (from EX), `GET/POST /p/<token>` (the
  recipient), and the admin UI at `/`.
- **The brain:** `domain.FlowEngine` — a pure state machine with no I/O of its own.
- **The transports:** `ex_client.EXClient` (EX API), `mailer.SMTPMailer` (email),
  `storage.CaseRepository` (database), `bounce.BounceMonitor` (IMAP).
- **The state:** one `AttachmentCase` per quarantined email, moving through the
  states in [Flow & States](03_flow_and_states.md).

---

# 2. Architecture

## Design principle

The codebase is **layered around a pure core**. All business logic lives in
`domain.py`, which performs **zero I/O**: it never touches the network, database,
SMTP, or clock directly. Instead the `FlowEngine` calls injected collaborators
(repository, EX client, mailer, scheduler). Every side-effecting concern is
isolated behind one of those collaborators. This is what makes the whole state
machine unit-testable with fakes and no mocking of transports.

```mermaid
flowchart TB
    subgraph io["Transports / I/O — injected collaborators"]
        direction LR
        EXC[ex_client]
        MAIL[mailer]
        REPO[storage]
        BNC[bounce]
        SCH[recheck]
    end
    ENG["domain.FlowEngine<br/><i>pure state machine — no I/O of its own</i>"]:::core
    ING["ingest<br/>EX alerts in"]
    WEB["web (UI + API)<br/>operators in"]

    ING --> ENG
    WEB --> ENG
    ENG --> io
    classDef core fill:#2d6ae0,stroke:#1b4fc0,color:#fff;
```

## Component diagram

```mermaid
flowchart TB
    subgraph external[External systems]
        EX[Trellix EX appliance]
        SMTP[SMTP relay]
        IMAP[(Sender mailbox / IMAP)]
        REC[Recipient browser]
        OP[Operator browser]
    end

    subgraph app[Attachment Decrypt process]
        direction TB
        ING[ingest.py<br/>webhook router]
        WEB[web/*<br/>dashboard, API, password form]
        ENG[domain.FlowEngine<br/>state machine]
        EXC[ex_client.EXClient]
        MAIL[mailer.SMTPMailer]
        BNC[bounce.BounceMonitor]
        SCH[recheck.RecheckScheduler]
        REPO[storage.CaseRepository]
        STORE[settings_store.SettingsStore]
        DB[(SQLite / SQL DB)]
    end

    EX -->|alert push| ING
    REC -->|one-time link| WEB
    OP -->|dashboard/settings| WEB
    ING --> ENG
    WEB --> ENG
    WEB --> STORE
    ENG --> EXC --> EX
    ENG --> MAIL --> SMTP
    ENG --> SCH
    ENG --> REPO --> DB
    STORE --> DB
    IMAP --> BNC --> ENG
    SCH -.recheck / retry.-> ENG
```

## Module map

| Layer | File | Responsibility |
|-------|------|----------------|
| Entrypoint | `__main__.py` | `python -m trellix_decrypt` / `--check`; starts uvicorn. |
| Composition | `app.py` | Build `Settings`, resolve `SECRET_KEY`, configure logging, wire the `AppContext`, return the FastAPI app. |
| Context | `context.py` | `AppContext` owns the live `FlowEngine`; `reload()` re-wires transports from current settings without a restart. |
| Config | `config.py` | `Settings` (env/`.env`), `resolve_secret_key`, `missing_required`/`is_configured`. |
| Config store | `settings_store.py` | UI-editable overrides layered over env defaults; secrets encrypted at rest. |
| **Core** | `domain.py` | `FlowEngine`, `FlowState`, `RiskwareRules`, `TokenService`, and the pure alert parsers. **No I/O.** |
| EX transport | `ex_client.py` | `EXClient`: auth, alerts, quarantine list/rescan/release/delete, alert-by-uuid. |
| Ingest | `ingest.py` | Webhook router: auth, body cap, parse, dispatch to the engine. |
| Mail | `mailer.py` | `SMTPMailer` + Jinja2 email rendering. |
| Persistence | `storage.py` | ORM models + `CaseRepository` (+ dashboard read models). |
| Web | `web/` | `server.py` (app factory), `auth.py`, `routes_password.py`, `routes_dashboard.py`, `routes_api.py`, `ratelimit.py`. |
| Scheduling | `recheck.py` | asyncio task scheduler: recheck polls + notify/resubmit retry sweeps. |
| Bounce | `bounce.py` | DSN parser + IMAP poller; flips accepted-then-bounced mail to `BOUNCED`. |
| Crypto | `crypto.py` | Fernet helper keyed by `SECRET_KEY`. |

## Two ways in, one brain

There are exactly two inbound triggers, and both funnel into the same
`FlowEngine`:

1. **`ingest.py`** — the EX webhook. It authenticates the caller, caps the body,
   parses alerts with the pure `domain.parse_alert`, and calls
   `engine.handle_alert(event)`. It is the consumer for *both* the first-time
   quarantine alert and the `_RA` re-detection push.
2. **`web/`** — the operator (dashboard, settings, resend/rescan actions) and the
   recipient (password form). Operator surfaces are auth-gated; the password form
   and webhook are public but individually protected (tokens, webhook auth, rate
   limits).

## Async model

Everything is `async` (FastAPI + httpx + aiosmtplib). Background work runs as
tracked asyncio tasks created by `RecheckScheduler`:

- **Recheck poll** (`schedule_recheck`) — after a resubmission, poll the EX
  quarantine list until the `_RA` verdict is known or the attempt budget is spent.
- **Resubmit task** (`schedule_resubmit`) — run the EX rescan in the background so
  the recipient's submission returns instantly, decoupled from EX availability.
- **Retry sweeps** (`start_notify_retrier`, `start_resubmit_retrier`) — periodic
  loops that re-attempt failed emails and failed rescans under their caps.
- **Reconcile** (`start_reconcile`) — a startup backfill (and optional periodic sweep)
  that queries EX for recent trigger alerts and creates any case missed while the app
  was down; idempotent (dedups by queue id), so it can't duplicate or re-email.
- **Bounce loop** (`start_loop`) — the IMAP poller.

## Live reconfiguration

The `AppContext` holds one long-lived `FlowEngine`. When settings change through
the UI, `AppContext.reload()` rebuilds the EX client, mailer, token service, and
rules from the new effective settings and swaps them into the *same* engine
instance — so in-flight cases and scheduled tasks keep running while configuration
changes take effect. (Infrastructure settings — bind host/port, logging — are read
at startup and take effect on the next restart; see [Security](06_security.md) and
the [User Guide](07_user_guide.md).)

## Configuration precedence

```mermaid
flowchart TB
    ENV["environment variables / .env<br/><i>Settings — defaults / bootstrap</i>"]
    DB["DB settings table overrides<br/><i>SettingsStore — UI-editable, secrets encrypted</i>"]
    EFF["effective Settings<br/><i>what FlowEngine uses; rebuilt on reload</i>"]
    ENV -->|overlaid by| DB
    DB -->|equals| EFF
```

`SECRET_KEY` and `DB_URL` are the two settings that are **not** UI-editable — they
bootstrap the very mechanisms (secret encryption, the database) the overrides rely
on, so they must come from the environment (or, for `SECRET_KEY`, be auto-generated
and persisted to `secret.key`).

## Trust boundaries

```mermaid
flowchart LR
    subgraph untrusted[Public / untrusted]
        REC[Recipient]
        NET[Internet]
    end
    subgraph edge[Reverse proxy — TLS termination]
        PROXY[HTTPS proxy]
    end
    subgraph trusted[Service process]
        WEBHOOK[/webhook/ex-alert<br/>Basic auth + IP allowlist/]
        FORM[/p/&lt;token&gt;<br/>signed token + rate limit/]
        ADMIN[/ and /settings<br/>session cookie + rate limit/]
        HEALTH[/healthz<br/>public/]
    end
    subgraph secrets[Secrets at rest]
        KEY[secret.key]
        DB[(encrypted settings + pwd_enc)]
    end
    NET --> PROXY --> WEBHOOK & FORM & ADMIN & HEALTH
    REC --> PROXY
    ADMIN -.reads.-> DB
    WEBHOOK -.reads.-> DB
    KEY -.keys.-> DB
```

- **HTTPS** is terminated by a reverse proxy in front of the service.
- The **webhook** requires HTTP Basic auth and/or a source-IP allowlist.
- The **password form** is public by necessity but guarded by unguessable signed
  tokens and a per-IP+token rate limit.
- The **admin surfaces** require a signed session cookie; login is rate-limited.
- **Secrets at rest** (settings secrets, the transient attachment password) are
  Fernet-encrypted with a key derived from `SECRET_KEY`.

---

# 3. Flow & States

This is the heart of the system: the `FlowEngine` state machine in `domain.py` and
the sequences that drive transitions.

## The states

`FlowState` (in `domain.py`) enumerates every state a case can be in:

| State | Meaning | Terminal? |
|-------|---------|-----------|
| `RECEIVED` | Alert matched; case created. | no |
| `AWAITING_PASSWORD` | One-time link emailed; waiting for the recipient. | no |
| `PASSWORD_SUBMITTED` | Recipient submitted the password (held encrypted). | no |
| `RESUBMITTED` | EX rescan issued with the password. | no |
| `RECHECKING` | Polling EX quarantine for the verdict (held vs released). | no |
| `DONE_PASSED` | Original released, no `_RA` → delivered. Shown as **Released**. | **yes** |
| `DONE_QUARANTINED` | Re-quarantined (`_RA` present) → still held. Shown as **Quarantined**. | **yes** |
| `FAILED_MAX_RETRIES` | Wrong password too many times; gave up. | yes* |
| `EXPIRED` | Case aged out without completion. | **yes** |
| `NOTIFY_FAILED` | SMTP error handing off the email (auto-retried, resendable). | no |
| `BOUNCED` | Email accepted then bounced (DSN); resendable. | **yes** |
| `RESUBMIT_FAILED` | Password captured but EX rescan failed (retryable). | no |

\* `FAILED_MAX_RETRIES` is an end-of-line for the retry loop but is not in the
`TERMINAL` set used for bounce-suppression; it is a settled outcome.

Two named groups drive the logic:

- **`RECHECKABLE`** = `{RESUBMITTED, RECHECKING}` — states from which a recheck poll
  or a pushed verdict may still resolve the case.
- **`TERMINAL`** = `{DONE_PASSED, DONE_QUARANTINED, FAILED_MAX_RETRIES, EXPIRED,
  BOUNCED}` — settled states that a late bounce must not overwrite.

## State machine

```mermaid
stateDiagram-v2
    [*] --> RECEIVED: alert matches trigger
    RECEIVED --> AWAITING_PASSWORD: email link sent
    RECEIVED --> NOTIFY_FAILED: SMTP error

    AWAITING_PASSWORD --> PASSWORD_SUBMITTED: recipient submits password
    AWAITING_PASSWORD --> AWAITING_PASSWORD: expired link reopened → reissued

    NOTIFY_FAILED --> AWAITING_PASSWORD: retry sweep / resend succeeds

    PASSWORD_SUBMITTED --> RESUBMITTED: EX rescan accepted
    PASSWORD_SUBMITTED --> RESUBMIT_FAILED: rescan error
    RESUBMIT_FAILED --> RESUBMITTED: retry sweep succeeds

    RESUBMITTED --> RECHECKING: first recheck poll
    RECHECKING --> AWAITING_PASSWORD: wrong password (still encrypted), under cap
    RECHECKING --> FAILED_MAX_RETRIES: wrong password, cap reached
    RESUBMITTED --> DONE_QUARANTINED: _RA present (held)
    RECHECKING --> DONE_QUARANTINED: _RA present (held)
    RESUBMITTED --> DONE_PASSED: original released (no _RA)
    RECHECKING --> DONE_PASSED: original released (no _RA)

    AWAITING_PASSWORD --> BOUNCED: DSN received
    DONE_QUARANTINED --> AWAITING_PASSWORD: later wrong-password push reopens (under cap)
    DONE_PASSED --> AWAITING_PASSWORD: later wrong-password push reopens (under cap)

    DONE_PASSED --> [*]
    DONE_QUARANTINED --> [*]
    FAILED_MAX_RETRIES --> [*]
    BOUNCED --> [*]
    EXPIRED --> [*]
```

## Journey 1 — Alert to password request

```mermaid
sequenceDiagram
    participant EX as Trellix EX
    participant W as webhook (ingest)
    participant E as FlowEngine
    participant R as RiskwareRules
    participant DB as CaseRepository
    participant M as SMTPMailer
    participant U as Recipient

    EX->>W: POST /webhook/ex-alert (RISKWARE_OBJECT + CustomPolicy.MVX.<ext>)
    W->>W: auth + body cap + parse_alert
    W->>E: handle_alert(event)
    E->>R: matches(event)?
    R-->>E: yes (alert name + malware name)
    E->>DB: get_or_create_case
    E->>M: send_password_request(recipients, link)
    M->>U: email with /p/<one-time-token>
    E->>DB: state = AWAITING_PASSWORD
```

If the SMTP hand-off fails, the case goes to `NOTIFY_FAILED` and the notify-retry
sweep re-attempts it (and an operator can "Resend" from the dashboard).

## Journey 2 — Password to rescan

```mermaid
sequenceDiagram
    participant U as Recipient
    participant P as password form
    participant E as FlowEngine
    participant DB as CaseRepository
    participant S as Scheduler
    participant X as EXClient
    participant EX as Trellix EX

    U->>P: POST /p/<token> (password)
    P->>P: rate-limit (IP+token)
    P->>E: handle_password(token, password)
    E->>DB: store encrypted pwd_enc, set state PASSWORD_SUBMITTED
    E-->>U: received, processing (immediate ack)
    E->>S: schedule_resubmit(case)
    Note over S,X: background — decoupled from the recipient
    S->>E: resubmit_case(case)
    E->>X: rescan_target(queue_id) → find rescannable entry
    E->>X: rescan(target, [password])
    X->>EX: POST /emailmgmt/quarantine/rescan/<queue_id>
    E->>DB: record pwd hash (audit), clear pwd_enc, set state RESUBMITTED
    E->>S: schedule_recheck(case)
```

The recipient's success does **not** depend on EX being reachable: the password is
stored encrypted and acknowledged immediately, and the rescan runs in the
background, retrying under `resubmit_max_retries` if EX is briefly down.

## Journey 3 — Re-detection classification (`_RA` push)

EX re-analyzes the resubmission and pushes the re-detection to the same webhook,
under `<queue_id>_RA`. The push only *triggers* a decision — the verdict is
confirmed from the authoritative quarantine list.

```mermaid
sequenceDiagram
    participant EX as Trellix EX
    participant W as webhook (ingest)
    participant E as FlowEngine
    participant DB as CaseRepository
    participant X as EXClient

    EX->>W: POST /webhook/ex-alert (<queue_id>_RA re-detection)
    W->>E: handle_alert(event)
    E->>E: strip _RA suffix → find parent case
    E->>E: _classify_resubmission(parent, event)
    alt still encrypted (wrong password)
        Note over E: CustomPolicy.MVX.<ext> OR PASSWORD_EXTRACTION_FAILED
        E->>DB: increment attempts
        alt under cap
            E->>DB: state = AWAITING_PASSWORD (re-ask)
        else cap reached
            E->>DB: state = FAILED_MAX_RETRIES
        end
    else not the wrong-password signal
        E->>X: has_resubmission_quarantine(queue_id)?
        alt <queue_id>_RA present
            E->>DB: state = DONE_QUARANTINED (held)
        else absent
            E->>DB: state = DONE_PASSED (delivered)
        end
    end
```

### Why the verdict comes from the quarantine list, not the push

A riskware rule can *alert without quarantining* (alert-but-allow), so a push
proves only that re-analysis happened — not that the email is held. The engine
therefore confirms held-vs-passed from `ex_client.has_resubmission_quarantine`,
which asks the actual quarantine list: **is there a record whose queue id is
exactly `<queue_id>_RA`?** Present → held; absent → delivered.

### Wire-format gotchas (lab-verified)

- Pushed alert names are hyphenated lowercase (`riskware-object`), so names are
  compared via `domain._canon_name`, never `== "RISKWARE_OBJECT"`.
- One `_RA` can arrive as several separate webhook POSTs (one per detected object),
  so classification is **order-independent**: a later `PASSWORD_EXTRACTION_FAILED`
  push reopens a case a re-quarantine confirm had already moved to
  `DONE_QUARANTINED`, and repeat pushes count as one attempt.
- The still-encrypted marker is **authoritative** and wins over any malware verdict
  (the wrong-password path is checked first).

## Journey 4 — Recheck poll (concludes clean/released emails)

A **held** email resolves almost instantly from the pushed `_RA` re-detection. A
**released/clean** email sends **no push**, so it is found only by the recheck poll.
The poll therefore reads a three-state verdict from the quarantine list each time
(`resubmission_outcome`) and concludes **as soon as it is decisive** — it does not wait
for the final poll — so a clean email doesn't linger in `RECHECKING`. Polling is
**eager**: the first check is soon after resubmission, then it backs off to
`recheck_interval`.

```mermaid
sequenceDiagram
    participant S as Scheduler
    participant E as FlowEngine
    participant X as EXClient

    S->>S: wait recheck_delay (first poll, eager)
    loop eager backoff, up to recheck_max_attempts
        S->>E: recheck(case, final?)
        alt already resolved by a push
            E-->>S: stop
        else list decisive now
            E->>X: resubmission_outcome(queue_id)
            Note over E,X: _RA present means held, original gone means released
            E->>E: conclude DONE_QUARANTINED or DONE_PASSED
            E-->>S: stop
        else still pending (original quarantined, no _RA)
            E->>E: set RECHECKING, keep polling
        end
        S->>S: back off toward recheck_interval
    end
```

## Correlation & clock-independence (two subtle invariants)

1. **`_RA` correlation** — a re-detection is joined to its parent case by *stripping*
   the `_RA` suffix(es) and matching the queue id (`find_case_by_queue_id`). An `_RA`
   alert is **never** turned into a new case.
2. **Clock-independent quarantine window** — per-case quarantine lookups query EX
   over a fixed 2000–2100 window, never a `now()`-relative one. EX filters the list
   by *its* clock; if we computed the window on *ours*, a skewed appliance clock
   would push the very `_RA` entry we need out of view — making a held email read as
   passed (the dangerous direction) or a rescan report "queue id not found". This was
   observed live and fixed by decoupling the window from both clocks. See
   [Code Reference](04_code_reference.md) → `ex_client`.

---

# 4. Code Reference

Module-by-module reference of the public classes and functions and their
contracts. Signatures are illustrative; the source is the authority.

---

## `domain.py` — pure core (no I/O)

### Enums & constants
- `FlowState(str, Enum)` — every case state (see [Flow & States](03_flow_and_states.md)).
- `RECHECKABLE` — `{RESUBMITTED, RECHECKING}`.
- `TERMINAL` — settled states a late bounce must not overwrite.
- `PASSWORD_FAILED_MARKERS` — `{"password_extraction_failed"}`; the authoritative
  wrong-password marker.

### Helpers
- `_canon_name(value) -> str` — canonicalize an EX name (lowercase, trim,
  `-`→`_`) so `MALWARE-OBJECT` == `malware_object`. **Always** compare names through
  this, never `==` a literal.
- `_detection_summary(event) -> str` — compact detection string (alert name +
  malware names + `(malicious)`) folded into the timeline; empty when there's no push.

### `AlertEvent` (dataclass)
Normalized EX alert: `queue_id`, `recipients`, `alert_name`, `malicious`, `sender`,
`subject`, `malware_names`, `raw`. `.recipient` returns the first recipient.

### `RiskwareRules`
Decides whether an alert triggers the flow.
- `matches(event) -> bool` — true iff the top-level alert name equals the configured
  trigger name **and** one malware name exactly equals a configured trigger malware
  name (case-insensitive). Empty trigger-name list → nothing matches (disabled).
- `name_matches` / `alert_name_matches` — the two halves of that test.

### `TokenService`
Mint/verify signed, TTL-expiring one-time links carrying a case id.
- `mint(case_id) -> str`
- `verify(token) -> str | None` — case id for a valid, **unexpired** token.
- `peek(token) -> str | None` — case id for a validly-signed token **regardless of
  age** (used to accept a just-expired link the recipient is actively submitting;
  single use is still enforced by case state).

### `hash_password(password) -> str`
SHA-256 hex, for de-duping/audit. Plaintext is never persisted.

### `FlowEngine` — the state machine / orchestrator
Constructed with injected collaborators: `repo, ex, mailer, tokens, rules, settings,
scheduler`. Key methods:

| Method | Contract |
|--------|----------|
| `handle_alert(event)` | Entry point for an incoming alert. Correlates `_RA` re-detections to the parent (classifies, never creates a case); otherwise gates on the trigger rules and starts the flow. Returns the case or `None`. |
| `handle_password(token, password)` | Store the password encrypted, ack immediately, schedule the background rescan. Returns `(case_or_None, status)`. |
| `resubmit_case(case_id)` | Background: decrypt the held password, find the rescannable entry, call EX rescan; on success record the hash, purge the password, schedule recheck; on failure count + `RESUBMIT_FAILED`. |
| `recheck(case_id, final)` | Poll toward a verdict: reads `resubmission_outcome` and concludes as soon as decisive — `held` → DONE_QUARANTINED, `released` (original gone) → DONE_PASSED — else keeps polling; the final poll concludes from the list. Returns `True` to stop polling. |
| `reissue_expired_link(token)` | Re-email a fresh link if an expired-but-valid link is opened while still `AWAITING_PASSWORD`. |
| `resend(case_id)` | Operator-triggered re-send for `NOTIFY_FAILED`/`AWAITING_PASSWORD`/`BOUNCED`. |
| `handle_bounce(bounce)` | Mark a case `BOUNCED` (correlate by `X-Case-Id`, else recipient); never overrides a terminal state. |
| `alert_details_for_case(case_id)` | **Display-only**: fetch every alert UUID for the case's quarantine records and return parsed detail. Best-effort; never a flow decision. |
| `resume_pending()` | On startup, reschedule mid-flight rechecks and resubmissions. |
| `reconcile(duration)` | Backfill **first-time** trigger alerts missed while down: query EX (`get_alerts`) over a window and start the flow for any matching email with no case. Idempotent — dedups by queue id, skips `_RA` re-detections, only emails brand-new cases. |
| `retry_failed_notifications()` / `retry_failed_resubmissions()` | Background sweep bodies. |

Private decision helpers: `_still_encrypted`, `_confirm_outcome`,
`_classify_resubmission`, `_fail_extraction`, `_send_password_request`.

### Pure alert parsers
- `iter_alerts(payload) -> list[dict]` — unwrap `Alerts`/`alerts`/`alert`/bare.
- `parse_alert(alert) -> AlertEvent` — map a raw alert (either wire format:
  camelCase query JSON or hyphenated `{"value": …}` push) to an `AlertEvent`.
- `parse_alert_detail(alert) -> dict` — compact display view for the drawer.
- `split_addrs`, `_text`, `_text_list`, `_dig`, `_first`, `_is_yes`,
  `_malware_entries` — tolerant field extractors covering both wire formats.

---

## `ex_client.py` — Trellix EX transport

All endpoint paths are defined at the top of the file (the single place to adjust
for another appliance): `EP_LOGIN`, `EP_ALERTS`, `EP_ALERT_DETAILS`,
`EP_QUARANTINE`, `EP_QUARANTINE_RESCAN`, `EP_QUARANTINE_RELEASE`,
`EP_QUARANTINE_DELETE`. API version `v2.0.0`.

### `EXClient`
- Auth: `X-FeApi-Token` (+ optional `X-FeClient-Token`), lazy login, automatic
  single re-auth on `401` (EX's 15-min idle timeout).
- `get_alerts(**filters)` — alerts query.
- `get_alert_by_uuid(uuid) -> dict | None` — full alert detail by UUID
  (undocumented endpoint; display-only). `None` on not-found.
- `list_quarantine(sender, subject, since, until, **params)` — quarantine list;
  `since`/`until` widen EX's default 24h window (padded by `_TIME_SKEW`).
- `rescan_target(queue_id, sender, subject) -> (queue_id, email_uuid)` — pick the
  **rescannable** entry (one with a real `quarantine_path`; `_RA` records have a null
  path and can't be rescanned).
- `rescan(target_id, passwords)` — `POST …/rescan/<id>` with
  `{"rescan_properties": {"pwd_list": [...]}}`.
- `has_resubmission_quarantine(queue_id, sender, subject) -> bool` — **authoritative
  verdict**: is there a record whose queue id is exactly `<queue_id>_RA`? Exact
  suffix match (via `_strip_ra`), never a loose prefix.
- `resubmission_outcome(queue_id, sender, subject) -> str` — three-state verdict for the
  recheck poll: `"held"` (the `<queue_id>_RA` is present), `"released"` (neither the
  `_RA` nor the original `<queue_id>` remains — delivered), or `"pending"` (original
  still quarantined, no `_RA` yet). Lets a clean email conclude without a push.
- `alert_uuids_for(queue_id, sender, subject) -> list[str]` — all alert UUIDs on the
  case's quarantine records, deduped, order-preserved.
- `release(queue_ids)` / `delete(queue_ids)` — quarantine actions.

### Clock-independence (critical)
`_list_for_case` sends a **fixed 2000–2100 window** for all per-case lookups
(`rescan_target`, `has_resubmission_quarantine`, `alert_uuids_for`). EX filters by
its own clock; a now-relative window computed on ours breaks under clock skew. **Do
not** make this window now-relative. `list_quarantine` still accepts `since`/`until`
for other callers/tests.

### Errors
- `EXAuthError` — login failure.
- `EXApiError(message, status_code, body)` — any non-2xx; `.not_found` recognizes
  EX's "email not quarantined / invalid queue id" 400/404 bodies.

### Helpers
`_qid`, `_strip_ra` (removes one-or-more `_RA` suffixes), `_ex_time`
(`YYYY-MM-DDTHH:MM:SS.SSS±HHMM`), `_as_quarantine_list`.

---

## `ingest.py` — webhook

- `build_webhook_router(ctx)` → `POST /webhook/ex-alert`. In order: **503 if not
  configured** (setup mode); require Basic auth and/or IP allowlist; **cap the body**
  at `max_request_bytes`; parse; dispatch each alert to `engine.handle_alert`.
- `_basic_credentials(request)` — decode the `Authorization: Basic` header.
- `AlertSource(ABC)` — pluggable transport interface (syslog etc. later).

---

## `web/` — HTTP surfaces

| File | Contents |
|------|----------|
| `server.py` | `create_app(ctx)`: mount static, include routers, lifespan (resume pending + start sweeps + bounce loop), `/healthz`. |
| `auth.py` | Shared-password admin session: `check_password` (constant-time), `issue_session`, `is_authenticated`, cookie `ui_session` (12h TTL). |
| `routes_password.py` | Public `/p/<token>`: GET renders/reissues, POST rate-limits then `handle_password`. |
| `routes_dashboard.py` | `/login`, `/logout`, `/`, `/settings`; login rate-limit; **setup mode** (`in_setup_mode`) opens `/settings` before an admin password exists. |
| `routes_api.py` | Auth JSON API: `/api/status`, `/api/cases`, `/api/cases/<id>`, `…/alerts`, `…/resend`, `…/rescan`, `/api/settings` (GET/POST). Settings endpoints use `_guard_settings` (open in setup mode). |
| `ratelimit.py` | `RateLimiter` (sliding window) + `client_ip` (honors `X-Forwarded-For` only when `trust_forwarded_for`). |

---

## `config.py` — settings

- `Settings(BaseSettings)` — all config from env/`.env`. Operationally-required
  fields default to empty so the app can boot into setup mode.
- `Settings.missing_required() -> list[str]` / `.is_configured() -> bool` — drive
  setup mode; require EX creds, SMTP, public URL, admin password, and webhook auth.
- `Settings.webhook_auth_configured()` — Basic creds and/or IP allowlist present.
- `resolve_secret_key(env_value, key_path) -> str` — explicit env key wins; else
  read/generate+persist a strong key to `key_path`. Placeholder values
  (`change-me`, …) count as unset.
- `INSECURE_SECRET_KEYS` — placeholders treated as unset.

## `settings_store.py`
- `SettingsStore(env, session_factory)`: `effective_settings()` (env overlaid with
  DB overrides), `masked()` (secrets shown as `********`), `update(changes)`.
- `EDITABLE` — UI-editable keys (everything except `SECRET_KEY` and `DB_URL`).
- `SECRET_KEYS` — encrypted at rest (includes `ui_password`).
- `LIST_KEYS` — CSV list fields (`trigger_malware_names`, `webhook_ip_allowlist`).
- `RESTART_REQUIRED` — editable but applied on restart (bind host/port, logging,
  rate-limit windows).

## `storage.py` — see [Data Model](05_data_model.md)

## `mailer.py`
`SMTPMailer(settings)` renders the Jinja2 recipient email (text+HTML) and sends via
aiosmtplib; TLS mode per `smtp_tls_mode`. Sets `X-Case-Id` for bounce correlation.

## `recheck.py`
`RecheckScheduler`: `schedule_recheck`, `schedule_resubmit`, `start_notify_retrier`,
`start_resubmit_retrier`, `start_reconcile`, `start_loop`, `shutdown`. Tasks read
settings live. The recheck poll uses an eager backoff; `start_reconcile` runs the
startup backfill + optional periodic reconcile sweep.

## `bounce.py`
`parse_bounce(raw) -> dict` (DSN parser) + `BounceMonitor` (IMAP poll of the sender
mailbox); flips accepted-then-bounced mail to `BOUNCED`.

## `crypto.py`
`fernet(secret_key) -> Fernet` — key derived as `urlsafe_b64encode(sha256(secret_key))`.

## `check.py`
`run_check()` / `check(settings)` — log in to EX and run a small alerts + quarantine
query using effective settings; prints a report; exit 0 = OK. Invoked by
`python -m trellix_decrypt --check`.

## `app.py` / `context.py` / `__main__.py`
- `app.build(settings)` — resolve `SECRET_KEY`, build context, configure logging from
  effective settings, warn on setup mode, return `(app, effective_settings)`.
- `AppContext` — owns the live engine; `reload()` re-wires transports.
- `__main__.main()` — `--check` or `uvicorn.run(app, host, port)`.

---

# 5. Data Model

Persistence is SQLAlchemy 2.0 over SQLite by default (`DB_URL`). Four tables, all
defined in `storage.py`. The repository (`CaseRepository`) returns detached ORM
instances (`expire_on_commit=False`) so the `FlowEngine` can treat cases as plain
value objects after the session closes.

## Entity–relationship diagram

```mermaid
erDiagram
    ATTACHMENT_CASES ||--o{ EVENT_LOG : "has timeline"
    ATTACHMENT_CASES ||--o{ PASSWORD_ATTEMPTS : "has audit hashes"
    SETTINGS }o..o{ ATTACHMENT_CASES : "config (unrelated rows)"

    ATTACHMENT_CASES {
        string id PK
        string queue_id UK "EX queue id (unique, indexed)"
        string recipient "comma-joined To addresses"
        string sender
        string subject
        string alert_name
        string malware_name "first malware name (the attachment kind)"
        enum   state "FlowState"
        int    attempts "wrong-password rounds"
        int    notify_attempts
        int    resubmit_attempts
        string pwd_enc "Fernet-encrypted password; purged after rescan"
        datetime created_at
        datetime updated_at
    }
    EVENT_LOG {
        string id PK
        string case_id FK
        enum   state "FlowState at this event"
        string detail "human-readable note"
        datetime created_at
    }
    PASSWORD_ATTEMPTS {
        string id PK
        string case_id FK
        string password_hash "sha256 — never plaintext"
        datetime created_at
    }
    SETTINGS {
        string key PK
        string value "encrypted if is_secret"
        bool   is_secret
        datetime updated_at
    }
```

## Tables

### `attachment_cases` — one row per quarantined email
The central aggregate. Keyed on `queue_id` (unique) so the same email re-notified
(one alert per recipient) merges into one case, unioning recipients. Notable columns:

- **`state`** — the `FlowState` enum; the case's position in the machine.
- **`recipient`** — all To addresses, comma-joined; every recipient gets the same
  one-time link.
- **`attempts`** — confirmed wrong-password rounds, checked against
  `max_password_attempts`.
- **`notify_attempts` / `resubmit_attempts`** — retry counters for the email and
  rescan sweeps, each capped independently.
- **`pwd_enc`** — the attachment password, **Fernet-encrypted**, held only from
  submission until the rescan succeeds, then set to `NULL`. Never plaintext.

### `event_log` — append-only case timeline
One row per state transition, with a human-readable `detail` (including the folded
detection summary on held/wrong-password transitions). Rendered as the timeline in
the dashboard drawer. `cascade="all, delete-orphan"` with the case.

### `password_attempts` — audit trail
A SHA-256 hash of each submitted password (for de-dup/audit) — **never** the
plaintext. Recording a hash does not itself count as a failure.

### `settings` — UI-editable config overrides
Key/value overrides layered over the environment defaults by `SettingsStore`.
`is_secret` rows are Fernet-encrypted at rest (keyed by `SECRET_KEY`).
`SECRET_KEY` and `DB_URL` never appear here — they bootstrap the encryption and the
database themselves.

## Repository read models

For the dashboard, `CaseRepository` exposes flattened dict read models:

- `list_cases(limit=300)` → `_case_dict` rows (newest first).
- `case_detail(case_id)` → a `_case_dict` plus a sorted `events` timeline.

These decouple the JSON API from the ORM shape.

## Lifecycle of the sensitive field

```mermaid
flowchart LR
    A[recipient submits password] --> B[Fernet-encrypt → pwd_enc]
    B --> C[background rescan reads + decrypts]
    C --> D{rescan ok?}
    D -- yes --> E[record sha256 hash → clear pwd_enc = NULL]
    D -- retry --> C
    E --> F[terminal outcome; only the hash remains]
```

---

# 6. Security

This document is the single place describing the service's security model: what is
protected, how, and what an operator must know — including the **rate-limit /
lockout behaviour and how to recover**.

## Attack surface at a glance

| Surface | Path | Protection |
|---------|------|------------|
| EX webhook | `POST /webhook/ex-alert` | HTTP Basic auth **and/or** source-IP allowlist; body-size cap; 503 until configured. |
| Recipient form | `GET/POST /p/<token>` | Unguessable signed, TTL-expiring token; single-use by case state; per-(IP+token) rate limit. |
| Admin dashboard/API | `/`, `/settings`, `/api/*` | Signed session cookie (12h); per-IP login rate limit. |
| Health | `/healthz` | Public, no data. |

## Secrets at rest

Everything sensitive is encrypted with **Fernet** (AES-128-CBC + HMAC), keyed by a
key derived from `SECRET_KEY` (`crypto.fernet`):

- **The attachment password** (`AttachmentCase.pwd_enc`) — held encrypted only from
  submission until the EX rescan succeeds, then purged (`NULL`). This transient
  storage is what lets the rescan auto-retry without re-asking the recipient. Only a
  SHA-256 hash survives, for audit.
- **UI-saved settings secrets** (`settings.value` where `is_secret`) — EX password,
  SMTP password, EX client token, webhook password, IMAP password, and the admin
  password (`ui_password`).

> **Rotating `SECRET_KEY`** invalidates every encrypted value: any held password
> becomes unreadable (the case will report the password unreadable and go to
> `RESUBMIT_FAILED`) and stored settings secrets must be re-entered. Rotate
> deliberately.

## `SECRET_KEY` — no shipped default

The service **never ships a usable default key**. On startup `resolve_secret_key`:

1. uses an explicit `SECRET_KEY` from the environment if set (and not a placeholder
   like `change-me`); otherwise
2. reads a previously generated key from `./secret.key`; otherwise
3. generates a strong random key (`secrets.token_urlsafe(48)`) and persists it to
   `./secret.key` with `0600` permissions.

`secret.key` is **gitignored**. This removes the classic "everyone runs the same
`change-me` key" weakness while keeping tokens and sessions stable across restarts.
Keep `secret.key` safe and backed up; deleting it invalidates all links and
sessions (and any DB-stored secrets).

## One-time links (recipient tokens)

- Signed with `itsdangerous` (HMAC), carrying the case id, salted `password-link`.
- **TTL-expiring** (`TOKEN_TTL`, default 24h). Opening an expired-but-validly-signed
  link auto-reissues a fresh one if the case still awaits a password.
- **Single-use** is enforced by **case state**, not the token: once a password is
  submitted the case leaves `AWAITING_PASSWORD`, so a replayed link is rejected.
- Tokens are unguessable; the form is additionally rate-limited (below).

## Admin authentication

- Shared password `UI_PASSWORD`, compared **constant-time** (`hmac.compare_digest`).
- On success, a signed session cookie `ui_session` (`httponly`, `samesite=lax`,
  12h TTL) is issued. All `/api/*` and admin pages require it.
- `SECRET_KEY` signs the cookie, so cookies are unforgeable without it.

## Webhook authentication

The webhook refuses to serve unless webhook auth is configured. It accepts a POST
only when:

1. the service **is configured** (else `503` — see setup mode), and
2. HTTP Basic credentials match (constant-time), **and/or**
3. the source IP is in the allowlist,

then it caps the body at `MAX_REQUEST_BYTES` before parsing.

## Rate limiting & lockout — and how to recover

Two **per-IP, self-healing sliding-window** limiters (`web/ratelimit.py`). There is
**no permanent lockout** and nothing an operator must manually unlock.

| Limiter | Key | Default | On exceed |
|---------|-----|---------|-----------|
| Admin login | client IP | 10 / 15 min | `HTTP 429`; clears as the window rolls off, and immediately on a successful login. |
| Password form | client IP **+** token | 10 / 5 min | `HTTP 429`; clears as the window rolls off. |

**Is lockout by IP?** Yes. The login limiter counts attempts per client IP; the
password-form limiter per IP **and** link. Counters live in memory only.

**Recovering from a login lockout** — any one of:

1. **Wait** — the window is short (15 min by default); the counter rolls off on its
   own.
2. **Restart the service** — counters are in-memory, so a restart clears them
   instantly.
3. **Use a different source IP** — the limit is per-IP.

A **successful** login also resets that IP's counter immediately, so a legitimate
admin who simply mistyped is not penalised once they get it right.

> Because there is no durable lockout state, there is no "unlock" button and no risk
> of bricking the admin account. The admin password itself is set via config/GUI,
> not recoverable-by-email; if it is *forgotten* (not locked out), reset it by
> setting `UI_PASSWORD` in the environment and restarting.

### Reverse proxies and the client IP

Behind a proxy the socket peer is the proxy, so all requests would share one IP. Set
`TRUST_FORWARDED_FOR=true` **only** when actually behind a trusted proxy that sets
`X-Forwarded-For`; the service then keys limits on the left-most forwarded address.
Leaving it off is safe (the header is otherwise spoofable and would defeat the
limit).

## First-run setup mode

Until the service `is_configured()` (EX creds, SMTP, public URL, admin password, and
webhook auth all present) it runs in **setup mode**:

- The webhook returns **503** — EX is told to retry rather than have alerts silently
  dropped.
- While **no admin password exists**, `/settings` and the settings API are reachable
  **without auth** — the only way to bootstrap the first password. The instant a
  password is set, setup mode ends and normal auth is enforced (the UI redirects to
  sign-in).

> **Operational note:** perform first-run setup on a trusted network or behind the
> reverse proxy, because the bootstrap window intentionally opens the settings page.
> It closes as soon as an admin password is saved.

## Denial-of-service hardening

- Request bodies (webhook and form) are capped at `MAX_REQUEST_BYTES` (1 MiB) before
  parsing.
- The password form and admin login are rate-limited.
- EX interactions have caps: `MAX_PASSWORD_ATTEMPTS`, `RESUBMIT_MAX_RETRIES`,
  `NOTIFY_MAX_RETRIES`, `RECHECK_MAX_ATTEMPTS` — no unbounded loops against EX.

## Repository hygiene

- `.claude/settings.json` denies reading/writing `.env*` and `*.sqlite3`.
- `.gitignore` excludes `.env*`, `secret.key`, `*.sqlite3`, log files, the vendor
  PDFs, and this `documentation/` folder.
- The attachment password is never logged in plaintext; a truncated SHA-8 fingerprint
  is logged at rescan time only to diagnose whitespace mismatches.

## Threat notes / residual risks

| Risk | Mitigation / status |
|------|--------------------|
| Password interception in transit | HTTPS terminated at the proxy; links are single-use and short-lived. |
| Replay of a captured link | Rejected by case state after first submission. |
| Brute-force of a token | Tokens are HMAC-signed and unguessable; form is rate-limited. |
| Compromise of `secret.key` | Grants decryption of stored secrets — protect the file (0600) and the host. |
| Setup-mode window | Time-boxed to before the first admin password; do setup on a trusted network. |
| Shared IP behind a proxy | Enable `TRUST_FORWARDED_FOR` so limits key on the real client. |

---

# 7. User Guide

A practical, step-by-step guide to installing, configuring, and operating the
service. For the security rationale behind these steps see [Security](06_security.md).

---

## 1. Prerequisites

- **Python ≥ 3.11**.
- Network reachability to your **Trellix EX** appliance (WSAPI) and an **SMTP**
  relay for outbound mail.
- An EX API account with the **API Analyst** role.
- (Optional) an **IMAP** mailbox for the `SMTP_FROM` sender, to detect bounces.
- A **reverse proxy** terminating HTTPS in front of the service (recommended).

## 2. Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## 3. Configure — two ways

You can configure the service entirely from the **web UI** (recommended, guided by
setup mode), or via environment variables / a `.env` file, or a mix. The UI writes
overrides to the database; the environment provides the defaults.

### Required settings

The service will not leave **setup mode** (and the webhook stays disabled) until all
of these are set:

| Setting | Purpose |
|---------|---------|
| `EX_BASE_URL`, `EX_USERNAME`, `EX_PASSWORD` | Reach and authenticate to EX. |
| `SMTP_HOST`, `SMTP_FROM` | Send the recipient email. |
| `PUBLIC_BASE_URL` | Build the one-time link (must match how recipients reach you). |
| `UI_PASSWORD` | Admin dashboard password (can be set in the UI on first run). |
| Webhook auth | `WEBHOOK_USERNAME`+`WEBHOOK_PASSWORD` and/or `WEBHOOK_IP_ALLOWLIST`. |

> **`SECRET_KEY` is not required** — leave it blank and a strong key is generated
> and saved to `./secret.key` on first run. **`DB_URL`** is environment-only.

### Option A — guided first-run setup (recommended)

1. Start the service with nothing configured (or only `DB_URL`):
   ```bash
   python -m trellix_decrypt
   ```
   The log shows `SETUP MODE — configuration incomplete, missing: …`.
2. Open `http://<host>:8080/` in a browser. You are redirected to **Settings**
   (no password required yet — this is the bootstrap window).
3. Fill in **Admin password** first, plus the EX, SMTP, public URL, and webhook
   fields. Click **Save changes**.
4. Setting the admin password ends setup mode; the UI redirects you to **sign in**.
   Log in with the password you just set.
5. The dashboard's "configuration incomplete" banner should be gone. The webhook is
   now live.

> Do first-run setup on a trusted network or behind your proxy — the bootstrap
> window intentionally opens the settings page until the admin password is set.

### Option B — environment / `.env`

```bash
cp env.example .env   # then edit .env (never committed)
python -m trellix_decrypt
```

`env.example` documents every variable with comments. Key groups: EX appliance,
trigger rules, SMTP, web/links, webhook auth, **security/rate limiting**, flow
tuning, bounce/IMAP, logging, storage.

## 4. Point EX at the webhook (add it as an HTTP notification destination)

EX delivers alerts to this service through its **HTTP notifications** feature: EX
posts a notification to one or more web servers when a malware object is detected.
You register this service as one of those servers, on the EX Web UI's **Notification
Settings** page. It has two parts — the shared **HTTP Settings** (defaults) and the
per-server entry — both under **Settings → Notifications → HTTP**.

> **Source:** *Trellix Email Security – Server User Guide, Release 11.x — "Configuring
> HTTP notifications using the Web UI"* (PDF in `docs/`; also online:
> [Notification settings](https://docs.trellix.com/bundle/ex_11.x_ug/page/UUID-48d03d0d-9e19-447e-1e07-775b91a5b021.html)
> ·
> [HTTP notifications](https://docs.trellix.com/bundle/ex_11.x_ug/page/UUID-25f43f87-0950-3685-63a3-9152b2ec2df8.html)).
> Requires **Admin** or **Operator** access, and the appliance needs network reach to
> this service. Field names below are verbatim from that guide.

### 4a. HTTP Settings (defaults)

1. On the Web UI, select the **Settings** tab.
2. Select **Notifications** on the side bar.
3. Click the **HTTP** tab to display the **Define Protocol Settings** area.
4. **Default delivery** — choose **Per Event** (Trellix-recommended; sends a
   notification each time an object is detected). *This service expects per-event
   pushes, not the Daily Digest.*
5. **Default provider** — leave **Generic** (recommended).
6. **Default format** — choose **JSON**, at **Normal** detail (recommended). Normal
   carries everything this service uses (recipients, queue id, sender, subject, malware
   names) and stays small. *Do not use Concise* (it can omit those fields). **Extended**
   also works — this service reads only the fields it needs and ignores the rest — but
   it is much larger (full static-analysis / file detail we don't use) and can approach
   the webhook body cap (`MAX_REQUEST_BYTES`, default 1 MiB); prefer Normal unless you
   have a reason to send Extended.
7. Click **Apply Settings** (changes are lost otherwise).

### 4b. Add the HTTP server (this service)

1. **Settings → Notifications → HTTP** tab → the **View and Add HTTP Servers** area.
2. Click **Add HTTP Server**.
3. In the **Server Name** box enter a name, e.g. `attachment-decrypt`, then click
   **Add New HTTP Server**. *(Do not put a URL in Server Name.)*
4. Select the **Enabled** checkbox for the new server.
5. In the **Server URL** box enter this service's webhook (reachable from the
   appliance):

   ```
   https://<your-public-host>/webhook/ex-alert
   ```

6. Click **Add New HTTP Server** to save the listing.

### 4c. Configure the server entry

1. In the **View and Add HTTP Servers** list, click the **edit** (pencil) icon for the
   server.
2. **Auth** — select the **Auth** checkbox and enter the **Username** and **Password**
   to match this service's `WEBHOOK_USERNAME` / `WEBHOOK_PASSWORD`. *(If you leave Auth
   off, you must instead put the appliance's source IP in `WEBHOOK_IP_ALLOWLIST` — this
   service requires Basic auth and/or an IP allowlist.)*
3. **Notification** — select **All Events**. This is **required**, not optional: the
   encrypted-attachment detection is a **`RISKWARE_OBJECT`**, and the **Malware Object**
   setting does **not** send riskware objects — so with "Malware Object" EX posts
   nothing for these emails and the flow never starts. **All Events** delivers the
   riskware alert (with the `CustomPolicy.MVX.<ext>` malware name your trigger matches)
   *and* the `_RA` re-detections. If you can pick specific event types instead of "All
   Events", you must include **riskware object**.
4. **Delivery** — **Per Event** (recommended).
5. **SSL Enable** + **SSL Verify** — select both if the endpoint is HTTPS (it should
   be; TLS is terminated by your reverse proxy). Use a certificate from a CA the
   appliance trusts.
6. **Default provider** — **Generic**.
7. **Message Format** — **JSON**, at **Normal** (or **Default** to inherit 4a). Not
   **Concise**. Extended works but is unnecessarily large (see 4a).
8. Click **Update**.

### 4d. Verify

First, confirm the URL is reachable and correctly spelled: open
`https://<your-public-host>/webhook/ex-alert` in a browser (or `curl` it). A **GET**
returns a small readiness response — `{"status": "ready", "method": "POST", …}` — so a
`200` here means the path is right. (Alerts themselves must be **POST**ed; a common
mistake is configuring the base host as the Server URL, which makes EX POST to `/` and
get a **405**.)

Then trigger or wait for a matching detection and confirm a `POST /webhook/ex-alert`
appears in this service's log (`LOG_FILE`) and the quarantined email shows up as a
case in the dashboard.

> **The `_RA` re-detection uses this same server.** After a resubmission, EX posts the
> re-analysis result to the *same* HTTP notification — no second destination is needed,
> which is why **All Events** / per-event delivery is recommended above.

## 5. Verify EX connectivity

Before relying on the webhook, run the self-test:

```bash
python -m trellix_decrypt --check
```

It logs in and runs a small alerts + quarantine query using the **effective**
settings, prints a readable report, and exits `0` on success.

## 6. The trigger rule

The flow fires only when an alert's top-level **name** equals `TRIGGER_ALERT_NAME`
(default `RISKWARE_OBJECT`) **and** one of its malware names exactly matches one of
`TRIGGER_MALWARE_NAMES`. The encrypted-attachment custom policy emits
`CustomPolicy.MVX.pdf` / `.zip` / `.docx` (and a `…PassExtractFailed` variant).

- Leaving `TRIGGER_MALWARE_NAMES` **empty disables triggering** entirely.
- Unrelated `CustomPolicy.MVX` rules (e.g. QR-code detections) must **not** be
  listed — matching is exact.

## 7. Run in production

Three ways to run it — **from source**, **Docker**, or a **prebuilt executable** —
each self-contained below. In every case: put the service behind a reverse proxy that
terminates HTTPS, and if that proxy is trusted, set `TRUST_FORWARDED_FOR=true` so rate
limits key on the real client IP.

### 7.1 Persistent state — `DATA_DIR` (read this first)

Two things must survive restarts, or sign-in sessions break and stored encrypted
settings become unreadable:

- **`secret.key`** — signs sessions and one-time links and encrypts stored secrets.
- **the database** — the case history and settings.

Both live under **`DATA_DIR`** (default: the current working directory). For anything
other than a quick local test, point `DATA_DIR` at a **dedicated, writable, persistent,
backed-up** folder the service owns. Back up `DATA_DIR` as a unit — the DB is partly
unreadable without its `secret.key`.

**What should `DATA_DIR` be?** A durable path (not a container's ephemeral layer or a
tmpfs), writable by the run-as user:

| Environment | Recommended `DATA_DIR` |
|-------------|------------------------|
| Docker | `/data` — a mounted volume (the compose default) |
| Linux (service) | `/var/lib/trellix-decrypt` |
| macOS | `/usr/local/var/trellix-decrypt` |
| Windows | `C:\ProgramData\trellix-decrypt` |
| Quick local test | leave unset → working directory |

Set it as your shell expects: `export DATA_DIR=…` (Linux/macOS bash/zsh),
`$env:DATA_DIR = "…"` (Windows PowerShell), or `set DATA_DIR=…` (cmd.exe).

### 7.2 SECRET_KEY — how to set it

Precedence: an explicit **`SECRET_KEY`** environment variable wins; otherwise the app
**generates a strong key on first run** and writes it to `DATA_DIR/secret.key` (file
permission `600`). You therefore have two supported options:

- **Let it auto-generate (simplest).** Do nothing — just make sure `DATA_DIR`
  persists so the generated `secret.key` is reused on restart.
- **Manage it yourself (env).** Generate one and set `SECRET_KEY`:

  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(48))"
  # then set SECRET_KEY=<that value> in the environment / .env / Docker secret
  ```

`SECRET_KEY` is intentionally **not** editable from the Settings UI (it protects the
DB the UI writes to). **Rotating it invalidates** every active session and makes any
held password and stored settings-secrets unreadable — rotate deliberately, then
re-enter settings secrets.

### 7.3 Database — what's required

- **Default (SQLite): nothing to set up.** The app **creates the database file
  automatically** on first run at `DATA_DIR/trellix_decrypt.sqlite3`. No server, no
  schema step. Just keep the file (it's inside `DATA_DIR`).
- **A different database (optional).** Set `DB_URL` to any SQLAlchemy URL, e.g.
  `postgresql+psycopg://user:pass@host/dbname`. Note the **driver is not bundled** —
  install it yourself (e.g. `pip install psycopg[binary]`) in your source/Docker
  build. `DB_URL` is environment-only (it can't be stored in the database it points
  at). Tables are created automatically; no migration tool is required.

### 7.4 From source

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
pip install -r requirements.txt
$env:DATA_DIR = "C:\ProgramData\trellix-decrypt"
python -m trellix_decrypt --check
python -m trellix_decrypt
```

Then open the UI to finish first-run setup (§3). Configuration can come from the
environment, a `.env` file, or entirely from the Settings UI.

### 7.5 Docker (recommended)

With **compose** (persists `DATA_DIR` in a named volume automatically):

```bash
docker compose up -d --build      # secret.key + DB live in the `data` volume
```

`docker-compose.yml` sets `DATA_DIR=/data` and mounts the `data` volume there. Provide
config via a local `.env` (optional — the app boots into setup mode; configure it from
the UI), or pass `SECRET_KEY` as an environment secret. The image runs as non-root,
exposes port 8080, and has a `/healthz` healthcheck.

To change the port, set `WEB_PORT` (container port — the app and healthcheck follow it)
and `HOST_PORT` (published host port) in `.env`; compose maps `HOST_PORT:WEB_PORT`. Set
the port this way in Docker rather than in the Settings UI, so the mapping and
healthcheck stay in sync.

Or with **plain `docker run`** (mount your own volume for `DATA_DIR`):

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

(Omit `-e SECRET_KEY=...` to let it auto-generate into the volume. Add `--env-file .env`
to pass operator config.)

### 7.6 Prebuilt executable

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

(The Windows binary is unsigned, so SmartScreen may warn on first run — choose *More
info → Run anyway*, or code-sign it in your own pipeline.)

### 7.7 Minimum configuration to go live

Whichever method you use, the service stays in **setup mode** (webhook returns 503)
until these are set — via env/`.env` or the Settings UI (see §3): EX base URL +
credentials, SMTP host + from address, public base URL, an admin password, and webhook
auth (Basic credentials and/or an IP allowlist). `SECRET_KEY` and `DB_URL` are **not**
required — they default as described in §7.2–7.3.

## 8. Daily operations (the dashboard)

Sign in at `/`:

- **Case list** — searchable, auto-refreshing, with status badges and a
  password-failure counter.
- **Case drawer** — lifecycle stepper + event timeline; and, best-effort, full EX
  alert detail fetched by UUID.
- **Actions** — **Resend** a link (for `Email failed` / `Awaiting` / `Bounced`
  cases), **Rescan** (re-run a pending resubmission), and **Reconcile** (top of the
  page) — on-demand backfill of any trigger alerts missed while the app was down
  (idempotent; also runs automatically on startup and, if configured, periodically).
- **Settings** (`/settings`) — every configurable option, applied **live** on save
  (except items tagged *restart to apply*: bind host/port, logging, rate-limit
  windows).

## 9. Settings reference (in the UI)

Every field has a **?** help icon — hover (or focus) it for an explanation and whether a
restart is required. TLS-certificate verification for EX and SMTP is **off by default**
(appliances/relays commonly use self-signed certs); enable it in production with trusted
certs.

The full per-setting reference — whether each option is **required or optional**, its
**default**, and what it's for — is in the [**Configuration reference**](#doc-09_config_reference)
appendix at the end.

**Secret fields (passwords, tokens).** These show `********` and never reveal the stored
value, so **leaving one blank means "keep the existing value"** — that is how you avoid
wiping a secret you simply didn't retype. To actually **remove** an optional secret
(EX client token, SMTP / IMAP / webhook password), tick its **remove** checkbox and
save; the value is cleared (which also blanks an env-provided value). The EX password
and admin password have no remove box — change them by typing a new value.

## 10. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Webhook returns **405** | EX is POSTing to the wrong path — usually the base host was set as the Server URL, so EX hits `/`. Set it to `https://<host>/webhook/ex-alert`. A GET to that URL returns `200 {"status":"ready"}` when correct. |
| Webhook returns **413** | Payload larger than `MAX_REQUEST_BYTES` (default 1 MiB) — usually **Extended** format or a **Daily Digest**. Switch EX to **Normal** + **Per Event**, or raise `MAX_REQUEST_BYTES`. |
| No alerts arrive / flow never starts (nothing in the log for these emails) | In EX Notification settings the HTTP server's **Notification** is set to **Malware Object** — that excludes `RISKWARE_OBJECT`, which is the encrypted-attachment trigger. Set it to **All Events** (or include **riskware object**). |
| Webhook returns **503** | Service in setup mode — finish required config (see the dashboard banner). |
| Webhook returns **401** | Missing/bad Basic auth, or webhook auth not configured. |
| Webhook returns **403** | Source IP not in `WEBHOOK_IP_ALLOWLIST`. |
| Everything reads **Released** / **Quarantined** wrongly, or rescan says "queue id not found" | Check the **EX appliance clock**. Per-case lookups use a clock-independent window, but a badly wrong EX clock has caused rescans to fail; fixing the clock resolves it. |
| A clean email sits in **Re-checking** for a while | The verdict for a released/clean email comes only from the poll (no push). It concludes once the original queue id leaves EX quarantine; the poll is eager (first check ~`RECHECK_DELAY`, default 10s). Lower `RECHECK_DELAY` / `RECHECK_INTERVAL` if you set them high. |
| Recipient link says expired | Links TTL-expire (`TOKEN_TTL`); opening one auto-reissues a fresh link if still awaiting a password. |
| Emails not sending | Check SMTP settings; failed sends go to `Email failed` and are auto-retried and resendable. Check `SMTP_TLS_MODE` and `SMTP_HELO_HOSTNAME` (some servers demand an FQDN). |
| Rescan keeps failing | Try flipping `EX_RESCAN_ID_FIELD` between `queue_id` and `email_uuid`; check the EX account's rescan permission. Failures retry under `RESUBMIT_MAX_RETRIES`. |
| Locked out of the admin login (429) | Wait out the window (15 min), **restart** the service, or use another IP. A correct login also clears the counter. See [Security](06_security.md). |
| Held password unreadable / secrets blank after a change | `SECRET_KEY` changed or `secret.key` was deleted — Fernet can't decrypt old values. Re-enter settings secrets; affected cases go to `RESUBMIT_FAILED`. |

## 11. Backups

Back up **two** things together:

1. the **database** (`DB_URL`, e.g. `trellix_decrypt.sqlite3`), and
2. **`secret.key`** — without it the encrypted settings in the DB are unreadable.

## 12. Test

```bash
pytest        # unit + respx-mocked EX client tests
```

---

# 8. Tech Stack

The technologies the service is built on, organised by the layer they serve. Exact
version pins live in `pyproject.toml`; the roles below explain *why* each is here.

## Where each technology sits

```mermaid
flowchart TB
    subgraph edge["Edge / HTTP"]
        UV[Uvicorn ASGI server]
        FA[FastAPI / Starlette]
        PM[python-multipart]
    end
    subgraph core["Pure core"]
        ENG[FlowEngine - plain async Python]
    end
    subgraph io["I/O libraries"]
        HX[httpx to Trellix EX]
        SM[aiosmtplib to SMTP]
        SA[SQLAlchemy to SQLite]
        IM[imaplib bounce poll]
    end
    UV --> FA --> ENG --> io
    PM -.forms.-> FA
    CR[cryptography Fernet] -.secrets at rest.-> ENG
    ID[itsdangerous] -.signed tokens.-> ENG
    J2[Jinja2] -.email + pages.-> FA
```

## At a glance

| Layer | Technology | Role |
|-------|------------|------|
| Language / runtime | **Python ≥ 3.11** | Async throughout (`asyncio`). |
| Packaging | **setuptools** (`pyproject.toml`) | Console entry point `trellix-decrypt`. |
| Web framework | **FastAPI** (≥ 0.110) | Webhook, password form, dashboard, JSON API. |
| ASGI server | **Uvicorn** (`[standard]`, ≥ 0.29) | Serves the app. |
| Routing / test client | **Starlette** (via FastAPI) | Routing; `TestClient` in tests. |
| Form parsing | **python-multipart** (≥ 0.0.9) | The password submission form. |
| HTTP client | **httpx** (≥ 0.27) | Async client for the Trellix WSAPI. |
| ORM | **SQLAlchemy 2.0** | `AttachmentCase`, `PasswordAttempt`, `EventLog`, `Setting`. |
| Database | **SQLite** (default, via `DB_URL`) | Local persistence; swappable. |
| Config | **pydantic-settings** (≥ 2.2) | `Settings` from env/`.env` + DB overrides. |
| Crypto | **cryptography** (≥ 42.0) — **Fernet** | Encrypts the held password and stored secrets. |
| Signing | **itsdangerous** (≥ 2.1) | One-time links + admin session cookie. |
| Email send | **aiosmtplib** (≥ 3.0) | Async SMTP delivery. |
| Templating | **Jinja2** (≥ 3.1) | Email bodies and web pages. |
| Bounce detection | **imaplib** (stdlib) + DSN parsing | `bounce.py` flips bounced mail to `BOUNCED`. |
| Frontend | Vanilla **HTML / CSS / JS** | `static/*.js`, `static/style.css`; no build step. |
| Tests | **pytest** + **pytest-asyncio** | Unit + web tests (auto async mode). |
| HTTP mocking | **respx** (≥ 0.21) | Mocks the EX API in tests. |
| Linting | **Ruff** (≥ 0.4) | Linter. |
| External system | **Trellix EX WSAPI v2.0.0** | Alerts, quarantine, rescan, alert-by-uuid. |

## Language & runtime

- **Python ≥ 3.11**, async end-to-end (`asyncio`); type-hinted public functions.
- Packaged with **setuptools** via `pyproject.toml`; run as `python -m trellix_decrypt`
  or the `trellix-decrypt` console script.

## Web / API

- **FastAPI + Starlette** power four surfaces: the EX webhook, the public password
  form, the admin dashboard, and the JSON API — all `async`.
- **Uvicorn** (`log_config=None`, so its access log reaches the app's handlers).
- **python-multipart** parses the recipient's password form POST.

## HTTP client (to the EX appliance)

- **httpx** async client (`ex_client.EXClient`): token auth with automatic re-auth,
  alerts, quarantine list/rescan/release/delete, and the alert-by-uuid detail call.

## Data & persistence

- **SQLAlchemy 2.0** ORM over **SQLite** by default; the repository returns detached
  instances so the pure core treats cases as value objects.

## Config & validation

- **pydantic-settings** builds `Settings` from environment/`.env`, overlaid with
  UI-editable overrides persisted in the `Setting` table.

## Security & crypto

- **cryptography (Fernet)** encrypts the transient attachment password and stored
  settings secrets, keyed by `SECRET_KEY`.
- **itsdangerous** signs the TTL-expiring one-time links and the admin session cookie.
- Rate limiting and webhook auth are hand-rolled on top of Starlette primitives —
  no extra dependency (see [Security](#doc-06_security)).

## Email

- **aiosmtplib** for async SMTP send; **Jinja2** renders the text+HTML notification;
  **imaplib** (stdlib) polls the sender mailbox for bounces (`bounce.py`).

## Frontend (no build step, no framework)

- Vanilla **HTML / CSS / JavaScript** served through Jinja2 templates:
  `static/app.js` (dashboard), `static/settings.js`, `static/style.css` (light/dark).

## Testing & tooling

- **pytest** + **pytest-asyncio** (auto mode); **respx** mocks the EX HTTP API so the
  client is tested without a live appliance; **Ruff** lints.

## External system integrated

- **Trellix Email Security (EX)** WSAPI **v2.0.0** (Reference Release 2025.1): token
  auth via `X-FeApi-Token` (+ optional `X-FeClient-Token`), alerts, quarantine
  management, rescan, and the alert-by-uuid detail endpoint.

---

# 9. Configuration reference

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

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `EX_BASE_URL` | Yes | `—` | HTTPS address of your EX appliance. This service calls the EX API here to list quarantine, rescan an email with a password, and fetch alert detail. |
| `EX_USERNAME` | Yes | `—` | Username of an EX **API account** (needs the *API Analyst* role); this service logs in with it. |
| `EX_PASSWORD` | Yes | `—` | Password for the EX API account. |
| `EX_VERIFY_TLS` | — | `false` | Validate the appliance's TLS certificate. Off by default (EX boxes usually present a self-signed cert). |
| `EX_CLIENT_TOKEN` | — | `—` | Optional extra `X-FeClient-Token` some appliances require alongside the login token. |
| `EX_RESCAN_ID_FIELD` | — | `queue_id` | Which id the rescan endpoint expects in its URL — `queue_id` or `email_uuid`. Flip if rescan returns an authorization error. |
| `EX_TIMEOUT` | — | `60` | Seconds to wait for an EX API call before giving up. |

### Webhook — the appliance → this service

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| *Webhook URL* (derived) | — | `…/webhook/ex-alert` | The endpoint EX POSTs to: `https://<PUBLIC_BASE_URL>/webhook/ex-alert`. Paste it into EX's HTTP-notification **Server URL**; derived from `PUBLIC_BASE_URL`. |
| `WEBHOOK_USERNAME` | Cond.† | `—` | HTTP **Basic-auth** username EX must send when it POSTs. Set the same value here *and* on the EX notification consumer. |
| `WEBHOOK_PASSWORD` | Cond.† | `—` | HTTP **Basic-auth** password EX must send (paired with the username above). |
| `WEBHOOK_IP_ALLOWLIST` | Cond.† | `—` | Comma-separated source IPs allowed to POST the webhook. Use instead of, or with, Basic auth. |

### Email delivery — SMTP

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `SMTP_HOST` | Yes | `—` | Outbound mail relay host used to send the recipient email. |
| `SMTP_PORT` | — | `587` | Relay port (587 STARTTLS, 465 implicit TLS, 25 plain). |
| `SMTP_USERNAME` | — | `—` | Relay auth username, if required. |
| `SMTP_PASSWORD` | — | `—` | Relay auth password, if required. |
| `SMTP_FROM` | Yes | `attachment-help@example.com` | From address recipients see on the email. |
| `SMTP_TLS_MODE` | — | `opportunistic` | How TLS is negotiated: `opportunistic`, `starttls`, `none`, or `ssl` (implicit, 465). |
| `SMTP_VERIFY_TLS` | — | `false` | Validate the relay's TLS certificate. Off by default for lab/self-signed CAs. |
| `SMTP_HELO_HOSTNAME` | — | `—` | HELO/EHLO name announced to the relay. Set an FQDN if the relay rejects the OS hostname. |

### Recipient links & the admin site

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `PUBLIC_BASE_URL` | Yes | `http://localhost:8080` | Externally-reachable URL of **this service**. Builds the one-time recipient link *and* the webhook URL. Must match how recipients/EX reach you. |
| `UI_PASSWORD` | Yes | `—` | Password for the admin dashboard. Setting it the first time ends setup mode. |
| `TOKEN_TTL` | — | `86400` | Seconds a one-time recipient link stays valid before expiring. |
| `WEB_HOST` | — | `0.0.0.0` | Interface this service binds to (`0.0.0.0` = all). *Restart to apply.* |
| `WEB_PORT` | — | `8080` | Port this service listens on. In Docker set `WEB_PORT`/`HOST_PORT` (§6). *Restart to apply.* |
| `SECRET_KEY` | — | `auto-generated` | Signs links/sessions and encrypts stored secrets. Auto-generated if unset; environment-only (not in the UI). |
| `DATA_DIR` | — | `working dir` | Directory for persistent state — `secret.key` and the default SQLite DB (§2). |
| `DB_URL` | — | `sqlite:///trellix_decrypt.sqlite3` | Database URL (§4). Environment-only. |

### What triggers the flow

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `TRIGGER_ALERT_NAME` | — | `RISKWARE_OBJECT` | The EX alert top-level **name** that starts the flow (the encrypted-attachment policy raises `RISKWARE_OBJECT`). |
| `TRIGGER_MALWARE_NAMES` | — | `CustomPolicy.MVX.pdf, CustomPolicy.MVX.zip, CustomPolicy.MVX.docx, CustomPolicy.MVX.65066.PassExtractFailed` | Comma-separated signature names that must also be present (`CustomPolicy.MVX.<ext>` or `...65066.PassExtractFailed`). Alert name **and** one signature name must match. Empty disables triggering. |

### Bounce detection — optional, IMAP

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `IMAP_HOST` | — | `—` | Mailbox host polled to detect **bounces** (DSNs). Blank disables bounce monitoring. |
| `IMAP_PORT` | — | `993` | IMAP port (993 for IMAPS). |
| `IMAP_USERNAME` | — | `—` | IMAP account username for the bounce mailbox. |
| `IMAP_PASSWORD` | — | `—` | IMAP account password. |
| `IMAP_MAILBOX` | — | `INBOX` | Mailbox scanned for bounces (e.g. `INBOX`). |
| `IMAP_SSL` | — | `true` | Connect to IMAP over SSL (IMAPS). |
| `BOUNCE_POLL_INTERVAL` | — | `120` | Seconds between bounce polls. |

### Security & rate limiting

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `LOGIN_RATE_LIMIT` | — | `10` | Failed admin sign-ins allowed per IP within the window before `429`. Self-healing. *Restart to apply.* |
| `LOGIN_RATE_WINDOW` | — | `900` | Window (seconds) for the login rate limit. *Restart to apply.* |
| `FORM_RATE_LIMIT` | — | `10` | Password-form submissions allowed per IP+link within the window. *Restart to apply.* |
| `FORM_RATE_WINDOW` | — | `300` | Window (seconds) for the password-form rate limit. *Restart to apply.* |
| `TRUST_FORWARDED_FOR` | — | `false` | Trust `X-Forwarded-For` for the client IP. Enable only behind a trusted reverse proxy. |
| `MAX_REQUEST_BYTES` | — | `1048576` | Reject webhook/form bodies larger than this (DoS guard; also large EX *Extended* alerts). |

### Retry, recheck & reconcile

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `MAX_PASSWORD_ATTEMPTS` | — | `3` | Wrong-password rounds allowed before giving up. |
| `RECHECK_DELAY` | — | `10` | Seconds before the first recheck poll after a resubmission. |
| `RECHECK_INTERVAL` | — | `30` | Steady-state seconds between later recheck polls. |
| `RECHECK_MAX_ATTEMPTS` | — | `12` | Number of recheck polls before concluding from the list. |
| `NOTIFY_MAX_RETRIES` | — | `5` | How many times to retry a failed recipient email. |
| `NOTIFY_RETRY_INTERVAL` | — | `300` | Seconds between email retry sweeps. |
| `RESUBMIT_MAX_RETRIES` | — | `5` | How many times to retry a failed EX rescan. |
| `RESUBMIT_RETRY_INTERVAL` | — | `120` | Seconds between rescan retry sweeps. |
| `RECONCILE_LOOKBACK` | — | `48_hours` | EX alerts-query window scanned to backfill missed alerts. |
| `RECONCILE_INTERVAL` | — | `1800` | Seconds between periodic reconcile sweeps (0 = startup only). |

### Logging

| Setting | Req. | Default | What it is / what it's for |
|---------|:----:|---------|----------------------------|
| `LOG_LEVEL` | — | `INFO` | Verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. *Restart to apply.* |
| `LOG_FILE` | — | `trellix_decrypt.log` | File to write logs to (blank = console only). *Restart to apply.* |
| `LOG_FILE_MAX_BYTES` | — | `10000000` | Rotate the log file at this size (bytes). *Restart to apply.* |
| `LOG_FILE_BACKUPS` | — | `5` | How many rotated log files to keep. *Restart to apply.* |
