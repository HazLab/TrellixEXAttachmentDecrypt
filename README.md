# Trellix EX Attachment Decrypt

A small, modular Python service that automates recovery of **password-protected
attachments** quarantined by **Trellix Email Security (EX)**.

When EX cannot extract an encrypted attachment (PDF, MS Office document, or
archive) it raises a *riskware* alert and quarantines the email. This service
asks the recipient for the password over a one-time link, resubmits the email to
EX for re-analysis, and tracks the outcome — retrying on wrong passwords and
stopping on malicious or clean results.

## Flow

1. EX posts a riskware alert to the webhook (`POST /webhook/ex-alert`).
2. If the alert's rule ID is a configured *trigger* (failed decryption), the
   recipient is emailed a randomized one-time link.
3. The recipient submits the attachment password.
4. The service calls the EX resubmission API (passwords accepted) to re-analyze.
5. A background job rechecks quarantine for the resubmitted message (same queue
   ID + `_RA` suffix):
   - failed extraction again → ask the recipient again (up to a retry cap);
   - malicious, or not quarantined → done.

See `CLAUDE.md` for architecture and module layout.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Configure

Configuration is read from environment variables (or a `.env` file you create —
**not committed**). Copy the template and fill it in:

```bash
cp env.example .env   # then edit .env
```

Full variable list is in `env.example`. Key ones:

```bash
# Trellix EX appliance
EX_BASE_URL=https://ex.example.com
EX_USERNAME=api_analyst        # account with API Analyst role
EX_PASSWORD=...
EX_VERIFY_TLS=true
EX_CLIENT_TOKEN=               # optional X-FeClient-Token from Trellix

# Trigger: alert "name" == TRIGGER_ALERT_NAME AND a malware name exactly equals
# one of TRIGGER_MALWARE_NAMES. The encrypted-attachment policy emits
# CustomPolicy.MVX.<ext>. (Empty TRIGGER_MALWARE_NAMES disables triggering.)
TRIGGER_ALERT_NAME=RISKWARE_OBJECT
TRIGGER_MALWARE_NAMES=CustomPolicy.MVX.pdf,CustomPolicy.MVX.zip,CustomPolicy.MVX.docx,CustomPolicy.MVX.65066.PassExtractFailed

# Outbound mail
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_FROM=attachment-help@example.com
SMTP_STARTTLS=true

# Web / links
PUBLIC_BASE_URL=https://decrypt.example.com   # used to build the one-time link
SECRET_KEY=change-me                          # signs tokens
TOKEN_TTL=86400                               # seconds

# Webhook auth
WEBHOOK_SECRET=change-me
WEBHOOK_IP_ALLOWLIST=                          # optional, comma-separated

# Flow tuning
MAX_PASSWORD_ATTEMPTS=3                         # cap 5
RECHECK_DELAY=120                               # seconds before first recheck
RECHECK_INTERVAL=60
RECHECK_MAX_ATTEMPTS=10

# Storage
DB_URL=sqlite:///trellix_decrypt.sqlite3
```

## Run

```bash
python -m trellix_decrypt
# or
trellix-decrypt
```

## Test

```bash
pytest
```

## Notes

- Endpoints/auth/rescan are based on the Trellix API Reference Release 2025.1
  (PDFs in `docs/`) and centralized in `trellix_decrypt/ex_client.py`. The rescan
  call is `POST /emailmgmt/quarantine/rescan/<email_uuid>` with
  `{"rescan_properties": {"pwd_list": [...]}}`.
- Passwords are used immediately and never stored in plaintext.

## License

MIT
