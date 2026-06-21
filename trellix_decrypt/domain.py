"""Pure business logic: models, riskware rules, one-time tokens, and the flow engine.

This module performs **no I/O of its own** — the FlowEngine drives the flow by
calling injected collaborators (repository, EX client, mailer, scheduler), so it
is fully unit-testable with fakes.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import logging

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .crypto import fernet

log = logging.getLogger(__name__)


class FlowState(str, enum.Enum):
    RECEIVED = "received"
    AWAITING_PASSWORD = "awaiting_password"
    PASSWORD_SUBMITTED = "password_submitted"
    RESUBMITTED = "resubmitted"
    RECHECKING = "rechecking"
    DONE_CLEAN = "done_clean"
    DONE_MALICIOUS = "done_malicious"
    FAILED_MAX_RETRIES = "failed_max_retries"
    EXPIRED = "expired"
    NOTIFY_FAILED = "notify_failed"   # couldn't hand the email to the mail server (SMTP error)
    BOUNCED = "bounced"               # accepted by the server then bounced (DSN)
    RESUBMIT_FAILED = "resubmit_failed"  # password captured, but EX rescan failed (retryable)


#: States from which a recheck poll may still run.
RECHECKABLE = (FlowState.RESUBMITTED, FlowState.RECHECKING)
#: Terminal states.
TERMINAL = (FlowState.DONE_CLEAN, FlowState.DONE_MALICIOUS, FlowState.FAILED_MAX_RETRIES,
            FlowState.EXPIRED, FlowState.BOUNCED)

#: Canonical EX alert name for "malicious after extraction".
MALWARE_ALERT_NAME = "malware_object"
#: Malware names EX puts on an `_RA` re-detection when extraction failed again (wrong
#: password). Authoritative even inside a MALWARE_OBJECT alert, whose other names are
#: signature hits on the still-encrypted blob rather than extracted content.
PASSWORD_FAILED_MARKERS = frozenset({"password_extraction_failed"})


def _canon_name(value) -> str:
    """Canonicalize an EX name: lowercase, trimmed, hyphens→underscores, so that
    'MALWARE-OBJECT', 'malware_object' and 'Malware-Object' all compare equal."""
    return str(value or "").strip().lower().replace("-", "_")


@dataclasses.dataclass
class AlertEvent:
    """Normalized EX alert. One quarantined email can list several recipients."""

    queue_id: str
    recipients: list[str] = dataclasses.field(default_factory=list)
    alert_name: str | None = None   # top-level alert "name", e.g. "RISKWARE_OBJECT"
    malicious: bool = False          # alert "malicious" == "yes"
    sender: str | None = None
    subject: str | None = None
    malware_names: list[str] = dataclasses.field(default_factory=list)
    raw: dict = dataclasses.field(default_factory=dict)

    @property
    def recipient(self) -> str:
        """Primary recipient (first To); the full set is ``recipients``."""
        return self.recipients[0] if self.recipients else ""


class RiskwareRules:
    """Decides whether an alert should trigger the recovery flow.

    An alert matches when its top-level name equals the configured alert name
    (e.g. "RISKWARE_OBJECT") AND one of its malware names exactly equals one of
    the configured malware names (case-insensitive). With no malware names
    configured nothing matches — this avoids firing on every riskware object
    (e.g. unrelated CustomPolicy.MVX QR-code detections).
    """

    def __init__(self, trigger_malware_names=(), trigger_alert_name="RISKWARE_OBJECT"):
        self._names = {str(n).strip().lower() for n in trigger_malware_names if str(n).strip()}
        self._alert_name = self._canon(trigger_alert_name)

    @staticmethod
    def _canon(value) -> str:
        """Canonicalize an alert name so RISKWARE_OBJECT == riskware-object."""
        return _canon_name(value)

    def name_matches(self, name) -> bool:
        """Exact (case-insensitive) match of one malware name against the triggers."""
        return str(name or "").strip().lower() in self._names

    def alert_name_matches(self, alert_name) -> bool:
        return not self._alert_name or self._canon(alert_name) == self._alert_name

    def matches(self, event: "AlertEvent") -> bool:
        if not self._names or not self.alert_name_matches(event.alert_name):
            return False
        return any(self.name_matches(n) for n in event.malware_names)


class TokenService:
    """Mint and verify signed, TTL-expiring one-time links carrying a case id.

    Single use is enforced by case state: once a password is submitted the case
    leaves AWAITING_PASSWORD, so a replayed link is rejected by the FlowEngine.
    """

    def __init__(self, secret_key: str, ttl: int):
        self._serializer = URLSafeTimedSerializer(secret_key, salt="password-link")
        self._ttl = ttl

    def mint(self, case_id: str) -> str:
        return self._serializer.dumps(case_id)

    def verify(self, token: str) -> str | None:
        """Case id for a valid, unexpired token."""
        try:
            return self._serializer.loads(token, max_age=self._ttl)
        except (BadSignature, SignatureExpired):
            return None

    def peek(self, token: str) -> str | None:
        """Case id for a validly-signed token regardless of age (None if tampered)."""
        try:
            return self._serializer.loads(token)
        except BadSignature:
            return None


def hash_password(password: str) -> str:
    """One-way hash for de-duping wrong attempts. Plaintext is never persisted."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class FlowEngine:
    """Orchestrates the recovery state machine across injected collaborators."""

    def __init__(self, repo, ex, mailer, tokens: TokenService, rules: RiskwareRules, settings, scheduler):
        self.repo = repo
        self.ex = ex
        self.mailer = mailer
        self.tokens = tokens
        self.rules = rules
        self.settings = settings
        self.scheduler = scheduler
        self._fernet = fernet(settings.secret_key)  # encrypts the held password at rest

    async def handle_alert(self, event: AlertEvent):
        """Entry point for an incoming EX alert. Returns the case, or None if ignored."""
        # A resubmitted email is re-analyzed and re-detected under the original queue
        # id + "_RA". EX *pushes* that re-detection here, carrying the verdict — so we
        # correlate it to the original case and classify it BEFORE the trigger rules:
        # a decrypted-malicious re-detection is MALWARE_OBJECT and would never pass the
        # riskware rules. Never create a separate case for an "_RA" alert.
        base = event.queue_id
        while base.endswith("_RA"):
            base = base[: -len("_RA")]
        if base != event.queue_id:
            parent = self.repo.find_case_by_queue_id(base)
            if parent is not None:
                await self._classify_resubmission(parent, event)
            return parent  # may be None (uncorrelated _RA) — still never created here

        # First-time detection: gate on the trigger rules, then start the flow.
        if not self.rules.matches(event):
            return None
        case = self.repo.get_or_create_case(event)
        if case.state == FlowState.RECEIVED:
            await self._send_password_request(case)
        return case

    async def _classify_resubmission(self, case, event: AlertEvent) -> None:
        """Decide a resubmission outcome from the pushed ``_RA`` alert.

        EX re-detects the resubmitted email and pushes the verdict. Two outcomes:
        - **Wrong password** — extraction failed again. EX signals this either as a
          RISKWARE_OBJECT + CustomPolicy.MVX re-detection, or by naming
          PASSWORD_EXTRACTION_FAILED among the malware (even inside a MALWARE_OBJECT
          alert, where the other names are signature hits on the still-encrypted blob).
          This is authoritative — re-ask the recipient.
        - **Malicious** — a correct password revealed malware: MALWARE_OBJECT /
          ``malicious: yes`` with no extraction-failure marker → stop (DONE_MALICIOUS).

        A single ``_RA`` can arrive as several webhook pushes (one per detected object),
        so a wrong-password marker must win even if a malware push for the same ``_RA``
        landed first — hence we reopen DONE_MALICIOUS when a marker arrives."""
        extraction_failed = (any(_canon_name(n) in PASSWORD_FAILED_MARKERS for n in event.malware_names)
                             or self.rules.matches(event))
        if extraction_failed:
            if case.state in RECHECKABLE or case.state == FlowState.DONE_MALICIOUS:
                await self._fail_extraction(case)  # reopen if a malware push jumped ahead
            return
        if case.state in RECHECKABLE and (event.malicious
                                          or _canon_name(event.alert_name) == MALWARE_ALERT_NAME):
            self.repo.clear_password(case)  # purge the held password; we're done
            detail = ", ".join(event.malware_names) or event.alert_name or "malicious"
            self.repo.set_state(case, FlowState.DONE_MALICIOUS,
                                f"re-detected malicious after extraction: {detail}")

    async def reissue_expired_link(self, token: str):
        """If an expired-but-valid link is opened and the case still awaits a
        password, e-mail a fresh link. Returns the case, or None."""
        case_id = self.tokens.peek(token)
        if not case_id:
            return None
        case = self.repo.get_case(case_id)
        if case is None or case.state != FlowState.AWAITING_PASSWORD:
            return None
        await self._send_password_request(case)  # mints a new token + re-emails
        return case

    async def handle_password(self, token: str, password: str):
        """Handle a password submission. Returns (case_or_None, status_string)."""
        # Accept a just-expired but validly-signed token (the recipient is actively
        # submitting); single use is still enforced by the case state below.
        case_id = self.tokens.peek(token)
        if not case_id:
            return None, "invalid_or_expired"
        case = self.repo.get_case(case_id)
        if case is None:
            return None, "not_found"
        if case.state != FlowState.AWAITING_PASSWORD:
            return case, "not_awaiting"

        # The recipient's part is done the moment we have the password. Store it
        # (encrypted), acknowledge immediately, and do the EX rescan in the
        # background — the user's success does not depend on EX being reachable.
        self.repo.store_password(case, self._fernet.encrypt(password.encode()).decode())
        self.repo.set_state(case, FlowState.PASSWORD_SUBMITTED, "password received")
        self.scheduler.schedule_resubmit(case.id)
        return case, "ok"

    async def resubmit_case(self, case_id: str):
        """Background step: rescan the quarantined email in EX with the held password.
        Independent of the recipient's submission; retryable until it succeeds."""
        case = self.repo.get_case(case_id)
        if case is None or case.state not in (FlowState.PASSWORD_SUBMITTED, FlowState.RESUBMIT_FAILED) or not case.pwd_enc:
            return
        try:
            password = self._fernet.decrypt(case.pwd_enc.encode()).decode()
        except Exception:  # noqa: BLE001 — unreadable (e.g. SECRET_KEY changed)
            self.repo.set_state(case, FlowState.RESUBMIT_FAILED, "stored password unreadable")
            return
        # Rescan the entry that actually holds a quarantined file (_RA re-analysis
        # records have a null path and can't be rescanned).
        queue_id, email_uuid = await self.ex.rescan_target(case.queue_id, case.sender, case.subject)
        if queue_id is None:
            log.warning("no rescannable quarantine entry for case %s (queue %s)", case.id, case.queue_id)
            self.repo.increment_resubmit_attempts(case)
            self.repo.set_state(case, FlowState.RESUBMIT_FAILED, "no rescannable quarantine entry found")
            return
        target = email_uuid if self.settings.ex_rescan_id_field == "email_uuid" else queue_id
        # Diagnostic (no plaintext): lets us verify the exact bytes we hand EX match the
        # password that works typed into the appliance. A len != stripped_len means a
        # stray space/newline slipped in; compare sha8 with `printf %s 'pw' | sha256sum`.
        fp = hashlib.sha256(password.encode()).hexdigest()[:8]
        log.info("rescan case %s target=%s pwd(len=%d stripped_len=%d sha8=%s)",
                 case.id, target, len(password), len(password.strip()), fp)
        try:
            await self.ex.rescan(target, [password])
        except Exception as exc:  # noqa: BLE001 — record + count for the retry cap, don't crash
            # Duck-type the transport's "email not quarantined" flag (a 400/404 from EX)
            # so domain stays free of the ex_client import. It's a race we can retry:
            # the email may have been listed a moment ago and not yet (re)indexed.
            if getattr(exc, "not_found", False):
                log.warning("rescan rejected for case %s (email not quarantined): %s", case.id, exc)
                reason = "quarantined email not found at rescan time"
            else:
                log.exception("rescan failed for case %s", case.id)
                reason = f"resubmission to EX failed: {exc}"
            self.repo.increment_resubmit_attempts(case)
            self.repo.set_state(case, FlowState.RESUBMIT_FAILED, reason)
            return
        self.repo.record_password_hash(case, hash_password(password))  # audit only — not a failure
        self.repo.clear_password(case)  # no longer needed
        self.repo.set_state(case, FlowState.RESUBMITTED, "resubmitted to EX (rescan)")
        self.scheduler.schedule_recheck(case.id)

    async def retry_failed_resubmissions(self):
        """Background sweep: re-attempt EX rescans for cases still holding a
        password (PASSWORD_SUBMITTED stuck, or RESUBMIT_FAILED) under the cap."""
        for case_id in self.repo.list_resubmit_pending_ids(self.settings.resubmit_max_retries):
            await self.resubmit_case(case_id)

    async def _fail_extraction(self, case) -> None:
        """A confirmed wrong password: the resubmission was re-quarantined as the same
        failed-extraction riskware. Count the attempt and re-ask, or give up at the cap."""
        self.repo.increment_attempts(case)
        if case.attempts >= self.settings.max_password_attempts:
            self.repo.set_state(case, FlowState.FAILED_MAX_RETRIES, "max password attempts reached")
        else:
            await self._send_password_request(case, retry=True)  # re-send the link to retry

    async def recheck(self, case_id: str, final: bool = False) -> bool:
        """Fail-closed timeout backstop for a resubmitted case. Returns True to stop polling.

        The verdict normally arrives via the pushed ``_RA`` alert (see handle_alert), so
        a resolved case has already left RECHECKABLE and we stop. If none has arrived by
        the final poll, we consult the quarantine list and only declare DONE_CLEAN when
        the email is genuinely no longer (re-)quarantined; if it still is, we treat it as
        a wrong password rather than risk releasing a held email."""
        case = self.repo.get_case(case_id)
        if case is None or case.state not in RECHECKABLE:
            return True  # already resolved (typically by the pushed _RA alert)
        if case.state == FlowState.RESUBMITTED:
            self.repo.set_state(case, FlowState.RECHECKING, "awaiting re-detection")
        if not final:
            return False  # keep waiting for the pushed verdict
        if await self.ex.has_resubmission_quarantine(case.queue_id, case.sender, case.subject):
            log.warning("case %s: re-quarantined but no _RA alert received; treating as wrong password",
                        case.id)
            await self._fail_extraction(case)
        else:
            self.repo.clear_password(case)
            self.repo.set_state(case, FlowState.DONE_CLEAN, "not re-quarantined: delivered")
        return True

    async def resume_pending(self):
        """On startup, reschedule work left mid-flight: rechecks and resubmissions."""
        for case_id in self.repo.list_pending_ids():
            self.scheduler.schedule_recheck(case_id)
        for case_id in self.repo.list_resubmit_pending_ids(self.settings.resubmit_max_retries):
            self.scheduler.schedule_resubmit(case_id)

    async def resend(self, case_id: str):
        """Operator-triggered re-send. Returns the send result, or None if the
        case isn't in a re-sendable state."""
        case = self.repo.get_case(case_id)
        resendable = (FlowState.NOTIFY_FAILED, FlowState.AWAITING_PASSWORD, FlowState.BOUNCED)
        if case is None or case.state not in resendable:
            return None
        return await self._send_password_request(case)

    async def retry_failed_notifications(self):
        """Background sweep: re-attempt emails for NOTIFY_FAILED cases under the cap."""
        for case_id in self.repo.list_notify_failed_ids(self.settings.notify_max_retries):
            case = self.repo.get_case(case_id)
            if case is not None:
                await self._send_password_request(case)

    def handle_bounce(self, bounce: dict) -> bool:
        """Record a delivery bounce (DSN). Correlate by X-Case-Id, else by recipient.
        Returns True if a case was marked BOUNCED."""
        case = None
        if bounce.get("case_id"):
            case = self.repo.get_case(bounce["case_id"])
        if case is None and bounce.get("recipient"):
            case = self.repo.find_open_case_by_recipient(bounce["recipient"])
        if case is None or case.state in TERMINAL:  # don't override a real verdict
            return False
        self.repo.set_state(case, FlowState.BOUNCED, f"delivery bounced: {bounce.get('reason', 'unknown')}")
        return True

    async def aclose(self):
        await self.ex.aclose()

    async def _send_password_request(self, case, retry: bool = False) -> bool:
        token = self.tokens.mint(case.id)
        link = f"{self.settings.public_base_url.rstrip('/')}/p/{token}"
        # One email lists all recipients (the case holds them comma-joined); every
        # To recipient gets the same one-time link — whoever has the password submits.
        recipients = split_addrs(case.recipient)
        try:
            await self.mailer.send_password_request(recipients, link, case, retry=retry)
        except Exception as exc:  # noqa: BLE001 — record send failures instead of crashing
            log.exception("failed to email %s for case %s", case.recipient, case.id)
            self.repo.increment_notify_attempts(case)
            self.repo.set_state(case, FlowState.NOTIFY_FAILED, f"email send failed: {exc}")
            return False
        self.repo.set_state(case, FlowState.AWAITING_PASSWORD, "password link sent" + (" (retry)" if retry else ""))
        return True


# --- Alert parsing ----------------------------------------------------------
# The single place that knows the wire shape of an EX alert. Verified against
# docs/sample_alert.json (webhook push) and docs/sample_alerts_query.json (API).
# Pure functions — reused by the webhook (ingest) and the EX client (recheck).


def _dig(obj, *path):
    """Walk dict keys / list indices, returning None if any step is missing."""
    cur = obj
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and -len(cur) <= key < len(cur):
            cur = cur[key]
        else:
            return None
    return cur


def _first(*values):
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _text(value):
    """Resolve a field that may be a scalar, a {"value": ...} wrapper, or a list of either.

    The HTTP notification push wraps element text in {"value": ...}; the alerts
    query returns plain scalars. This normalizes both.
    """
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, dict):
        value = value.get("value")
    return None if value in (None, "") else str(value)


def split_addrs(value) -> list[str]:
    """Split a recipients string ('a@x, b@x; c@x') into a de-duplicated list,
    order preserved. Used to unpack the stored, comma-joined recipient column."""
    out, seen = [], set()
    for part in str(value or "").replace(";", ",").split(","):
        addr = part.strip()
        if addr and addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _text_list(value) -> list[str]:
    """Normalize an EX recipient field to a list of addresses. Handles a scalar, a
    {"value": ...} wrapper, a list of either, and a single string carrying several
    comma/semicolon-separated addresses — covering both wire formats."""
    items = value if isinstance(value, list) else [value]
    out, seen = [], set()
    for item in items:
        if isinstance(item, dict):
            item = item.get("value")
        for addr in split_addrs(item):
            if addr not in seen:
                seen.add(addr)
                out.append(addr)
    return out


def _is_yes(value) -> bool:
    return str(value or "").strip().lower() in ("yes", "true", "1")


def _malware_entries(alert: dict) -> list[dict]:
    entries = _first(
        _dig(alert, "explanation", "malware-detected", "malware"),   # push (hyphenated)
        _dig(alert, "explanation", "malwareDetected", "malware"),     # query (camelCase)
        alert.get("malware"),
    ) or []
    if isinstance(entries, dict):
        entries = [entries]
    return [e for e in entries if isinstance(e, dict)]


def iter_alerts(payload: dict) -> list[dict]:
    """EX wraps alerts under ``Alerts``/``alerts``/``alert`` (or a bare alert); accept all."""
    alerts = payload.get("Alerts") or payload.get("alerts") or payload.get("alert") or payload
    return alerts if isinstance(alerts, list) else [alerts]


def parse_alert(alert: dict) -> AlertEvent:
    """Map one raw EX alert dict to an AlertEvent.

    Handles both wire formats: the alerts-query JSON (camelCase scalars, e.g.
    ``queueId``, ``dst.smtpTo``) and the HTTP notification push (hyphenated keys
    with ``{"value": ...}`` wrappers, e.g. ``queue-id``, ``dst.smtp-to.value``).
    """
    return AlertEvent(
        queue_id=_text(_first(
            alert.get("queue-id"), alert.get("queueId"), alert.get("queue_id"),
            _dig(alert, "smtp-message", "queue-id"), _dig(alert, "smtpMessage", "queueId"),
        )) or "",
        recipients=_text_list(_first(
            _dig(alert, "dst", "smtp-to"), _dig(alert, "dst", "smtpTo"),
            _dig(alert, "smtpMessage", "rcptTo"), alert.get("recipient"), alert.get("rcpt_to"),
        )),
        alert_name=_text(_first(alert.get("name"), alert.get("alert_name"))),
        malicious=_is_yes(_text(alert.get("malicious"))),
        sender=_text(_first(
            _dig(alert, "src", "smtp-mail-from"), _dig(alert, "src", "smtpMailFrom"),
            _dig(alert, "smtpMessage", "mailFrom"), alert.get("sender"),
        )),
        subject=_text(_first(
            _dig(alert, "smtp-message", "subject"), _dig(alert, "smtpMessage", "subject"),
            alert.get("subject"),
        )),
        malware_names=[name for m in _malware_entries(alert)
                       if (name := _text(m.get("name")) or _text(m.get("malware_name"))) is not None],
        raw=alert,
    )
