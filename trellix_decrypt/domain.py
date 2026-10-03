# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""Pure business logic: models, riskware rules, one-time tokens, and the flow engine.

This module performs **no I/O of its own** — the FlowEngine drives the flow by
calling injected collaborators (repository, EX client, mailer, scheduler), so it
is fully unit-testable with fakes.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import logging

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .alerts import (  # noqa: F401 — AlertEvent/iter_alerts/parse_alert re-exported for callers
    AlertEvent,
    is_pre_extraction_alert,
    iter_alerts,
    parse_alert,
    parse_alert_detail,
    split_addrs,
)
from .crypto import fernet
from .reconcile import run_reconcile

log = logging.getLogger(__name__)


class FlowState(str, enum.Enum):
    RECEIVED = "received"
    AWAITING_PASSWORD = "awaiting_password"
    PASSWORD_SUBMITTED = "password_submitted"
    RESUBMITTED = "resubmitted"
    RECHECKING = "rechecking"
    DONE_PASSED = "done_passed"           # not re-quarantined after resubmission: delivered
    DONE_QUARANTINED = "done_quarantined"  # re-quarantined after resubmission: held (terminal)
    FAILED_MAX_RETRIES = "failed_max_retries"
    EXPIRED = "expired"
    NOTIFY_FAILED = "notify_failed"   # couldn't hand the email to the mail server (SMTP error)
    BOUNCED = "bounced"               # accepted by the server then bounced (DSN)
    RESUBMIT_FAILED = "resubmit_failed"  # password captured, but EX rescan failed (retryable)


class SubmitStatus(str, enum.Enum):
    """Result of a recipient's password submission (``FlowEngine.handle_password``)."""
    OK = "ok"
    INVALID_OR_EXPIRED = "invalid_or_expired"
    NOT_FOUND = "not_found"
    NOT_AWAITING = "not_awaiting"


class ResubmissionOutcome(str, enum.Enum):
    """What the quarantine list says about a resubmitted email (the recheck poll)."""
    HELD = "held"          # the ``_RA`` re-quarantine is present
    PENDING = "pending"    # original still quarantined, no ``_RA`` yet — keep polling
    RELEASED = "released"  # neither remains: delivered


#: States from which a recheck poll may still run.
RECHECKABLE = (FlowState.RESUBMITTED, FlowState.RECHECKING)
#: Terminal states.
TERMINAL = (FlowState.DONE_PASSED, FlowState.DONE_QUARANTINED, FlowState.FAILED_MAX_RETRIES,
            FlowState.EXPIRED, FlowState.BOUNCED)

#: Malware names EX puts on an `_RA` re-detection when extraction failed again (wrong
#: password). Authoritative even inside a MALWARE_OBJECT alert, whose other names are
#: signature hits on the still-encrypted blob rather than extracted content.
PASSWORD_FAILED_MARKERS = frozenset({"password_extraction_failed"})


def _canon_name(value) -> str:
    """Canonicalize an EX name: lowercase, trimmed, hyphens→underscores, so that
    'MALWARE-OBJECT', 'malware_object' and 'Malware-Object' all compare equal."""
    return str(value or "").strip().lower().replace("-", "_")


def _detection_summary(event: "AlertEvent | None") -> str:
    """Compact detection detail from a pushed alert — the alert type plus the malware
    names EX reported — for the case timeline. This is the info the removed alert-detail
    API lookup used to surface; it now rides in on the webhook push. Empty string when
    there's no push (the recheck-timer path), so callers can append it unconditionally."""
    if event is None:
        return ""
    parts: list[str] = []
    if event.alert_name:
        parts.append(str(event.alert_name))
    if event.malware_names:
        parts.append("[" + ", ".join(dict.fromkeys(event.malware_names)) + "]")
    if event.malicious:
        parts.append("(malicious)")
    return " ".join(parts)


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

    @property
    def alert_name(self) -> str:
        """Canonical alert name an alert must carry to trigger ('' = any)."""
        return self._alert_name

    @property
    def malware_names(self) -> list[str]:
        """Lower-cased malware names that trigger the flow, sorted."""
        return sorted(self._names)

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
        # id + "_RA". EX *pushes* that re-detection here — we correlate it to the
        # original case and classify it BEFORE the trigger rules, since a re-detection
        # need not match the first-time riskware rules. Never create a separate case
        # for an "_RA" alert.
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

    def _still_encrypted(self, event: AlertEvent) -> bool:
        """Wrong-password signal: the re-detection shows the attachment is still
        encrypted — a CustomPolicy.MVX.<ext> match (the encrypted-attachment custom
        policy, see ``rules.matches``) or a PASSWORD_EXTRACTION_FAILED marker name."""
        return (self.rules.matches(event)
                or any(_canon_name(n) in PASSWORD_FAILED_MARKERS for n in event.malware_names))

    def _finish(self, case, held: bool, event: AlertEvent | None = None) -> None:
        """Record the terminal resubmission verdict and purge the held password.
        ``held`` → DONE_QUARANTINED (with the pushed detection detail, if any); otherwise
        DONE_PASSED (released/delivered)."""
        self.repo.clear_password(case)  # terminal either way — held password no longer needed
        if held:
            detail = "re-quarantined after resubmission: held"
            summary = _detection_summary(event)
            self.repo.set_state(case, FlowState.DONE_QUARANTINED,
                                f"{detail} — {summary}" if summary else detail)
        else:
            self.repo.set_state(case, FlowState.DONE_PASSED, "not re-quarantined after resubmission: released")

    async def _confirm_outcome(self, case, event: AlertEvent | None = None) -> None:
        """Terminal outcome, decided by the **actual quarantine list** — never by a
        pushed alert's type. A riskware rule may raise an alert without quarantining
        (alert-but-allow), so a push proves only that re-analysis happened, not that
        the email is held. We ask EX whether the ``_RA`` is still quarantined:
        present → DONE_QUARANTINED (held); absent → DONE_PASSED (released).

        ``event`` is the pushed re-detection (None on the recheck-timer path); when held,
        its detection detail is recorded on the timeline."""
        held = await self.ex.has_resubmission_quarantine(case.queue_id, case.sender, case.subject)
        self._finish(case, held, event)

    async def _classify_resubmission(self, case, event: AlertEvent) -> None:
        """Handle a pushed ``_RA`` re-detection for a resubmitted case.

        The push only *triggers* a decision; its alert type is not trusted. Order:
        1. **Wrong password** — a still-encrypted signal (see ``_still_encrypted``)
           means extraction failed again → re-ask the recipient (up to the cap). This
           must be checked first: a still-encrypted ``_RA`` is itself quarantined, so
           without this it would read as "quarantined/held".
        2. Otherwise **confirm from the quarantine list** (``_confirm_outcome``):
           present → DONE_QUARANTINED, absent → DONE_PASSED.

        A single ``_RA`` can arrive as several webhook pushes (one per detected
        object), so the wrong-password signal wins even if a bare re-quarantine push
        landed first — hence we reopen DONE_QUARANTINED on a later marker."""
        if self._still_encrypted(event):
            # Reopen even a terminal verdict: a wrong-password re-detection can arrive
            # after the recheck poll concluded (held or released early).
            if case.state in RECHECKABLE or case.state in (FlowState.DONE_QUARANTINED, FlowState.DONE_PASSED):
                await self._fail_extraction(case, event)
            return
        if case.state in RECHECKABLE:
            await self._confirm_outcome(case, event)

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
        """Handle a password submission. Returns (case_or_None, SubmitStatus)."""
        # Accept a just-expired but validly-signed token (the recipient is actively
        # submitting); single use is still enforced by the case state below.
        case_id = self.tokens.peek(token)
        if not case_id:
            return None, SubmitStatus.INVALID_OR_EXPIRED
        case = self.repo.get_case(case_id)
        if case is None:
            return None, SubmitStatus.NOT_FOUND
        if case.state != FlowState.AWAITING_PASSWORD:
            return case, SubmitStatus.NOT_AWAITING

        # The recipient's part is done the moment we have the password. Store it
        # (encrypted), acknowledge immediately, and do the EX rescan in the
        # background — the user's success does not depend on EX being reachable.
        self.repo.store_password(case, self._fernet.encrypt(password.encode()).decode())
        self.repo.set_state(case, FlowState.PASSWORD_SUBMITTED, "password received")
        self.scheduler.schedule_resubmit(case.id)
        return case, SubmitStatus.OK

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
        queue_id, _ = await self.ex.rescan_target(case.queue_id, case.sender, case.subject)
        if queue_id is None:
            log.warning("no rescannable quarantine entry for case %s (queue %s)", case.id, case.queue_id)
            self.repo.increment_resubmit_attempts(case)
            self.repo.set_state(case, FlowState.RESUBMIT_FAILED, "no rescannable quarantine entry found")
            return
        target = queue_id  # rescan is always keyed on the queue id (the API doc mislabels it "email_uuid")
        # Diagnostic (no plaintext): lets us verify the exact bytes we hand EX match the
        # password that works typed into the appliance. A len != stripped_len means a
        # stray space/newline slipped in; compare sha8 with `printf %s 'pw' | sha256sum`.
        # DEBUG only: even a truncated hash helps confirm guesses, so it stays out of normal logs.
        if log.isEnabledFor(logging.DEBUG):
            fp = hashlib.sha256(password.encode()).hexdigest()[:8]
            log.debug("rescan case %s target=%s pwd(len=%d stripped_len=%d sha8=%s)",
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

    async def _fail_extraction(self, case, event: AlertEvent | None = None) -> None:
        """A confirmed wrong password: the resubmission was re-quarantined as the same
        failed-extraction riskware. Count the attempt and re-ask, or give up at the cap.
        ``event`` is the still-encrypted re-detection whose detail we record."""
        self.repo.increment_attempts(case)
        summary = _detection_summary(event)
        note = f"wrong password: {summary}" if summary else "wrong password"
        if case.attempts >= self.settings.max_password_attempts:
            self.repo.set_state(case, FlowState.FAILED_MAX_RETRIES, f"max password attempts reached — {note}")
        else:
            await self._send_password_request(case, retry=True, note=note)  # re-send the link to retry

    async def recheck(self, case_id: str, final: bool = False) -> bool:
        """Poll a resubmitted case toward a verdict. Returns True to stop polling.

        A wrong-password push resolves the case early (it leaves RECHECKABLE). Otherwise
        we read the quarantine list each poll and conclude **as soon as it is decisive**,
        so a clean email doesn't sit in RECHECKING for the whole window waiting for a push
        that never comes (clean content pushes nothing):
        - ``held`` (the ``_RA`` is present) → DONE_QUARANTINED;
        - ``released`` (neither ``_RA`` nor the original remains) → DONE_PASSED;
        - ``pending`` (original still quarantined, no ``_RA`` yet) → keep polling, and on
          the final poll conclude from the list as a push would (``_confirm_outcome``)."""
        case = self.repo.get_case(case_id)
        if case is None or case.state not in RECHECKABLE:
            return True  # already resolved (typically by a wrong-password _RA push)
        if case.state == FlowState.RESUBMITTED:
            self.repo.set_state(case, FlowState.RECHECKING, "awaiting re-detection")
        outcome = await self.ex.resubmission_outcome(case.queue_id, case.sender, case.subject)
        if outcome == ResubmissionOutcome.HELD:
            log.info("recheck case %s: concluded HELD (early _RA present)", case.id)
            self._finish(case, True)
            return True
        if outcome == ResubmissionOutcome.RELEASED:
            log.info("recheck case %s: concluded RELEASED (original left quarantine)", case.id)
            self._finish(case, False)
            return True
        if final:  # still 'pending' at the deadline — conclude from the list
            log.info("recheck case %s: still 'pending' at final poll — concluding from the "
                     "quarantine list (original never left the list within the window)", case.id)
            await self._confirm_outcome(case)
            return True
        return False  # re-analysis unfinished; keep polling

    async def resume_pending(self):
        """On startup, reschedule work left mid-flight: rechecks and resubmissions."""
        for case_id in self.repo.list_pending_ids():
            self.scheduler.schedule_recheck(case_id)
        for case_id in self.repo.list_resubmit_pending_ids(self.settings.resubmit_max_retries):
            self.scheduler.schedule_resubmit(case_id)

    async def reconcile(self, duration: str | None = None) -> dict:
        """Backfill trigger cases missed while the app was down (quarantine-first,
        idempotent). See ``reconcile.run_reconcile`` for the algorithm."""
        return await run_reconcile(self, duration)

    async def resend(self, case_id: str):
        """Operator-triggered re-send. Returns the send result, or None if the
        case isn't in a re-sendable state."""
        case = self.repo.get_case(case_id)
        resendable = (FlowState.NOTIFY_FAILED, FlowState.AWAITING_PASSWORD, FlowState.BOUNCED)
        if case is None or case.state not in resendable:
            return None
        return await self._send_password_request(case)

    async def alert_details_for_case(self, case_id: str) -> list[dict]:
        """Extra, display-only alert details for the case drawer: every alert EX attaches
        to this email's quarantine records (original + any ``_RA`` re-analysis), fetched
        by UUID. Best-effort and never part of a flow decision — a quarantine record can
        carry several ``alert_uuids``, so we fetch and return all of them. Empty list for
        an unknown case."""
        case = self.repo.get_case(case_id)
        if case is None:
            return []
        uuids = await self.ex.alert_uuids_for(case.queue_id, case.sender, case.subject)
        raws = await asyncio.gather(*(self.ex.get_alert_by_uuid(u) for u in uuids))
        details = [parse_alert_detail(r) for r in raws if r]
        # Hide the pre-password-extraction trigger alert on the ORIGINAL record — it's the
        # encrypted-attachment detection that landed the email in the app, so it's redundant
        # in the drawer. Keep any _RA re-detection (a wrong-password re-encryption is useful).
        return [d for d in details if not is_pre_extraction_alert(d)]

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

    async def _send_password_request(self, case, retry: bool = False, note: str = "") -> bool:
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
        detail = "password link sent" + (" (retry)" if retry else "")
        self.repo.set_state(case, FlowState.AWAITING_PASSWORD, f"{detail} — {note}" if note else detail)
        return True
