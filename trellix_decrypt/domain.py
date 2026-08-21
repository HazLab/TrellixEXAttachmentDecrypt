"""Pure business logic: models, riskware rules, one-time tokens, and the flow engine.

This module performs **no I/O of its own** — the FlowEngine drives the flow by
calling injected collaborators (repository, EX client, mailer, scheduler), so it
is fully unit-testable with fakes.
"""

from __future__ import annotations

import asyncio
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
    DONE_PASSED = "done_passed"           # not re-quarantined after resubmission: delivered
    DONE_QUARANTINED = "done_quarantined"  # re-quarantined after resubmission: held (terminal)
    FAILED_MAX_RETRIES = "failed_max_retries"
    EXPIRED = "expired"
    NOTIFY_FAILED = "notify_failed"   # couldn't hand the email to the mail server (SMTP error)
    BOUNCED = "bounced"               # accepted by the server then bounced (DSN)
    RESUBMIT_FAILED = "resubmit_failed"  # password captured, but EX rescan failed (retryable)


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
        if outcome == "held":
            self._finish(case, True)
            return True
        if outcome == "released":
            self._finish(case, False)
            return True
        if final:  # still 'pending' at the deadline — conclude from the list
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
        """Backfill trigger alerts missed while the app was down.

        Queries EX for recent alerts and starts the flow for any matching email we have
        no case for. **Idempotent**: dedups by queue id and skips ``_RA`` re-detections
        (those are recovered by the recheck poll), so it is safe to run repeatedly and
        alongside EX's own HTTP-notification retries — it never creates duplicates or
        re-emails an existing case. Returns a summary dict for logging/UI. In-flight
        cases are already recovered separately by ``resume_pending`` + the recheck poll;
        this covers only *first-time* alerts that never reached the webhook."""
        if not self.settings.ex_base_url:
            return {"scanned": 0, "created": 0, "already_known": 0, "skipped": 0,
                    "note": "EX not configured"}
        duration = duration or self.settings.reconcile_lookback
        # info_level=extended so the alerts query embeds the full envelope AND the
        # explanation.malwareDetected block. At lower levels EX omits the malware detail
        # from the LIST, which would leave malware_names empty and skip every alert. If a
        # box rejects extended for this window, fall back to a plain query — the per-alert
        # UUID detail fetch below then recovers the malware names.
        try:
            raw = await self.ex.get_alerts(duration=duration, info_level="extended")
        except Exception:
            log.warning("reconcile: extended alerts query failed, retrying at default level",
                        exc_info=True)
            raw = await self.ex.get_alerts(duration=duration)
        alerts = iter_alerts(raw)
        log.info("reconcile(duration=%s): EX returned %d alert(s)", duration, len(alerts))
        created = already = skipped = 0
        for a in alerts:
            ev = parse_alert(a)
            # _RA re-detections are handled by the recheck poll, not here.
            if ev.queue_id.endswith("_RA"):
                skipped += 1
                continue
            # Belt-and-suspenders: if the top-level alert name matches the trigger but the
            # list row carried no malware detail (some EX info_levels/box builds still trim
            # it from the list), fetch the full alert by UUID and re-parse before deciding.
            if self.rules.alert_name_matches(ev.alert_name) and not ev.malware_names:
                uuid = _text(a.get("uuid"))
                detail = await self.ex.get_alert_by_uuid(uuid) if uuid else None
                if detail:
                    ev = parse_alert(detail)
            if not ev.queue_id or not ev.recipient or not self.rules.matches(ev):
                log.debug("reconcile skip queue=%r name=%r malware=%r recipient=%r",
                          ev.queue_id, ev.alert_name, ev.malware_names, ev.recipient)
                skipped += 1
                continue
            if self.repo.find_case_by_queue_id(ev.queue_id) is not None:
                already += 1
                continue
            if await self.handle_alert(ev) is not None:  # creates the case + emails
                created += 1
        summary = {"scanned": len(alerts), "created": created,
                   "already_known": already, "skipped": skipped}
        log.info("reconcile(duration=%s): %s", duration, summary)
        return summary

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
        return [parse_alert_detail(r) for r in raws if r]

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


def parse_alert_detail(alert: dict) -> dict:
    """Compact, display-only view of one raw EX alert (from GET /alerts/alert/<uuid>).

    Pure. Surfaces the fields worth showing in the case drawer — alert type/verdict,
    severity/action, when it occurred, the console link, and the detected malware
    (name + hashes). Tolerates both the camelCase query shape and the hyphenated push."""
    return {
        "uuid": _text(alert.get("uuid")),
        "name": _text(_first(alert.get("name"), alert.get("alert_name"))),
        "malicious": _is_yes(_text(alert.get("malicious"))),
        "severity": _text(alert.get("severity")),
        "action": _text(alert.get("action")),
        "occurred": _text(_first(alert.get("occurred"), alert.get("attackTime"), alert.get("attack-time"))),
        "alert_url": _text(_first(alert.get("alertUrl"), alert.get("alert-url"))),
        "queue_id": _text(_first(
            _dig(alert, "smtpMessage", "queueId"), _dig(alert, "smtp-message", "queue-id"),
            alert.get("queueId"), alert.get("queue-id"))),
        "malware": [
            {"name": _text(m.get("name")),
             "sha256": _text(_first(m.get("sha256"), m.get("sha-256"))),
             "md5": _text(_first(m.get("md5Sum"), m.get("md5sum"), m.get("md5")))}
            for m in _malware_entries(alert)
        ],
    }
