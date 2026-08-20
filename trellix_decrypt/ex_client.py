"""Trellix EX (FireEye-lineage) Web Services API client.

Verified against the Trellix API Reference Release 2025.1 PDFs in docs/
(authentication, alerts, email_quarantine_management). All endpoint paths live
at the top of this file — the single place to adjust for another appliance.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx

log = logging.getLogger(__name__)

#: The quarantine-list default window is only now()-24h, but a full decrypt cycle
#: (notify -> recipient submits -> rescan -> re-analysis) can outlast that. A caller can
#: pass ``since``/``until`` to widen it; ``_TIME_SKEW`` pads each open end.
_TIME_SKEW = timedelta(hours=1)

#: Clock-INDEPENDENT window for the per-case lookups. EX filters the list by its OWN
#: clock while we'd compute a now-relative window on ours, so a wrong appliance clock
#: (skew > the pad) pushes the very entry we need outside the window — the list comes
#: back empty and a rescan/confirm wrongly finds "no queue id". A fixed wide span avoids
#: any dependence on the two clocks agreeing; `from`+`subject`+exact-queue-id still narrow
#: the result. Verified failure mode: EX clock off by hours -> rescan target not found.
_ALL_TIME_START = datetime(2000, 1, 1, tzinfo=timezone.utc)
_ALL_TIME_END = datetime(2100, 1, 1, tzinfo=timezone.utc)


def _ex_time(dt: datetime) -> str:
    """Format a datetime as EX expects: ``YYYY-MM-DDTHH:MM:SS.SSS-HHMM`` (UTC)."""
    if dt.tzinfo is None:  # DB round-trips can drop tzinfo; our timestamps are UTC
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}{dt:%z}"

# --- Endpoints (Trellix WSAPI v2.0.0) ---------------------------------------
API_VERSION = "v2.0.0"
_BASE = f"/wsapis/{API_VERSION}"
EP_LOGIN = f"{_BASE}/auth/login"
EP_LOGOUT = f"{_BASE}/auth/logout"
EP_ALERTS = f"{_BASE}/alerts"
EP_ALERT_DETAILS = f"{_BASE}/alerts/alert"  # + /<uuid>; undocumented but present on the appliance
EP_QUARANTINE = f"{_BASE}/emailmgmt/quarantine"
EP_QUARANTINE_RELEASE = f"{_BASE}/emailmgmt/quarantine/release"
EP_QUARANTINE_DELETE = f"{_BASE}/emailmgmt/quarantine/delete"
EP_QUARANTINE_RESCAN = f"{_BASE}/emailmgmt/quarantine/rescan"  # + /<queue_id> (doc mislabels it email_uuid)

TOKEN_HEADER = "X-FeApi-Token"
CLIENT_TOKEN_HEADER = "X-FeClient-Token"


class EXAuthError(RuntimeError):
    pass


class EXApiError(RuntimeError):
    """A non-2xx response from EX. Carries the status + body for clean handling."""

    def __init__(self, message: str, status_code: int | None = None, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body

    @property
    def not_found(self) -> bool:
        """True when EX reports the email isn't (or is no longer) quarantined —
        e.g. rescanning an id that has no quarantined file behind it. EX answers
        this with a 400/404 whose body mentions the missing email / invalid id."""
        if self.status_code not in (400, 404):
            return False
        body = self.body.lower()
        return any(s in body for s in ("could not find", "not quarantined", "invalid queueid", "does not exist"))


class EXClient:
    """Async client handling the auth-token lifecycle and the operations we need."""

    def __init__(self, base_url: str, username: str, password: str,
                 verify_tls: bool = True, client_token: str = "", timeout: float = 60.0):
        self._auth = httpx.BasicAuth(username, password)
        self._client_token = client_token
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), verify=verify_tls, timeout=timeout)
        self._token: str | None = None

    async def aclose(self):
        await self._client.aclose()

    # --- auth ---------------------------------------------------------------
    async def _login(self):
        headers = {CLIENT_TOKEN_HEADER: self._client_token} if self._client_token else {}
        resp = await self._client.post(EP_LOGIN, auth=self._auth, headers=headers)
        if resp.status_code != 200:
            raise EXAuthError(f"EX login failed: HTTP {resp.status_code}")
        self._token = resp.headers.get(TOKEN_HEADER)
        if not self._token:
            raise EXAuthError(f"EX login response missing {TOKEN_HEADER}")

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        if self._token is None:
            await self._login()
        headers = {TOKEN_HEADER: self._token, "Accept": "application/json"}
        if self._client_token:
            headers[CLIENT_TOKEN_HEADER] = self._client_token
        headers.update(kwargs.pop("headers", {}))
        resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code == 401:  # token expired (15-min idle timeout) — re-auth once
            await self._login()
            headers[TOKEN_HEADER] = self._token
            resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code >= 400:
            raise EXApiError(f"{method} {url} -> HTTP {resp.status_code}: {resp.text[:1000]}",
                             status_code=resp.status_code, body=resp.text)
        return resp

    # --- alerts -------------------------------------------------------------
    async def get_alerts(self, **filters) -> dict:
        params = {"info_level": "normal", **filters}
        resp = await self._request("GET", EP_ALERTS, params=params)
        return resp.json()

    async def get_alert_by_uuid(self, uuid: str) -> dict | None:
        """Fetch one alert's full detail by UUID via ``GET /alerts/alert/<uuid>``.

        Undocumented but present on the appliance; quarantine records reference their
        alerts by ``alert_uuids``. Returns the raw alert dict (EX wraps it in an ``alert``
        array), or None if EX has no such alert. Used only for display, never for flow
        decisions."""
        try:
            resp = await self._request("GET", f"{EP_ALERT_DETAILS}/{uuid}")
        except EXApiError as exc:
            if exc.status_code == 404 or exc.not_found:  # no such alert
                return None
            raise
        data = resp.json()
        alerts = data.get("alert") if isinstance(data, dict) else None
        return alerts[0] if isinstance(alerts, list) and alerts else None

    # --- quarantine ---------------------------------------------------------
    async def list_quarantine(self, sender: str | None = None, subject: str | None = None,
                              since: datetime | None = None, until: datetime | None = None,
                              **params) -> list[dict]:
        # The EX list filters are `from` and `subject`; narrow by the email when known.
        if sender:
            params["from"] = sender
        if subject:
            params["subject"] = subject
        # Without start_time/end_time EX only looks back 24h. Passing either widens it;
        # the doc requires them as a pair, so we fill the open end and pad it by the skew.
        if since is not None or until is not None:
            start = (since if since is not None else _ALL_TIME_START) - _TIME_SKEW
            end = (until if until is not None else datetime.now(timezone.utc)) + _TIME_SKEW
            params["start_time"] = _ex_time(start)
            params["end_time"] = _ex_time(end)
        resp = await self._request("GET", EP_QUARANTINE, params=params)
        return _as_quarantine_list(resp.json())

    async def _list_for_case(self, sender: str | None, subject: str | None) -> list[dict]:
        """Quarantine list for a per-case lookup, over a clock-INDEPENDENT window (see
        ``_ALL_TIME_START``): overrides EX's 24h default without depending on our clock
        agreeing with the appliance's, so a wrong EX clock can't hide the entry."""
        return await self.list_quarantine(sender=sender, subject=subject,
                                          since=_ALL_TIME_START, until=_ALL_TIME_END)

    async def rescan_target(self, queue_id: str, sender: str | None = None, subject: str | None = None):
        """Return (queue_id, email_uuid) of the RESCANNABLE quarantine entry for this
        email — i.e. one with an actual quarantined file (`quarantine_path` set).
        `_RA` re-analysis records have a null path and are NOT rescannable."""
        entries = await self._list_for_case(sender, subject)
        rescannable = [e for e in entries if e.get("quarantine_path")]
        exact = [e for e in rescannable if _qid(e) == queue_id]
        for entry in exact or rescannable:
            return _qid(entry), (entry.get("email_uuid") or entry.get("emailUuid"))
        return None, None

    async def rescan(self, target_id: str, passwords: list[str]) -> dict:
        """Rescan a quarantined email (by queue id or email_uuid), supplying password(s)."""
        url = f"{EP_QUARANTINE_RESCAN}/{target_id}"
        payload = {"rescan_properties": {"pwd_list": passwords}}
        resp = await self._request("POST", url, json=payload, headers={"Content-Type": "application/json"})
        return resp.json() if resp.content else {}

    async def release(self, queue_ids: list[str]) -> dict:
        resp = await self._request("POST", EP_QUARANTINE_RELEASE, json={"queue_ids": queue_ids})
        return resp.json() if resp.content else {}

    async def delete(self, queue_ids: list[str]) -> dict:
        resp = await self._request("POST", EP_QUARANTINE_DELETE, json={"queue_ids": queue_ids})
        return resp.json() if resp.content else {}

    # --- recheck backstop ---------------------------------------------------
    async def has_resubmission_quarantine(self, queue_id: str, sender: str | None = None,
                                          subject: str | None = None) -> bool:
        """True if EX still holds the re-analysis (``_RA``) quarantine entry for this email.

        This is the authoritative resubmission verdict: the FlowEngine decides
        DONE_QUARANTINED vs DONE_PASSED from it, because a pushed ``_RA`` alert proves
        only that re-analysis happened, not that the email is held (a riskware rule can
        alert without quarantining).

        The signal is simple and exact: is there a quarantine record whose queue id is
        **this email's queue id with an ``_RA`` suffix**? Present → still held
        (DONE_QUARANTINED); absent → released/delivered (DONE_PASSED). We match the
        ``_RA``-suffixed id exactly (via ``_strip_ra``), NOT a loose prefix: a prefix
        match also catches the original entry's siblings and any longer unrelated id,
        which is what wrongly flagged every resubmission as held. The clock-independent
        window matters here too: a skewed EX clock could hide the ``_RA`` and mislabel a
        held email as passed — the dangerous direction."""
        entries = await self._list_for_case(sender, subject)
        related = [(_qid(e), e.get("quarantine_path")) for e in entries if _strip_ra(_qid(e)) == queue_id]
        log.info("has_resubmission_quarantine(base=%s) entries for this queue id: %s", queue_id, related)
        return any(_qid(e).endswith("_RA") and _strip_ra(_qid(e)) == queue_id for e in entries)

    async def resubmission_outcome(self, queue_id: str, sender: str | None = None,
                                   subject: str | None = None) -> str:
        """Three-state resubmission verdict from the quarantine list, for the recheck poll.

        Lets a clean email conclude promptly instead of waiting the whole recheck window
        for a push that never comes (clean content pushes nothing):
        - ``"held"`` — the ``<queue_id>_RA`` re-quarantine is present (still held).
        - ``"released"`` — neither the ``_RA`` nor the original ``<queue_id>`` remains, so
          EX released and delivered it (clean).
        - ``"pending"`` — the original ``<queue_id>`` is still quarantined and no ``_RA``
          yet, i.e. EX hasn't finished re-analysis; keep polling.
        """
        entries = await self._list_for_case(sender, subject)
        qids = [_qid(e) for e in entries]
        log.info("resubmission_outcome(base=%s) queue ids: %s", queue_id, qids)
        if any(q.endswith("_RA") and _strip_ra(q) == queue_id for q in qids):
            return "held"
        return "pending" if any(q == queue_id for q in qids) else "released"

    async def alert_uuids_for(self, queue_id: str, sender: str | None = None,
                              subject: str | None = None) -> list[str]:
        """Every alert UUID EX attaches to this email's quarantine records — the original
        and any ``<queue_id>_RA`` re-analysis. A record can list several ``alert_uuids``,
        so we collect them all, order preserved and de-duplicated."""
        entries = await self._list_for_case(sender, subject)
        out: list[str] = []
        seen: set[str] = set()
        for e in entries:
            if _strip_ra(_qid(e)) != queue_id:
                continue
            for uuid in e.get("alert_uuids") or e.get("alertUuids") or []:
                if uuid and uuid not in seen:
                    seen.add(uuid)
                    out.append(str(uuid))
        return out


# --- helpers ----------------------------------------------------------------
def _qid(entry: dict) -> str:
    return str(entry.get("queue_id") or entry.get("queueId") or "")


def _strip_ra(queue_id: str) -> str:
    """The base queue id, with EX's one-or-more ``_RA`` re-analysis suffixes removed."""
    while queue_id.endswith("_RA"):
        queue_id = queue_id[: -len("_RA")]
    return queue_id


def _as_quarantine_list(data) -> list[dict]:
    """The list-quarantine response is a JSON array; tolerate a wrapped object too."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("email", "emails", "quarantine"):
            if isinstance(data.get(key), list):
                return data[key]
    return []
