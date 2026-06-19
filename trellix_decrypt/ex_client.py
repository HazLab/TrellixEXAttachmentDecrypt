"""Trellix EX (FireEye-lineage) Web Services API client.

Verified against the Trellix API Reference Release 2025.1 PDFs in docs/
(authentication, alerts, email_quarantine_management). All endpoint paths live
at the top of this file — the single place to adjust for another appliance.
"""

from __future__ import annotations

import httpx

# --- Endpoints (Trellix WSAPI v2.0.0) ---------------------------------------
API_VERSION = "v2.0.0"
_BASE = f"/wsapis/{API_VERSION}"
EP_LOGIN = f"{_BASE}/auth/login"
EP_LOGOUT = f"{_BASE}/auth/logout"
EP_ALERTS = f"{_BASE}/alerts"
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

    # --- quarantine ---------------------------------------------------------
    async def list_quarantine(self, sender: str | None = None, subject: str | None = None, **params) -> list[dict]:
        # The EX list filters are `from` and `subject`; narrow by the email when known.
        if sender:
            params["from"] = sender
        if subject:
            params["subject"] = subject
        resp = await self._request("GET", EP_QUARANTINE, params=params)
        return _as_quarantine_list(resp.json())

    async def rescan_target(self, queue_id: str, sender: str | None = None, subject: str | None = None):
        """Return (queue_id, email_uuid) of the RESCANNABLE quarantine entry for this
        email — i.e. one with an actual quarantined file (`quarantine_path` set).
        `_RA` re-analysis records have a null path and are NOT rescannable."""
        entries = await self.list_quarantine(sender=sender, subject=subject)
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
        """True if EX still holds a re-analysis (``_RA``) quarantine entry for this email.

        The resubmission verdict normally arrives as a pushed ``<queueId>_RA`` alert
        (handled in the FlowEngine). This is only a fail-closed backstop for the recheck
        timeout: an email is declared clean *only* when no re-analysis entry remains, so
        a missed alert push never lets a still-quarantined email be treated as delivered.
        Matched by sender+subject, then by queue-id prefix (we never build the suffix)."""
        entries = await self.list_quarantine(sender=sender, subject=subject)
        return any(_qid(e) != queue_id and _qid(e).startswith(queue_id) for e in entries)


# --- helpers ----------------------------------------------------------------
def _qid(entry: dict) -> str:
    return str(entry.get("queue_id") or entry.get("queueId") or "")


def _as_quarantine_list(data) -> list[dict]:
    """The list-quarantine response is a JSON array; tolerate a wrapped object too."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("email", "emails", "quarantine"):
            if isinstance(data.get(key), list):
                return data[key]
    return []
