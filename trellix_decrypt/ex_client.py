"""Trellix EX (FireEye-lineage) Web Services API client.

Verified against the Trellix API Reference Release 2025.1 PDFs in docs/
(authentication, alerts, email_quarantine_management). All endpoint paths live
at the top of this file — the single place to adjust for another appliance.
"""

from __future__ import annotations

import httpx

from .domain import QuarantineOutcome, RiskwareRules, iter_alerts, parse_alert

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
    pass


class EXClient:
    """Async client handling the auth-token lifecycle and the operations we need."""

    def __init__(self, base_url: str, username: str, password: str,
                 verify_tls: bool = True, client_token: str = ""):
        self._auth = httpx.BasicAuth(username, password)
        self._client_token = client_token
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), verify=verify_tls, timeout=30.0)
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
            raise EXApiError(f"{method} {url} -> HTTP {resp.status_code}: {resp.text[:1000]}")
        return resp

    # --- alerts -------------------------------------------------------------
    async def get_alerts(self, **filters) -> dict:
        params = {"info_level": "normal", **filters}
        resp = await self._request("GET", EP_ALERTS, params=params)
        return resp.json()

    # --- quarantine ---------------------------------------------------------
    async def list_quarantine(self, **params) -> list[dict]:
        resp = await self._request("GET", EP_QUARANTINE, params=params)
        return _as_quarantine_list(resp.json())

    async def quarantine_ids(self, queue_id: str) -> tuple[str | None, str | None]:
        """Return (queue_id, email_uuid) for the email currently quarantined under
        `queue_id`. After a failed resubmission EX re-quarantines under the original
        id plus a suffix it appends (e.g. `_RA`); we read that back (exact match
        wins, otherwise the prefixed re-quarantine entry) rather than constructing it.
        """
        entries = await self.list_quarantine()
        exact = [e for e in entries if _qid(e) == queue_id]
        prefixed = [e for e in entries if _qid(e) != queue_id and _qid(e).startswith(queue_id)]
        for entry in exact or prefixed:
            return _qid(entry), (entry.get("email_uuid") or entry.get("emailUuid"))
        return None, None

    async def rescan(self, queue_id: str, passwords: list[str]) -> dict:
        """Rescan a quarantined email by queue id, supplying decryption password(s)."""
        url = f"{EP_QUARANTINE_RESCAN}/{queue_id}"
        payload = {"rescan_properties": {"pwd_list": passwords}}
        resp = await self._request("POST", url, json=payload, headers={"Content-Type": "application/json"})
        return resp.json() if resp.content else {}

    async def release(self, queue_ids: list[str]) -> dict:
        resp = await self._request("POST", EP_QUARANTINE_RELEASE, json={"queue_ids": queue_ids})
        return resp.json() if resp.content else {}

    async def delete(self, queue_ids: list[str]) -> dict:
        resp = await self._request("POST", EP_QUARANTINE_DELETE, json={"queue_ids": queue_ids})
        return resp.json() if resp.content else {}

    # --- recheck classification --------------------------------------------
    async def classify_resubmission(self, queue_id: str, recipient: str, rules: RiskwareRules) -> QuarantineOutcome:
        """Classify a resubmitted email by reading EX state for the re-quarantine.

        EX re-quarantines a failed resubmission under the original queue id plus a
        suffix it appends (e.g. `_RA`). We detect it in the quarantine list by
        prefix (never fabricating the suffix), then read the reason from alerts:
          not re-quarantined         -> NOT_QUARANTINED (delivered / clean)
          MALWARE_OBJECT / malicious -> MALICIOUS (stop)
          still a riskware trigger   -> FAILED_EXTRACTION (wrong password, retry)
        """
        requarantined = [e for e in await self.list_quarantine()
                         if _qid(e) != queue_id and _qid(e).startswith(queue_id)]
        if not requarantined:
            return QuarantineOutcome.NOT_QUARANTINED

        events = [parse_alert(a) for a in iter_alerts(await self.get_alerts(recipient_email=recipient))]
        redetections = [e for e in events if e.queue_id and e.queue_id != queue_id and e.queue_id.startswith(queue_id)]
        if any(e.malicious or (e.alert_name or "").upper() == "MALWARE_OBJECT" for e in redetections):
            return QuarantineOutcome.MALICIOUS
        return QuarantineOutcome.FAILED_EXTRACTION


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
