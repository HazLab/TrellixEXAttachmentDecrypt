"""Trellix EX (FireEye-lineage) Web Services API client.

ALL endpoint paths and the resubmit payload shape are defined at the top of this
file — this is the single place to correct against a live appliance. The Trellix
API docs are JS-rendered and not publicly scrapable, so confirm these before
production use.
"""

from __future__ import annotations

import httpx

from .domain import QuarantineOutcome, RiskwareRules, iter_alerts, parse_alert

# --- Endpoints (CONFIRM against your appliance) -----------------------------
API_VERSION = "v2.0.0"
_BASE = f"/wsapis/{API_VERSION}"
EP_LOGIN = f"{_BASE}/auth/login"
EP_LOGOUT = f"{_BASE}/auth/logout"
EP_ALERTS = f"{_BASE}/alerts"
EP_QUARANTINE = f"{_BASE}/emailmgmt/quarantine"
EP_QUARANTINE_RELEASE = f"{_BASE}/emailmgmt/quarantine/release"
EP_QUARANTINE_DELETE = f"{_BASE}/emailmgmt/quarantine/delete"
EP_QUARANTINE_RESUBMIT = f"{_BASE}/emailmgmt/quarantine/resubmit"

TOKEN_HEADER = "X-FeApi-Token"


class EXAuthError(RuntimeError):
    pass


class EXApiError(RuntimeError):
    pass


class EXClient:
    """Async client handling auth-token lifecycle and the operations we need."""

    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = True):
        self._auth = httpx.BasicAuth(username, password)
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"), verify=verify_tls, timeout=30.0)
        self._token: str | None = None

    async def aclose(self):
        await self._client.aclose()

    # --- auth ---------------------------------------------------------------
    async def _login(self):
        resp = await self._client.post(EP_LOGIN, auth=self._auth)
        if resp.status_code != 200:
            raise EXAuthError(f"EX login failed: HTTP {resp.status_code}")
        self._token = resp.headers.get(TOKEN_HEADER)
        if not self._token:
            raise EXAuthError(f"EX login response missing {TOKEN_HEADER}")

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        if self._token is None:
            await self._login()
        headers = {TOKEN_HEADER: self._token, "Accept": "application/json"}
        headers.update(kwargs.pop("headers", {}))
        resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code == 401:  # token expired — re-auth once
            await self._login()
            headers[TOKEN_HEADER] = self._token
            resp = await self._client.request(method, url, headers=headers, **kwargs)
        if resp.status_code >= 400:
            raise EXApiError(f"{method} {url} -> HTTP {resp.status_code}: {resp.text[:200]}")
        return resp

    # --- operations ---------------------------------------------------------
    async def get_alerts(self, **params) -> dict:
        resp = await self._request("GET", EP_ALERTS, params={"info_level": "normal", **params})
        return resp.json()

    async def list_quarantine(self, **params) -> dict:
        resp = await self._request("GET", EP_QUARANTINE, params=params)
        return resp.json()

    async def resubmit(self, queue_id: str, passwords: list[str]) -> dict:
        # CONFIRM payload field names against the appliance docs.
        payload = {"queue_id": queue_id, "passwords": passwords}
        resp = await self._request("POST", EP_QUARANTINE_RESUBMIT, json=payload)
        return resp.json() if resp.content else {}

    async def release(self, queue_ids: list[str]) -> dict:
        resp = await self._request("POST", EP_QUARANTINE_RELEASE, json={"queue_ids": queue_ids})
        return resp.json() if resp.content else {}

    async def delete(self, queue_ids: list[str]) -> dict:
        resp = await self._request("POST", EP_QUARANTINE_DELETE, json={"queue_ids": queue_ids})
        return resp.json() if resp.content else {}

    async def classify_resubmission(self, queue_id: str, rules: RiskwareRules) -> QuarantineOutcome:
        """Classify the resubmitted message by inspecting alerts for `<queue_id>_RA`.

        EX re-detects a resubmitted email under the same queue id + `_RA` suffix.
          no alert for it                                  -> NOT_QUARANTINED (delivered/clean)
          a MALWARE_OBJECT / malicious alert               -> MALICIOUS (stop)
          still a riskware trigger (CustomPolicy.MVX.<ext>) -> FAILED_EXTRACTION (wrong password)
        """
        ra_id = f"{queue_id}_RA"
        events = [parse_alert(a) for a in iter_alerts(await self.get_alerts())]
        relevant = [e for e in events if e.queue_id == ra_id]
        if not relevant:
            return QuarantineOutcome.NOT_QUARANTINED
        if any(e.malicious or (e.alert_name or "").upper() == "MALWARE_OBJECT" for e in relevant):
            return QuarantineOutcome.MALICIOUS
        if any(rules.matches(e) for e in relevant):
            return QuarantineOutcome.FAILED_EXTRACTION
        return QuarantineOutcome.MALICIOUS  # re-detected for some other reason
