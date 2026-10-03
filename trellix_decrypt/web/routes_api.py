# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""Auth-gated JSON API for the dashboard: case list, case detail, settings."""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from .. import tls
from ..settings_store import EDITABLE, SettingsValidationError
from .routes_dashboard import in_setup_mode, is_admin, setup_allowed

log = logging.getLogger(__name__)

# FlowState value -> (human label, unique badge class for CSS).
STATUS_META = {
    "received": ("Received", "received"),
    "awaiting_password": ("Password requested", "awaiting"),
    "password_submitted": ("Password received", "submitted"),
    "resubmitted": ("Resubmitted", "resubmitted"),
    "rechecking": ("Re-checking", "rechecking"),
    "done_passed": ("Released", "passed"),
    "done_quarantined": ("Quarantined", "quarantined"),
    "failed_max_retries": ("Wrong password", "wrongpw"),
    "expired": ("Expired", "expired"),
    "notify_failed": ("Email failed", "emailfail"),
    "bounced": ("Bounced", "bounced"),
    "resubmit_failed": ("Resubmit failed", "resubmitfail"),
}


def _decorate(case: dict) -> dict:
    label, kind = STATUS_META.get(case["state"], (case["state"], "neutral"))
    case["status_label"] = label
    case["status_kind"] = kind
    return case


def build_api_router(ctx) -> APIRouter:
    router = APIRouter(prefix="/api")

    def guard(request: Request):
        if not is_admin(request, ctx):
            raise HTTPException(status_code=401, detail="unauthorized")

    def guard_settings(request: Request):
        # The settings endpoints are also reachable during first-run setup (no admin
        # password yet) so the operator can bootstrap — but only with the one-time setup
        # token from the server log. Otherwise they require a signed-in admin.
        if in_setup_mode(ctx):
            if not setup_allowed(request, ctx):
                raise HTTPException(status_code=403, detail="setup token required")
            return
        guard(request)

    _case_routes(router, ctx, guard)
    _tls_routes(router, ctx, guard_settings)
    _settings_routes(router, ctx, guard_settings)
    return router


def _case_routes(router: APIRouter, ctx, guard) -> None:
    """Status, reconcile and the case list/detail/actions — signed-in admin only."""

    @router.get("/status")
    async def status(request: Request):
        guard(request)
        s = ctx.engine.settings
        return {"configured": s.is_configured(), "missing": s.missing_required(),
                "setup_mode": in_setup_mode(ctx)}

    @router.post("/reconcile")
    async def reconcile(request: Request):
        """Manually backfill any trigger alerts missed while the app was down (idempotent)."""
        guard(request)
        try:
            return {"ok": True, "result": await ctx.engine.reconcile()}
        except Exception as exc:  # noqa: BLE001 — surface a clean error to the UI
            log.warning("manual reconcile failed: %s", exc)
            return {"ok": False, "error": "reconcile failed — check EX connectivity and logs"}

    @router.get("/cases")
    async def list_cases(request: Request):
        guard(request)
        return {"cases": [_decorate(c) for c in ctx.repo.list_cases()]}

    @router.get("/cases/{case_id}")
    async def case_detail(request: Request, case_id: str):
        guard(request)
        case = ctx.repo.case_detail(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="not found")
        return _decorate(case)

    @router.get("/cases/{case_id}/alerts")
    async def case_alerts(request: Request, case_id: str):
        """Extra, display-only EX alert details for the drawer (fetched by UUID). Degrades
        gracefully — this is supplementary info and must never break the case view."""
        guard(request)
        if ctx.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="not found")
        try:
            return {"alerts": await ctx.engine.alert_details_for_case(case_id)}
        except Exception as exc:  # noqa: BLE001 — supplementary; never surface as a hard error
            log.warning("alert detail fetch failed for case %s: %s", case_id, exc)
            return {"alerts": [], "error": "could not fetch alert details from EX"}

    @router.post("/cases/{case_id}/resend")
    async def resend(request: Request, case_id: str):
        guard(request)
        result = await ctx.engine.resend(case_id)
        if result is None:
            raise HTTPException(status_code=409, detail="case is not in a re-sendable state")
        case = ctx.repo.case_detail(case_id)
        return {"sent": bool(result), "state": case["state"] if case else None}

    @router.post("/cases/{case_id}/rescan")
    async def rescan(request: Request, case_id: str):
        guard(request)
        if ctx.repo.get_case(case_id) is None:
            raise HTTPException(status_code=404, detail="not found")
        await ctx.engine.resubmit_case(case_id)  # no-op unless it still holds the password
        case = ctx.repo.case_detail(case_id)
        return {"state": case["state"] if case else None}


def _tls_routes(router: APIRouter, ctx, guard_settings) -> None:
    """HTTPS certificate management (also reachable during token-gated setup)."""

    @router.get("/tls")
    async def tls_status(request: Request):
        guard_settings(request)
        return tls.status(ctx.engine.settings)

    @router.post("/tls")
    async def tls_import(request: Request, mode: str = Form("pem"),
                         cert: UploadFile | None = File(None), key: UploadFile | None = File(None),
                         key_password: str = Form(""),
                         p12: UploadFile | None = File(None), p12_password: str = Form("")):
        """Import the TLS cert/key (PEM pair, or a PKCS#12/.pfx bundle). Applied on restart."""
        guard_settings(request)
        s = ctx.engine.settings
        try:
            if mode == "p12" or p12 is not None:
                if p12 is None:
                    raise ValueError("no PKCS#12 file provided")
                info = tls.install_pkcs12(s, await p12.read(), p12_password)
            else:
                if cert is None or key is None:
                    raise ValueError("both a certificate and a key file are required")
                info = tls.install_pem(s, await cert.read(), await key.read(), key_password)
        except Exception as exc:  # noqa: BLE001 — surface a clean message to the UI
            log.warning("TLS import failed: %s", exc)
            return {"ok": False, "error": f"import failed: {exc}"}
        return {"ok": True, "restart_required": True, "cert": info}

    @router.post("/tls/self-signed")
    async def tls_self_signed(request: Request, hostnames: str = Form("")):
        """Generate a self-signed cert (opt-in convenience; untrusted). Applied on restart."""
        guard_settings(request)
        s = ctx.engine.settings
        hosts = [h for h in re.split(r"[,\s]+", hostnames) if h]
        if not hosts:
            from urllib.parse import urlparse
            hosts = [urlparse(s.public_base_url).hostname or s.web_host or "localhost"]
        try:
            info = tls.generate_self_signed(s, hosts)
        except Exception as exc:  # noqa: BLE001
            log.warning("self-signed generation failed: %s", exc)
            return {"ok": False, "error": f"generation failed: {exc}"}
        return {"ok": True, "restart_required": True, "self_signed": True, "cert": info}

    @router.post("/tls/remove")
    async def tls_remove(request: Request):
        guard_settings(request)
        tls.remove(ctx.engine.settings)
        return {"ok": True, "restart_required": True}


def _settings_routes(router: APIRouter, ctx, guard_settings) -> None:
    """Read/update the UI-editable settings (also reachable during token-gated setup)."""

    @router.get("/settings")
    async def get_settings(request: Request):
        guard_settings(request)
        masked = ctx.store.masked()
        return {"settings": masked, "setup_mode": in_setup_mode(ctx),
                "missing": ctx.engine.settings.missing_required()}

    @router.post("/settings")
    async def update_settings(request: Request):
        guard_settings(request)
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="expected a JSON object")
        clear = [k for k in (body.get("__clear__") or []) if k in EDITABLE]  # explicit removals
        if "ui_password" in clear:  # blanking it would drop the app back into setup mode
            raise HTTPException(status_code=400, detail="the admin password can be changed but not removed")
        changes = {k: v for k, v in body.items() if k in EDITABLE}
        try:
            ctx.store.update(changes, clear=clear)  # validated before anything is saved
        except SettingsValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        await ctx.reload()  # apply live
        return {"saved": True, "settings": ctx.store.masked(),
                "setup_mode": in_setup_mode(ctx), "missing": ctx.engine.settings.missing_required()}
