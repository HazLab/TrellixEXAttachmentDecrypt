"""Auth-gated JSON API for the dashboard: case list, case detail, settings."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from . import auth
from ..settings_store import EDITABLE

# FlowState value -> (human label, badge kind for CSS).
STATUS_META = {
    "received": ("Received", "neutral"),
    "awaiting_password": ("Password requested", "info"),
    "password_submitted": ("Password received", "info"),
    "resubmitted": ("Resubmitted", "info"),
    "rechecking": ("Re-checking", "info"),
    "done_clean": ("Clean", "success"),
    "done_malicious": ("Malicious", "danger"),
    "failed_max_retries": ("Wrong password", "warn"),
    "expired": ("Expired", "neutral"),
    "notify_failed": ("Email failed", "danger"),
    "bounced": ("Bounced", "danger"),
}


def _decorate(case: dict) -> dict:
    label, kind = STATUS_META.get(case["state"], (case["state"], "neutral"))
    case["status_label"] = label
    case["status_kind"] = kind
    return case


def build_api_router(ctx) -> APIRouter:
    router = APIRouter(prefix="/api")

    def _guard(request: Request):
        if not auth.is_authenticated(request, ctx.env.secret_key):
            raise HTTPException(status_code=401, detail="unauthorized")

    @router.get("/cases")
    async def list_cases(request: Request):
        _guard(request)
        return {"cases": [_decorate(c) for c in ctx.repo.list_cases()]}

    @router.get("/cases/{case_id}")
    async def case_detail(request: Request, case_id: str):
        _guard(request)
        case = ctx.repo.case_detail(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="not found")
        return _decorate(case)

    @router.post("/cases/{case_id}/resend")
    async def resend(request: Request, case_id: str):
        _guard(request)
        result = await ctx.engine.resend(case_id)
        if result is None:
            raise HTTPException(status_code=409, detail="case is not in a re-sendable state")
        case = ctx.repo.case_detail(case_id)
        return {"sent": bool(result), "state": case["state"] if case else None}

    @router.get("/settings")
    async def get_settings(request: Request):
        _guard(request)
        return ctx.store.masked()

    @router.post("/settings")
    async def update_settings(request: Request):
        _guard(request)
        changes = {k: v for k, v in (await request.json()).items() if k in EDITABLE}
        ctx.store.update(changes)
        await ctx.reload()  # apply live
        return {"saved": True, "settings": ctx.store.masked()}

    return router
