"""Public recipient-facing password form (no auth — recipients aren't admins).

Rate-limited per (client IP + token) so the form can't be hammered; the real
guess cap is enforced upstream by EX (``max_password_attempts``). The limit is a
self-healing time window — see ``ratelimit``."""

from __future__ import annotations

import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .ratelimit import RateLimiter, client_ip

_RESULTS = {
    "ok": "Thanks — we've received your password and are processing your attachment.",
    "invalid_or_expired": "This link is invalid or has expired.",
    "not_found": "We couldn't find a matching request.",
    "not_awaiting": "This request has already been processed.",
    "rate_limited": "Too many attempts. Please wait a few minutes and try again.",
}
_REISSUED = "Your previous link had expired, so we've emailed you a fresh one. Please use the new link."


def build_password_router(ctx, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()
    s = ctx.env
    limiter = RateLimiter(s.form_rate_limit, s.form_rate_window)

    @router.get("/p/{token}", response_class=HTMLResponse)
    async def show_form(request: Request, token: str):
        if ctx.engine.tokens.verify(token) is not None:
            return templates.TemplateResponse(request, "form.html", {"token": token})
        # Expired/invalid: auto-reissue a fresh link if the case still awaits a password.
        if await ctx.engine.reissue_expired_link(token) is not None:
            return templates.TemplateResponse(request, "result.html", {"message": _REISSUED})
        return templates.TemplateResponse(request, "error.html",
                                          {"reason": "This link is invalid or has expired."}, status_code=404)

    @router.post("/p/{token}", response_class=HTMLResponse)
    async def submit_form(request: Request, token: str, password: str = Form(...)):
        env = ctx.engine.settings
        ip = client_ip(request, env.trust_forwarded_for)
        if not limiter.allow(f"{ip}:{token}", time.monotonic()):
            return templates.TemplateResponse(request, "error.html",
                                              {"reason": _RESULTS["rate_limited"]}, status_code=429)
        _, status = await ctx.engine.handle_password(token, password)
        ok = status == "ok"
        template = "result.html" if ok else "error.html"
        key = "message" if ok else "reason"
        return templates.TemplateResponse(request, template,
                                          {key: _RESULTS.get(status, "Something went wrong.")},
                                          status_code=200 if ok else 400)

    return router
