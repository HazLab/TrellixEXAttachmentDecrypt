# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""Public recipient-facing password form (no auth — recipients aren't admins).

Rate-limited per (client IP + token) so the form can't be hammered; the real
guess cap is enforced upstream by EX (``max_password_attempts``). The limit is a
self-healing time window — see ``ratelimit``."""

from __future__ import annotations

import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..domain import SubmitStatus
from .ratelimit import RateLimiter, client_ip

_RESULTS = {
    SubmitStatus.OK: "Thanks — we've received your password and are processing your attachment.",
    SubmitStatus.INVALID_OR_EXPIRED: "This link is invalid or has expired.",
    SubmitStatus.NOT_FOUND: "We couldn't find a matching request.",
    SubmitStatus.NOT_AWAITING: "This request has already been processed.",
}
_RATE_LIMITED = "Too many attempts. Please wait a few minutes and try again."
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
                                              {"reason": _RATE_LIMITED}, status_code=429)
        _, status = await ctx.engine.handle_password(token, password)
        ok = status == SubmitStatus.OK
        template = "result.html" if ok else "error.html"
        key = "message" if ok else "reason"
        return templates.TemplateResponse(request, template,
                                          {key: _RESULTS.get(status, "Something went wrong.")},
                                          status_code=200 if ok else 400)

    return router
