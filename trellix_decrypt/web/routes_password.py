"""Public recipient-facing password form (no auth — recipients aren't admins)."""

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

_RESULTS = {
    "ok": "Thanks — we've received your password and are processing your attachment.",
    "invalid_or_expired": "This link is invalid or has expired.",
    "not_found": "We couldn't find a matching request.",
    "not_awaiting": "This request has already been processed.",
}
_REISSUED = "Your previous link had expired, so we've emailed you a fresh one. Please use the new link."


def build_password_router(ctx, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

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
        _, status = await ctx.engine.handle_password(token, password)
        ok = status == "ok"
        template = "result.html" if ok else "error.html"
        key = "message" if ok else "reason"
        return templates.TemplateResponse(request, template,
                                          {key: _RESULTS.get(status, "Something went wrong.")},
                                          status_code=200 if ok else 400)

    return router
