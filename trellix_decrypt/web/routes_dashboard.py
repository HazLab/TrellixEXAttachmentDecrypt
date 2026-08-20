"""Auth-gated HTML pages: dashboard, settings, and the login flow.

Two safety rails wrap the admin surfaces:
- **Login rate limit** — per client IP, a self-healing time window (see ``ratelimit``);
  clears on a successful sign-in and on restart, so there is no permanent lockout.
- **Setup mode** — while no admin password is configured you can't sign in, so the
  settings page (and its API) are reachable *without* auth purely to bootstrap the
  first admin password + core config. The moment a password is set, auth is enforced.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import auth
from .ratelimit import RateLimiter, client_ip


def in_setup_mode(ctx) -> bool:
    """True until an admin password exists: the only state where admin pages open up."""
    return not bool(ctx.engine.settings.ui_password)


def build_dashboard_router(ctx, templates) -> APIRouter:
    router = APIRouter()
    secret = ctx.env.secret_key
    limiter = RateLimiter(ctx.env.login_rate_limit, ctx.env.login_rate_window)

    def _ctx(request: Request, **extra) -> dict:
        base = {"setup_mode": in_setup_mode(ctx),
                "missing": ctx.engine.settings.missing_required()}
        base.update(extra)
        return base

    @router.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        if auth.is_authenticated(request, secret):
            return RedirectResponse("/", status_code=303)
        if in_setup_mode(ctx):  # nothing to log into yet — go set up
            return RedirectResponse("/settings", status_code=303)
        return templates.TemplateResponse(request, "login.html", _ctx(request, error=None, configured=True))

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request, password: str = Form(...)):
        ip = client_ip(request, ctx.engine.settings.trust_forwarded_for)
        if not limiter.allow(ip, time.monotonic()):
            return templates.TemplateResponse(
                request, "login.html",
                _ctx(request, error="Too many attempts. Please wait a few minutes.", configured=True),
                status_code=429)
        if auth.check_password(ctx.engine.settings, password):
            limiter.reset(ip)  # successful auth clears the IP's counter
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(auth.COOKIE, auth.issue_session(secret),
                            httponly=True, samesite="lax", max_age=auth.SESSION_TTL)
            return resp
        return templates.TemplateResponse(request, "login.html",
                                          _ctx(request, error="Incorrect password.", configured=True),
                                          status_code=401)

    @router.get("/logout")
    async def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(auth.COOKIE)
        return resp

    @router.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if in_setup_mode(ctx):
            return RedirectResponse("/settings", status_code=303)
        if not auth.is_authenticated(request, secret):
            return auth.login_redirect()
        return templates.TemplateResponse(request, "dashboard.html", _ctx(request))

    @router.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        # Reachable without auth ONLY during first-run setup (no admin password yet).
        if not in_setup_mode(ctx) and not auth.is_authenticated(request, secret):
            return auth.login_redirect()
        return templates.TemplateResponse(request, "settings.html", _ctx(request))

    return router
