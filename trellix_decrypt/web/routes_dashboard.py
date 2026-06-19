"""Auth-gated HTML pages: dashboard, settings, and the login flow."""

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import auth


def build_dashboard_router(ctx, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()
    secret = ctx.env.secret_key

    @router.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        if auth.is_authenticated(request, secret):
            return RedirectResponse("/", status_code=303)
        return templates.TemplateResponse(request, "login.html",
                                          {"error": None, "configured": bool(ctx.env.ui_password)})

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request, password: str = Form(...)):
        if auth.check_password(ctx.env, password):
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(auth.COOKIE, auth.issue_session(secret),
                            httponly=True, samesite="lax", max_age=auth.SESSION_TTL)
            return resp
        return templates.TemplateResponse(request, "login.html",
                                          {"error": "Incorrect password.", "configured": bool(ctx.env.ui_password)},
                                          status_code=401)

    @router.get("/logout")
    async def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(auth.COOKIE)
        return resp

    @router.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not auth.is_authenticated(request, secret):
            return auth.login_redirect()
        return templates.TemplateResponse(request, "dashboard.html", {})

    @router.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        if not auth.is_authenticated(request, secret):
            return auth.login_redirect()
        return templates.TemplateResponse(request, "settings.html", {})

    return router
