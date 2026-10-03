# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""FastAPI app factory: wires public + admin routers, static files, lifespan."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..ingest import build_webhook_router
from .routes_api import build_api_router
from .routes_dashboard import build_dashboard_router
from .routes_password import build_password_router

_PKG = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = _PKG / "templates"
STATIC_DIR = _PKG / "static"


#: Sent on every response. The CSP still allows inline script/style because the pages
#: use them (theme bootstrap, the reveal button, a few style attributes); it does stop
#: framing, foreign script/style/form targets, plugins and <base> hijacking.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",  # one-time links must not leak via the Referer header
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
}


def create_app(ctx) -> FastAPI:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await ctx.engine.resume_pending()
        ctx.scheduler.start_notify_retrier()
        ctx.scheduler.start_resubmit_retrier()
        ctx.scheduler.start_reconcile()  # backfill alerts missed while down + periodic sweep
        ctx.scheduler.start_loop(ctx.bounce_monitor.run())
        yield
        await ctx.scheduler.shutdown()
        await ctx.engine.aclose()

    # No public API explorer: /docs, /redoc and /openapi.json would map the admin API
    # for anyone who can reach the port.
    app = FastAPI(title="Trellix EX Attachment Decrypt", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        for name, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(build_webhook_router(ctx))                 # public
    app.include_router(build_password_router(ctx, templates))     # public
    app.include_router(build_dashboard_router(ctx, templates))    # admin pages + login
    app.include_router(build_api_router(ctx))                     # admin JSON API

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
