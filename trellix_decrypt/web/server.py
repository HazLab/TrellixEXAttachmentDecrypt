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


def create_app(ctx) -> FastAPI:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await ctx.engine.resume_pending()
        ctx.scheduler.start_notify_retrier()
        yield
        await ctx.scheduler.shutdown()
        await ctx.engine.aclose()

    app = FastAPI(title="Trellix EX Attachment Decrypt", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(build_webhook_router(ctx))                 # public
    app.include_router(build_password_router(ctx, templates))     # public
    app.include_router(build_dashboard_router(ctx, templates))    # admin pages + login
    app.include_router(build_api_router(ctx))                     # admin JSON API

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
