"""FastAPI app: webhook router, the recipient password form, and health.

Kept deliberately thin so a richer UI can be added on top later.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .domain import FlowEngine
from .ingest import build_webhook_router

TEMPLATES_DIR = Path(__file__).parent / "templates"


def build_password_router(engine: FlowEngine, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

    @router.get("/p/{token}", response_class=HTMLResponse)
    async def show_form(request: Request, token: str):
        if engine.tokens.verify(token) is None:
            return templates.TemplateResponse(request, "error.html", {"reason": "This link is invalid or has expired."}, status_code=404)
        return templates.TemplateResponse(request, "form.html", {"token": token})

    @router.post("/p/{token}", response_class=HTMLResponse)
    async def submit_form(request: Request, token: str, password: str = Form(...)):
        _, status = await engine.handle_password(token, password)
        messages = {
            "ok": "Thanks — we're re-checking your attachment. You'll hear from us if we need anything else.",
            "invalid_or_expired": "This link is invalid or has expired.",
            "not_found": "We couldn't find a matching request.",
            "not_awaiting": "This request has already been processed.",
        }
        ok = status == "ok"
        template = "result.html" if ok else "error.html"
        key = "message" if ok else "reason"
        return templates.TemplateResponse(request, template, {key: messages.get(status, "Something went wrong.")}, status_code=200 if ok else 400)

    return router


def create_app(engine: FlowEngine, settings) -> FastAPI:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await engine.resume_pending()
        yield
        await engine.scheduler.shutdown()
        await engine.aclose()

    app = FastAPI(title="Trellix EX Attachment Decrypt", lifespan=lifespan)
    app.include_router(build_webhook_router(engine, settings))
    app.include_router(build_password_router(engine, templates))

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
