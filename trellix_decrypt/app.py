"""Composition root: build settings, wire every layer, return the FastAPI app."""

from __future__ import annotations

import logging

from .config import Settings
from .context import AppContext
from .recheck import RecheckScheduler
from .settings_store import SettingsStore
from .storage import CaseRepository, build_session_factory
from .web import create_app

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _configure_logging(settings: Settings) -> None:
    """Console + optional rotating file, both capturing EVERYTHING — including every
    HTTP request (uvicorn's access log reaches the root handlers because we start
    uvicorn with log_config=None; see __main__). Useful for inspecting raw EX
    notifications hitting the box, not just our own app events."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if settings.log_file:
        from logging.handlers import RotatingFileHandler
        handlers.append(RotatingFileHandler(
            settings.log_file, maxBytes=settings.log_file_max_bytes,
            backupCount=settings.log_file_backups, encoding="utf-8"))
    logging.basicConfig(level=level, format=_LOG_FORMAT, handlers=handlers, force=True)


def build_context(settings: Settings) -> AppContext:
    session_factory = build_session_factory(settings.db_url)
    repo = CaseRepository(session_factory)
    store = SettingsStore(settings, session_factory)
    scheduler = RecheckScheduler()
    return AppContext(settings, store, repo, scheduler)


def build(settings: Settings | None = None):
    settings = settings or Settings()
    _configure_logging(settings)
    ctx = build_context(settings)
    eff = ctx.engine.settings
    log = logging.getLogger(__name__)
    log.info("trigger config: alert_name=%r malware_names=%r", eff.trigger_alert_name, eff.trigger_malware_names)
    log.info("serving on http://%s:%s — password links built from PUBLIC_BASE_URL=%s "
             "(scheme/host/port must match how recipients reach this server)",
             settings.web_host, settings.web_port, eff.public_base_url)
    return create_app(ctx), settings
