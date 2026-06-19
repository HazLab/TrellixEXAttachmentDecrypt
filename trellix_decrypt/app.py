"""Composition root: build settings, wire every layer, return the FastAPI app."""

from __future__ import annotations

import logging

from .config import Settings
from .context import AppContext
from .recheck import RecheckScheduler
from .settings_store import SettingsStore
from .storage import CaseRepository, build_session_factory
from .web import create_app


def build_context(settings: Settings) -> AppContext:
    session_factory = build_session_factory(settings.db_url)
    repo = CaseRepository(session_factory)
    store = SettingsStore(settings, session_factory)
    scheduler = RecheckScheduler()
    return AppContext(settings, store, repo, scheduler)


def build(settings: Settings | None = None):
    settings = settings or Settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ctx = build_context(settings)
    eff = ctx.engine.settings
    logging.getLogger(__name__).info(
        "trigger config: alert_name=%r malware_names=%r", eff.trigger_alert_name, eff.trigger_malware_names)
    return create_app(ctx), settings
