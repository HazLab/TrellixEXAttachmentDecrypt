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
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = settings or Settings()
    ctx = build_context(settings)
    return create_app(ctx), settings
