"""Composition root: build settings, wire every layer, return the FastAPI app."""

from __future__ import annotations

import logging

from .config import Settings
from .domain import FlowEngine, RiskwareRules, TokenService
from .ex_client import EXClient
from .mailer import SMTPMailer
from .recheck import RecheckScheduler
from .storage import CaseRepository, build_session_factory
from .web import create_app


def build_engine(settings: Settings) -> FlowEngine:
    repo = CaseRepository(build_session_factory(settings.db_url))
    ex = EXClient(settings.ex_base_url, settings.ex_username, settings.ex_password, settings.ex_verify_tls)
    mailer = SMTPMailer(settings)
    tokens = TokenService(settings.secret_key, settings.token_ttl)
    rules = RiskwareRules(settings.trigger_rule_ids)
    scheduler = RecheckScheduler(settings)

    engine = FlowEngine(repo, ex, mailer, tokens, rules, settings, scheduler)
    scheduler.bind(engine)
    return engine


def build(settings: Settings | None = None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = settings or Settings()
    engine = build_engine(settings)
    return create_app(engine, settings), settings
