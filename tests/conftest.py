"""Shared fixtures: in-memory repo-backed engine with fake EX/mailer/scheduler."""

from __future__ import annotations

import pytest

from trellix_decrypt.config import Settings
from trellix_decrypt.context import AppContext
from trellix_decrypt.domain import FlowEngine, QuarantineOutcome, RiskwareRules, TokenService
from trellix_decrypt.settings_store import SettingsStore
from trellix_decrypt.storage import CaseRepository, build_session_factory

# Encrypted-attachment custom-policy malware name.
TRIGGER_MALWARE_NAME = "CustomPolicy.MVX.zip"


def make_settings(**overrides) -> Settings:
    base = dict(
        ex_base_url="https://ex.test", ex_username="u", ex_password="p",
        smtp_host="smtp.test", public_base_url="https://decrypt.test",
        secret_key="test-secret", webhook_username="exuser", webhook_password="expass",
        trigger_alert_name="RISKWARE_OBJECT",
        trigger_malware_names=[TRIGGER_MALWARE_NAME],
        max_password_attempts=3,
        recheck_delay=0, recheck_interval=0, recheck_max_attempts=3,
        db_url="sqlite://",  # in-memory
    )
    base.update(overrides)
    return Settings(**base)


class FakeEX:
    def __init__(self, outcomes=None):
        self.rescanned = []
        self.outcomes = list(outcomes or [])

    async def current_queue_id(self, queue_id):
        return queue_id

    async def rescan(self, queue_id, passwords):
        self.rescanned.append((queue_id, passwords))
        return {}

    async def classify_resubmission(self, queue_id, recipient, rules):
        return self.outcomes.pop(0) if self.outcomes else QuarantineOutcome.NOT_QUARANTINED

    async def aclose(self):
        pass


class FakeMailer:
    def __init__(self):
        self.sent = []
        self.fail = False

    async def send_password_request(self, recipient, link, case, retry=False):
        if self.fail:
            raise RuntimeError("smtp boom")
        self.sent.append((recipient, link, retry))


class FakeScheduler:
    def __init__(self):
        self.scheduled = []

    def bind(self, engine):
        self.engine = engine

    def schedule_recheck(self, case_id):
        self.scheduled.append(case_id)

    def start_notify_retrier(self):
        pass

    async def shutdown(self):
        pass


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def engine(settings):
    repo = CaseRepository(build_session_factory(settings.db_url))
    ex, mailer, scheduler = FakeEX(), FakeMailer(), FakeScheduler()
    eng = FlowEngine(repo, ex, mailer, TokenService(settings.secret_key, settings.token_ttl),
                     RiskwareRules(settings.trigger_malware_names, settings.trigger_alert_name), settings, scheduler)
    scheduler.bind(eng)
    return eng


def make_context(ex=None, **setting_overrides):
    """Build an AppContext wired with fakes, for web-layer tests."""
    settings = make_settings(**setting_overrides)
    session_factory = build_session_factory(settings.db_url)
    repo = CaseRepository(session_factory)
    store = SettingsStore(settings, session_factory)
    scheduler = FakeScheduler()
    engine = FlowEngine(repo, ex or FakeEX(), FakeMailer(),
                        TokenService(settings.secret_key, settings.token_ttl),
                        RiskwareRules(settings.trigger_malware_names, settings.trigger_alert_name),
                        settings, scheduler)
    return AppContext(settings, store, repo, scheduler, engine=engine)
