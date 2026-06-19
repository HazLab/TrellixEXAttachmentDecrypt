"""Shared fixtures: in-memory repo-backed engine with fake EX/mailer/scheduler."""

from __future__ import annotations

import pytest

from trellix_decrypt.config import Settings
from trellix_decrypt.context import AppContext
from trellix_decrypt.domain import FlowEngine, RiskwareRules, TokenService
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
    def __init__(self, ra_quarantined=False):
        self.rescanned = []
        self.rescan_fail = False
        self.rescan_not_found = False  # simulate EX "email not quarantined" (400)
        self.ra_quarantined = ra_quarantined  # backstop: an _RA entry still in quarantine

    async def rescan_target(self, queue_id, sender=None, subject=None):
        return queue_id, f"uuid-{queue_id}"

    async def rescan(self, target_id, passwords):
        if self.rescan_not_found:
            exc = RuntimeError("EX 400: Could not find quarantined email")
            exc.not_found = True
            raise exc
        if self.rescan_fail:
            raise RuntimeError("EX 400: insufficient authorization")
        self.rescanned.append((target_id, passwords))
        return {}

    async def has_resubmission_quarantine(self, queue_id, sender=None, subject=None):
        return self.ra_quarantined

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
        self.resubmits = []

    def bind(self, engine):
        self.engine = engine

    def schedule_recheck(self, case_id):
        self.scheduled.append(case_id)

    def schedule_resubmit(self, case_id):
        self.resubmits.append(case_id)

    def start_resubmit_retrier(self):
        pass

    def start_notify_retrier(self):
        pass

    def start_loop(self, coro):
        coro.close()  # don't run it in tests; avoid 'coroutine never awaited'

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
