"""Token expiry / auto-reissue behavior."""

from __future__ import annotations

import pytest

from trellix_decrypt.domain import AlertEvent, FlowState, TokenService

from .conftest import make_settings
from .conftest import FakeEX, FakeMailer, FakeScheduler  # noqa: F401  (fixtures use engine)


def test_peek_accepts_expired_but_rejects_tampered():
    svc = TokenService("secret", ttl=-1)  # negative ttl -> always expired
    token = svc.mint("case-1")
    assert svc.verify(token) is None          # expired
    assert svc.peek(token) == "case-1"        # still readable (valid signature)
    assert svc.peek(token + "x") is None       # tampered


async def test_expired_link_reissues_when_awaiting(engine):
    # Force an already-expired token service on the engine.
    engine.tokens = TokenService(engine.settings.secret_key, ttl=-1)
    case = engine.repo.get_or_create_case(AlertEvent(
        queue_id="Q1", recipients=["u@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    engine.repo.set_state(case, FlowState.AWAITING_PASSWORD, "sent")
    token = engine.tokens.mint(case.id)

    reissued = await engine.reissue_expired_link(token)
    assert reissued is not None
    assert len(engine.mailer.sent) == 1        # a fresh link was emailed


async def test_expired_link_not_reissued_when_not_awaiting(engine):
    engine.tokens = TokenService(engine.settings.secret_key, ttl=-1)
    case = engine.repo.get_or_create_case(AlertEvent(
        queue_id="Q2", recipients=["u@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    engine.repo.set_state(case, FlowState.DONE_PASSED, "done")
    token = engine.tokens.mint(case.id)
    assert await engine.reissue_expired_link(token) is None


async def test_submission_tolerates_just_expired_token(engine):
    engine.tokens = TokenService(engine.settings.secret_key, ttl=-1)
    case = await engine.handle_alert(AlertEvent(
        queue_id="Q3", recipients=["u@corp.test"], alert_name="RISKWARE_OBJECT",
        malware_names=["CustomPolicy.MVX.zip"]))
    token = engine.tokens.mint(case.id)
    _, status = await engine.handle_password(token, "pw")  # token already expired
    assert status == "ok"                                   # still accepted (state-gated)
