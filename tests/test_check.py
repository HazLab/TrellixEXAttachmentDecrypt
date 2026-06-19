"""Connectivity check command (respx-mocked EX)."""

from __future__ import annotations

import httpx
import respx

from trellix_decrypt import ex_client as ex
from trellix_decrypt.check import check

from .conftest import make_settings

BASE = "https://ex.test"


def _login(router):
    router.post(BASE + ex.EP_LOGIN).mock(return_value=httpx.Response(200, headers={ex.TOKEN_HEADER: "tok"}))


@respx.mock
async def test_check_passes_when_ex_reachable():
    router = respx.mock
    _login(router)
    router.get(BASE + ex.EP_ALERTS).mock(return_value=httpx.Response(200, json={"alert": []}))
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(200, json=[]))
    assert await check(make_settings()) == 0


@respx.mock
async def test_check_fails_on_auth_error():
    router = respx.mock
    router.post(BASE + ex.EP_LOGIN).mock(return_value=httpx.Response(401))
    router.get(BASE + ex.EP_QUARANTINE).mock(return_value=httpx.Response(401))
    assert await check(make_settings()) == 1
