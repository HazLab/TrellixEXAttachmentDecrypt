"""Sliding-window rate limiter + client-IP resolution."""

from __future__ import annotations

from types import SimpleNamespace

from trellix_decrypt.web.ratelimit import RateLimiter, client_ip


def test_allows_up_to_limit_then_blocks():
    rl = RateLimiter(limit=3, window_seconds=60)
    assert [rl.allow("k", now=t) for t in (0, 1, 2)] == [True, True, True]
    assert rl.allow("k", now=3) is False  # 4th within the window is blocked


def test_window_slides_and_recovers():
    rl = RateLimiter(limit=2, window_seconds=10)
    assert rl.allow("k", now=0) is True
    assert rl.allow("k", now=1) is True
    assert rl.allow("k", now=2) is False       # blocked while both hits are in-window
    assert rl.allow("k", now=11) is True        # first hit (t=0) has rolled off -> allowed again


def test_keys_are_independent():
    rl = RateLimiter(limit=1, window_seconds=60)
    assert rl.allow("a", now=0) is True
    assert rl.allow("b", now=0) is True         # different key, own budget
    assert rl.allow("a", now=0) is False


def test_reset_clears_counter():
    rl = RateLimiter(limit=1, window_seconds=60)
    assert rl.allow("a", now=0) is True
    assert rl.allow("a", now=0) is False
    rl.reset("a")
    assert rl.allow("a", now=0) is True         # as if never hit -> supports login reset-on-success


def _req(host="1.2.3.4", xff=None):
    headers = {"x-forwarded-for": xff} if xff else {}
    return SimpleNamespace(client=SimpleNamespace(host=host), headers=headers)


def test_client_ip_uses_socket_peer_by_default():
    assert client_ip(_req(host="9.9.9.9", xff="1.1.1.1"), trust_forwarded_for=False) == "9.9.9.9"


def test_client_ip_honors_forwarded_when_trusted():
    # The right-most entry is the one our proxy appended; entries to its left are
    # client-supplied and spoofable, so they must not key a rate limit.
    assert client_ip(_req(host="9.9.9.9", xff="1.1.1.1, 2.2.2.2"), trust_forwarded_for=True) == "2.2.2.2"
    assert client_ip(_req(host="9.9.9.9", xff="2.2.2.2"), trust_forwarded_for=True) == "2.2.2.2"


def test_client_ip_falls_back_when_no_forwarded_header():
    assert client_ip(_req(host="9.9.9.9"), trust_forwarded_for=True) == "9.9.9.9"


def test_idle_keys_are_evicted():
    from trellix_decrypt.web import ratelimit
    rl = RateLimiter(limit=5, window_seconds=10)
    for i in range(ratelimit._SWEEP_EVERY - 1):
        rl.allow(f"k{i}", now=0)                 # a flood of one-shot keys (e.g. random tokens)
    rl.allow("fresh", now=100)                   # the sweep runs; every old key has aged out
    assert set(rl._hits) == {"fresh"}


def test_key_count_is_capped(monkeypatch):
    from trellix_decrypt.web import ratelimit
    monkeypatch.setattr(ratelimit, "_MAX_KEYS", 100)
    rl = RateLimiter(limit=5, window_seconds=10_000)
    for i in range(1000):
        rl.allow(f"k{i}", now=i)                 # all still in-window: only the cap can bound it
    assert len(rl._hits) <= 100
