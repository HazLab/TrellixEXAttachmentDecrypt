"""In-memory sliding-window rate limiter for the public-facing POST endpoints.

Deliberately process-local and self-healing: counters live in memory, so they
reset on restart and roll off as their window elapses — there is no permanent
lockout and nothing an operator must manually clear. A single process behind one
reverse proxy is the deployment model; if this ever scales out, swap this for a
shared store (Redis) behind the same ``allow()`` interface.
"""

from __future__ import annotations

from collections import defaultdict, deque

from fastapi import Request


def client_ip(request: Request, trust_forwarded_for: bool = False) -> str:
    """Best-effort client IP. Behind a reverse proxy the socket peer is the proxy,
    so when ``trust_forwarded_for`` is set we take the left-most X-Forwarded-For
    entry the proxy appended. Off by default: a spoofable header must not be
    trusted unless the deployment actually sits behind a proxy that sets it."""
    if trust_forwarded_for:
        fwd = request.headers.get("x-forwarded-for", "")
        first = fwd.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """Fixed-cost sliding-window limiter keyed by an arbitrary string.

    ``allow(key)`` records a hit and returns False once more than ``limit`` hits
    have landed within the trailing ``window_seconds``. Time is injected (``now``)
    so it stays unit-testable without wall-clock — the caller passes a monotonic
    or loop timestamp.
    """

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float) -> bool:
        hits = self._hits[key]
        cutoff = now - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def reset(self, key: str | None = None) -> None:
        """Clear one key (e.g. after a successful login) or all keys."""
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)
