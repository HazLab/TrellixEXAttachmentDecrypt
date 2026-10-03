# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

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

#: Sweep idle keys every this many ``allow()`` calls, and never track more than
#: ``_MAX_KEYS`` — an attacker can mint unlimited keys (e.g. random link tokens),
#: so memory use must not grow with the number of distinct keys seen.
_SWEEP_EVERY = 1024
_MAX_KEYS = 50_000


def client_ip(request: Request, trust_forwarded_for: bool = False) -> str:
    """Best-effort client IP. Behind a reverse proxy the socket peer is the proxy,
    so when ``trust_forwarded_for`` is set we take the **right-most** X-Forwarded-For
    entry — the one our own proxy appended. Anything to its left was supplied by the
    client and is spoofable, so it must not key a rate limit. (One proxy hop is the
    deployment model.) Off by default: the header must not be trusted at all unless
    the deployment actually sits behind a proxy that sets it."""
    if trust_forwarded_for:
        fwd = request.headers.get("x-forwarded-for", "")
        last = fwd.split(",")[-1].strip()
        if last:
            return last
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
        self._calls = 0

    def allow(self, key: str, now: float) -> bool:
        self._calls += 1
        if self._calls % _SWEEP_EVERY == 0 or len(self._hits) >= _MAX_KEYS:
            self._sweep(now)
        hits = self._hits[key]
        cutoff = now - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def _sweep(self, now: float) -> None:
        """Drop keys whose newest hit has left the window; if still over the cap,
        shed the least-recently-hit keys."""
        cutoff = now - self.window
        for key in [k for k, hits in self._hits.items() if not hits or hits[-1] <= cutoff]:
            del self._hits[key]
        excess = len(self._hits) - int(_MAX_KEYS * 0.9)  # shed 10% so we don't re-sort per call
        if len(self._hits) >= _MAX_KEYS:
            for key in sorted(self._hits, key=lambda k: self._hits[k][-1])[:excess]:
                del self._hits[key]

    def reset(self, key: str | None = None) -> None:
        """Clear one key (e.g. after a successful login) or all keys."""
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)
