"""Background recheck scheduling using lightweight asyncio tasks.

After a resubmission we poll EX quarantine for the ``_RA`` re-quarantine. Absence
only means "passed/delivered" once EX has had time to finish analysis, so we poll
up to ``recheck_max_attempts`` times before the FlowEngine concludes DONE_PASSED.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)

#: Fallback eager ramp if recheck_ramp is blank/unparseable (seconds after the first poll).
_DEFAULT_RAMP = [2, 2, 3, 3, 5, 5, 8]


def _parse_ramp(spec: str) -> list[int]:
    """Parse the comma-separated recheck_ramp (e.g. "2,2,3,3,5,5,8") into positive
    second-delays. Bad/blank input falls back to a sane eager default."""
    steps = []
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except ValueError:
            continue
        if n > 0:
            steps.append(n)
    return steps or list(_DEFAULT_RAMP)


class RecheckScheduler:
    def __init__(self):
        self._engine = None  # bound after the FlowEngine is built (avoids a cycle)
        self._tasks: set[asyncio.Task] = set()

    def bind(self, engine) -> None:
        self._engine = engine

    def schedule_recheck(self, case_id: str) -> None:
        task = asyncio.create_task(self._poll(case_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def schedule_resubmit(self, case_id: str) -> None:
        """Run the EX rescan for a case in the background (decoupled from the
        recipient's password submission)."""
        task = asyncio.create_task(self._engine.resubmit_case(case_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def start_resubmit_retrier(self) -> None:
        """Periodic background sweep that re-attempts failed EX resubmissions."""
        task = asyncio.create_task(self._resubmit_loop())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _resubmit_loop(self) -> None:
        while True:
            await asyncio.sleep(max(30, self._engine.settings.resubmit_retry_interval))
            try:
                await self._engine.retry_failed_resubmissions()
            except Exception:
                log.exception("resubmit retry sweep failed")

    def start_notify_retrier(self) -> None:
        """Periodic background sweep that re-sends emails for NOTIFY_FAILED cases."""
        task = asyncio.create_task(self._notify_loop())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def start_reconcile(self) -> None:
        """Startup backfill of alerts missed while down, then an optional periodic sweep."""
        task = asyncio.create_task(self._reconcile_loop())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _reconcile_loop(self) -> None:
        await asyncio.sleep(5)  # let startup settle before the first EX query
        try:
            await self._engine.reconcile()  # backfill anything missed while down
        except Exception:
            log.exception("startup reconcile failed")
        while True:
            interval = self._engine.settings.reconcile_interval
            if interval <= 0:  # periodic sweep disabled — poll the setting in case it changes
                await asyncio.sleep(300)
                continue
            await asyncio.sleep(max(60, interval))
            try:
                await self._engine.reconcile()
            except Exception:
                log.exception("reconcile sweep failed")

    def start_loop(self, coro) -> None:
        """Run an arbitrary long-lived coroutine as a tracked background task."""
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _notify_loop(self) -> None:
        while True:
            await asyncio.sleep(max(30, self._engine.settings.notify_retry_interval))
            try:
                await self._engine.retry_failed_notifications()
            except Exception:  # never let the sweep die
                log.exception("notify retry sweep failed")

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()

    async def _poll(self, case_id: str) -> None:
        s = self._engine.settings  # read live so settings changes apply
        interval = max(3, s.recheck_interval)
        # Eager backoff: a released/clean email sends no push, so poll rapidly at first to
        # catch the release (the original queue id leaving quarantine) within seconds, then
        # settle to recheck_interval. Held emails usually resolve even sooner via the _RA push.
        # ramp = first delay (recheck_delay) + the configurable early steps (recheck_ramp).
        ramp = [max(1, s.recheck_delay), *_parse_ramp(s.recheck_ramp)]
        delays = ramp + [interval] * max(0, s.recheck_max_attempts - len(ramp))
        for i, delay in enumerate(delays):
            await asyncio.sleep(delay)
            final = i == len(delays) - 1
            try:
                if await self._engine.recheck(case_id, final=final):
                    return
            except Exception:  # transient EX/network error — keep polling
                log.exception("recheck failed for case %s", case_id)
