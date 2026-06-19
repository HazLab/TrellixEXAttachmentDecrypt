"""Background recheck scheduling using lightweight asyncio tasks.

After a resubmission we poll EX quarantine for the ``_RA`` re-quarantine. Absence
only means "clean" once EX has had time to finish analysis, so we poll up to
``recheck_max_attempts`` times before the FlowEngine concludes DONE_CLEAN.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


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

    def start_notify_retrier(self) -> None:
        """Periodic background sweep that re-sends emails for NOTIFY_FAILED cases."""
        task = asyncio.create_task(self._notify_loop())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

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
        await asyncio.sleep(s.recheck_delay)
        for attempt in range(s.recheck_max_attempts):
            final = attempt == s.recheck_max_attempts - 1
            try:
                if await self._engine.recheck(case_id, final=final):
                    return
            except Exception:  # transient EX/network error — keep polling
                log.exception("recheck failed for case %s", case_id)
            await asyncio.sleep(s.recheck_interval)
