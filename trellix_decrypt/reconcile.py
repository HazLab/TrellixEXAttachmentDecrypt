# Trellix EX Attachment Decrypt
# Developed by Hazem Aljawhari

"""Reconcile: backfill trigger cases missed while the app was down — **quarantine-first**.

The authoritative set of emails that need recovery is what EX is *actually holding*,
so we start from the quarantine list (a riskware rule can alert without quarantining,
so an alerts-only scan risks emailing about already-delivered mail). For each held,
non-``_RA`` entry we have no case for, we confirm the trigger from the entry's own
alerts (fetched by UUID → full malware detail) and start the flow.

A **secondary alerts sweep** then covers the rare held entry whose quarantine record
carries no ``alert_uuids`` linkage: it matches trigger alerts by queue id but only
for emails that are *also in the held set*, so it never fires on alert-but-allow mail.

**Idempotent**: dedups by queue id and skips ``_RA`` re-detections (owned by the
recheck poll), so it is safe to run repeatedly and alongside EX's own notification
retries — never duplicating or re-emailing. The quarantine window is clock-independent
(see ``EXClient.list_held``); ``duration`` bounds only the fallback alerts query.

No I/O of its own: everything goes through the engine's injected collaborators.
"""

from __future__ import annotations

import logging

from .alerts import (
    AlertEvent,
    alert_uuid,
    entry_alert_uuids,
    entry_queue_id,
    iter_alerts,
    parse_alert,
)

log = logging.getLogger(__name__)


async def _trigger_event(engine, entry: dict) -> AlertEvent | None:
    """For a held quarantine entry, fetch its referenced alerts (full detail by UUID)
    and return the first one that matches the trigger rule — the event we'd have gotten
    from the webhook. None if the entry references no matching trigger alert (e.g. a
    malware-object quarantine, or an entry with no ``alert_uuids`` linkage)."""
    for uuid in entry_alert_uuids(entry):
        detail = await engine.ex.get_alert_by_uuid(uuid)
        if not detail:
            continue
        ev = parse_alert(detail)
        if engine.rules.matches(ev):
            return ev
    return None


async def _from_quarantine(engine, held: list[dict], handled: set[str]) -> tuple[int, int]:
    """Primary pass over the held entries. Returns (created, already_known) and adds
    every queue id it created or found a case for to ``handled``."""
    created = already = 0
    for entry in held:
        qid = entry_queue_id(entry)
        if not qid or qid.endswith("_RA") or qid in handled:
            continue
        if engine.repo.find_case_by_queue_id(qid) is not None:
            already += 1
            handled.add(qid)
            continue
        ev = await _trigger_event(engine, entry)
        if ev is None or not ev.recipient:
            log.debug("reconcile skip held queue=%r (no matching trigger alert / recipient)", qid)
            continue  # left unhandled → counted as skipped (the fallback may still catch it)
        handled.add(qid)
        if await engine.handle_alert(ev) is not None:  # creates the case + emails
            created += 1
    return created, already


async def _from_alerts(engine, remaining: set[str], handled: set[str], duration: str) -> int:
    """Fallback alerts sweep, constrained to still-uncreated held emails. Returns the
    number of cases created."""
    try:
        raw = await engine.ex.get_alerts(duration=duration, info_level="extended")
    except Exception:
        log.warning("reconcile: extended alerts query failed, retrying at default level",
                    exc_info=True)
        raw = await engine.ex.get_alerts(duration=duration)
    created = 0
    for a in iter_alerts(raw):
        ev = parse_alert(a)
        if ev.queue_id in handled or ev.queue_id not in remaining:
            continue
        if not ev.malware_names:  # some info_levels trim malware from the list row
            uuid = alert_uuid(a)
            detail = await engine.ex.get_alert_by_uuid(uuid) if uuid else None
            if detail:
                ev = parse_alert(detail)
        if not ev.recipient or not engine.rules.matches(ev):
            continue
        handled.add(ev.queue_id)
        if await engine.handle_alert(ev) is not None:
            created += 1
    return created


async def run_reconcile(engine, duration: str | None = None) -> dict:
    """Run one reconcile pass for ``engine`` (a FlowEngine). Returns the summary
    ``{"held", "created", "already_known", "skipped"}``."""
    if not engine.settings.ex_base_url:
        return {"held": 0, "created": 0, "already_known": 0, "skipped": 0,
                "note": "EX not configured"}
    duration = duration or engine.settings.reconcile_lookback
    handled: set[str] = set()  # candidate queue ids created or confirmed-known this run

    try:
        held = await engine.ex.list_held()
    except Exception:
        log.warning("reconcile: quarantine list failed", exc_info=True)
        held = []
    held_qids = {q for e in held if (q := entry_queue_id(e)) and not q.endswith("_RA")}
    log.info("reconcile: %d held entr(y/ies), %d candidate queue id(s)",
             len(held), len(held_qids))

    created, already = await _from_quarantine(engine, held, handled)
    remaining = held_qids - handled
    if remaining:
        created += await _from_alerts(engine, remaining, handled, duration)

    # Held candidates we neither created nor already had a case for (no confirmable
    # trigger, or missing recipient) — reported for visibility.
    summary = {"held": len(held), "created": created,
               "already_known": already, "skipped": len(held_qids - handled)}
    log.info("reconcile: %s", summary)
    return summary
