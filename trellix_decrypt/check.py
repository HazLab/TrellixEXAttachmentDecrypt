"""`trellix-decrypt --check`: validate EX connectivity before wiring the webhook.

Logs in and runs a small alerts + quarantine query against the appliance, using
the effective settings (env defaults overlaid with any UI-saved overrides).
Prints a readable report and returns a process exit code (0 = all OK).
"""

from __future__ import annotations

import asyncio

from .config import Settings
from .domain import iter_alerts
from .ex_client import EXClient
from .settings_store import SettingsStore
from .storage import build_session_factory


async def check(settings: Settings) -> int:
    eff = SettingsStore(settings, build_session_factory(settings.db_url)).effective_settings()
    print(f"Checking EX at {eff.ex_base_url}  (user={eff.ex_username}, verify_tls={eff.ex_verify_tls})")
    ex = EXClient(eff.ex_base_url, eff.ex_username, eff.ex_password, eff.ex_verify_tls, eff.ex_client_token)
    ok = True
    try:
        alerts = await ex.get_alerts(duration="1_hour")
        print(f"  [ok] auth + alerts query — {len(iter_alerts(alerts))} alert(s) in the last hour")
    except Exception as exc:  # noqa: BLE001 — surface any failure to the operator
        ok = False
        print(f"  [FAIL] alerts query: {exc}")
    try:
        quarantined = await ex.list_quarantine()
        print(f"  [ok] quarantine list — {len(quarantined)} quarantined email(s)")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"  [FAIL] quarantine list: {exc}")
    await ex.aclose()
    print("Result:", "all checks passed" if ok else "one or more checks FAILED")
    return 0 if ok else 1


def run_check(settings: Settings | None = None) -> int:
    return asyncio.run(check(settings or Settings()))
