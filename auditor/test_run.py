"""No-network proof for auditor/run.py: real parallelism under the declared cap, the hard
budget rail stopping early with a recorded partial run + logged drops, and resume skipping
existing records. call_model is stubbed (zero spend); the mutation gate runs for real.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_run.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import run as run_mod  # noqa: E402
from test_author import ENTRY, GOOD_BATTERY, GOOD_REF  # noqa: E402


class ConcurrencyProbe:
    """Stub gateway: sleeps to force overlap, counts concurrent in-flight calls. Prompt-aware —
    authoring is now TWO independent calls per attempt (reference, then battery), so it returns
    the matching snippet and each function costs 2x `cost`."""

    def __init__(self, cost: float = 0.02, delay: float = 0.4):
        self.cost = cost
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, model, system, user, **kwargs):
        with self._lock:
            self.active += 1
            self.calls += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.delay)
        with self._lock:
            self.active -= 1
        code = GOOD_BATTERY if "BATTERY" in user else GOOD_REF
        return {"code": code, "raw": code, "in_tok": 100, "out_tok": 200,
                "cost": self.cost, "elapsed": self.delay}


def _manifest(n: int) -> dict:
    return {"target": "fixture",
            "functions": [{**ENTRY, "qualname": f"intcmp{i}", "deterministic": True}
                          for i in range(n)]}


def main() -> None:
    real = author_mod.call_model
    try:
        # 1) parallelism: 6 functions, cap 4 -> overlap >= 2, never above the cap
        probe = ConcurrencyProbe()
        author_mod.call_model = probe
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            os.environ["AUDIT_BUDGET_USD"] = "50"
            s = asyncio.run(run_mod.run_audit(_manifest(6), "stub", run_dir,
                                              concurrency=4, attempts=2))
            assert s["completed"] == 6 and s["green"] == 6, s
            assert not s["budget_stopped"] and s["dropped_by_budget"] == [], s
            recs = sorted((run_dir / "records").glob("*.json"))
            assert len(recs) == 6
            costs = [json.loads(p.read_text())["cost"] for p in recs]
            assert abs(s["spent_usd"] - sum(costs)) < 1e-9, (s["spent_usd"], sum(costs))
            assert 2 <= probe.max_active <= 4, probe.max_active
            print(f"parallelism ok: max in-flight {probe.max_active} (cap 4), "
                  f"6/6 green, spent ${s['spent_usd']}")

        # 2) hard budget rail: cap admits ~2 calls; partial run recorded, drops logged
        probe = ConcurrencyProbe(cost=0.02)
        author_mod.call_model = probe
        old_est = run_mod.EST_FIRST_CALL_USD
        run_mod.EST_FIRST_CALL_USD = 0.04  # one ATTEMPT is now 2 calls (ref + battery) x $0.02
        try:
            with tempfile.TemporaryDirectory() as td:
                run_dir = Path(td) / "run"
                os.environ["AUDIT_BUDGET_USD"] = "0.05"
                s = asyncio.run(run_mod.run_audit(_manifest(8), "stub", run_dir,
                                                  concurrency=8, attempts=1))
                assert s["budget_stopped"] is True, s
                # one 2-call attempt (~$0.04) fits under $0.05; the rest are dropped + logged.
                assert s["completed"] == 1 and len(s["dropped_by_budget"]) == 7, s
                assert s["spent_usd"] <= 0.05, s
                assert len(list((run_dir / "records").glob("*.json"))) == 1
                print(f"budget rail ok: stopped at ${s['spent_usd']} of $0.05, "
                      f"1 recorded, {len(s['dropped_by_budget'])} dropped (logged)")

                # 3) resume: same run-dir with budget restored finishes the rest
                os.environ["AUDIT_BUDGET_USD"] = "50"
                s2 = asyncio.run(run_mod.run_audit(_manifest(8), "stub", run_dir,
                                                   concurrency=8, attempts=1))
                assert len(s2["resumed_skips"]) == 1 and s2["completed"] == 7, s2
                assert len(list((run_dir / "records").glob("*.json"))) == 8
                print(f"resume ok: skipped {len(s2['resumed_skips'])} existing, "
                      f"completed remaining {s2['completed']}")
        finally:
            run_mod.EST_FIRST_CALL_USD = old_est
    finally:
        author_mod.call_model = real
        os.environ.pop("AUDIT_BUDGET_USD", None)
    print("test_run: OK")


if __name__ == "__main__":
    main()
