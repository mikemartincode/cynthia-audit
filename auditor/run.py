#!/usr/bin/env python3
"""auditor/run.py — fan the A02 author+gate worker across every auditable function,
with bounded concurrency and a HARD spend cap.

Two pools, matched to the two workloads:
  * authoring is I/O-bound (a gateway call idles 1-3 min) -> asyncio.to_thread under a
    semaphore of AUTHOR_CONCURRENCY (default 32; the gateway handles ~64).
  * gating is subprocess-bound (one subprocess per mutant) -> ProcessPoolExecutor sized
    cpu_count()-2, so gate storms never oversubscribe the box or block the event loop.
The per-function retry-on-RED loop (author -> gate -> author...) is orchestrated in async
land: each attempt's authoring call holds the author semaphore, each gate run a pool slot.

Budget is a hard rail, not advisory: before EVERY authoring dispatch the tracker checks
spent + reserved-in-flight + estimate <= cap and stops dispatching when the next call could
cross it. Dropped functions are LOGGED, never silently truncated. Cumulative spend comes
from real response usage tokens x gateway rates.

Resume: one record file per function (results/<run>/records/<safe>.json); a re-run with
--run-dir skips functions that already have a record, so a budget stop is resumable.

Usage:
    python auditor/run.py --manifest targets/hyperlink/manifest.json \
        --model deepseek-v4-pro [--limit N] [--run-dir results/<id>] [--concurrency 32]

Env: LITELLM_GATEWAY, LITELLM_KEY (required); AUDIT_BUDGET_USD (default 50).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
from author import (  # noqa: E402
    DEFAULT_ATTEMPTS, DEFAULT_MAX_TOKENS, ResultRecord, _normalize_verdict, _safe_leaf,
    build_prompt, gate_authored,
)

# conservative per-call estimate used only BEFORE a model's first real cost lands;
# afterwards the tracker uses the max cost actually observed for the model.
EST_FIRST_CALL_USD = 0.10


class BudgetTracker:
    """Single-threaded (event-loop-confined) hard spend rail.

    reserve() is called BEFORE an authoring dispatch: it answers whether the call may
    proceed without risking the cap, counting both real spend and in-flight reservations.
    settle() swaps a reservation for the real cost from response usage."""

    def __init__(self, cap_usd: float):
        self.cap = cap_usd
        self.spent = 0.0
        self.reserved = 0.0
        self.max_seen = 0.0
        self.stopped = False

    def estimate(self) -> float:
        return self.max_seen if self.max_seen > 0 else EST_FIRST_CALL_USD

    def reserve(self) -> float | None:
        est = self.estimate()
        if self.spent + self.reserved + est > self.cap:
            self.stopped = True
            return None
        self.reserved += est
        return est

    def settle(self, reservation: float, real_cost: float) -> None:
        self.reserved -= reservation
        self.spent += real_cost
        self.max_seen = max(self.max_seen, real_cost)


async def _author_one_attempt(entry: dict, model: str, spec: str, contract: str,
                              module_name: str, oracles_dir: Path, max_tokens: int,
                              sem: asyncio.Semaphore, budget: BudgetTracker) -> dict | None:
    """One budget-gated authoring call. None => budget exhausted (do not retry)."""
    reservation = budget.reserve()
    if reservation is None:
        return None
    try:
        async with sem:
            r = await asyncio.to_thread(author_mod.call_model, model,
                                        author_mod.SYSTEM_PROMPT, spec + "\n" + contract,
                                        max_tokens=max_tokens)
    except Exception as exc:  # noqa: BLE001 — gateway failure is a RED attempt, not a crash
        budget.settle(reservation, 0.0)
        return {"error": f"{type(exc).__name__}: {exc}"}
    budget.settle(reservation, r["cost"])
    (oracles_dir / f"{module_name}.py").write_text(r["code"])
    (oracles_dir / f"{module_name}_raw.txt").write_text(r["raw"])
    return r


async def process_function(entry: dict, model: str, run_dir: Path, target: str,
                           sem: asyncio.Semaphore, gate_pool: ProcessPoolExecutor,
                           budget: BudgetTracker, *, attempts: int = DEFAULT_ATTEMPTS,
                           max_tokens: int = DEFAULT_MAX_TOKENS,
                           gate_cap: int = 40) -> ResultRecord | None:
    """The async twin of author.author_and_gate: same retry-on-RED loop, but the authoring
    call is budget-gated + semaphore-bounded and the gate runs in the process pool.
    Returns None iff the budget stopped this function before its first authoring call."""
    t0 = time.time()
    qhash = hashlib.sha1(entry["qualname"].encode()).hexdigest()[:10]
    oracles_dir = run_dir / "oracles" / f"{_safe_leaf(entry['qualname'])}_{qhash}"
    oracles_dir.mkdir(parents=True, exist_ok=True)
    spec, contract = build_prompt(entry, target=target)
    rec = ResultRecord(qualname=entry["qualname"], model=model)
    loop = asyncio.get_running_loop()

    for n in range(1, attempts + 1):
        module_name = f"orc_{qhash}_a{n}"
        r = await _author_one_attempt(entry, model, spec, contract, module_name,
                                      oracles_dir, max_tokens, sem, budget)
        if r is None:  # budget wall
            if n == 1:
                return None
            rec.attempt_log.append({"attempt": n, "error": "budget exhausted mid-retry"})
            break
        rec.attempts = n
        if "error" in r:
            rec.attempt_log.append({"attempt": n, "error": r["error"]})
            rec.gate = _normalize_verdict(author_mod._Broken(f"author call failed: {r['error']}"))
            continue
        rec.cost += r["cost"]
        rec.tokens["in"] += r["in_tok"]
        rec.tokens["out"] += r["out_tok"]
        rec.oracle_path = str(oracles_dir / f"{module_name}.py")
        rec.gate = await loop.run_in_executor(gate_pool, _gate_in_pool,
                                              module_name, str(oracles_dir), gate_cap)
        rec.attempt_log.append({"attempt": n, "green": rec.gate["green"],
                                "kill_rate": rec.gate["kill_rate"], "note": rec.gate["note"],
                                "out_tok": r["out_tok"], "cost": round(r["cost"], 6),
                                "elapsed": r["elapsed"]})
        if rec.gate["green"]:
            break
    rec.elapsed = time.time() - t0
    return rec


def _gate_in_pool(module_name: str, oracles_dir: str, cap: int) -> dict:
    """Picklable wrapper for the process pool."""
    return gate_authored(module_name, Path(oracles_dir), cap=cap)


def _record_path(records_dir: Path, qualname: str) -> Path:
    return records_dir / (re.sub(r"\W", "_", qualname) + ".json")


async def run_audit(manifest: dict, model: str, run_dir: Path, *, limit: int = 0,
                    concurrency: int = 32, attempts: int = DEFAULT_ATTEMPTS,
                    gate_cap: int = 40) -> dict:
    records_dir = run_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    target = manifest.get("target", "")

    todo = [f for f in manifest["functions"]
            if f["deterministic"] and f["auditability"] != "none"]
    if limit:
        todo = todo[:limit]
    skipped_existing = [f for f in todo if _record_path(records_dir, f["qualname"]).exists()]
    todo = [f for f in todo if not _record_path(records_dir, f["qualname"]).exists()]

    budget = BudgetTracker(float(os.environ.get("AUDIT_BUDGET_USD", "50")))
    sem = asyncio.Semaphore(concurrency)
    # asyncio.to_thread uses the loop's default executor, whose default size
    # (min(32, cpu+4)) would silently cap authoring below the declared concurrency.
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=concurrency + 4))
    workers = max(2, (os.cpu_count() or 4) - 2)
    done = 0
    dropped: list[str] = []
    t0 = time.time()

    with ProcessPoolExecutor(max_workers=workers) as gate_pool:
        async def one(entry: dict) -> None:
            nonlocal done
            rec = await process_function(entry, model, run_dir, target, sem, gate_pool,
                                         budget, attempts=attempts, gate_cap=gate_cap)
            if rec is None:
                dropped.append(entry["qualname"])
                return
            _record_path(records_dir, entry["qualname"]).write_text(
                json.dumps(rec.to_dict(), indent=2) + "\n")
            done += 1
            print(f"[{done}/{len(todo)}] {entry['qualname']}: green={rec.green} "
                  f"attempts={rec.attempts} ${rec.cost:.4f} | spent ${budget.spent:.2f} "
                  f"of ${budget.cap:.2f}", flush=True)

        await asyncio.gather(*(one(e) for e in todo))

    summary = {
        "model": model, "run_dir": str(run_dir), "elapsed_s": round(time.time() - t0, 1),
        "eligible": len(todo) + len(skipped_existing),
        "resumed_skips": [f["qualname"] for f in skipped_existing],
        "completed": done,
        "green": sum(1 for f in todo
                     if _record_path(records_dir, f["qualname"]).exists()
                     and json.loads(_record_path(records_dir, f["qualname"]).read_text())["green"]),
        "budget_cap_usd": budget.cap, "spent_usd": round(budget.spent, 4),
        "budget_stopped": budget.stopped, "dropped_by_budget": dropped,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="parallel author+gate audit run")
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--model", default="deepseek-v4-pro")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--run-dir", type=Path, default=None)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    ap.add_argument("--gate-cap", type=int, default=40)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text())
    run_dir = args.run_dir or Path("results") / f"run-{time.strftime('%Y%m%d-%H%M%S')}"
    summary = asyncio.run(run_audit(manifest, args.model, run_dir, limit=args.limit,
                                    concurrency=args.concurrency, attempts=args.attempts,
                                    gate_cap=args.gate_cap))
    print(json.dumps(summary, indent=2))
    if summary["budget_stopped"]:
        print(f"BUDGET STOP: dropped {len(summary['dropped_by_budget'])} functions "
              f"(re-run with --run-dir {summary['run_dir']} to resume)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
