#!/usr/bin/env python3
"""auditor/bakeoff.py - STEP 0: the model bake-off (generalizes seed/deepseek_author.py).

Settles who authors before any basket run. On ONE calibration repo (hyperlink - distinct from the
held-out basket), author a value-shape oracle per function with each candidate model, gate it, and
report per model: gate-GREEN rate, strict-GREEN rate, cost/function, mean latency. The green-rate
sizes the (deferred) Opus tail; the cost/latency picks the primary author. Routed through the REAL
pipeline (coverage_exp cells -> author_and_gate's independent ref+battery, attempts=1) so the numbers
predict the basket, not a toy single-call path.

Also runs a CACHE PREFLIGHT: two different functions authored SEQUENTIALLY for one model; the second
call must report cache_read > 0, proving the static-first prompt assembly makes the passive prefix
cache fire. A zero here means the prefix isn't stable - the cheapest catch of the most expensive
silent mistake (paying full input price hundreds of times).

Decision rule (apply AFTER measuring, report to Mike): M3 near DeepSeek -> M3 primary (free); M3
clearly worse -> DeepSeek primary. The gate is the ONLY trust authority throughout - models author,
never approve.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import coverage_exp as ce  # noqa: E402

DEFAULT_MODELS = ["minimax-m3", "deepseek-v4-pro", "deepseek-v4-flash"]


async def cache_preflight(funcs: list[dict], target: str, run_dir: Path, model: str) -> dict:
    """Verify the static-first prompt makes the passive prefix cache fire. Tiny (max_tokens=40) direct
    calls - this measures caching, not authoring. Three reference calls: A (cold store of system+
    contract+specA), B (a DIFFERENT spec - shares only the static contract prefix), then A again
    (identical to the first). cache_read>0 on B proves the CONTRACT prefix transfers across functions;
    on A-again it proves the cache fired at all. Three calls makes the signal robust to DeepSeek's
    async cache-write propagation delay (which can zero a strict back-to-back A,B pair while the
    real concurrent workload - hundreds of cells over minutes - stays warm)."""
    probe = funcs[:2]
    contract = author_mod._REFERENCE_CONTRACTS["value"]
    specs = [author_mod.build_spec(f, target=target, shape="value") for f in probe]

    def _probe(spec: str) -> int:
        r = author_mod.call_model(model, author_mod.SYSTEM_PROMPT, contract + "\n\n" + spec,
                                  max_tokens=40, temperature=0.0)
        return r.get("cache_read", 0)

    reads = []
    for spec in (specs[0], specs[1] if len(specs) > 1 else specs[0], specs[0]):
        reads.append(await asyncio.to_thread(_probe, spec))
    run_dir.mkdir(parents=True, exist_ok=True)
    return {"model": model, "cache_reads": reads,
            "cache_fires": any(x > 0 for x in reads[1:]),
            "contract_prefix_transfers": reads[1] > 0,
            "note": "calls are [A cold, B diff-spec, A-again]; B>0 => contract prefix shared; "
                    "A-again>0 => cache firing"}


def aggregate_model(results: list[ce.CellResult], model: str) -> dict:
    rs = [r for r in results if r.model == model and not r.error]
    n = len(rs)
    if not n:
        return {"model": model, "n": 0, "note": "no successful cells"}
    green = sum(r.gate_green for r in rs)
    strict = sum(r.strict_green for r in rs)
    return {
        "model": model, "n": n,
        "errors": sum(1 for r in results if r.model == model and r.error),
        "gate_green": green, "gate_green_rate": round(green / n, 4),
        "strict_green": strict, "strict_green_rate": round(strict / n, 4),
        "cost_per_fn": round(sum(r.cost for r in rs) / n, 5),
        "total_cost": round(sum(r.cost for r in rs), 4),
        "mean_latency_s": round(statistics.mean(r.elapsed for r in rs), 1),
        "cache_read_total": sum(r.cache_read for r in rs),
        "cells_cache_hit": sum(1 for r in rs if r.cache_read > 0),
    }


async def run_bakeoff(manifest_path: Path, run_dir: Path, models: list[str], *, limit: int = 30,
                      concurrency: int = 16, budget_cap: float | None = None) -> dict:
    funcs = ce.load_manifest_functions(manifest_path, include_nondeterministic=False)  # value needs pure ref
    funcs = funcs[:limit]
    target = json.loads(manifest_path.read_text()).get("target", "")
    print(f"bake-off on {target}: {len(funcs)} deterministic functions × {len(models)} models "
          f"(value shape, 1 attempt)", flush=True)

    # cache preflight on the first model that uses the gateway prefix cache (deepseek-v4-pro).
    preflight_model = "deepseek-v4-pro" if "deepseek-v4-pro" in models else models[0]
    pf = await cache_preflight(funcs, target, run_dir, preflight_model)
    print(f"CACHE PREFLIGHT [{pf['model']}]: reads={pf['cache_reads']} fires={pf['cache_fires']}",
          flush=True)

    per_model = {}
    for model in models:
        mdir = run_dir / f"model_{model}"
        cells = [ce.Cell(repo=target, entry=f, strategy="value", rep=0) for f in funcs]
        await ce.run_cells(cells, model, mdir, target_of={target: target}, concurrency=concurrency,
                           budget_cap=budget_cap, progress_label=f"bakeoff-{model}")
        results = ce.load_cell_results(mdir)
        per_model[model] = aggregate_model(results, model)
        m = per_model[model]
        print(f"  {model}: gate {m.get('gate_green_rate')} strict {m.get('strict_green_rate')} "
              f"${m.get('cost_per_fn')}/fn lat {m.get('mean_latency_s')}s "
              f"cache_hits {m.get('cells_cache_hit')}/{m.get('n')}", flush=True)

    report = {"calibration_repo": target, "n_functions": len(funcs), "models": models,
              "cache_preflight": pf, "per_model": per_model, "generated_ts": time.time()}
    ce._atomic_write_json(run_dir / "bakeoff_report.json", report)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="model bake-off (step 0)")
    ap.add_argument("--manifest", type=Path, default=Path("targets/hyperlink/manifest.json"))
    ap.add_argument("--run-dir", type=Path, default=Path("results/bakeoff"))
    ap.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--budget-cap", type=float, default=None)
    args = ap.parse_args()
    report = asyncio.run(run_bakeoff(args.manifest, args.run_dir, args.models, limit=args.limit,
                                     concurrency=args.concurrency, budget_cap=args.budget_cap))
    print("\n=== BAKE-OFF ===")
    print(f"{'model':18} {'gate':>6} {'strict':>7} {'$/fn':>9} {'lat(s)':>7} {'cache_hit':>10}")
    for model, m in report["per_model"].items():
        if m.get("n"):
            print(f"{model:18} {m['gate_green_rate']:>6} {m['strict_green_rate']:>7} "
                  f"{m['cost_per_fn']:>9} {m['mean_latency_s']:>7} "
                  f"{m['cells_cache_hit']}/{m['n']:>3}")
    pf = report["cache_preflight"]
    print(f"cache preflight: {pf['model']} reads={pf['cache_reads']} fires={pf['cache_fires']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
