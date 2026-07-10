#!/usr/bin/env python3
"""auditor/bench_authors.py - multi-author CONVERGENCE bench: do M3 and deepseek, run against the same
functions with the gate as the neutral arbiter, COVER MORE TOGETHER than either alone - and at what
output-token / dollar cost.

The robust prior finding this operationalizes: M3 and deepseek green NEAR-DISJOINT sets of functions
(overlap ~1/6 on dateutil), so their UNION ≈ 2× either alone. Author DIVERSITY - not any single
author - is the coverage lever. This bench measures that union directly, plus the two efficiency dials:
  * output tokens  (think-OFF vs think-ON; deepseek reasoning_effort=low; a max_tokens cap),
  * dollars        (M3 is free; deepseek billed - a cost-minimizing CASCADE runs deepseek only on the
                    functions M3 already failed, so the paid model only ever touches the residual).

One UNIT = (function, author-config): author ONE oracle of the function's recall-best shape (single-shape
keeps it ~3× cheaper than the 3-shape ladder AND holds the shape fixed so the author swap is the only
variable), gate it (capped hard-kill subprocess - the SOLE authority; no author approves its own oracle),
record {green, strict, out_tok, cost, wall}. Coverage = gate-GREEN = non-vacuity, NOT correctness.

Per function we run EVERY config, so the same function is authored by each - giving per-config coverage,
the union, pairwise disjointness, the cascade, and exemplar lift (incl. CROSS-MODEL transfer: the
exemplar corpus is deepseek-authored, so an M3 author with exemplar is learning from deepseek's wins).

Resumable: per-function records checkpoint atomically; a hard budget rail stops deepseek cleanly before
a call could cross the cap (M3 cells are free and never consume it).
"""

from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import coverage_exp as ce  # noqa: E402
import exemplar_ab as eab  # noqa: E402 - reuse select_targets (single-shape, LOO exemplars)
from gate_subprocess import _gate_subprocess  # noqa: E402
from recall_strategy import StrategyRecall, shape_key as _shape_key  # noqa: E402
from run import BudgetTracker  # noqa: E402

# The author matrix. thinking: "off"->reasoning OFF; "on"/None-> provider default (M3 reasons, deepseek
# reasons). reasoning_effort is the deepseek output-token dial (M3 ignores it - use thinking there).
# exemplar: inject the LOO same-shape GREEN oracle (augmented generation, #1).
CONFIGS: list[dict] = [
    {"label": "m3_thinkoff",    "model": "minimax-m3",     "thinking": "off", "reasoning_effort": None, "exemplar": False, "free": True},
    {"label": "m3_thinkoff_ex", "model": "minimax-m3",     "thinking": "off", "reasoning_effort": None, "exemplar": True,  "free": True},
    {"label": "m3_thinkon",     "model": "minimax-m3",     "thinking": "on",  "reasoning_effort": None, "exemplar": False, "free": True},
    {"label": "m3_thinkon_ex",  "model": "minimax-m3",     "thinking": "on",  "reasoning_effort": None, "exemplar": True,  "free": True},
    {"label": "deepseek",      "model": "deepseek-v4-pro", "thinking": None,  "reasoning_effort": None, "exemplar": False, "free": False},
    {"label": "deepseek_rlow", "model": "deepseek-v4-pro", "thinking": None,  "reasoning_effort": "low", "exemplar": False, "free": False},
    {"label": "deepseek_ex",   "model": "deepseek-v4-pro", "thinking": None,  "reasoning_effort": None, "exemplar": True,  "free": False},
]


def _thinking_arg(cfg: dict) -> dict | None:
    return {"type": "disabled"} if cfg["thinking"] == "off" else None


def _cell_dir(run_dir: Path, repo: str, qual: str, label: str) -> Path:
    import hashlib
    qh = hashlib.sha1(f"{repo}:{qual}".encode()).hexdigest()[:10]
    return run_dir / "oracles" / f"{author_mod._safe_leaf(qual)}_{qh}_{label}"


async def _run_cell(tgt: dict, strategy: str, cfg: dict, run_dir: Path, *, gate_sem: asyncio.Semaphore,
                    budget: BudgetTracker, max_tokens: int, gate_cap: int, timeout: int = 300) -> dict:
    """Author + gate one (function, config) unit. Never raises; returns a verdict dict. A budget wall
    (deepseek only) returns {budget_stopped}; an author/gateway failure returns {error}; a gate that
    can't render a verdict returns {gate_failed} - none of these is a RED, so the report excludes them."""
    entry, repo = tgt["entry"], tgt["repo"]
    model = cfg["model"]
    exemplar = tgt["exemplars"].get(strategy) if cfg["exemplar"] else None
    if cfg["exemplar"] and not exemplar:
        return {"skipped": "no exemplar"}
    reservation = budget.reserve() if not cfg["free"] else 0.0
    if reservation is None:
        return {"budget_stopped": True}
    t0 = time.time()
    r = await asyncio.to_thread(
        author_mod._author_independent, entry, model, author_mod._battery_model(model),
        target=tgt["target"], max_tokens=max_tokens, shape=strategy, timeout=timeout,
        stream=ce._wants_stream(model), temperature=0.3, thinking=_thinking_arg(cfg),
        reasoning_effort=cfg["reasoning_effort"], exemplar=exemplar,
        trace_meta={"repo": repo, "config": cfg["label"], "strategy": strategy})
    if "error" in r:
        if not cfg["free"]:
            budget.settle(reservation, 0.0)
        return {"error": r["error"], "wall": round(time.time() - t0, 1)}
    if not cfg["free"]:
        budget.settle(reservation, r["cost"])
    cdir = _cell_dir(run_dir, repo, entry["qualname"], cfg["label"])
    cdir.mkdir(parents=True, exist_ok=True)
    mod = f"orc_{cfg['label']}"
    (cdir / f"{mod}.py").write_text(r["code"])
    async with gate_sem:
        verdict = await asyncio.to_thread(_gate_subprocess, mod, str(cdir), gate_cap, entry["qualname"])
    return {"green": bool(verdict.get("green")), "strict_green": bool(verdict.get("strict_green")),
            "gate_failed": bool(verdict.get("gate_failed")), "ref_passes": bool(verdict.get("ref_passes")),
            "out_tok": r["out_tok"], "cost": r["cost"], "wall": round(time.time() - t0, 1),
            "note": verdict.get("note", "")}


def _fn_record_path(run_dir: Path, tgt: dict) -> Path:
    import hashlib
    qh = hashlib.sha1(f"{tgt['repo']}:{tgt['entry']['qualname']}".encode()).hexdigest()[:10]
    return run_dir / "records" / f"{author_mod._safe_leaf(tgt['entry']['qualname'])}_{qh}.json"


async def run_bench(targets: list[dict], configs: list[dict], run_dir: Path, *, concurrency: int,
                    max_tokens: int, gate_cap: int, budget_cap: float, timeout: int = 300,
                    gate_concurrency: int | None = None) -> dict:
    (run_dir / "records").mkdir(parents=True, exist_ok=True)
    pending = [t for t in targets if not _fn_record_path(run_dir, t).exists()]
    budget = BudgetTracker(budget_cap)
    func_sem = asyncio.Semaphore(concurrency)  # function-level => DEPTH-first => verdicts trickle early
    gate_sem = asyncio.Semaphore(gate_concurrency or max(2, (os.cpu_count() or 4) - 2))
    done = {"n": 0}
    t0 = time.time()

    async def one(tgt: dict) -> None:
        async with func_sem:
            strategy = tgt["strategies"][0]  # single-shape: exactly one
            cells: dict[str, dict] = {}
            for cfg in configs:  # configs SEQUENTIAL within a function (bounds in-flight calls to ~concurrency)
                try:
                    cells[cfg["label"]] = await _run_cell(tgt, strategy, cfg, run_dir, gate_sem=gate_sem,
                                                          budget=budget, max_tokens=max_tokens,
                                                          gate_cap=gate_cap, timeout=timeout)
                except Exception as exc:  # noqa: BLE001
                    cells[cfg["label"]] = {"error": f"{type(exc).__name__}: {exc}"}
            rec = {"repo": tgt["repo"], "qualname": tgt["entry"]["qualname"], "strategy": strategy,
                   "shape_key": _shape_key(tgt["entry"]),
                   "exemplar_from": tgt["exemplars"].get(strategy, {}).get("from") if tgt["exemplars"].get(strategy) else None,
                   "cells": cells}
            ce._atomic_write_json(_fn_record_path(run_dir, tgt), rec)
        done["n"] += 1
        greens = [lbl for lbl, c in cells.items() if c.get("green")]
        ce._atomic_write_json(run_dir / "heartbeat.json",
                              {"completed": done["n"], "total": len(pending), "spent": round(budget.spent, 4),
                               "cap": budget.cap, "budget_stopped": budget.stopped,
                               "last_finish": time.time(), "elapsed_s": round(time.time() - t0, 1)})
        print(f"[bench {done['n']}/{len(pending)}] {tgt['repo']}:{tgt['entry']['qualname']} "
              f"[{strategy}] green={greens or '-'} | spent ${budget.spent:.2f}/{budget.cap:.0f}", flush=True)

    await asyncio.gather(*(one(t) for t in pending))
    summary = report(run_dir, [c["label"] for c in configs])
    summary["elapsed_s"] = round(time.time() - t0, 1)
    summary["deepseek_spent_usd"] = round(budget.spent, 4)
    ce._atomic_write_json(run_dir / "summary.json", summary)
    return summary


# ---------------------------------------------------------------- report (pure; re-runnable)


def _clean_green(cell: dict) -> tuple[bool, bool]:
    """(counted, green) for one cell. A cell is COUNTED only if the gate rendered a real verdict; an
    error / gate_failed / budget-stop / skip is NOT a RED and must not depress the denominator."""
    if cell.get("green"):
        return True, True
    if cell.get("error") or cell.get("gate_failed") or cell.get("budget_stopped") or cell.get("skipped"):
        return False, False
    return True, False  # a real RED verdict


def report(run_dir: Path, labels: list[str]) -> dict:
    recs = []
    for p in sorted((run_dir / "records").glob("*.json")):
        try:
            recs.append(json.loads(p.read_text()))
        except Exception:  # noqa: BLE001
            continue
    n = len(recs)
    # per-config coverage (over the functions where THAT config rendered a verdict) + token/cost/wall
    per_config: dict[str, dict] = {}
    green_sets: dict[str, set] = {}
    for lbl in labels:
        counted = green = out_tok = 0
        cost = wall = 0.0
        gs: set[str] = set()
        for r in recs:
            cell = r["cells"].get(lbl, {})
            c, g = _clean_green(cell)
            if c:
                counted += 1
            if g:
                green += 1
                gs.add(f"{r['repo']}:{r['qualname']}")
            out_tok += int(cell.get("out_tok", 0) or 0)
            cost += float(cell.get("cost", 0.0) or 0.0)
            wall += float(cell.get("wall", 0.0) or 0.0)
        green_sets[lbl] = gs
        per_config[lbl] = {"counted": counted, "green": green,
                           "coverage": round(green / counted, 4) if counted else 0.0,
                           "mean_out_tok": round(out_tok / counted) if counted else 0,
                           "total_out_tok": out_tok, "total_cost_usd": round(cost, 4),
                           "mean_wall_s": round(wall / counted, 1) if counted else 0.0}
    # the convergence headline: union over ALL configs, and per-model union
    def union(lbls: list[str]) -> set:
        return set(itertools.chain.from_iterable(green_sets[l] for l in lbls))
    m3 = [l for l in labels if l.startswith("m3")]
    ds = [l for l in labels if l.startswith("deepseek")]
    union_all = union(labels)
    # pairwise disjointness for the two single best authors per family (no-exemplar baseline)
    disjoint = {}
    base_m3 = next((l for l in ("m3_thinkon", "m3_thinkoff") if l in green_sets), m3[0] if m3 else None)
    base_ds = next((l for l in ("deepseek", "deepseek_rlow") if l in green_sets), ds[0] if ds else None)
    if base_m3 and base_ds:
        a, b = green_sets[base_m3], green_sets[base_ds]
        disjoint = {"pair": [base_m3, base_ds], "m3_only": len(a - b), "deepseek_only": len(b - a),
                    "both": len(a & b), "union": len(a | b),
                    "jaccard": round(len(a & b) / len(a | b), 3) if (a | b) else 0.0}
    # cost-minimizing cascade: free authors (M3) first, then each deepseek config runs ONLY on the
    # functions still uncovered - so the paid model's cost is summed over just that residual.
    cascade = []
    prior_covered: set = set()
    ds_spend = 0.0
    for lbl in m3 + ds:  # free authors first, then paid
        if lbl in ds:  # pay deepseek only for functions not already covered by earlier (cheaper) configs
            for r in recs:
                fn = f"{r['repo']}:{r['qualname']}"
                if fn not in prior_covered:
                    ds_spend += float(r["cells"].get(lbl, {}).get("cost", 0.0) or 0.0)
        new = green_sets[lbl] - prior_covered
        prior_covered |= green_sets[lbl]
        cascade.append({"after_adding": lbl, "cumulative_covered": len(prior_covered),
                        "newly_covered": len(new), "cumulative_deepseek_cost_usd": round(ds_spend, 4)})
    return {
        "functions": n,
        "per_config": per_config,
        "union_all_configs": len(union_all),
        "union_m3_only": len(union(m3)), "union_deepseek_only": len(union(ds)),
        "disjointness_m3_vs_deepseek": disjoint,
        "cascade_free_first": cascade,
        "union_functions": sorted(union_all),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="multi-author convergence bench (M3 + deepseek)")
    ap.add_argument("--recall-db", type=Path, default=Path("results/corpus/recall.db"))
    ap.add_argument("--corpus-root", type=Path, default=Path("results/corpus"))
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--all-functions", action="store_true", help="don't restrict to the all-RED hard set")
    ap.add_argument("--configs", default=None,
                    help="comma-sep config labels to include (default: all). e.g. m3_thinkon,deepseek")
    ap.add_argument("--no-deepseek", action="store_true", help="M3 configs only (free)")
    ap.add_argument("--concurrency", type=int, default=3, help="functions in flight (depth-first)")
    ap.add_argument("--gate-concurrency", type=int, default=None, help="concurrent gates (default cpu-2)")
    ap.add_argument("--timeout", type=int, default=300, help="per-call HTTP read timeout (raise for "
                    "high concurrency so ballooned think-ON calls complete instead of timing out)")
    ap.add_argument("--max-tokens", type=int, default=16000, help="output cap (kills reasoning runaway)")
    ap.add_argument("--gate-cap", type=int, default=40)
    ap.add_argument("--budget-cap", type=float, default=5.0, help="hard deepseek $ ceiling")
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()

    configs = list(CONFIGS)
    if args.configs:
        want = set(args.configs.split(","))
        configs = [c for c in CONFIGS if c["label"] in want]
    if args.no_deepseek:
        configs = [c for c in configs if c["free"]]

    if args.report_only:
        print(json.dumps(report(args.run_dir, [c["label"] for c in configs]), indent=2))
        return 0

    args.run_dir.mkdir(parents=True, exist_ok=True)
    qdst = args.run_dir / "queue.json"
    if not qdst.exists():
        shutil.copy(args.corpus_root / "queue.json", qdst)
    recall = StrategyRecall(args.recall_db)
    targets = eab.select_targets(recall, args.run_dir, hard_only=not args.all_functions,
                                 limit=args.limit, exemplar_model=None, single_shape=True)
    print(f"[bench] {len(targets)} functions (single-shape) x {len(configs)} configs "
          f"= {len(targets) * len(configs)} cells | configs={[c['label'] for c in configs]} | "
          f"max_tokens={args.max_tokens} deepseek_cap=${args.budget_cap:.0f}", flush=True)
    summary = asyncio.run(run_bench(targets, configs, args.run_dir, concurrency=args.concurrency,
                                    max_tokens=args.max_tokens, gate_cap=args.gate_cap,
                                    budget_cap=args.budget_cap, timeout=args.timeout,
                                    gate_concurrency=args.gate_concurrency))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
