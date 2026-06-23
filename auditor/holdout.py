#!/usr/bin/env python3
"""auditor/holdout.py — the leave-one-out held-out evaluation: build N stochastic reps of every
(function × candidate-strategy) cell for the held-out repo, then SIMULATE the three arms over those
recorded outcomes (zero extra spend, full variance bands, no budget-rigging).

Why simulate instead of running each arm live: coverage depends only on the per-(function,strategy)
gate outcome. Record N independent reps of each cell once, and every arm is a deterministic function
of those samples — so Arm1/Arm2/Arm3 are compared on the SAME stochastic draws (the cleanest possible
A/B), and the coverage-vs-budget curve falls out for free. rep j is one "run of the world": within a
walk we try the arm's strategy order up to budget K, taking each strategy's rep-j sample; the function
is covered in walk j iff any tried strategy greened at rep j. N reps -> N coverage samples per arm ->
mean +/- spread.

Arms (author MODEL is fixed across all three — only the retry ORDER differs; Opus does NOT author):
  Arm1 baseline     : K=1, the default strategy (value for deterministic, stubbed_seam otherwise).
  Arm2 blind retry  : budget K, candidate strategies in the FIXED ladder order, stop at green.
  Arm3 recall retry : budget K, candidate strategies in RECALL-recommended order (excluding the
                      held-out repo's own rows), stop at green.
recall is PROVEN iff Arm3 > Arm2 > top of Arm1's variance band. Arm3 ~= Arm2 => the ladder won, not
recall (reported honestly). Coverage = gate-GREEN = non-vacuity, NOT correctness.
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
import coverage_exp as ce  # noqa: E402
from recall_strategy import (  # noqa: E402
    LADDER_ORDER, StrategyRecall, candidate_strategies, shape_key,
)

DEFAULT_REPS = 5
DEFAULT_BUDGET_K = 2


# ---------------------------------------------------------------- cell construction


def build_holdout_cells(funcs: list[dict], repo: str, reps: int = DEFAULT_REPS) -> list[ce.Cell]:
    """Every (function × candidate-strategy × rep) cell for the held-out repo."""
    cells: list[ce.Cell] = []
    for f in funcs:
        for strat in candidate_strategies(f):
            for rep in range(reps):
                cells.append(ce.Cell(repo=repo, entry=f, strategy=strat, rep=rep))
    return cells


# ---------------------------------------------------------------- PURE arm simulation


def outcomes_from_results(results: list[ce.CellResult]) -> dict[str, dict[str, dict[int, bool]]]:
    """results -> outcomes[qualname][strategy][rep] = gate_green. A missing/errored cell simply
    isn't present; the simulator treats an absent (strategy,rep) as a non-cover (conservative)."""
    out: dict[str, dict[str, dict[int, bool]]] = {}
    for r in results:
        out.setdefault(r.qualname, {}).setdefault(r.strategy, {})[r.rep] = bool(r.gate_green)
    return out


def _covered_in_walk(order: list[str], outcomes_fn: dict[str, dict[int, bool]], rep: int,
                     budget_k: int) -> bool:
    """One stochastic walk: try the first `budget_k` strategies of `order`, each at sample `rep`;
    covered iff any greened. Absent samples count as RED."""
    for strat in order[:budget_k]:
        if outcomes_fn.get(strat, {}).get(rep, False):
            return True
    return False


def _arm_order(arm: str, entry: dict, recall: StrategyRecall | None, held_out_repo: str) -> list[str]:
    cands = candidate_strategies(entry)
    if arm == "baseline":
        return cands[:1]
    if arm == "blind":
        return [s for s in LADDER_ORDER if s in cands]
    if arm == "recall":
        assert recall is not None
        return recall.recommend_order(shape_key(entry), cands, exclude_repo=held_out_repo)
    raise ValueError(arm)


def _arm_budget(arm: str, budget_k: int) -> int:
    return 1 if arm == "baseline" else budget_k


def simulate_arm(arm: str, funcs: list[dict], outcomes: dict, recall: StrategyRecall | None,
                 held_out_repo: str, *, reps: int, budget_k: int) -> dict:
    """Per-rep coverage for one arm (mean over functions), plus mean/spread over reps and the K=inf
    ceiling. Pure: a function of the recorded outcomes + the arm's ordering policy only."""
    k = _arm_budget(arm, budget_k)
    per_rep: list[float] = []
    ceiling_per_rep: list[float] = []
    for rep in range(reps):
        covered = 0
        ceil = 0
        for f in funcs:
            order = _arm_order(arm, f, recall, held_out_repo)
            ofn = outcomes.get(f["qualname"], {})
            covered += int(_covered_in_walk(order, ofn, rep, k))
            ceil += int(_covered_in_walk(order, ofn, rep, len(order)))
        n = len(funcs) or 1
        per_rep.append(covered / n)
        ceiling_per_rep.append(ceil / n)
    return {
        "arm": arm, "budget_k": k, "reps": reps, "n_functions": len(funcs),
        "coverage_per_rep": per_rep,
        "coverage_mean": statistics.mean(per_rep) if per_rep else 0.0,
        "coverage_lo": min(per_rep) if per_rep else 0.0,
        "coverage_hi": max(per_rep) if per_rep else 0.0,
        "coverage_stdev": statistics.pstdev(per_rep) if len(per_rep) > 1 else 0.0,
        "ceiling_mean": statistics.mean(ceiling_per_rep) if ceiling_per_rep else 0.0,
    }


def simulate_all_arms(funcs: list[dict], outcomes: dict, recall: StrategyRecall, held_out_repo: str,
                      *, reps: int = DEFAULT_REPS, budget_k: int = DEFAULT_BUDGET_K) -> dict:
    arms = {a: simulate_arm(a, funcs, outcomes, recall, held_out_repo, reps=reps, budget_k=budget_k)
            for a in ("baseline", "blind", "recall")}
    b1, b2, b3 = arms["baseline"], arms["blind"], arms["recall"]
    verdict = {
        "arm3_gt_arm2": b3["coverage_mean"] > b2["coverage_mean"],
        "arm2_gt_arm1_band": b2["coverage_mean"] > b1["coverage_hi"],
        "recall_proven": (b3["coverage_mean"] > b2["coverage_mean"]
                          and b2["coverage_mean"] > b1["coverage_hi"]),
        "arm3_minus_arm2": round(b3["coverage_mean"] - b2["coverage_mean"], 4),
        "ladder_only": abs(b3["coverage_mean"] - b2["coverage_mean"]) < 1e-9,
    }
    return {"held_out_repo": held_out_repo, "budget_k": budget_k, "reps": reps,
            "arms": arms, "verdict": verdict}


# ---------------------------------------------------------------- live driver (spend)


async def run_holdout(manifest_path: Path, repo: str, run_dir: Path, model: str, recall_db: Path,
                      *, reps: int = DEFAULT_REPS, budget_k: int = DEFAULT_BUDGET_K,
                      concurrency: int = 24, budget_cap: float | None = None,
                      include_nondeterministic: bool = True, func_limit: int = 0) -> dict:
    funcs = ce.load_manifest_functions(manifest_path, include_nondeterministic=include_nondeterministic)
    if func_limit:  # cap for wall-clock; the same capped set drives cells AND the arm simulation
        funcs = funcs[:func_limit]
    target = json.loads(manifest_path.read_text()).get("target", repo)
    cells = build_holdout_cells(funcs, repo, reps=reps)
    print(f"held-out {repo}: {len(funcs)} functions × strategies × {reps} reps = {len(cells)} cells",
          flush=True)
    await ce.run_cells(cells, model, run_dir, target_of={repo: target}, concurrency=concurrency,
                       budget_cap=budget_cap, progress_label=f"holdout-{repo}")
    results = [r for r in ce.load_cell_results(run_dir) if r.repo == repo]
    outcomes = outcomes_from_results(results)
    recall = StrategyRecall(recall_db)
    report = simulate_all_arms(funcs, outcomes, recall, repo, reps=reps, budget_k=budget_k)
    report["generated_ts"] = time.time()
    ce._atomic_write_json(run_dir / "holdout_report.json", report)
    ce._atomic_write_json(run_dir / "holdout_outcomes.json",
                          {q: {s: {str(rp): g for rp, g in d.items()} for s, d in by.items()}
                           for q, by in outcomes.items()})
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="held-out 3-arm coverage evaluation")
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--repo", required=True, help="held-out repo name (must match recall rows)")
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--recall-db", type=Path, required=True)
    ap.add_argument("--model", default="deepseek-v4-pro")
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS)
    ap.add_argument("--budget-k", type=int, default=DEFAULT_BUDGET_K)
    ap.add_argument("--concurrency", type=int, default=24)
    ap.add_argument("--budget-cap", type=float, default=None)
    ap.add_argument("--func-limit", type=int, default=0, help="cap held-out functions (0 = all)")
    args = ap.parse_args()
    report = asyncio.run(run_holdout(args.manifest, args.repo, args.run_dir, args.model,
                                     args.recall_db, reps=args.reps, budget_k=args.budget_k,
                                     concurrency=args.concurrency, budget_cap=args.budget_cap,
                                     func_limit=args.func_limit))
    print(json.dumps(report["verdict"], indent=2))
    for a, d in report["arms"].items():
        print(f"  {a:9} K={d['budget_k']} coverage {d['coverage_mean']:.3f} "
              f"[{d['coverage_lo']:.3f}..{d['coverage_hi']:.3f}] ceiling {d['ceiling_mean']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
