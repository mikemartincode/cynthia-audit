#!/usr/bin/env python3
"""auditor/exemplar_ab.py — the augmented-generation recall A/B (#1, the headline open thesis).

Tests whether injecting a GREEN same-shape oracle as a generation EXEMPLAR lets a FIXED author write a
gate-passing oracle for functions it fails un-augmented — i.e. author PAST its one-shot ceiling. This
is the REAL "recall" idea; the shipped recall_strategy only REORDERS which shape to try (a selector),
which is ceiling-capped. Here recall RETRIEVES the GREEN oracle CODE of the nearest same-shape function
(leave-one-out clean) and injects it, so the model has a worked example to imitate.

Invariants the result rests on:
  * PAIRED, author FIXED. Each function is authored TWICE with the SAME model, max_tokens, temperature,
    and oracle-shape ladder; the ONLY difference between arms is whether the exemplar is injected — so a
    flipped verdict is attributable to the exemplar, not to author variance across arms.
  * Per-function COVERAGE = gate-GREEN on ANY candidate strategy (the corpus metric). The mutation gate
    (capped hard-kill subprocess) is the SOLE authority; the exemplar is never trusted, only the gate's
    verdict on the oracle it helped write. (Claim boundary: coverage = non-vacuity, NOT correctness.)
  * LEAVE-ONE-OUT clean. The exemplar for a function in repo R is retrieved with exclude_repo=R, so a
    function is never shown an oracle from its own repo — the same statelessness recall_strategy proves
    for selection (test_recall_strategy::test_nearest_exemplar_is_leave_one_out_clean).
  * McNemar on the discordant pairs: rescued = GREEN only WITH exemplar; broken = GREEN only WITHOUT.

Resumable: per-function records are checkpointed atomically; a re-run skips finished functions. A hard
budget rail (run.BudgetTracker) stops cleanly before a call could cross the cap.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author as author_mod  # noqa: E402
import coverage_exp as ce  # noqa: E402
from gate_subprocess import _gate_subprocess  # noqa: E402
from recall_strategy import StrategyRecall, candidate_strategies, shape_key as _shape_key  # noqa: E402
from run import BudgetTracker  # noqa: E402

ARMS = ("base", "exemplar")  # base = un-augmented; exemplar = augmented-generation recall


# ---------------------------------------------------------------- function set


def _hard_functions(recall: StrategyRecall) -> set[tuple[str, str]]:
    """The (repo, qualname) set that was RED in EVERY strategy in the corpus — the functions the
    corpus author could not cover one-shot. The A/B's spend goes here (where the ceiling bites); the
    PAIRING controls for author, so selecting the set on the corpus author's failures does not bias
    the paired McNemar even if the A/B author differs (a function only counts as rescued if the
    exemplar flips the SAME author's verdict)."""
    seen: dict[tuple[str, str], bool] = {}
    with recall._conn() as c:
        for r in c.execute("SELECT repo, qualname, gate_green FROM obs"):
            k = (r[0], r[1])
            seen[k] = seen.get(k, False) or bool(r[2])
    return {k for k, any_green in seen.items() if not any_green}


def _exemplar_for(recall: StrategyRecall, entry: dict, strategy: str, repo: str,
                  model: str | None) -> dict | None:
    """The {reference, battery} exemplar halves for one (function, strategy), LOO-clean. Returns None
    if neither role has an other-repo GREEN same-shape oracle (then the arm authors un-augmented and
    the cell is concordant-by-construction — logged so the report can exclude no-exemplar cells)."""
    sk = _shape_key(entry)
    ref = recall.nearest_exemplar(sk, strategy, role="reference", exclude_repo=repo, model=model)
    bat = recall.nearest_exemplar(sk, strategy, role="battery", exclude_repo=repo, model=model)
    if not ref and not bat:
        return None
    return {"reference": ref["code"] if ref else None, "battery": bat["code"] if bat else None,
            "from": {"reference": ref and f"{ref['repo']}:{ref['qualname']}",
                     "battery": bat and f"{bat['repo']}:{bat['qualname']}"}}


def select_targets(recall: StrategyRecall, run_root: Path, *, hard_only: bool, limit: int,
                   exemplar_model: str | None, single_shape: bool = False) -> list[dict]:
    """Eligible A/B targets, richest-exemplar-first. Each target carries its manifest entry, repo,
    target-library name, and the per-strategy exemplars (so retrieval is done ONCE, deterministically,
    not re-queried per arm). Functions with NO exemplar on any candidate strategy are dropped — the
    exemplar arm would be identical to base, so they carry no signal and waste spend.

    `single_shape=True` reduces each function to the ONE recall-recommended strategy that also has a
    LOO exemplar — the output-token lever (1 shape vs the 3-shape ladder ≈ 3× fewer author calls) AND
    a cleaner controlled comparison (the oracle shape is held fixed across arms/authors, so the
    exemplar — or the author swap — is the only variable, no shape confound)."""
    queue = json.loads((run_root / "queue.json").read_text())["repos"]
    hard = _hard_functions(recall) if hard_only else None
    targets: list[dict] = []
    for repo in queue:
        name, manifest_path = repo["name"], Path(repo["manifest"])
        if not manifest_path.exists():
            continue
        target_lib = json.loads(manifest_path.read_text()).get("target", name)
        for f in ce.load_manifest_functions(manifest_path, include_nondeterministic=True):
            qual = f["qualname"]
            if hard is not None and (name, qual) not in hard:
                continue
            strategies = candidate_strategies(f)
            ex_by_strategy = {s: _exemplar_for(recall, f, s, name, exemplar_model) for s in strategies}
            if single_shape:
                # recall's best-first order, restricted to strategies that actually have an exemplar
                order = recall.recommend_order(_shape_key(f), list(strategies), exclude_repo=name)
                best = next((s for s in order if ex_by_strategy.get(s)), None)
                if best is None:
                    continue
                strategies = [best]
                ex_by_strategy = {best: ex_by_strategy[best]}
            n_with_ex = sum(1 for v in ex_by_strategy.values() if v)
            if n_with_ex == 0:
                continue
            targets.append({"repo": name, "entry": f, "target": target_lib,
                            "strategies": strategies, "exemplars": ex_by_strategy,
                            "n_with_ex": n_with_ex})
    # richest-exemplar-first, then deterministic by qualname — informative cells get the budget first
    targets.sort(key=lambda t: (-t["n_with_ex"], t["repo"], t["entry"]["qualname"]))
    return targets[:limit] if limit else targets


# ---------------------------------------------------------------- author + gate one (function, arm)


def _cell_dir(run_dir: Path, repo: str, qual: str, arm: str, strategy: str) -> Path:
    qh = hashlib.sha1(f"{repo}:{qual}".encode()).hexdigest()[:10]
    return run_dir / "oracles" / f"{author_mod._safe_leaf(qual)}_{qh}_{arm}_{strategy}"


async def _arm_coverage(tgt: dict, arm: str, model: str, run_dir: Path, *, sem: asyncio.Semaphore,
                        gate_sem: asyncio.Semaphore, budget: BudgetTracker, max_tokens: int,
                        temperature: float, gate_cap: int, thinking: dict | None = None) -> dict:
    """Author+gate one function under one arm, walking its candidate ladder, early-exiting at the FIRST
    gate-GREEN (coverage = any-green). Returns {covered, green_strategy, per_strategy:[...], cost,...}.
    The base arm injects no exemplar; the exemplar arm injects the LOO exemplar for that strategy."""
    entry, repo = tgt["entry"], tgt["repo"]
    bat_model = author_mod._battery_model(model)
    per_strategy: list[dict] = []
    covered = False
    green_strategy = ""
    cost = out_tok = 0
    stopped = False
    for strategy in tgt["strategies"]:
        exemplar = tgt["exemplars"][strategy] if arm == "exemplar" else None
        if arm == "exemplar" and not exemplar:
            per_strategy.append({"strategy": strategy, "skipped": "no exemplar"})
            continue
        async with sem:
            reservation = budget.reserve()
            if reservation is None:
                stopped = True
                break
            cdir = _cell_dir(run_dir, repo, entry["qualname"], arm, strategy)
            cdir.mkdir(parents=True, exist_ok=True)
            r = await asyncio.to_thread(
                author_mod._author_independent, entry, model, bat_model, target=tgt["target"],
                max_tokens=max_tokens, shape=strategy, stream=ce._wants_stream(model),
                temperature=temperature, thinking=thinking, exemplar=exemplar,
                trace_meta={"repo": repo, "arm": arm, "strategy": strategy})
        if "error" in r:
            budget.settle(reservation, 0.0)
            per_strategy.append({"strategy": strategy, "error": r["error"]})
            continue
        budget.settle(reservation, r["cost"])
        cost += r["cost"]
        out_tok += r["out_tok"]
        mod = f"orc_{arm}_{strategy}"
        (cdir / f"{mod}.py").write_text(r["code"])
        async with gate_sem:
            verdict = await asyncio.to_thread(_gate_subprocess, mod, str(cdir), gate_cap,
                                              entry["qualname"])
        row = {"strategy": strategy, "green": bool(verdict.get("green")),
               "strict_green": bool(verdict.get("strict_green")),
               "gate_failed": bool(verdict.get("gate_failed")),
               "ref_passes": bool(verdict.get("ref_passes")), "note": verdict.get("note", "")}
        per_strategy.append(row)
        if row["green"]:
            covered, green_strategy = True, strategy
            break  # coverage = any-green: stop the ladder
    return {"arm": arm, "covered": covered, "green_strategy": green_strategy,
            "per_strategy": per_strategy, "cost": cost, "out_tok": out_tok, "budget_stopped": stopped}


def _arm_trustworthy(arm: dict) -> bool:
    """An arm's covered=False is trustworthy ONLY if every attempted strategy rendered a REAL gate
    verdict. An author error (gateway timeout/500) or a gate_failed (gate could not evaluate), or a
    budget stop mid-ladder, could be HIDING a would-be-GREEN — so such an arm must not stand in as a
    clean RED. Counting an infrastructure failure as a RED verdict would contaminate the McNemar with
    non-results (the bug that bit the first think-ON run: concurrency-induced 300s timeouts)."""
    if arm["covered"]:
        return True
    if arm.get("budget_stopped"):
        return False
    return not any(r.get("error") or r.get("gate_failed") for r in arm["per_strategy"])


def _fn_record_path(run_dir: Path, tgt: dict) -> Path:
    qh = hashlib.sha1(f"{tgt['repo']}:{tgt['entry']['qualname']}".encode()).hexdigest()[:10]
    return run_dir / "records" / f"{author_mod._safe_leaf(tgt['entry']['qualname'])}_{qh}.json"


async def run_ab(targets: list[dict], model: str, run_dir: Path, *, concurrency: int,
                 max_tokens: int, temperature: float, gate_cap: int,
                 budget_cap: float, thinking: dict | None = None) -> dict:
    (run_dir / "records").mkdir(parents=True, exist_ok=True)
    pending = [t for t in targets if not _fn_record_path(run_dir, t).exists()]
    budget = BudgetTracker(budget_cap)
    sem = asyncio.Semaphore(concurrency)
    gate_sem = asyncio.Semaphore(max(2, (os.cpu_count() or 4) - 2))
    done = {"n": 0, "rescued": 0, "broken": 0, "both": 0, "neither": 0}
    t0 = time.time()

    async def one(tgt: dict) -> None:
        try:
            base = await _arm_coverage(tgt, "base", model, run_dir, sem=sem, gate_sem=gate_sem,
                                       budget=budget, max_tokens=max_tokens, temperature=temperature,
                                       gate_cap=gate_cap, thinking=thinking)
            ex = await _arm_coverage(tgt, "exemplar", model, run_dir, sem=sem, gate_sem=gate_sem,
                                     budget=budget, max_tokens=max_tokens, temperature=temperature,
                                     gate_cap=gate_cap, thinking=thinking)
        except Exception as exc:  # noqa: BLE001 — one function's surprise must not crash the gather
            rec = {"repo": tgt["repo"], "qualname": tgt["entry"]["qualname"],
                   "error": f"{type(exc).__name__}: {exc}"}
            ce._atomic_write_json(_fn_record_path(run_dir, tgt), rec)
            return
        clean = _arm_trustworthy(base) and _arm_trustworthy(ex)
        rec = {"repo": tgt["repo"], "qualname": tgt["entry"]["qualname"],
               "shape_key": _shape_key(tgt["entry"]), "n_with_ex": tgt["n_with_ex"],
               "base": base, "exemplar": ex,
               "base_covered": base["covered"], "exemplar_covered": ex["covered"],
               "clean": clean,  # both arms rendered real verdicts (no timeout/error/budget-stop hiding a green)
               "rescued": clean and ex["covered"] and not base["covered"],
               "broken": clean and base["covered"] and not ex["covered"],
               "exemplar_from": {s: (v and v["from"]) for s, v in tgt["exemplars"].items()}}
        ce._atomic_write_json(_fn_record_path(run_dir, tgt), rec)
        done["n"] += 1
        done["rescued"] += int(rec["rescued"])
        done["broken"] += int(rec["broken"])
        done["both"] += int(base["covered"] and ex["covered"])
        done["neither"] += int(not base["covered"] and not ex["covered"])
        ce._atomic_write_json(run_dir / "heartbeat.json",
                              {"completed": done["n"], "total": len(pending), **done,
                               "spent": round(budget.spent, 4), "cap": budget.cap,
                               "budget_stopped": budget.stopped, "last_finish": time.time(),
                               "elapsed_s": round(time.time() - t0, 1)})
        print(f"[ab {done['n']}/{len(pending)}] {tgt['repo']}:{tgt['entry']['qualname']} "
              f"base={base['covered']} ex={ex['covered']} "
              f"{'RESCUED' if rec['rescued'] else 'BROKEN' if rec['broken'] else ''} "
              f"| spent ${budget.spent:.2f}/{budget.cap:.0f}", flush=True)

    await asyncio.gather(*(one(t) for t in pending))
    summary = report(run_dir)
    summary["elapsed_s"] = round(time.time() - t0, 1)
    summary["spent_usd"] = round(budget.spent, 4)
    summary["budget_stopped"] = budget.stopped
    ce._atomic_write_json(run_dir / "summary.json", summary)
    return summary


# ---------------------------------------------------------------- report (pure; re-runnable)


def _mcnemar_p(b: int, c: int) -> float:
    """Exact two-sided McNemar p over the discordant pairs (b rescued, c broken) — a binomial test
    against p=0.5. Small n, so exact not chi-square. Pure stdlib."""
    n = b + c
    if n == 0:
        return 1.0
    from math import comb
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def report(run_dir: Path) -> dict:
    all_recs = []
    for p in sorted((run_dir / "records").glob("*.json")):
        try:
            d = json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        if "error" not in d:
            all_recs.append(d)
    # ONLY clean functions (both arms rendered real verdicts) enter the contingency table — a
    # timed-out/errored arm is a non-result, not a RED, and must not pollute the McNemar.
    recs = [r for r in all_recs if r.get("clean", True)]
    excluded = len(all_recs) - len(recs)
    n = len(recs)
    rescued = [r for r in recs if r["rescued"]]
    broken = [r for r in recs if r["broken"]]
    both = sum(1 for r in recs if r["base_covered"] and r["exemplar_covered"])
    neither = sum(1 for r in recs if not r["base_covered"] and not r["exemplar_covered"])
    base_cov = sum(1 for r in recs if r["base_covered"])
    ex_cov = sum(1 for r in recs if r["exemplar_covered"])
    by_repo = collections.Counter(r["repo"] for r in recs)
    return {
        "functions_clean": n, "functions_excluded_unclean": excluded,
        "base_coverage": base_cov, "exemplar_coverage": ex_cov,
        "base_coverage_rate": round(base_cov / n, 4) if n else 0.0,
        "exemplar_coverage_rate": round(ex_cov / n, 4) if n else 0.0,
        "contingency": {"both_green": both, "rescued_by_exemplar": len(rescued),
                        "broken_by_exemplar": len(broken), "both_red": neither},
        "net_rescued": len(rescued) - len(broken),
        "mcnemar_p_two_sided": round(_mcnemar_p(len(rescued), len(broken)), 4),
        "by_repo_functions": dict(by_repo),
        "rescued": [f"{r['repo']}:{r['qualname']} (via {r['exemplar']['green_strategy']})"
                    for r in rescued],
        "broken": [f"{r['repo']}:{r['qualname']}" for r in broken],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="augmented-generation recall A/B (#1)")
    ap.add_argument("--recall-db", type=Path, default=Path("results/corpus/recall.db"))
    ap.add_argument("--corpus-root", type=Path, default=Path("results/corpus"),
                    help="dir holding queue.json (manifest paths) — the corpus repos")
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--model", default="minimax-m3", help="the FIXED author (both arms)")
    ap.add_argument("--exemplar-model", default=None,
                    help="restrict exemplars to oracles authored by this model (default: any)")
    ap.add_argument("--limit", type=int, default=20, help="max functions (0 = all eligible)")
    ap.add_argument("--all-functions", action="store_true",
                    help="don't restrict to the corpus all-RED hard set")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--max-tokens", type=int, default=None)
    ap.add_argument("--temperature", type=float, default=0.3)
    ap.add_argument("--thinking", choices=("off", "on", "adaptive"), default="off",
                    help="reasoning mode for a reasoning author (M3): off={'type':'disabled'} is the "
                         "fast path; on=provider default; adaptive={'type':'adaptive'}")
    ap.add_argument("--gate-cap", type=int, default=40)
    ap.add_argument("--budget-cap", type=float, default=None)
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()
    thinking = {"off": {"type": "disabled"}, "adaptive": {"type": "adaptive"}, "on": None}[args.thinking]

    if args.report_only:
        print(json.dumps(report(args.run_dir), indent=2))
        return 0

    recall = StrategyRecall(args.recall_db)
    # queue.json lives at corpus-root; the driver reads manifests via it
    (args.run_dir).mkdir(parents=True, exist_ok=True)
    import shutil
    qsrc = args.corpus_root / "queue.json"
    qdst = args.run_dir / "queue.json"
    if not qdst.exists():
        shutil.copy(qsrc, qdst)
    targets = select_targets(recall, args.run_dir, hard_only=not args.all_functions,
                             limit=args.limit, exemplar_model=args.exemplar_model)
    max_tokens = args.max_tokens or author_mod.DEFAULT_MAX_TOKENS
    cap = args.budget_cap if args.budget_cap is not None else float(os.environ.get("AUDIT_BUDGET_USD", "10"))
    print(f"[ab] {len(targets)} eligible targets (model={args.model}, "
          f"hard_only={not args.all_functions}, max_tokens={max_tokens}, cap=${cap:.0f})", flush=True)
    summary = asyncio.run(run_ab(targets, args.model, args.run_dir, concurrency=args.concurrency,
                                 max_tokens=max_tokens, temperature=args.temperature,
                                 gate_cap=args.gate_cap, budget_cap=cap, thinking=thinking))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
