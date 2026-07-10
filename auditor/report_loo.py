#!/usr/bin/env python3
"""auditor/report_loo.py - assemble the LEAVE-ONE-OUT deliverables across all eligible held-out repos.

For each eligible repo R: re-simulate the 3 arms (baseline / blind / recall) over R's recorded
held-out cell outcomes, with R EXCLUDED from the recall store (the leave-one-out lever - identical to
deleting R's rows because recall is stateless aggregation). Reports per repo AND a pooled
micro-average (total covered functions / total functions across repos). Two slices: DETERMINISTIC-only
(the meaningful one - where the strategy ladder has >1 candidate so order can matter) and ALL functions
(includes nondeterministic stubbed_seam, ~0 recovery on this basket, dilutes equally across arms).

Pure: reads results/holdout/<repo>/records + results/corpus/recall.db; writes a grouped-bar SVG +
RESULTS.md. No spend, no model. Coverage = gate-GREEN = non-vacuity, NOT correctness (claim boundary).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coverage_exp as ce  # noqa: E402
import holdout as H  # noqa: E402
from recall_strategy import StrategyRecall  # noqa: E402

ELIGIBLE = ["packaging", "dateutil", "markdown-it-py", "bleach"]
PRECOMMITTED = "dateutil"  # lowest baseline coverage - the pre-committed primary pick


def _load_repo(repo: str, recall: StrategyRecall, reps: int, budget_k: int, func_limit: int) -> dict:
    funcs = ce.load_manifest_functions(Path(f"targets/{repo}/manifest.json"),
                                       include_nondeterministic=True)
    if func_limit:
        funcs = funcs[:func_limit]
    det = [f for f in funcs if f.get("deterministic")]
    results = [r for r in ce.load_cell_results(Path(f"results/holdout/{repo}")) if r.repo == repo]
    outcomes = H.outcomes_from_results(results)
    sim_all = H.simulate_all_arms(funcs, outcomes, recall, repo, reps=reps, budget_k=budget_k)
    sim_det = H.simulate_all_arms(det, outcomes, recall, repo, reps=reps, budget_k=budget_k)
    return {"repo": repo, "n_all": len(funcs), "n_det": len(det), "all": sim_all, "det": sim_det,
            "cells": len(results)}


def _pooled(per_repo: list[dict], slice_key: str) -> dict:
    """Micro-average across repos: total covered functions / total functions, per arm (each repo's
    arm coverage weighted by its function count = its own leave-one-out result)."""
    nkey = "n_det" if slice_key == "det" else "n_all"
    arms = {}
    for arm in ("baseline", "blind", "recall"):
        num = sum(r[slice_key]["arms"][arm]["coverage_mean"] * r[nkey] for r in per_repo)
        den = sum(r[nkey] for r in per_repo) or 1
        arms[arm] = num / den
    return {"baseline": arms["baseline"], "blind": arms["blind"], "recall": arms["recall"],
            "n": sum(r[nkey] for r in per_repo)}


# ---------------------------------------------------------------- grouped-bar SVG


def _svg_grouped(per_repo: list[dict], slice_key: str, pooled: dict) -> str:
    groups = [(r["repo"], r[slice_key]["arms"]) for r in per_repo]
    groups.append(("POOLED", {"baseline": {"coverage_mean": pooled["baseline"], "coverage_lo": pooled["baseline"], "coverage_hi": pooled["baseline"], "ceiling_mean": 0},
                              "blind": {"coverage_mean": pooled["blind"], "coverage_lo": pooled["blind"], "coverage_hi": pooled["blind"], "ceiling_mean": 0},
                              "recall": {"coverage_mean": pooled["recall"], "coverage_lo": pooled["recall"], "coverage_hi": pooled["recall"], "ceiling_mean": 0}}))
    arms = ["baseline", "blind", "recall"]
    colors = {"baseline": "#9aa0a6", "blind": "#4285f4", "recall": "#34a853"}
    W, H_ = 820, 460
    ml, mr, mt, mb = 60, 140, 50, 70
    pw, ph = W - ml - mr, H_ - mt - mb
    ymax = max(0.4, max(a[arm]["coverage_mean"] for _, a in groups for arm in arms) * 1.25)

    def y(v): return mt + ph * (1 - v / ymax)
    gw = pw / len(groups)
    bw = gw * 0.24
    P = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H_}" font-family="sans-serif" font-size="12">',
         f'<rect width="{W}" height="{H_}" fill="white"/>',
         f'<text x="{W/2}" y="22" text-anchor="middle" font-size="15" font-weight="bold">'
         f'Held-out oracle coverage by arm - leave-one-out, {slice_key}-functions</text>']
    for g in range(0, 11, 2):
        v = ymax * g / 10
        P.append(f'<line x1="{ml}" y1="{y(v):.1f}" x2="{W-mr}" y2="{y(v):.1f}" stroke="#eee"/>')
        P.append(f'<text x="{ml-6}" y="{y(v)+4:.1f}" text-anchor="end" fill="#555">{v:.2f}</text>')
    for gi, (name, a) in enumerate(groups):
        gx = ml + gw * gi
        for ai, arm in enumerate(arms):
            d = a[arm]
            cx = gx + gw * 0.5 + (ai - 1) * (bw + 3)
            mean = d["coverage_mean"]
            if arm == "baseline" and d.get("coverage_hi", 0) > d.get("coverage_lo", 0):
                P.append(f'<rect x="{cx-bw/2:.1f}" y="{y(d["coverage_hi"]):.1f}" width="{bw:.1f}" '
                         f'height="{y(d["coverage_lo"])-y(d["coverage_hi"]):.1f}" fill="#9aa0a6" opacity="0.3"/>')
            P.append(f'<rect x="{cx-bw/2:.1f}" y="{y(mean):.1f}" width="{bw:.1f}" '
                     f'height="{mt+ph-y(mean):.1f}" fill="{colors[arm]}" opacity="0.88"/>')
        P.append(f'<text x="{gx+gw*0.5:.1f}" y="{mt+ph+18:.1f}" text-anchor="middle" '
                 f'fill="#333" font-size="11">{name}</text>')
    # legend
    for i, arm in enumerate(arms):
        ly = mt + 10 + i * 20
        P.append(f'<rect x="{W-mr+15}" y="{ly}" width="12" height="12" fill="{colors[arm]}"/>')
        P.append(f'<text x="{W-mr+32}" y="{ly+11}" fill="#333">{arm}</text>')
    P.append('</svg>')
    return "\n".join(P)


def _table(per_repo: list[dict], slice_key: str, pooled: dict) -> str:
    rows = ["| held-out repo | n | Arm1 baseline | Arm2 blind | Arm3 recall | Arm3−Arm2 |",
            "|---|---|---|---|---|---|"]
    for r in per_repo:
        a = r[slice_key]["arms"]
        n = r["n_det"] if slice_key == "det" else r["n_all"]
        lift = a["recall"]["coverage_mean"] - a["blind"]["coverage_mean"]
        star = " ⟵ pre-committed" if r["repo"] == PRECOMMITTED else ""
        rows.append(f"| {r['repo']}{star} | {n} | {a['baseline']['coverage_mean']:.3f} "
                    f"[{a['baseline']['coverage_lo']:.2f}-{a['baseline']['coverage_hi']:.2f}] "
                    f"| {a['blind']['coverage_mean']:.3f} | {a['recall']['coverage_mean']:.3f} "
                    f"| {lift:+.3f} |")
    rows.append(f"| **POOLED (micro-avg)** | {pooled['n']} | **{pooled['baseline']:.3f}** "
                f"| **{pooled['blind']:.3f}** | **{pooled['recall']:.3f}** "
                f"| **{pooled['recall']-pooled['blind']:+.3f}** |")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="leave-one-out coverage-recall report")
    ap.add_argument("--out-dir", type=Path, default=Path("results/RESULTS"))
    ap.add_argument("--recall-db", type=Path, default=Path("results/corpus/recall.db"))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--budget-k", type=int, default=2)
    ap.add_argument("--func-limit", type=int, default=30)
    ap.add_argument("--repos", nargs="+", default=ELIGIBLE)
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    recall = StrategyRecall(args.recall_db)
    per_repo = [_load_repo(r, recall, args.reps, args.budget_k, args.func_limit)
                for r in args.repos if Path(f"results/holdout/{r}/records").exists()]
    if not per_repo:
        print("no held-out results found yet")
        return 1
    pooled_det = _pooled(per_repo, "det")
    pooled_all = _pooled(per_repo, "all")
    (args.out_dir / "coverage_by_arm_det.svg").write_text(_svg_grouped(per_repo, "det", pooled_det))
    (args.out_dir / "coverage_by_arm_all.svg").write_text(_svg_grouped(per_repo, "all", pooled_all))

    md = _build_md(per_repo, pooled_det, pooled_all)
    (args.out_dir / "RESULTS.md").write_text(md)
    json.dump({"per_repo": [{"repo": r["repo"], "det": r["det"]["verdict"],
                             "det_arms": {k: v["coverage_mean"] for k, v in r["det"]["arms"].items()}}
                            for r in per_repo],
               "pooled_det": pooled_det, "pooled_all": pooled_all},
              open(args.out_dir / "loo_summary.json", "w"), indent=2)
    print(f"wrote {args.out_dir}/RESULTS.md + 2 charts + loo_summary.json")
    print("\nPOOLED (deterministic):", {k: round(v, 3) for k, v in pooled_det.items() if k != "n"})
    return 0


def _build_md(per_repo: list[dict], pooled_det: dict, pooled_all: dict) -> str:
    lift = pooled_det["recall"] - pooled_det["blind"]
    L = ["# Coverage-Recovery A/B - does shape->strategy recall lift oracle coverage?",
         "",
         "**Claim boundary.** *Coverage* = fraction of auditable functions whose authored oracle passes "
         "the cynthia-core **mutation gate** (gate-GREEN = proven non-vacuous). The gate proves teeth, "
         "**not** correctness. This measures whether recall learns *which authoring strategy maximizes "
         "gate-GREEN per function shape* - necessary, not sufficient, for correctness. No model ever "
         "*approves* an oracle; the gate is the sole authority.",
         "",
         "**'recall' here** = a run-history *shape->strategy* lookup (which oracle shape - value / "
         "invariant / property - most often gates GREEN for a function's coarse shape), learned across "
         "repos. NOT cynthia-audit's E04 input-coverage \"recall\", NOT the cynthia-v3 run-history service.",
         "",
         "## Design",
         "- **Author model fixed** = deepseek-v4-pro across the corpus and all arms (Opus does not author).",
         "- **Leave-one-out across all 4 eligible repos** (packaging, dateutil, markdown-it-py, bleach; "
         "idna + hyperlink excluded as auditor-built). No single cherry-picked held-out repo - every "
         "eligible repo is held out in turn. The **pre-committed** rule (held-out = lowest baseline "
         "coverage) names **dateutil**; it is reported, but all four are shown.",
         "- For each held-out repo, recall is queried with that repo's own rows **excluded** (≡ deleting "
         "them - recall is stateless aggregation, so leave-one-out is exact by construction).",
         "- Arms (per function, author fixed): **Arm1 baseline** = default strategy, 1 attempt; "
         "**Arm2 blind** = fixed ladder order, budget K=2; **Arm3 recall** = recall-recommended order, "
         "K=2. Coverage simulated over 3 independent stochastic reps of each (function × strategy) cell.",
         "",
         "## Result - deterministic functions (where the ladder has >1 candidate)",
         _table(per_repo, "det", pooled_det),
         "",
         "![coverage by arm, deterministic](coverage_by_arm_det.svg)",
         "",
         f"**Pooled recall lift over blind retry (Arm3 − Arm2): {lift:+.3f}.** "
         + ("Recall beats blind retry." if lift > 1e-9 else
            "Recall did NOT beat blind retry on this corpus (the lift, if any, came from the ladder, "
            "not from shape-conditioned ordering) - reported as a null/negative result."),
         "",
         "### Reading this honestly",
         "- This is a **hard corpus**: independently-authored oracles gate-GREEN on a small fraction of "
         "these functions (PEP 440 specifiers, timezone logic, parsers/renderers). Absolute coverage is "
         "low, so there is little *headroom* for any retry policy to recover - recall can only reorder "
         "toward strategies that work, and on low-ceiling repos (dateutil, packaging) almost no strategy "
         "works at all.",
         "- Where there IS headroom (bleach, markdown-it-py - invariant/property recover functions value "
         "misses), that is where any Arm3>Arm2 signal appears; where there isn't, all arms collapse "
         "together. The per-repo table makes this visible rather than averaging it away.",
         "",
         "## All functions (incl. nondeterministic / stubbed-seam)",
         _table(per_repo, "all", pooled_all),
         "",
         "_Nondeterministic functions have a single candidate strategy (stubbed_seam), which recovered "
         "~0 coverage on this basket (its functions are IO/factory, not scalar-seam-injectable). They "
         "dilute every arm equally and cannot contribute to lift; shown for completeness._",
         "",
         "## Limitations (under-claim)",
         "- **Coverage = gate-pass = non-vacuity, NOT correctness.** strict-GREEN (memorizer-killing) "
         "was recorded alongside and is rarer still; full correctness needs the differential sweep + a "
         "human (out of scope).",
         "- **Coarse shape key** (auditability · deterministic · arity-bucket · has-inverse).",
         "- **Low absolute coverage on this basket** bounds how large any lift can be; a basket chosen "
         "for higher independent-oracle coverage (or best-of-N authoring) would give more headroom.",
         "- 4 held-out repos, one author model, one gateway snapshot - a point estimate, not a distribution.",
         "",
         "---", "_Generated by auditor/report_loo.py from the run artifacts._"]
    return "\n".join(L)


if __name__ == "__main__":
    raise SystemExit(main())
