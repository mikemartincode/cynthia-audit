#!/usr/bin/env python3
"""auditor/measure_e04.py - measure the RECALL LIFT E04 input generation buys, honestly.

Two independent axes, both deterministic and model-free:

  A. BRANCH LIFT (self-contained, always run). Drive the pre-E04 baseline (`strategies.URL_POOL`)
     and then the baseline ∪ E04 corpus through the SAME fixed battery, counting distinct lines
     reached in the vendored target source via sys.settrace. The delta is attributable to the
     inputs alone (identical battery). This is the headline, dependency-free number.

  B. CANDIDATE LIFT (only if a gate-GREEN records dir exists). Re-run the differential sweep over
     the url-convention oracles with the E04 corpus appended to the `url` convention, and compare
     surviving candidate divergences + total generated inputs against the baseline run. More
     candidates surfaced over the same gate-proven oracles = more of the input space exercised.

HONESTY: this reports "more branches reached / more candidates surfaced," NOT "exhaustive." The
E04 corpus is bounded by stated caps/budgets (printed). A bug behind a branch none of the three
axes reaches is still missed - recall is raised, not completed.

Usage:
    ~/projects/cynthia-core/.venv/bin/python auditor/measure_e04.py \
        [--records results/a06-final] [--out results/e04-recall] \
        [--grammar-limit 300] [--seed-cap 600] [--fuzz-budget 2000]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import strategies  # noqa: E402
from grammar import build_e04_inputs, lines_hit  # noqa: E402
from strategies import CONVENTION, URL_POOL  # noqa: E402


def measure_branch_lift(e04_inputs: list[str]) -> dict:
    """Distinct target lines hit by the baseline pool vs baseline ∪ E04, same battery."""
    base_lines = lines_hit(URL_POOL)
    e04_lines = lines_hit(list(URL_POOL) + e04_inputs)
    gained = sorted(e04_lines - base_lines)
    return {
        "baseline_inputs": len(URL_POOL),
        "e04_inputs": len(URL_POOL) + len(e04_inputs),
        "baseline_lines_hit": len(base_lines),
        "e04_lines_hit": len(e04_lines),
        "lines_gained": len(gained),
        "lift_pct": round(100.0 * len(gained) / max(1, len(base_lines)), 1),
        "sample_new_lines": gained[:25],
    }


def measure_candidate_lift(records_dir: Path, out_dir: Path, e04_stats: dict) -> dict | None:
    """Run the sweep twice over the url-convention oracles - baseline pool, then E04-augmented -
    and compare. Returns None if the records dir is absent (axis B simply not available)."""
    rec_glob = sorted((records_dir / "records").glob("*.json"))
    if not rec_glob:
        return None
    from sweep import sweep_one  # local import: sweep pulls in the target + adapters

    url_oracles = []
    for rp in rec_glob:
        r = json.loads(rp.read_text())
        if r.get("green") and CONVENTION.get(r["qualname"]) == "url":
            url_oracles.append((r["qualname"], r["oracle_path"]))

    def run(label: str) -> dict:
        gen = diverg = 0
        per = []
        for qual, op in url_oracles:
            o = sweep_one(qual, op, cap=10_000, max_record=0)
            if not o["mappable"]:
                continue
            gen += o["generated"]
            diverg += o["divergences"]
            per.append({"qualname": qual, "generated": o["generated"],
                        "divergences": o["divergences"]})
        return {"label": label, "url_oracles_mappable": len(per),
                "total_generated_inputs": gen, "surviving_divergences": diverg, "per_oracle": per}

    # baseline: E04 disabled
    strategies._E04_EXTRA = []
    base = run("baseline")
    # E04: append the corpus to the url convention (returns build stats already captured upstream)
    strategies.enable_e04(grammar_limit=e04_stats["grammar"]["requested"],
                          seed_cap=e04_stats["seed_corpus"]["from_tests"]["cap"],
                          fuzz_budget=e04_stats["coverage_guided"]["budget"])
    e04 = run("e04")
    strategies._E04_EXTRA = []  # restore

    return {
        "url_convention_oracles": len(url_oracles),
        "baseline": base,
        "e04": e04,
        "extra_generated_inputs": e04["total_generated_inputs"] - base["total_generated_inputs"],
        "extra_surviving_divergences": e04["surviving_divergences"] - base["surviving_divergences"],
        "new_divergence_qualnames": sorted(
            {p["qualname"] for p in e04["per_oracle"] if p["divergences"]}
            - {p["qualname"] for p in base["per_oracle"] if p["divergences"]}),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="measure E04 recall lift (branches + candidates)")
    ap.add_argument("--records", type=Path, default=Path("results/a06-final"))
    ap.add_argument("--out", type=Path, default=Path("results/e04-recall"))
    ap.add_argument("--grammar-limit", type=int, default=300)
    ap.add_argument("--seed-cap", type=int, default=600)
    ap.add_argument("--fuzz-budget", type=int, default=2000)
    args = ap.parse_args()

    e04_inputs, e04_stats = build_e04_inputs(grammar_limit=args.grammar_limit,
                                             seed_cap=args.seed_cap, fuzz_budget=args.fuzz_budget)
    branch = measure_branch_lift(e04_inputs)
    candidate = measure_candidate_lift(args.records, args.out, e04_stats)

    report = {"e04_corpus": {"total_distinct": e04_stats["total_distinct"],
                             "grammar_kept": e04_stats["grammar"]["kept"],
                             "seed_corpus_total": e04_stats["seed_corpus"]["total"],
                             "coverage_guided_kept": e04_stats["coverage_guided"]["kept_expanding"],
                             "coverage_guided_budget_hit": e04_stats["coverage_guided"]["budget_hit"]},
              "caps": {"grammar_limit": args.grammar_limit, "seed_cap": args.seed_cap,
                       "fuzz_budget": args.fuzz_budget},
              "branch_lift": branch, "candidate_lift": candidate, "full_e04_stats": e04_stats}

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "recall.json").write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps({k: report[k] for k in ("e04_corpus", "caps", "branch_lift")}, indent=2))
    print(f"\nBRANCH LIFT: {branch['baseline_lines_hit']} -> {branch['e04_lines_hit']} distinct "
          f"target lines (+{branch['lines_gained']}, +{branch['lift_pct']}%) on the same battery")
    if candidate is not None:
        print(f"CANDIDATE LIFT: over {candidate['url_convention_oracles']} url-convention "
              f"gate-GREEN oracles, generated inputs "
              f"{candidate['baseline']['total_generated_inputs']} -> "
              f"{candidate['e04']['total_generated_inputs']} "
              f"(+{candidate['extra_generated_inputs']}); surviving divergences "
              f"{candidate['baseline']['surviving_divergences']} -> "
              f"{candidate['e04']['surviving_divergences']} "
              f"(+{candidate['extra_surviving_divergences']})")
    else:
        print("CANDIDATE LIFT: skipped (no gate-GREEN records dir) - branch lift stands alone")
    if e04_stats["coverage_guided"]["budget_hit"]:
        print(f"NOTE: coverage-guided loop hit its {args.fuzz_budget}-mutation budget cap (logged)")
    print("HONEST: recall raised (more branches / more candidates), NOT exhaustive - bounded by "
          "the stated caps; no symbolic execution.")
    print(f"wrote {args.out / 'recall.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
