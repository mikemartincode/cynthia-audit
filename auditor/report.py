#!/usr/bin/env python3
"""auditor/report.py - assemble the deliverables from the run artifacts: the numbers table, one
coverage-by-arm chart (SVG, with Arm-1's variance band drawn), and RESULTS.md in the honest voice of
the findings/ reports. Pure: reads bakeoff_report.json / corpus_report.json / holdout_report.json and
writes; no spend, no model.

The chart is hand-emitted SVG (stdlib only - no matplotlib): three bars (baseline / blind retry /
recall-guided), Arm-1's stochastic band drawn as a shaded rect lo..hi, error bars on the retry arms,
and the K=infinity ceiling as a dashed line. SVG because it is a real vector figure with zero deps.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


# ---------------------------------------------------------------- SVG chart (stdlib)


def _svg_coverage_chart(arms: dict, held_out_repo: str, budget_k: int) -> str:
    order = ["baseline", "blind", "recall"]
    labels = {"baseline": "Arm1 baseline\n(K=1)", "blind": f"Arm2 blind\n(K={budget_k})",
              "recall": f"Arm3 recall\n(K={budget_k})"}
    colors = {"baseline": "#9aa0a6", "blind": "#4285f4", "recall": "#34a853"}
    W, H = 680, 440
    ml, mr, mt, mb = 70, 30, 50, 70
    pw, ph = W - ml - mr, H - mt - mb

    def x(i): return ml + pw * (i + 0.5) / len(order)
    def y(v): return mt + ph * (1 - v)

    bw = pw / len(order) * 0.45
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
             f'font-family="sans-serif" font-size="13">',
             f'<rect width="{W}" height="{H}" fill="white"/>',
             f'<text x="{W/2}" y="24" text-anchor="middle" font-size="16" font-weight="bold">'
             f'Oracle coverage by arm - held-out: {held_out_repo}</text>']
    # y gridlines + axis
    for g in range(0, 11, 2):
        v = g / 10
        yy = y(v)
        parts.append(f'<line x1="{ml}" y1="{yy:.1f}" x2="{W-mr}" y2="{yy:.1f}" '
                     f'stroke="#eee"/>')
        parts.append(f'<text x="{ml-8}" y="{yy+4:.1f}" text-anchor="end" fill="#555">{v:.1f}</text>')
    parts.append(f'<text x="18" y="{mt+ph/2}" text-anchor="middle" fill="#333" '
                 f'transform="rotate(-90 18 {mt+ph/2})">gate-GREEN coverage</text>')

    # ceiling (K=inf) of the recall arm = full strategy set ceiling; draw the max ceiling as dashed
    ceiling = max(arms[a].get("ceiling_mean", 0.0) for a in order)
    yc = y(ceiling)
    parts.append(f'<line x1="{ml}" y1="{yc:.1f}" x2="{W-mr}" y2="{yc:.1f}" stroke="#aa00aa" '
                 f'stroke-dasharray="6 4"/>')
    parts.append(f'<text x="{W-mr}" y="{yc-5:.1f}" text-anchor="end" fill="#aa00aa">'
                 f'ceiling K=∞ {ceiling:.2f}</text>')

    for i, a in enumerate(order):
        d = arms[a]
        cx = x(i)
        mean, lo, hi = d["coverage_mean"], d["coverage_lo"], d["coverage_hi"]
        # Arm1 stochastic band as a shaded rect lo..hi behind the bar
        if a == "baseline" and hi > lo:
            parts.append(f'<rect x="{cx-bw:.1f}" y="{y(hi):.1f}" width="{2*bw:.1f}" '
                         f'height="{y(lo)-y(hi):.1f}" fill="#9aa0a6" opacity="0.25"/>')
        parts.append(f'<rect x="{cx-bw:.1f}" y="{y(mean):.1f}" width="{2*bw:.1f}" '
                     f'height="{mt+ph-y(mean):.1f}" fill="{colors[a]}" opacity="0.85"/>')
        # error bar lo..hi
        parts.append(f'<line x1="{cx:.1f}" y1="{y(lo):.1f}" x2="{cx:.1f}" y2="{y(hi):.1f}" '
                     f'stroke="#222"/>')
        for yv in (lo, hi):
            parts.append(f'<line x1="{cx-5:.1f}" y1="{y(yv):.1f}" x2="{cx+5:.1f}" y2="{y(yv):.1f}" '
                         f'stroke="#222"/>')
        parts.append(f'<text x="{cx:.1f}" y="{y(mean)-8:.1f}" text-anchor="middle" '
                     f'font-weight="bold">{mean:.2f}</text>')
        for j, line in enumerate(labels[a].split("\n")):
            parts.append(f'<text x="{cx:.1f}" y="{mt+ph+20+j*16:.1f}" text-anchor="middle" '
                         f'fill="#333">{line}</text>')
    parts.append('</svg>')
    return "\n".join(parts)


# ---------------------------------------------------------------- markdown tables


def _bakeoff_table(bk: dict) -> str:
    rows = ["| model | gate-GREEN | strict-GREEN | $/fn | mean latency (s) | cache hits |",
            "|---|---|---|---|---|---|"]
    for model, m in bk.get("per_model", {}).items():
        if not m.get("n"):
            rows.append(f"| {model} | (no successful cells) | | | | |")
            continue
        rows.append(f"| {model} | {m['gate_green_rate']:.2f} ({m['gate_green']}/{m['n']}) "
                    f"| {m['strict_green_rate']:.2f} ({m['strict_green']}/{m['n']}) "
                    f"| ${m['cost_per_fn']:.4f} | {m['mean_latency_s']} | "
                    f"{m['cells_cache_hit']}/{m['n']} |")
    pf = bk.get("cache_preflight", {})
    rows.append("")
    rows.append(f"_Cache preflight ({pf.get('model','?')}): sequential reads "
                f"{pf.get('cache_reads')}, prefix cache fires = **{pf.get('cache_fires')}**._")
    return "\n".join(rows)


def _per_repo_baseline_table(corpus: dict, recall_db: str) -> str:
    """Per-repo baseline gate-GREEN coverage from the corpus pass (the held-out selection input)."""
    rows = ["| repo | functions×strategies cells | gate-GREEN cells | corpus gate-GREEN rate |",
            "|---|---|---|---|"]
    for p in corpus.get("processed", []):
        comp = p.get("completed", 0)
        gr = p.get("gate_green", 0)
        rate = gr / comp if comp else 0.0
        rows.append(f"| {p['repo']} | {p.get('cells_total', p.get('cells','?'))} | {gr} | {rate:.2f} |")
    return "\n".join(rows)


def _arms_table(ho: dict) -> str:
    rows = ["| arm | strategy order | budget K | coverage (mean) | band [lo..hi] | ceiling K=∞ |",
            "|---|---|---|---|---|---|"]
    desc = {"baseline": "default only", "blind": "fixed ladder", "recall": "recall-recommended"}
    for a in ("baseline", "blind", "recall"):
        d = ho["arms"][a]
        rows.append(f"| {a} | {desc[a]} | {d['budget_k']} | **{d['coverage_mean']:.3f}** "
                    f"| [{d['coverage_lo']:.3f}..{d['coverage_hi']:.3f}] | {d['ceiling_mean']:.3f} |")
    return "\n".join(rows)


# ---------------------------------------------------------------- RESULTS.md


def build_results_md(bk: dict | None, corpus: dict | None, ho: dict | None, *,
                     holdout_rule: str, chart_path: str) -> str:
    L = ["# Coverage-Recovery A/B - does shape->strategy recall lift oracle coverage?",
         "",
         "**Claim boundary (read first).** *Coverage* here = the fraction of auditable functions for "
         "which a model authored an oracle that passes the cynthia-core **mutation gate** "
         "(gate-GREEN = proven non-vacuous). The gate proves an oracle has *teeth*, **not** that it is "
         "correct beyond non-vacuity. So this experiment measures whether recall learns *which "
         "authoring strategy maximizes gate-GREEN per function shape* - necessary-but-not-sufficient "
         "for correctness. We do **not** claim recall learns correctness. (strict-GREEN, recorded "
         "alongside, additionally kills an author-blind memorizer - a tighter bar; full correctness "
         "would need the differential sweep + a human, out of scope here.)",
         "",
         "**Trust primitive.** No model ever *approves* an oracle. Models only *author*; the mutation "
         "gate is the sole authority that marks an oracle covered. Every number below is gate-decided.",
         "",
         "**'recall' disambiguation.** This is a run-history shape->strategy lookup built for this "
         "experiment - *not* cynthia-audit's E04 input-coverage \"RECALL LIFT\" (source lines reached) "
         "and *not* the cynthia-v3 run-history `recall` service (env_version / tool sequences).",
         ""]
    if bk:
        L += ["## 1. Model bake-off (step 0)",
              f"Calibration repo: **{bk.get('calibration_repo')}** ({bk.get('n_functions')} "
              "deterministic functions, value-shape oracle, 1 attempt). Distinct from the held-out "
              "basket by construction.", "", _bakeoff_table(bk), ""]
    if corpus:
        L += ["## 2. Per-repo baseline coverage (corpus pass)",
              "Try-all over every basket repo (each candidate strategy on each function) - the "
              "training rows for recall, and the input to the held-out selection rule.", "",
              _per_repo_baseline_table(corpus, corpus.get("recall_db", "")), ""]
    if ho:
        v = ho["verdict"]
        L += ["## 3. Held-out evaluation (leave-one-out)",
              f"**Pre-committed selection rule:** {holdout_rule}",
              f"Held-out repo: **{ho['held_out_repo']}**. Author model fixed across all three arms; "
              "Opus does not author inside arms; recall queried with the held-out repo's own rows "
              "EXCLUDED (≡ deleting them, since recall is stateless aggregation). Arms simulated over "
              f"{ho['reps']} independent stochastic reps of each (function × strategy) cell.", "",
              _arms_table(ho), "",
              f"![coverage by arm]({chart_path})", "",
              "### What is (and isn't) shown",
              f"- **recall vs blind retry (the thesis): Arm3 − Arm2 = "
              f"{v['arm3_minus_arm2']:+.3f}** -> recall beats blind retry: "
              f"**{v['arm3_gt_arm2']}**.",
              f"- retrying at all helps (Arm2 > top of Arm1 band): **{v['arm2_gt_arm1_band']}**.",
              f"- strict 3-way chain (Arm3 > Arm2 > Arm1 band) - the handoff's IFF: "
              f"**{v['recall_proven']}**.",
              ("- ⚠ Arm3 ≈ Arm2 -> the lift came from the *ladder*, not recall (honest negative)."
               if v["ladder_only"] else
               "- The Arm3/Arm2 gap is the recall-attributable lift (the ladder alone is Arm2)."),
              "",
              "### Limitations (under-claim)",
              "- **A single held-out repo, not N** - this is one leave-one-out point, not a "
              "distribution. Cross-repo transfer is shown once, not characterized.",
              "- **Coarse shape key** (`auditability | deterministic | arity-bucket | has-inverse`) - "
              "a finer key needs more corpus per cell to stay non-noisy.",
              "- **Coverage = gate-pass = non-vacuity, not correctness** (see claim boundary).",
              "- Arm coverage is reported at budget K with the K=∞ ceiling shown; the lift is "
              "budget-sensitive by design (recall buys *reaching the right strategy within budget*).",
              ""]
    L += ["---", "_Generated by auditor/report.py from the run artifacts._"]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="assemble coverage-recall deliverables")
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--bakeoff", type=Path, default=None)
    ap.add_argument("--corpus", type=Path, default=None)
    ap.add_argument("--holdout", type=Path, default=None)
    ap.add_argument("--holdout-rule", default="held-out = basket repo with the LOWEST baseline "
                    "gate-GREEN coverage, among repos not used to build the auditor.")
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    bk = json.loads(args.bakeoff.read_text()) if args.bakeoff and args.bakeoff.exists() else None
    corpus = json.loads(args.corpus.read_text()) if args.corpus and args.corpus.exists() else None
    ho = json.loads(args.holdout.read_text()) if args.holdout and args.holdout.exists() else None

    chart_rel = "coverage_by_arm.svg"
    if ho:
        svg = _svg_coverage_chart(ho["arms"], ho["held_out_repo"], ho["budget_k"])
        (args.out_dir / chart_rel).write_text(svg)
    md = build_results_md(bk, corpus, ho, holdout_rule=args.holdout_rule, chart_path=chart_rel)
    (args.out_dir / "RESULTS.md").write_text(md)
    print(f"wrote {args.out_dir/'RESULTS.md'}" + (f" + {chart_rel}" if ho else " (no holdout yet)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
