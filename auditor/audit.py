#!/usr/bin/env python3
"""auditor/audit.py — the one-command full audit: author+gate -> differential sweep -> triage,
then an honest REPORT.md. Resumable, hard $-capped across stages, prints running spend.

The pipeline's trust hinges on CROSS-FAMILY independence: the first oracle is authored by one
family (deepseek), the triage second oracle + vote by ANOTHER (minimax-m3). A same-family vote
re-derives the same spec misreading and launders a value divergence into a false "real-bug" — so
the vote model MUST differ from the author model. The default does: author deepseek, vote m3.

A "real-bug" finding here is conservative BY CONSTRUCTION (triage.classify_candidate): only a
library CRASH on a valid input is promoted; every value divergence is bad-oracle / invalid-input /
spec-ambiguity (human review), never an auto-asserted bug. A clean "0 real-bug" pass is therefore a
real result — evidence the tool is a verifier first — not a failure to report.

Usage:
    python auditor/audit.py --target hyperlink [--run-dir results/<id>] \
        [--resume-from results/a03-live] [--author-model deepseek-v4-pro] \
        [--vote-model minimax-m3] [--budget 12] [--limit N]

Env: LITELLM_GATEWAY, LITELLM_KEY (required). --budget overrides AUDIT_BUDGET_USD.
Resume: --resume-from seeds a prior run's records+oracles so authoring is not re-spent; a re-run
with the same --run-dir likewise skips already-authored functions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import run_audit  # noqa: E402
from sweep import run_sweep  # noqa: E402
from triage import SPEC_MODEL, VOTE_MODEL, run_triage  # noqa: E402


def _records(run_dir: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted((run_dir / "records").glob("*.json"))]


def _fmt_input(s: str, n: int = 120) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def write_report(run_dir: Path, manifest: dict, s_sweep: dict, s_tri: dict, real_bugs: list[dict],
                 review_q: list[dict], walls: dict, serial_est_s: float) -> Path:
    recs = _records(run_dir)
    green = [r for r in recs if r.get("green")]
    author_cost = sum(r.get("cost", 0.0) for r in recs)
    total_cost = author_cost + s_tri.get("spent_usd", 0.0)
    summ = manifest.get("summary", {})
    counts = s_tri.get("per_candidate_counts", {})
    wall_total = sum(walls.values())

    L: list[str] = []
    L.append(f"# Audit report — {manifest.get('target')}")
    L.append("")
    L.append(f"- **Target:** `{manifest.get('target')}` @ commit "
             f"`{(manifest.get('commit') or '?')[:10]}`")
    L.append(f"- **Authored by:** `{recs[0]['model'] if recs else '?'}`  ·  "
             f"**Cross-family vote:** `{s_tri.get('vote_model')}`  ·  "
             f"**Spec arbiter:** `{s_tri.get('spec_model')}`")
    L.append(f"- **Functions:** {summ.get('total_public_functions', '?')} public  ·  "
             f"{summ.get('auditable', '?')} auditable (deterministic + spec/invariant basis)")
    L.append(f"- **Oracles gate-GREEN:** {len(green)} / {len(recs)} authored "
             f"(the mutation gate proved each non-vacuous)")
    L.append(f"- **Sweep candidates:** {s_sweep.get('candidates_recorded')} "
             f"(from {s_sweep.get('raw_disagreements')} raw disagreements, "
             f"−{s_sweep.get('filtered_invalid_input')} invalid-input filtered)")
    L.append(f"- **Triaged:** real-bug **{counts.get('real-bug', 0)}** · "
             f"bad-oracle {counts.get('bad-oracle', 0)} · "
             f"invalid-input {counts.get('invalid-input', 0)} · "
             f"spec-ambiguity {counts.get('spec-ambiguity', 0)}")
    L.append(f"- **Cross-family-verified real-bug findings:** "
             f"**{s_tri.get('real_bug_findings', 0)}** "
             f"{s_tri.get('real_bug_by_confidence', {})}")
    L.append(f"- **Human-review queue (spec-ambiguity, not asserted bugs):** "
             f"{s_tri.get('human_review_queue', len(review_q))}")
    L.append(f"- **Spend:** ${total_cost:.4f} total "
             f"(authoring ${author_cost:.4f} + triage ${s_tri.get('spent_usd', 0.0):.4f}); "
             f"cap ${s_tri.get('budget_cap_usd', '?')}, stopped={s_tri.get('budget_stopped')}")
    L.append(f"- **Wall-clock:** {wall_total:.0f}s "
             f"(author {walls.get('author', 0):.0f}s + sweep {walls.get('sweep', 0):.0f}s + "
             f"triage {walls.get('triage', 0):.0f}s); "
             f"sweep fanned across {s_sweep.get('distinct_worker_pids')} worker processes")
    L.append("")

    if real_bugs:
        by_fn: dict[str, int] = {}
        for f in real_bugs:
            by_fn[f["qualname"]] = by_fn.get(f["qualname"], 0) + 1
        L.append("## Real-bug findings (library crashes on a valid input — A07 must reproduce)")
        L.append("")
        L.append(f"{len(real_bugs)} finding(s) across {len(by_fn)} function(s): "
                 + ", ".join(f"`{q}`×{n}" for q, n in sorted(by_fn.items())) + ". Multiple inputs "
                 "under one function are the SAME root cause shown by different minimal triggers — "
                 "count findings by function, not by row.")
        L.append("")
        L.append("Each promotion required a CRASH divergence on a VALID input (never a value "
                 "disagreement) plus corroboration from the cross-family second oracle and/or the "
                 "independent spec re-derivation (`evidence` records which fired; an inconclusive "
                 "cross-family vote still needs spec agreement to promote). Confidence is medium "
                 "pending an independent A07 repro — none is asserted as a confirmed bug here.")
        L.append("")
        for f in real_bugs:
            ev = f.get("evidence", {})
            L.append(f"### `{f['qualname']}`  ({f.get('confidence')})")
            L.append(f"- **Minimal input:** `{_fmt_input(f.get('minimal_input'))}`")
            L.append(f"- **Library result:** `{_fmt_input(f.get('real_result'))}`")
            L.append(f"- **Oracle expected:** `{_fmt_input(f.get('oracle_expected'))}`")
            L.append(f"- **Evidence:** cross-oracle vote `{ev.get('cross_oracle_vote')}` · "
                     f"spec re-derive `{ev.get('spec_rederivation')}` · "
                     f"crash-divergence `{ev.get('is_crash_divergence')}`")
            L.append("")
    else:
        L.append("## No real-bug findings on this pass")
        L.append("")
        L.append(f"An honest, recorded outcome. Across {len(green)} gate-validated oracles and "
                 f"{s_sweep.get('candidates_recorded')} swept candidates, no library CRASH on a "
                 f"valid input survived cross-family triage. The {counts.get('spec-ambiguity', 0)} "
                 f"spec-ambiguity divergences are queued for human review, not asserted as bugs. "
                 f"On this target the tool behaves as a *verifier*, not a *bug-finder*.")
        L.append("")

    L.append("## Method note")
    L.append("")
    L.append("Every number above traces to this run's artifacts: `records/*.json` (authoring + "
             "gate), `sweep/summary.json` (differential sweep), `triage/summary.json` + "
             "`triage/findings.json` (classification). The gate's non-vacuity guarantee is what "
             "lets a cheap model's oracle be trusted without a human reading it; the cross-family "
             "split is what keeps a shared spec-misreading from becoming a false finding.")
    L.append("")
    L.append(f"_Serial author estimate ~{serial_est_s:.0f}s vs {walls.get('author', 0):.0f}s "
             f"parallel; sweep + triage fan across process pools._")
    L.append("")

    out = run_dir / "REPORT.md"
    out.write_text("\n".join(L))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="one-command full audit + honest report")
    ap.add_argument("--target", default="hyperlink")
    ap.add_argument("--manifest", type=Path, default=None)
    ap.add_argument("--run-dir", type=Path, default=None)
    ap.add_argument("--resume-from", type=Path, default=None,
                    help="seed records+oracles from a prior authoring run (skip re-spend)")
    ap.add_argument("--author-model", default="deepseek-v4-pro")
    ap.add_argument("--vote-model", default=VOTE_MODEL)
    ap.add_argument("--spec-model", default=SPEC_MODEL)
    ap.add_argument("--budget", type=float,
                    default=float(os.environ.get("AUDIT_BUDGET_USD", "50")))
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if args.author_model.split("-")[0] == args.vote_model.split("-")[0]:
        print(f"REFUSED: author ({args.author_model}) and vote ({args.vote_model}) share a family — "
              f"cross-family independence is the trust premise. Pick different families.",
              file=sys.stderr)
        return 2

    manifest_path = args.manifest or Path(f"targets/{args.target}/manifest.json")
    manifest = json.loads(manifest_path.read_text())
    run_dir = args.run_dir or Path("results") / f"audit-{args.target}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)

    if args.resume_from:
        for sub in ("records", "oracles"):
            src = args.resume_from / sub
            if src.exists():
                shutil.copytree(src, run_dir / sub, dirs_exist_ok=True)
        print(f"[audit] seeded {len(_records(run_dir))} records from {args.resume_from}", flush=True)

    os.environ["AUDIT_BUDGET_USD"] = str(args.budget)
    walls: dict[str, float] = {}

    # STAGE 1 — author + gate (skips functions that already have a record)
    t = time.time()
    s_auth = asyncio.run(run_audit(manifest, args.author_model, run_dir, limit=args.limit,
                                   concurrency=args.concurrency))
    walls["author"] = time.time() - t
    n_green = len([r for r in _records(run_dir) if r.get("green")])
    print(f"[audit] author+gate: {s_auth['completed']} new this pass, {n_green} green total, "
          f"+${s_auth['spent_usd']:.4f}", flush=True)

    # STAGE 2 — differential sweep (deterministic; process-pool fan-out)
    t = time.time()
    s_sweep = run_sweep(run_dir, run_dir / "sweep")
    walls["sweep"] = time.time() - t
    print(f"[audit] sweep: {s_sweep['green_oracles']} oracles → "
          f"{s_sweep['candidates_recorded']} candidates", flush=True)

    # STAGE 3 — cross-family triage. Cap triage to the budget remaining after authoring.
    author_cost = sum(r.get("cost", 0.0) for r in _records(run_dir))
    os.environ["AUDIT_BUDGET_USD"] = str(max(0.0, args.budget - s_auth["spent_usd"]))
    t = time.time()
    s_tri, real_bugs, review_q = run_triage(run_dir / "sweep" / "candidates.json", run_dir,
                                            manifest_path, run_dir / "triage",
                                            vote_model=args.vote_model, spec_model=args.spec_model)
    walls["triage"] = time.time() - t
    total = author_cost + s_tri.get("spent_usd", 0.0)
    print(f"[audit] triage: {s_tri['real_bug_findings']} real-bug "
          f"{s_tri.get('real_bug_by_confidence', {})}, +${s_tri.get('spent_usd', 0.0):.4f} "
          f"(total ${total:.4f})", flush=True)

    # per-function author wall estimate (median) × count, for the serial-vs-parallel note
    elapsed = [r.get("elapsed", 0.0) for r in _records(run_dir) if r.get("elapsed")]
    serial_est = sum(elapsed)
    report = write_report(run_dir, manifest, s_sweep, s_tri, real_bugs, review_q, walls, serial_est)
    print(f"[audit] REPORT → {report}", flush=True)
    print(f"[audit] DONE: {s_tri['real_bug_findings']} cross-family real-bug finding(s), "
          f"${total:.4f} total spend, {sum(walls.values()):.0f}s wall", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
