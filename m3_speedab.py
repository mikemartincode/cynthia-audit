#!/usr/bin/env python3
"""M3 best-of-N speed x quality A/B driver.

Measures minimax-m3 think-OFF best-of-N as the coverage-recall oracle AUTHOR, to decide
whether it can replace the (paid) deepseek-v4-pro author. Per function it runs
author_best_of_n(model=minimax-m3, n, thinking=disabled) and records
{green, kill_rate, wall_s, out_tok, cost}. Functions run SEQUENTIALLY (the N drafts fan
out in parallel inside), which keeps the mutation-gate subprocess swarm bounded to one
function at a time (the author docstring's OOM guard).

Baseline to beat (deepseek-v4-pro best-of-5, on disk results/ceiling_bon/):
  dateutil 16/87 GREEN (18.4%), ~76min wall, $6.72.

--fallback OFF by default ON PURPOSE: the adaptive reasoning-ON fallback would mask the
pure think-OFF GREEN rate (and balloon wall ~150-200s per RED function). This run measures
the FAST path alone, which is the question.
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auditor.author import author_best_of_n  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--model", default="minimax-m3")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--shape", default="value", choices=("value", "invariant"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--fallback", action="store_true", help="enable the adaptive reasoning-ON fallback")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text())
    funcs = manifest["functions"]
    if args.limit:
        funcs = funcs[: args.limit]
    target = manifest["target"]
    run_dir = Path("results") / f"m3bon-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)

    args.out.write_text("qualname\tgreen\tkill_rate\twall_s\tout_tok\tcost\tnote\n")
    rows = []
    for i, entry in enumerate(funcs, 1):
        q = entry["qualname"]
        t0 = time.time()
        try:
            rec = author_best_of_n(entry, args.model, run_dir, n=args.n, target=target,
                                   shape=args.shape, adaptive_fallback=args.fallback)
            wall = time.time() - t0
            green = bool(rec.green)
            kr = max((a.get("kill_rate", 0.0) for a in rec.attempt_log if "kill_rate" in a), default=0.0)
            out_tok = int(rec.tokens.get("out", 0))
            cost = float(rec.cost)
            note = ""
        except Exception as e:  # noqa: BLE001 — one bad function must not kill the sweep
            wall = time.time() - t0
            green, kr, out_tok, cost, note = False, 0.0, 0, 0.0, f"ERR {type(e).__name__}: {e}"[:140]
        with args.out.open("a") as fh:
            fh.write(f"{q}\t{green}\t{kr:.2f}\t{wall:.1f}\t{out_tok}\t{cost:.5f}\t{note}\n")
        print(f"[{i}/{len(funcs)}] {q}: green={green} kr={kr:.2f} wall={wall:.0f}s "
              f"out={out_tok} {note}", flush=True)
        rows.append((green, wall, out_tok, cost))

    n = len(rows)
    if not n:
        print("no functions", flush=True)
        return 1
    g = sum(1 for r in rows if r[0])
    walls = [r[1] for r in rows]
    print("=" * 64, flush=True)
    print(f"M3 best-of-{args.n} think-OFF (fallback={args.fallback}) | {target} | n={n}", flush=True)
    print(f"GREEN: {g}/{n} = {g / n:.3f}   (deepseek-v4-pro best-of-5 dateutil baseline = 0.184)", flush=True)
    print(f"wall:  median={statistics.median(walls):.0f}s  total={sum(walls) / 60:.1f}min", flush=True)
    print(f"out_tok total={sum(r[2] for r in rows):,}   cost total=${sum(r[3] for r in rows):.4f}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
