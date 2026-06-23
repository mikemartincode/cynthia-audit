#!/usr/bin/env python3
"""Function-PARALLEL variant of m3_speedab — proves the OOM is orthogonal to the speed lever.

Insight: authoring (the M3 calls) is the SLOW part and is RAM-cheap (holds response strings,
gateway-bound). Gating (run_mutation_gate's mutant-subprocess swarm) is the RAM hog but is FAST
(~2s/fn). So we DON'T parallelize the gate — we serialize EVERY gate through one global lock
(RAM stays at today's safe single-swarm level) while authoring fans out across functions.

Mechanism: monkeypatch auditor.author.gate_authored with a lock-wrapped version (author_best_of_n
calls it as a module global, so the patch takes effect), then run functions in a ThreadPoolExecutor.
func_workers x 8 drafts must stay <= gateway max_parallel (64); default 6 -> ~48 concurrent calls.

GREEN set must reproduce the sequential run (same logic, different schedule) — that's the correctness
check. The metric is TOTAL wall (per-function walls are contention-inflated and not meaningful here).
"""
import argparse
import csv
import json
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auditor.author as A  # noqa: E402

_GATE_LOCK = threading.Lock()
_real_gate = A.gate_authored


def _serial_gate(*a, **k):
    with _GATE_LOCK:  # only ONE mutant-subprocess swarm in flight, ever -> RAM-safe
        return _real_gate(*a, **k)


A.gate_authored = _serial_gate


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--model", default="minimax-m3")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--shape", default="value", choices=("value", "invariant"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--func-workers", type=int, default=6)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text())
    funcs = manifest["functions"][: args.limit] if args.limit else manifest["functions"]
    target = manifest["target"]
    run_dir = Path("results") / f"m3bonpar-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)

    def run_one(entry):
        q = entry["qualname"]; t0 = time.time()
        try:
            rec = A.author_best_of_n(entry, args.model, run_dir, n=args.n, target=target,
                                     shape=args.shape, adaptive_fallback=False)
            errs = [a["error"] for a in rec.attempt_log if "error" in a]
            note = "" if not errs else f"{len(errs)}/{args.n} draft-err: {errs[0][:60]}"
            return q, bool(rec.green), time.time() - t0, note
        except Exception as e:  # noqa: BLE001
            return q, False, time.time() - t0, f"ERR {type(e).__name__}: {e}"[:120]

    wall0 = time.time()
    rows = []
    with ThreadPoolExecutor(max_workers=args.func_workers) as pool:
        futs = [pool.submit(run_one, e) for e in funcs]
        for i, fut in enumerate(as_completed(futs), 1):
            q, green, w, note = fut.result()
            rows.append((q, green, w, note))
            print(f"[{i}/{len(funcs)}] {q}: green={green} fn_wall={w:.0f}s {note}", flush=True)
    total = time.time() - wall0

    args.out.write_text("qualname\tgreen\tfn_wall_s\tnote\n")
    with args.out.open("a") as fh:
        for q, green, w, note in rows:
            fh.write(f"{q}\t{green}\t{w:.1f}\t{note}\n")

    n = len(rows); g = sum(1 for r in rows if r[1])
    fnw = [r[2] for r in rows]
    print("=" * 64, flush=True)
    print(f"M3 best-of-{args.n} think-OFF | PARALLEL (func_workers={args.func_workers}) | {target} | n={n}", flush=True)
    print(f"GREEN: {g}/{n} = {g/n:.3f}   (sequential value run got 3/24=0.125 — must match)", flush=True)
    print(f"TOTAL WALL: {total/60:.1f}min   (sequential value run was 28.6min)", flush=True)
    print(f"per-fn wall (contention-inflated): median={statistics.median(fnw):.0f}s max={max(fnw):.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
