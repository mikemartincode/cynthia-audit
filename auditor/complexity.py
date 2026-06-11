#!/usr/bin/env python3
"""auditor/complexity.py — cost/complexity probe: superlinear growth + ReDoS (E05).

Every other probe in this auditor compares VALUES (oracle sweep, real-vs-real differential).
This one measures COST: it times target functions across geometrically scaled input sizes
(n, 2n, 4n, 8n), fits the growth curve, and flags superlinear behavior; and it throws
catastrophic-backtracking attack strings at regex-bearing functions and flags runaway time
against a same-length benign baseline (ReDoS). A `complexity` finding carries the measured
per-size timings as its evidence — the curve IS the claim.

THE HONESTY LINE (timing is noisy; a finding must be a clear, repeated signal):
  * median-of-k per size, after warmup, each timed call on a DISTINCT payload (no
    memoization flattery); sub-resolution calls are re-measured in batches of distinct
    payloads so the per-call estimate stays above timer noise.
  * the growth verdict is a least-squares log-log slope + R^2, and it must hold in EVERY
    one of `trials` independent re-measurements (fresh process each) — a single slow trial
    never flags. Constant-factor noise has slope ~0 and fails the fit; it cannot trip this.
  * reported as MEASURED growth over the probed range ("superlinear on n..8n, slope=2.0"),
    never an asymptotic proof. "consistent with quadratic" only when every trial's slope
    lands in the quadratic band.
  * a function whose largest-size median is still below ASSESS_FLOOR_S is recorded
    `below-noise` (too fast to assess at the bounded sizes) — honestly unassessed, never
    extrapolated into a finding.

BOUNDED BY CONSTRUCTION: each trial runs in a forked child that STREAMS one result per size
through a pipe; the parent enforces a wall-clock bound and kills the child on breach, keeping
the partial per-size data already received. A genuinely-exponential function therefore cannot
hang the run — the breach is logged as `bound-hit`, and it promotes to a candidate only when
the partial curve ALREADY shows a clean superlinear fit (>=3 sizes); otherwise it stays
`bound-hit-unassessed` (a logged limit, not a finding).

ReDoS RULE: an attack string flags only if (a) the bounded child never finished (runaway so
bad the wall died), or (b) a single call took >= REDOS_ABS_S AND was >= REDOS_RATIO x the
same-length benign baseline. The baseline comparison is what separates "this regex
backtracks catastrophically on THIS shape" from "this function is slow on every 64KB input"
— the latter is the growth probe's business, not a ReDoS finding.

Like differential.py, this is a separate module rather than a mode on sweep.py on purpose:
the sweep is built around oracle calling-conventions and value equality; a cost probe has
neither. It shares only the target (vendored hyperlink) and the results-dir convention.

Usage:
    python auditor/complexity.py [--out results/e05-complexity] [--base-n 128]
        [--trials 3] [--k 7] [--wall 30]

Linux-only (uses the fork start method so closures cross into children unpickled).
"""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import sys
import time
from pathlib import Path
from statistics import median

# the target lives under the vendored repo, imported by absolute path (never an installed
# copy) — same rule as adapters.py.
_REPO_SRC = str((Path(__file__).resolve().parent.parent / "targets/hyperlink/repo/src"))
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

from hyperlink import URL  # noqa: E402

# ---------------------------------------------------------------- tunables

MIN_RELIABLE_S = 5e-5     # per-call medians below this are re-measured in batches
ASSESS_FLOOR_S = 2e-5     # largest-size median below this => below-noise, unassessed
SUPERLINEAR_SLOPE = 1.5   # log-log slope at/above this (every trial) => superlinear
LINEAR_SLOPE = 1.3        # below this (every trial) => linear-ish; between => indeterminate
FIT_R2_MIN = 0.97         # a flagging fit must be clean, not a noise cloud
QUADRATIC_BAND = (1.8, 2.2)  # "consistent with quadratic" only inside this, every trial

REDOS_ABS_S = 0.25        # a single attack call at/above this is runaway-slow...
REDOS_RATIO = 50.0        # ...if also this many times the same-length benign baseline
REDOS_SIZES = (1024, 4096, 16384, 65536)
REDOS_REPS = 3            # median-of-3 per (shape, size) — attack calls can be SLOW


# ---------------------------------------------------------------- bounded child harness

def _run_bounded(target, args, wall_s: float):
    """Fork a child running target(*args, conn); collect streamed messages until 'done' or
    the wall expires. Returns (messages, bound_hit). The child is killed on breach; messages
    already streamed survive — that partial data is the point of streaming."""
    ctx = mp.get_context("fork")
    rd, wr = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=target, args=(*args, wr), daemon=True)
    proc.start()
    wr.close()
    msgs: list = []
    bound_hit = False
    deadline = time.monotonic() + wall_s
    done = False
    while not done:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            bound_hit = True
            break
        if rd.poll(min(remaining, 0.05)):
            try:
                m = rd.recv()
            except EOFError:  # child died without 'done' (crash) — keep what we have
                break
            if m == "done":
                done = True
            else:
                msgs.append(m)
        elif not proc.is_alive():
            # drain anything that landed between the last poll and death
            while rd.poll(0):
                try:
                    m = rd.recv()
                except EOFError:
                    break
                if m == "done":
                    done = True
                else:
                    msgs.append(m)
            break
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        if proc.is_alive():  # pragma: no cover - terminate is normally enough
            proc.kill()
            proc.join()
    else:
        proc.join()
    rd.close()
    return msgs, bound_hit


# ---------------------------------------------------------------- growth probe

def _measure_size(build, n: int, k: int) -> float:
    """Median per-call seconds of fn over k DISTINCT payloads at size n (1 warmup payload).
    Payload construction is OUTSIDE the timed region by design: build() returns ready
    arguments and only fn(payload) is timed."""
    fn, payloads = build(n, k + 1)
    fn(payloads[0])  # warmup
    ts = []
    for p in payloads[1:]:
        t0 = time.perf_counter()
        fn(p)
        ts.append(time.perf_counter() - t0)
    med = median(ts)
    if med < MIN_RELIABLE_S:
        # too fast for single-call resolution: time batches of r distinct payloads each
        r = max(2, min(256, int(MIN_RELIABLE_S * 4 / max(med, 1e-9))))
        fn, payloads = build(n, r * k)
        ts = []
        for g in range(k):
            grp = payloads[g * r:(g + 1) * r]
            t0 = time.perf_counter()
            for p in grp:
                fn(p)
            ts.append((time.perf_counter() - t0) / r)
        med = median(ts)
    return med


def _child_growth(build, sizes, k, conn):
    for n in sizes:
        conn.send(("size", n, _measure_size(build, n, k)))
    conn.send("done")
    conn.close()


def _fit_loglog(sizes: list[int], meds: list[float]) -> tuple[float, float]:
    """Least-squares slope + R^2 in log-log space. slope ~1 linear, ~2 quadratic."""
    xs = [math.log(s) for s in sizes]
    ys = [math.log(max(t, 1e-9)) for t in meds]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx if sxx else 0.0
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (my + slope * (x - mx))) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 - ss_res / ss_tot if ss_tot else 1.0
    return slope, r2


def measure_growth(qualname: str, axis: str, build, *, base_n: int = 128, n_sizes: int = 4,
                   k: int = 7, trials: int = 3, wall_s: float = 30.0) -> dict:
    """Time build's function across base_n * (1,2,4,...) in `trials` independent bounded
    children; classify the aggregate. Returns the full growth record (a JSON-able dict)."""
    sizes = [base_n * (2 ** i) for i in range(n_sizes)]
    trial_recs: list[dict] = []
    any_bound = False
    for _ in range(trials):
        msgs, bound_hit = _run_bounded(_child_growth, (build, sizes, k), wall_s)
        any_bound = any_bound or bound_hit
        got = [(n, t) for tag, n, t in msgs if tag == "size"]
        tr = {"sizes": [n for n, _ in got], "medians_s": [round(t, 7) for _, t in got],
              "bound_hit": bound_hit, "slope": None, "r2": None}
        if len(got) >= 3:
            slope, r2 = _fit_loglog([n for n, _ in got], [t for _, t in got])
            tr["slope"], tr["r2"] = round(slope, 3), round(r2, 4)
        trial_recs.append(tr)

    fitted = [t for t in trial_recs if t["slope"] is not None]
    rec = {"qualname": qualname, "axis": axis, "probe": "growth",
           "sizes_requested": sizes, "k": k, "trials": trial_recs,
           "classification": "indeterminate", "candidate": False, "note": ""}

    if any_bound:
        # partial curves only promote when they ALREADY show a clean superlinear fit.
        if fitted and all(t["slope"] >= SUPERLINEAR_SLOPE and t["r2"] >= FIT_R2_MIN
                          for t in fitted) and len(fitted) == len(trial_recs):
            rec["classification"] = "superlinear"
            rec["candidate"] = True
            rec["note"] = (f"wall bound {wall_s}s hit; partial curve still fits superlinear "
                           f"in all {len(fitted)} trials")
        else:
            rec["classification"] = "bound-hit-unassessed"
            rec["note"] = (f"wall bound {wall_s}s hit before a full curve; partial data kept, "
                           "no finding (a logged limit, not evidence)")
        return rec

    if len(fitted) < len(trial_recs):
        rec["note"] = "a trial returned <3 sizes without a bound hit (child crash?)"
        return rec
    if all(t["medians_s"][-1] < ASSESS_FLOOR_S for t in trial_recs):
        rec["classification"] = "below-noise"
        rec["note"] = (f"largest-size median under {ASSESS_FLOOR_S}s in every trial — too "
                       "fast to assess at these sizes; honestly unassessed")
        return rec

    slopes = [t["slope"] for t in trial_recs]
    if all(s >= SUPERLINEAR_SLOPE for s in slopes) and \
       all(t["r2"] >= FIT_R2_MIN for t in trial_recs):
        rec["classification"] = "superlinear"
        rec["candidate"] = True
        lo, hi = QUADRATIC_BAND
        shape = ("consistent with quadratic" if all(lo <= s <= hi for s in slopes)
                 else "superlinear (shape beyond the quadratic band or mixed)")
        rec["note"] = (f"slope {min(slopes)}..{max(slopes)} across {len(slopes)} trials on "
                       f"n={sizes[0]}..{sizes[-1]}; {shape}. Measured growth on this range, "
                       "not an asymptotic proof.")
    elif all(s < LINEAR_SLOPE for s in slopes):
        rec["classification"] = "linear"
        rec["note"] = f"slope {min(slopes)}..{max(slopes)} across {len(slopes)} trials"
    else:
        rec["note"] = (f"slopes {sorted(slopes)} straddle the thresholds or fit poorly — "
                       "not a clear repeated signal, so not flagged")
    return rec


# ---------------------------------------------------------------- ReDoS probe

def _child_redos(fn, attack, benign, sizes, conn):
    for n in sizes:
        a, b = attack(n), benign(n)
        _t1(fn, b)  # warmup on the benign shape (exception-tolerant like the timed calls)
        bt = median([_t1(fn, b) for _ in range(REDOS_REPS)])
        at = median([_t1(fn, a) for _ in range(REDOS_REPS)])
        conn.send(("size", n, at, bt))
    conn.send("done")
    conn.close()


def _t1(fn, x) -> float:
    t0 = time.perf_counter()
    try:
        fn(x)
    except Exception:  # noqa: BLE001 - a rejecting parse still spends the time we measure
        pass
    t1 = time.perf_counter()
    return t1 - t0


def probe_redos(qualname: str, fn, shapes: dict, *, sizes=REDOS_SIZES,
                wall_s: float = 10.0, benign=None) -> dict:
    """Throw each attack shape at fn across sizes, each shape in its own bounded child,
    timing attack vs a same-length benign baseline. Returns the redos record."""
    if benign is None:
        benign = lambda n: "http://h/" + "a" * max(0, n - 9)  # noqa: E731
    shape_recs: list[dict] = []
    for name, attack in shapes.items():
        msgs, bound_hit = _run_bounded(_child_redos, (fn, attack, benign, list(sizes)), wall_s)
        rows = [{"size": n, "attack_s": round(at, 6), "benign_s": round(bt, 6),
                 "ratio": round(at / bt, 1) if bt > 0 else None}
                for tag, n, at, bt in msgs if tag == "size"]
        slow = [r for r in rows
                if r["attack_s"] >= REDOS_ABS_S and (r["ratio"] or 0) >= REDOS_RATIO]
        runaway = bound_hit or bool(slow)
        if bound_hit:
            why = (f"wall bound {wall_s}s hit at "
                   f"size>{rows[-1]['size'] if rows else sizes[0]} — runaway backtracking")
        elif slow:
            w = slow[0]
            why = (f"attack {w['attack_s']}s vs benign {w['benign_s']}s at size {w['size']} "
                   f"(x{w['ratio']}, thresholds {REDOS_ABS_S}s / x{REDOS_RATIO})")
        else:
            why = "attack tracked the benign baseline at every size"
        shape_recs.append({"shape": name, "example": repr(attack(min(sizes)))[:80],
                           "timings": rows, "bound_hit": bound_hit,
                           "runaway": runaway, "note": why})
    flagged = [s for s in shape_recs if s["runaway"]]
    return {"qualname": qualname, "probe": "redos", "sizes": list(sizes),
            "shapes": shape_recs, "candidate": bool(flagged),
            "classification": "redos" if flagged else "no-runaway",
            "flagged_shapes": [s["shape"] for s in flagged]}


# ---------------------------------------------------------------- hyperlink targets

# Growth axes: each builder returns (fn, [payload]*k) with construction OUTSIDE the timed
# call. Payloads vary trivially so no call can be served by interning/caching.

def _gt_parse_segments(n, k):
    base = "http://h/" + "/".join(f"s{i}" for i in range(n))
    payloads = [base + f"/x{j}" for j in range(k)]
    return URL.from_text, payloads


def _gt_parse_query(n, k):
    base = "http://h/p?" + "&".join(f"k{i}=v{i}" for i in range(n))
    payloads = [base + f"&z={j}" for j in range(k)]
    return URL.from_text, payloads


def _gt_normalize_dots(n, k):
    payloads = [URL.from_text("http://h/" + "a/../" * n + f"x{j}") for j in range(k)]
    return (lambda u: u.normalize()), payloads


def _gt_to_uri_unicode(n, k):
    payloads = [URL.from_text("http://h/" + "/".join("café" for _ in range(n)) + f"/x{j}")
                for j in range(k)]
    return (lambda u: u.to_uri()), payloads


def _gt_to_text_segments(n, k):
    payloads = [URL.from_text("http://h/" + "/".join(f"s{i}" for i in range(n)) + f"/x{j}")
                for j in range(k)]
    return (lambda u: u.to_text()), payloads


def _gt_click_dotdot(n, k):
    base = URL.from_text("http://h/" + "/".join(f"s{i}" for i in range(n)) + "/")
    payloads = [(base, "../" * n + f"x{j}") for j in range(k)]
    return (lambda p: p[0].click(p[1])), payloads


GROWTH_TARGETS = [
    ("URL.from_text", "path-segments", _gt_parse_segments),
    ("URL.from_text", "query-params", _gt_parse_query),
    ("URL.normalize", "dot-segments", _gt_normalize_dots),
    ("URL.to_uri", "unicode-segments", _gt_to_uri_unicode),
    ("URL.to_text", "path-segments", _gt_to_text_segments),
    ("URL.click", "dotdot-href", _gt_click_dotdot),
]

# ReDoS attack shapes for the URL grammar's regexes (_URL_RE / _AUTHORITY_RE / _SCHEME_RE):
# long runs that sit inside overlapping character classes, near-miss terminators, repeated
# authority separators, unclosed IPv6 brackets, percent storms.
REDOS_SHAPES = {
    "no-colon-run": lambda n: "a" * n,
    "colon-at-end": lambda n: "a" * (n - 1) + ":",
    "userinfo-seps": lambda n: "//" + "a@" * (n // 2),
    "port-colons": lambda n: "//h" + ":" * (n - 3),
    "unclosed-ipv6": lambda n: "//[" + "a" * (n - 3),
    "percent-storm": lambda n: "http://h/" + "%" * (n - 9),
    "query-amps": lambda n: "http://h/?" + "&" * (n - 10),
    "alternating-colon": lambda n: "a:" * (n // 2),
}

REDOS_TARGETS = [("URL.from_text", URL.from_text)]


# ---------------------------------------------------------------- driver

def run_complexity(out_dir: Path, *, base_n: int = 128, k: int = 7, trials: int = 3,
                   wall_s: float = 30.0, growth_targets=None, redos_targets=None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    growth = [measure_growth(q, ax, b, base_n=base_n, k=k, trials=trials, wall_s=wall_s)
              for q, ax, b in (growth_targets or GROWTH_TARGETS)]
    redos = [probe_redos(q, fn, REDOS_SHAPES, wall_s=wall_s)
             for q, fn in (redos_targets or REDOS_TARGETS)]

    candidates = (
        [{"qualname": g["qualname"], "probe": "growth", "axis": g["axis"],
          "classification": "complexity", "note": g["note"],
          "evidence": {"trials": g["trials"]}} for g in growth if g["candidate"]]
        + [{"qualname": r["qualname"], "probe": "redos",
            "classification": "complexity",
            "note": f"runaway shapes: {', '.join(r['flagged_shapes'])}",
            "evidence": {"shapes": [s for s in r["shapes"] if s["runaway"]]}}
           for r in redos if r["candidate"]]
    )
    summary = {
        "growth_probed": len(growth),
        "growth_by_class": {c: sum(1 for g in growth if g["classification"] == c)
                            for c in sorted({g["classification"] for g in growth})},
        "redos_probed": len(redos),
        "redos_shapes_per_function": len(REDOS_SHAPES),
        "redos_flagged": sum(1 for r in redos if r["candidate"]),
        "complexity_candidates": len(candidates),
        "params": {"base_n": base_n, "k": k, "trials": trials, "wall_s": wall_s},
    }
    (out_dir / "growth.json").write_text(json.dumps(growth, indent=2) + "\n")
    (out_dir / "redos.json").write_text(json.dumps(redos, indent=2) + "\n")
    (out_dir / "candidates.json").write_text(json.dumps(candidates, indent=2) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="cost/complexity probe: growth + ReDoS")
    ap.add_argument("--out", type=Path, default=Path("results/e05-complexity"))
    ap.add_argument("--base-n", type=int, default=128)
    ap.add_argument("--k", type=int, default=7)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--wall", type=float, default=30.0)
    args = ap.parse_args()
    s = run_complexity(args.out, base_n=args.base_n, k=args.k, trials=args.trials,
                       wall_s=args.wall)
    print(json.dumps(s, indent=2))
    growth = json.loads((args.out / "growth.json").read_text())
    for g in growth:
        sl = [t["slope"] for t in g["trials"] if t["slope"] is not None]
        print(f"  {g['qualname']} [{g['axis']}]: {g['classification']}"
              + (f" (slopes {sl})" if sl else ""))
    redos = json.loads((args.out / "redos.json").read_text())
    for r in redos:
        print(f"  {r['qualname']} [redos x{len(r['shapes'])} shapes]: {r['classification']}")
    n = s["complexity_candidates"]
    print(f"{n} complexity candidate(s)" if n else
          "0 complexity candidates (a valid, recorded outcome)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
