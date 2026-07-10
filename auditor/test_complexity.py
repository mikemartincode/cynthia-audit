"""Self-contained proof for auditor/complexity.py - the cost/complexity probe (E05).
No network and no model: planted RED/GREEN control functions prove the probe's detection
power and its noise immunity, then the real (vendored) hyperlink target is probed.

What it demonstrates, end to end (the E05 done-criteria):
  1. DETECTION: a planted quadratic function is flagged `superlinear` with the per-size
     timing curve as evidence (slope ~2, clean R^2, in EVERY trial), and a planted
     catastrophic-backtracking regex is flagged `redos` (runaway vs the benign baseline,
     or the wall bound itself).
  2. NOISE IMMUNITY: a linear scan and a constant-time function are NOT flagged - the
     median-of-k + log-log fit + all-trials rule means constant-factor noise cannot trip
     a finding. This is checked positively, not assumed.
  3. BOUNDED: a function that would run far past the wall is killed at the bound and
     recorded as a logged limit (`bound-hit-unassessed`), never silently hung and never
     promoted without a clean partial fit.
  4. REAL TARGET: >=1 size-scalable hyperlink function is timed across n..8n and reports a
     growth class with the measured curve; the ReDoS shapes run against the regex-bearing
     parser entry point (URL.from_text). The real outcomes are recorded, not asserted -
     "0 complexity candidates" is a valid result for a well-built library.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_complexity.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from complexity import (  # noqa: E402
    GROWTH_TARGETS, REDOS_SHAPES, measure_growth, probe_redos, run_complexity,
)

# ---------------------------------------------------------------- planted controls

def _build_quadratic(n, k):
    """O(n^2): for each char, scan the whole string."""
    payloads = ["ab" * (n // 2) + str(j) for j in range(k)]
    return (lambda s: sum(s.count(c) for c in s)), payloads


def _build_linear(n, k):
    """O(n): a few full scans, constant per char."""
    payloads = ["ab" * (n // 2) + str(j) for j in range(k)]
    return (lambda s: s.count("a") + s.count("b")), payloads


def _build_constant(n, k):
    """O(1): touches only the length, regardless of n."""
    payloads = ["a" * n + str(j) for j in range(k)]
    return len, payloads


def _build_sleeper(n, k):
    """Far slower than any sane wall: proves the bound kills + logs, not hangs."""
    payloads = [n] * k
    return (lambda _: time.sleep(3600)), payloads


_CATASTROPHIC = re.compile(r"^(a+)+$")   # the textbook nested-quantifier ReDoS
_SAFE = re.compile(r"^a*!?$")

def _redos_vulnerable(s):
    return _CATASTROPHIC.match(s)

def _redos_safe(s):
    return _SAFE.match(s)


# ---------------------------------------------------------------- growth: RED / GREEN

def test_growth_red_quadratic():
    """The planted O(n^2) is flagged superlinear, candidate=True, with per-size timings as
    evidence and a slope near 2 in every trial."""
    rec = measure_growth("control.quadratic", "chars", _build_quadratic,
                         base_n=2000, k=5, trials=3, wall_s=60.0)
    assert rec["classification"] == "superlinear", rec
    assert rec["candidate"] is True
    for tr in rec["trials"]:
        assert len(tr["sizes"]) == 4 and len(tr["medians_s"]) == 4, tr
        assert tr["slope"] >= 1.5 and tr["r2"] >= 0.97, tr
    slopes = [t["slope"] for t in rec["trials"]]
    assert all(1.6 <= s <= 2.4 for s in slopes), slopes  # measured ~quadratic
    assert "not an asymptotic proof" in rec["note"], rec["note"]
    print(f"RED growth: quadratic flagged, slopes {slopes}")


def test_growth_green_linear():
    """The planted O(n) is NOT flagged."""
    rec = measure_growth("control.linear", "chars", _build_linear,
                         base_n=4000, k=5, trials=3, wall_s=60.0)
    assert rec["classification"] != "superlinear", rec
    assert rec["candidate"] is False, rec
    print(f"GREEN growth: linear not flagged ({rec['classification']}, "
          f"slopes {[t['slope'] for t in rec['trials']]})")


def test_growth_constant_noise_immunity():
    """O(1) work - pure constant-factor noise across sizes - must never flag. Either the
    flat slope fails the superlinear fit or the floor marks it below-noise; both are
    non-findings."""
    rec = measure_growth("control.constant", "chars", _build_constant,
                         base_n=1000, k=5, trials=3, wall_s=60.0)
    assert rec["classification"] in ("linear", "indeterminate", "below-noise"), rec
    assert rec["candidate"] is False, rec
    print(f"GREEN growth: constant-time not flagged ({rec['classification']})")


def test_growth_bound_kills_and_logs():
    """A call that would run for an hour is killed at the wall and recorded as a logged
    limit - not a hang, and not a finding (no clean partial fit exists)."""
    t0 = time.monotonic()
    rec = measure_growth("control.sleeper", "n", _build_sleeper,
                         base_n=10, k=2, trials=1, wall_s=1.5)
    elapsed = time.monotonic() - t0
    assert elapsed < 10, f"bound did not kill promptly: {elapsed:.1f}s"
    assert rec["classification"] == "bound-hit-unassessed", rec
    assert rec["candidate"] is False
    assert "no finding" in rec["note"], rec["note"]
    print(f"BOUND: sleeper killed at wall in {elapsed:.1f}s, logged, not a finding")


# ---------------------------------------------------------------- redos: RED / GREEN

def test_redos_red_catastrophic():
    """(a+)+$ against 'a'*n + '!' blows up exponentially - the probe must flag runaway,
    either by the abs+ratio rule at a small size or by hitting the wall bound."""
    shapes = {"near-miss": lambda n: "a" * n + "!"}
    rec = probe_redos("control.catastrophic", _redos_vulnerable, shapes,
                      sizes=(18, 20, 22, 24, 26), wall_s=6.0,
                      benign=lambda n: "a" * n)
    assert rec["candidate"] is True, rec
    assert rec["classification"] == "redos"
    assert rec["flagged_shapes"] == ["near-miss"]
    sh = rec["shapes"][0]
    assert sh["bound_hit"] or any(
        r["attack_s"] >= 0.25 and (r["ratio"] or 0) >= 50 for r in sh["timings"]), sh
    print(f"RED redos: catastrophic regex flagged ({sh['note']})")


def test_redos_green_safe():
    """A linear regex over the same shapes never diverges from the baseline."""
    shapes = {"near-miss": lambda n: "a" * n + "!"}
    rec = probe_redos("control.safe", _redos_safe, shapes,
                      sizes=(1024, 4096, 16384), wall_s=6.0,
                      benign=lambda n: "a" * n)
    assert rec["candidate"] is False, rec
    assert rec["classification"] == "no-runaway"
    print("GREEN redos: safe regex not flagged")


# ---------------------------------------------------------------- real hyperlink target

def test_real_hyperlink_growth():
    """>=1 size-scalable hyperlink function is timed across n..8n and reports a growth
    class with the full measured curve attached. The class itself is recorded, not
    presumed - that is the probe doing its job either way."""
    q, ax, build = GROWTH_TARGETS[0]  # URL.from_text / path-segments
    rec = measure_growth(q, ax, build, base_n=128, k=5, trials=2, wall_s=30.0)
    assert rec["qualname"] == "URL.from_text"
    assert rec["classification"] in (
        "linear", "superlinear", "indeterminate", "below-noise"), rec
    for tr in rec["trials"]:
        assert tr["sizes"] == [128, 256, 512, 1024], tr
        assert all(t > 0 for t in tr["medians_s"]), tr
    print(f"REAL: {q} [{ax}] -> {rec['classification']} "
          f"(slopes {[t['slope'] for t in rec['trials']]})")


def test_full_run_writes_outputs():
    """run_complexity covers every registered axis + the ReDoS battery against the real
    parser and writes the four result files with consistent counts."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        s = run_complexity(out, base_n=64, k=3, trials=2, wall_s=20.0)
        for f in ("growth.json", "redos.json", "candidates.json", "summary.json"):
            assert (out / f).exists(), f
        growth = json.loads((out / "growth.json").read_text())
        redos = json.loads((out / "redos.json").read_text())
        cands = json.loads((out / "candidates.json").read_text())
        assert s["growth_probed"] == len(GROWTH_TARGETS) == len(growth)
        assert s["redos_probed"] == len(redos) == 1
        assert len(redos[0]["shapes"]) == len(REDOS_SHAPES)
        assert s["complexity_candidates"] == len(cands)
        assert all(c["classification"] == "complexity" and c["evidence"] for c in cands)
        print(f"FULL RUN: {s['growth_probed']} growth axes {s['growth_by_class']}, "
              f"{s['redos_probed']} redos target x{len(REDOS_SHAPES)} shapes, "
              f"{s['complexity_candidates']} candidates")


def main() -> None:
    test_growth_red_quadratic()
    test_growth_green_linear()
    test_growth_constant_noise_immunity()
    test_growth_bound_kills_and_logs()
    test_redos_red_catastrophic()
    test_redos_green_safe()
    test_real_hyperlink_growth()
    test_full_run_writes_outputs()
    print("test_complexity: OK")


if __name__ == "__main__":
    main()
