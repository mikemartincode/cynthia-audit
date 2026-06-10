#!/usr/bin/env python3
"""auditor/sweep.py — differential sweep of the REAL hyperlink code against every
gate-GREEN oracle from A03, with an invalid-input filter.

The gate (cynthia-core mutation gate, A02/A03) proved each GREEN oracle's `check_impl` has
TEETH: it kills mutants and its `REFERENCE_FUNC` passes it. That makes the oracle a
non-vacuous, independent encoding of the function's spec. This sweep is where the real
library finally meets that oracle and a candidate discrepancy either falls out or doesn't.

Two comparison fronts, both routed through a per-function adapter (auditor/adapters.py) that
calls the real code in the oracle's one-argument convention:

  1. PROBE REPLAY (strong evidence). Run the oracle's own `check_impl(adapter)`. Each FAIL is
     the real code disagreeing with a mutation-PROVEN spec expectation on the author's
     hand-picked edge inputs.
  2. GENERATED DIFF (medium evidence). Over an adversarial generated input set
     (auditor/strategies.py), compare `REFERENCE_FUNC(x)` vs `adapter(x)`. Here the reference
     is an extended oracle (mutation-validated only on the probes), so these are weaker.

FIDELITY GATE first. An adapter is only a valid bridge if it reproduces the oracle's
mutation-proven probe expectations. We compute probe pass-rate = check_impl(adapter)
pass fraction; an oracle below FIDELITY_MIN is an UNMAPPABLE representation mismatch (the
oracle chose an output encoding structurally different from the real API — e.g. a path tuple
with a leading empty segment). Those are recorded as excluded coverage and produce NO
candidates: counting their pervasive encoding disagreements as bugs would be dishonest.

INVALID-INPUT FILTER. A disagreement where the REAL code raised `ValueError`/`URLParseError`
is the library correctly rejecting a spec-invalid input — tagged `invalid-input`, not a
divergence. A real raise that is NOT a ValueError but DID originate inside the library
(e.g. `NotImplementedError` from `URL.click`) is kept as a `divergence` (the library crashing
where the spec wants a value is a real candidate). An exception that never reached the
library (the adapter's own unpacking) is `adapter-error` and excluded from findings.

"0 surviving candidate divergences" is a valid, recorded outcome — this tool is a verifier
first; whether it is also a bug-finder is exactly what the sweep measures.

Parallel: one process per oracle (embarrassingly parallel, CPU-bound). Spot-check it is not
serial via the printed per-worker pids + the wall-clock vs summed-elapsed in the summary.

Usage:
    python auditor/sweep.py --records results/a03-live --out results/a03-live/sweep \
        [--cap 400] [--max-record 25] [--workers N]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adapters import ADAPTERS, OBSERVABLE, BridgeInapplicable, _REPO_SRC  # noqa: E402
from strategies import CONVENTION, DEFAULT_CAP, strategy_for  # noqa: E402

FIDELITY_MIN = 0.5  # an adapter must reproduce >=50% of mutation-proven probes to be a bridge


# ---------------------------------------------------------------- call + classify

def _load_oracle(path: str):
    name = Path(path).stem
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _from_library(exc: BaseException) -> bool:
    tb = exc.__traceback__
    while tb is not None:
        if _REPO_SRC in (tb.tb_frame.f_code.co_filename or ""):
            return True
        tb = tb.tb_next
    return False


def _call(fn, x):
    """(ok, value, exc, from_library)."""
    try:
        return (True, fn(x), None, False)
    except Exception as exc:  # noqa: BLE001 — every failure mode is data for classification
        return (False, None, exc, _from_library(exc))


def _reduce(qual, value):
    obs = OBSERVABLE.get(qual)
    return obs(value) if obs else value


def _reduce_repr(qual, value):
    """repr() of the observed value, never raising — a finding record must always serialize."""
    try:
        return repr(_reduce(qual, value))
    except Exception as exc:  # noqa: BLE001
        return f"<unreprable {type(value).__name__}: {type(exc).__name__}>"


def _equal(qual, a, b, key) -> bool:
    try:
        ra, rb = _reduce(qual, a), _reduce(qual, b)
    except Exception:  # noqa: BLE001 — an observable that can't reduce => treat as differing
        return False
    try:
        if key:
            return key(ra) == key(rb)
        return ra == rb
    except Exception:  # noqa: BLE001
        return repr(ra) == repr(rb)


def _short(s: str, n: int = 200) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def classify(qual, x, adapter, ref, key):
    """Return a candidate dict, or None if real and oracle agree.

    classification ∈ {divergence, invalid-input, adapter-error}."""
    r_ok, r_val, r_exc, r_lib = _call(adapter, x)
    o_ok, o_val, o_exc, _ = _call(ref, x)

    def rec(cls, real_repr, oracle_repr, note=""):
        return {"qualname": qual, "input": _short(repr(x)),
                "real_result": _short(real_repr), "oracle_expected": _short(oracle_repr),
                "classification": cls, "note": note}

    if not r_ok:
        # the argument didn't fit the oracle's invented tuple convention — a bridge artifact
        # (the oracle's non-tuple-rejection probe), never a real-code finding.
        if isinstance(r_exc, BridgeInapplicable):
            return rec("adapter-error", f"RAISED {type(r_exc).__name__}: {r_exc}",
                       "n/a", note="input does not fit the oracle's calling convention")
        # real raised. ValueError/URLParseError => library rejected the value as invalid;
        # TypeError from inside the library => library rejected a wrong-TYPE input. Both are
        # the real code correctly refusing a spec-invalid input, not a divergence.
        if isinstance(r_exc, ValueError) or (isinstance(r_exc, TypeError) and r_lib):
            if o_ok:
                return rec("invalid-input", f"RAISED {type(r_exc).__name__}: {r_exc}",
                           _reduce_repr(qual, o_val))
            return None  # both reject => agreement
        if r_lib:
            # a non-ValueError/TypeError raised INSIDE the library (e.g. NotImplementedError) —
            # a real crash where the spec wants a value, IF the oracle produced one.
            if o_ok:
                return rec("divergence", f"RAISED {type(r_exc).__name__}: {r_exc}",
                           _reduce_repr(qual, o_val),
                           note=f"library raised {type(r_exc).__name__}")
            return None
        # exception never reached the library => adapter/bridge fault, not a finding.
        return rec("adapter-error", f"RAISED {type(r_exc).__name__}: {r_exc}",
                   "n/a", note="exception did not originate in target library")

    # real returned a value.
    if not o_ok:
        # real accepts what the oracle rejects — a candidate (real may be too lenient).
        return rec("divergence", _reduce_repr(qual, r_val),
                   f"RAISED {type(o_exc).__name__}: {o_exc}",
                   note="oracle rejects, real accepts")

    if _equal(qual, r_val, o_val, key):
        return None
    return rec("divergence", _reduce_repr(qual, r_val), _reduce_repr(qual, o_val))


# ---------------------------------------------------------------- per-oracle worker

def sweep_one(qualname: str, oracle_path: str, cap: int, max_record: int) -> dict:
    """Process-pool task: fidelity-gate one oracle, then collect probe + generated
    candidates. Returns a JSON-able per-oracle record."""
    t0 = time.time()
    pid = os.getpid()
    out = {"qualname": qualname, "pid": pid, "oracle_path": oracle_path,
           "mappable": False, "fidelity": 0.0, "probe_pass": 0, "probe_n": 0,
           "convention": CONVENTION.get(qualname), "generated": 0, "gen_capped": False,
           "raw_disagreements": 0, "invalid_input": 0, "adapter_error": 0,
           "divergences": 0, "div_probe": 0, "div_generated": 0,
           "candidates": [], "note": ""}
    try:
        m = _load_oracle(oracle_path)
    except Exception as exc:  # noqa: BLE001
        out["note"] = f"oracle import failed: {type(exc).__name__}: {exc}"
        out["elapsed"] = round(time.time() - t0, 2)
        return out
    # the registry is the primary bridge source; an oracle may also self-describe its bridge
    # via a module-level `ADAPTER` (and `GEN_INPUTS`), which keeps the bridge with the oracle
    # and lets a self-contained oracle be swept without a registry entry.
    adapter = ADAPTERS.get(qualname) or getattr(m, "ADAPTER", None)
    if adapter is None:
        out["note"] = "no adapter registered or module-defined"
        out["elapsed"] = round(time.time() - t0, 2)
        return out

    ref = m.REFERENCE_FUNC
    key = getattr(m, "EQUIV_KEY", None)
    probes = list(getattr(m, "PROBE_INPUTS", []))

    # FIDELITY GATE — check_impl(adapter) pass-rate over the mutation-proven probes.
    try:
        graded = m.check_impl(adapter)
        probe_pass = sum(1 for ok, _ in graded if ok)
        probe_n = len(graded)
    except Exception as exc:  # noqa: BLE001 — a bridge that crashes check_impl is unmappable
        out["note"] = f"check_impl(adapter) raised: {type(exc).__name__}: {exc}"
        out["elapsed"] = round(time.time() - t0, 2)
        return out
    out["probe_pass"], out["probe_n"] = probe_pass, probe_n
    out["fidelity"] = round(probe_pass / probe_n, 3) if probe_n else 0.0
    if probe_n == 0 or out["fidelity"] < FIDELITY_MIN:
        out["note"] = ("UNMAPPABLE: adapter reproduces only "
                       f"{probe_pass}/{probe_n} mutation-proven probes — the oracle's output "
                       "representation is structurally incompatible with the real API; "
                       "excluded from divergence counting")
        out["elapsed"] = round(time.time() - t0, 2)
        return out
    out["mappable"] = True

    cands: list[dict] = []
    raw = inval = adpt = diverg = div_probe = div_gen = 0
    recorded = {"divergence": 0, "invalid-input": 0, "adapter-error": 0}

    def consider(x, source):
        nonlocal raw, inval, adpt, diverg, div_probe, div_gen
        c = classify(qualname, x, adapter, ref, key)
        if c is None:
            return
        raw += 1
        cls = c["classification"]
        if cls == "invalid-input":
            inval += 1
        elif cls == "adapter-error":
            adpt += 1
        else:
            diverg += 1
            if source == "probe":
                div_probe += 1
            else:
                div_gen += 1
        if recorded[cls] < max_record:
            recorded[cls] += 1
            c["source"] = source
            cands.append(c)

    # PROBE REPLAY — authoritative (check_impl is the gated grader). Emit a candidate for
    # every probe check_impl rejects, classified via the same real-vs-oracle logic.
    for i, x in enumerate(probes):
        if i < len(graded) and graded[i][0]:
            continue  # check_impl passed real on this probe
        consider(x, "probe")

    # GENERATED DIFF — adversarial inputs, deduped against the probes already replayed.
    # Registered conventions use the strategy generators; a self-describing oracle may carry
    # its own `GEN_INPUTS` list instead.
    seen = {repr(p) for p in probes}
    if CONVENTION.get(qualname):
        gen, _total, capped = strategy_for(qualname, cap=cap)
    else:
        gen, capped = list(getattr(m, "GEN_INPUTS", [])), False
    out["gen_capped"] = capped
    n_gen = 0
    for x in gen:
        if repr(x) in seen:
            continue
        n_gen += 1
        consider(x, "generated")
    out["generated"] = n_gen

    out["raw_disagreements"] = raw
    out["invalid_input"] = inval
    out["adapter_error"] = adpt
    out["divergences"] = diverg
    out["div_probe"] = div_probe
    out["div_generated"] = div_gen
    out["candidates"] = cands
    out["elapsed"] = round(time.time() - t0, 2)
    return out


# ---------------------------------------------------------------- driver

def run_sweep(records_dir: Path, out_dir: Path, *, cap: int = DEFAULT_CAP,
              max_record: int = 25, workers: int | None = None) -> dict:
    green = []
    for rp in sorted((records_dir / "records").glob("*.json")):
        rec = json.loads(rp.read_text())
        if rec.get("green"):
            green.append((rec["qualname"], rec["oracle_path"]))
    out_dir.mkdir(parents=True, exist_ok=True)
    workers = workers or max(2, (os.cpu_count() or 4) - 2)

    t0 = time.time()
    results: list[dict] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(sweep_one, q, op, cap, max_record): q for q, op in green}
        for fut in futs:
            results.append(fut.result())
    wall = time.time() - t0
    results.sort(key=lambda r: r["qualname"])

    mappable = [r for r in results if r["mappable"]]
    unmappable = [r for r in results if not r["mappable"]]
    # candidates.json holds only true candidates (divergence | invalid-input); adapter-error
    # entries are bridge artifacts, kept in per_oracle.json for debugging but never findings.
    all_cands = [c for r in mappable for c in r["candidates"]
                 if c["classification"] != "adapter-error"]
    summary = {
        "records_dir": str(records_dir),
        "green_oracles": len(green),
        "swept_mappable": len(mappable),
        "excluded_unmappable": len(unmappable),
        "unmappable_qualnames": [r["qualname"] for r in unmappable],
        "total_generated_inputs": sum(r["generated"] for r in mappable),
        "any_gen_capped": any(r["gen_capped"] for r in mappable),
        "raw_disagreements": sum(r["raw_disagreements"] for r in mappable),
        "filtered_invalid_input": sum(r["invalid_input"] for r in mappable),
        "filtered_adapter_error": sum(r["adapter_error"] for r in mappable),
        "surviving_divergences": sum(r["divergences"] for r in mappable),
        "divergences_probe_strong": sum(r["div_probe"] for r in mappable),
        "divergences_generated_weak": sum(r["div_generated"] for r in mappable),
        "divergence_qualnames": sorted({r["qualname"] for r in mappable if r["divergences"]}),
        "probe_divergence_qualnames": sorted({r["qualname"] for r in mappable if r["div_probe"]}),
        "wall_clock_s": round(wall, 1),
        "sum_worker_elapsed_s": round(sum(r["elapsed"] for r in results), 1),
        "workers": workers,
        "candidates_recorded": len(all_cands),
        "pids": sorted({r["pid"] for r in results}),
    }
    # parallelism evidence: distinct worker PIDs prove the work fanned across processes.
    # A wall-clock speedup is only meaningful when the run is long enough to measure; this
    # 27-oracle target completes sub-second, so report the speedup only above a 0.5s floor.
    summary["distinct_worker_pids"] = len(summary["pids"])
    summary["parallel_speedup_x"] = (round(summary["sum_worker_elapsed_s"] / wall, 1)
                                     if wall >= 0.5 else None)
    (out_dir / "per_oracle.json").write_text(json.dumps(results, indent=2) + "\n")
    (out_dir / "candidates.json").write_text(json.dumps(all_cands, indent=2) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="differential sweep: real code vs gate-proven oracles")
    ap.add_argument("--records", type=Path, default=Path("results/a03-live"))
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--cap", type=int, default=DEFAULT_CAP)
    ap.add_argument("--max-record", type=int, default=25)
    ap.add_argument("--workers", type=int, default=0)
    args = ap.parse_args()
    out_dir = args.out or (args.records / "sweep")
    s = run_sweep(args.records, out_dir, cap=args.cap, max_record=args.max_record,
                  workers=args.workers or None)
    print(json.dumps(s, indent=2))
    print(f"\n{s['green_oracles']} gate-GREEN oracles | "
          f"{s['swept_mappable']} swept, {s['excluded_unmappable']} excluded (unmappable)")
    print(f"{s['total_generated_inputs']} generated inputs"
          + (" (CAP TRUNCATED some functions)" if s["any_gen_capped"] else ""))
    print(f"{s['raw_disagreements']} raw disagreements -> "
          f"{s['filtered_invalid_input']} invalid-input, "
          f"{s['filtered_adapter_error']} adapter-error filtered -> "
          f"{s['surviving_divergences']} surviving candidate divergences")
    print(f"  evidence split: {s['divergences_probe_strong']} STRONG (mutation-proven probe "
          f"inputs) + {s['divergences_generated_weak']} WEAK (generated, ref-as-extended-oracle)")
    speed = (f"~{s['parallel_speedup_x']}x" if s["parallel_speedup_x"]
             else "sub-second; speedup not meaningfully measurable at this size")
    print(f"parallel: {s['workers']} workers across {s['distinct_worker_pids']} distinct "
          f"PIDs {s['pids']}, wall {s['wall_clock_s']}s vs summed "
          f"{s['sum_worker_elapsed_s']}s ({speed})")
    if s["surviving_divergences"]:
        print(f"divergences in: {', '.join(s['divergence_qualnames'])}")
    else:
        print("0 surviving candidate divergences (a valid, recorded outcome)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
