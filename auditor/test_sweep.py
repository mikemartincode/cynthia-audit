"""Self-contained proof for auditor/sweep.py - no network and no live A03 run required (the
target clone is needed only to import the auditor, like all auditor code). Synthetic
self-describing oracles (each ships its own ADAPTER + GEN_INPUTS) exercise the full
differential sweep WITHOUT touching the real target: the fidelity gate (mappable vs
unmappable), probe replay, generated diff, the invalid-input filter, the bridge-artifact
guard, the strong/weak evidence split, real process-pool parallelism, and the honest "0
divergences" outcome. The classification taxonomy is unit-tested directly, including the
library-crash path via a monkeypatched target root.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_sweep.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sweep as sweep_mod  # noqa: E402
from sweep import classify, run_sweep  # noqa: E402
from adapters import BridgeInapplicable  # noqa: E402
from strategies import strategy_for, URL_POOL  # noqa: E402


# ---------------------------------------------------------------- classify() taxonomy

def test_classify():
    def boom_value(_):
        raise ValueError("invalid")

    def boom_bridge(_):
        raise BridgeInapplicable("not a tuple")

    # both return, differ -> divergence
    c = classify("q", "x", lambda a: "A", lambda a: "B", None)
    assert c and c["classification"] == "divergence", c

    # both return, equal -> agreement (no candidate)
    assert classify("q", "x", lambda a: "A", lambda a: "A", None) is None

    # real raises ValueError, oracle returns -> invalid-input
    c = classify("q", "x", boom_value, lambda a: "v", None)
    assert c and c["classification"] == "invalid-input", c

    # real raises bridge-inapplicable -> adapter-error (excluded from findings)
    c = classify("q", "x", boom_bridge, lambda a: "v", None)
    assert c and c["classification"] == "adapter-error", c

    # real returns, oracle rejects -> divergence (real too lenient)
    c = classify("q", "x", lambda a: "a", boom_value, None)
    assert c and c["classification"] == "divergence", c

    # both raise -> agreement
    assert classify("q", "x", boom_value, boom_value, None) is None

    # EQUIV_KEY projection: differ on full value but agree on the graded projection -> None
    assert classify("q", "x", lambda a: 1, lambda a: 5, key=lambda v: v > 0) is None
    print("test_classify: taxonomy OK (divergence / invalid-input / adapter-error / agree / equiv-key)")


def test_classify_library_crash():
    """A non-ValueError raised INSIDE the target library (e.g. NotImplementedError) is a real
    crash where the spec wants a value -> divergence, not invalid-input."""
    with tempfile.TemporaryDirectory() as td:
        libdir = Path(td) / "fakelib"
        libdir.mkdir()
        (libdir / "fakelib.py").write_text(
            "def do(x):\n    raise NotImplementedError('rootless path')\n")
        sys.path.insert(0, str(libdir))
        old_root = sweep_mod._REPO_SRC
        sweep_mod._REPO_SRC = str(libdir)  # mark this dir as "the target library"
        try:
            import fakelib  # noqa: F401
            c = classify("q", "x", lambda a: fakelib.do(a), lambda a: "value", None)
            assert c and c["classification"] == "divergence", c
            assert "NotImplementedError" in c["note"], c
            # the same exception type raised OUTSIDE the library is a bridge fault, not a finding
            def outside(_):
                raise NotImplementedError("from the adapter itself")
            c2 = classify("q", "x", outside, lambda a: "value", None)
            assert c2 and c2["classification"] == "adapter-error", c2
        finally:
            sweep_mod._REPO_SRC = old_root
            sys.path.remove(str(libdir))
    print("test_classify_library_crash: library NotImplementedError -> divergence; "
          "adapter NotImplementedError -> adapter-error OK")


# ---------------------------------------------------------------- strategy caps

def test_strategy_caps():
    # url convention: as many inputs as the pool, never capped
    inp, total, capped = strategy_for("URL.scheme", cap=10_000)
    assert inp == URL_POOL and total == len(URL_POOL) and capped is False, (total, capped)
    # a big-product convention truncates at the cap and flags it
    inp, total, capped = strategy_for("URL.click", cap=50)
    assert len(inp) == 50 and capped is True and total is None, (len(inp), total, capped)
    # an unregistered (unmappable) convention yields nothing
    assert strategy_for("URL.path") == ([], 0, False)
    print("test_strategy_caps: pool size, cap truncation flag, unmapped-empty OK")


# ---------------------------------------------------------------- end-to-end run_sweep

# Each synthetic oracle is a real importable module carrying REFERENCE_FUNC + PROBE_INPUTS +
# check_impl (the spec) AND a self-describing ADAPTER + GEN_INPUTS (the "real code" bridge).

_FAITHFUL = textwrap.dedent('''
    import time
    def ref(arg):
        if not isinstance(arg, str): raise ValueError("not str")
        if arg == "X": return "xacc"     # oracle ACCEPTS X; real rejects -> invalid-input
        if arg == "D": return "DIFF"     # oracle/real disagree on value -> divergence
        if arg == "G": return "GREF"     # generated-only divergence
        return arg.upper()
    REFERENCE_FUNC = ref
    PROBE_INPUTS = ["a", "b", "D", "X", "c"]
    def check_impl(fn):
        time.sleep(0.08)                 # force worker overlap so >1 PID is exercised
        expected = {"a": "A", "b": "B", "D": "DIFF", "X": "xacc", "c": "C"}
        out = []
        for p in PROBE_INPUTS:
            try:
                got = fn(p); err = False
            except Exception as e:
                got = e; err = True
            ok = (not err) and got == expected[p]
            out.append((ok, "" if ok else f"{p}->{got!r}"))
        return out
    def ADAPTER(arg):
        if arg in ("X", "Y"): raise ValueError("real rejects")
        return arg.upper()               # real == upper; disagrees with oracle on D and G
    GEN_INPUTS = ["G", "Y", "e", "D"]    # G=div, Y=invalid, e=agree, D=dedup'd vs probe
''')

_UNMAPPABLE = textwrap.dedent('''
    def ref(arg): return arg.upper()
    REFERENCE_FUNC = ref
    PROBE_INPUTS = ["Aa", "Bb", "Cc", "Dd"]
    def check_impl(fn):
        exp = {p: p.upper() for p in PROBE_INPUTS}
        return [(fn(p) == exp[p], "") for p in PROBE_INPUTS]
    def ADAPTER(arg): return arg.lower()    # structurally wrong representation -> 0/4 probes
    GEN_INPUTS = ["zz"]
''')

_CLEAN = textwrap.dedent('''
    import time
    def ref(arg): return arg.upper()
    REFERENCE_FUNC = ref
    PROBE_INPUTS = ["m", "n", "o"]
    def check_impl(fn):
        time.sleep(0.08)
        return [(fn(p) == p.upper(), "") for p in PROBE_INPUTS]
    def ADAPTER(arg): return arg.upper()    # real == oracle everywhere
    GEN_INPUTS = ["p", "q", "r"]
''')


def _write_oracle(d: Path, stem: str, src: str) -> Path:
    p = d / f"{stem}.py"
    p.write_text(src)
    return p


def test_run_sweep_end_to_end():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        odir = root / "oracles"
        rdir = root / "records"
        odir.mkdir()
        rdir.mkdir()
        specs = [("syn.faithful", "orc_faithful", _FAITHFUL),
                 ("syn.unmappable", "orc_unmappable", _UNMAPPABLE),
                 ("syn.clean", "orc_clean", _CLEAN)]
        for qual, stem, src in specs:
            opath = _write_oracle(odir, stem, src)
            (rdir / f"{stem}.json").write_text(json.dumps(
                {"qualname": qual, "green": True, "oracle_path": str(opath)}))
        # also a RED record that must be ignored
        (rdir / "red.json").write_text(json.dumps(
            {"qualname": "syn.red", "green": False, "oracle_path": "nope.py"}))

        out = root / "sweep"
        s = run_sweep(root, out, cap=400, max_record=25, workers=3)

        # green selection + fidelity gate
        assert s["green_oracles"] == 3, s
        assert s["swept_mappable"] == 2, s
        assert s["excluded_unmappable"] == 1, s
        assert s["unmappable_qualnames"] == ["syn.unmappable"], s

        # invalid-input filter + strong/weak split.
        # faithful: probe -> {D divergence, X invalid-input}; generated -> {G divergence,
        # Y invalid-input}. clean: 0 divergences.
        assert s["surviving_divergences"] == 2, s
        assert s["divergences_probe_strong"] == 1, s       # D (probe)
        assert s["divergences_generated_weak"] == 1, s     # G (generated)
        assert s["filtered_invalid_input"] == 2, s         # X (probe) + Y (generated)
        assert s["filtered_adapter_error"] == 0, s
        assert s["divergence_qualnames"] == ["syn.faithful"], s

        # honest finds-nothing: the clean oracle contributes zero divergences
        per = json.loads((out / "per_oracle.json").read_text())
        clean = next(r for r in per if r["qualname"] == "syn.clean")
        assert clean["mappable"] and clean["divergences"] == 0, clean

        # candidates.json shape - every required field present
        cands = json.loads((out / "candidates.json").read_text())
        assert cands, "expected candidate records"
        for c in cands:
            for k in ("qualname", "input", "real_result", "oracle_expected",
                      "classification", "source"):
                assert k in c, (k, c)
            assert c["classification"] in ("divergence", "invalid-input"), c
        # the D divergence is present and reads correctly
        d = next(c for c in cands if c["input"] == repr("D"))
        assert d["classification"] == "divergence" and d["source"] == "probe", d
        assert d["real_result"] == repr("D") and d["oracle_expected"] == repr("DIFF"), d

        # real parallelism: distinct worker PIDs (not a single serial process)
        assert s["distinct_worker_pids"] >= 2, s

        # all three output files written
        for f in ("per_oracle.json", "candidates.json", "summary.json"):
            assert (out / f).exists(), f
    print(f"test_run_sweep_end_to_end: 3 green -> 2 mappable / 1 unmappable; "
          f"2 divergences (1 strong + 1 weak), 2 invalid-input filtered; "
          f"{s['distinct_worker_pids']} distinct PIDs; honest 0-div clean path OK")


def main():
    test_classify()
    test_classify_library_crash()
    test_strategy_caps()
    test_run_sweep_end_to_end()
    print("test_sweep: OK")


if __name__ == "__main__":
    main()
