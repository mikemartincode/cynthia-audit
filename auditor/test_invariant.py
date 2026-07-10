"""Self-contained proof for the INVARIANT (metamorphic) oracle shape - a SECOND oracle type
alongside the value oracle, sharing the SAME mutation gate (cynthia-core), authored through the
same independent ref+battery contract. No network: authoring is stubbed; the mutation gate and the
differential sweep run for real, the sweep against the REAL hyperlink library.

What it demonstrates, end to end:
  1. AUTHOR (shape="invariant"): the round-trip invariant oracle for URL.from_text/to_text assembles
     from an independent reference + an independent metamorphic battery and is gate-GREEN.
  2. GATE NON-VACUITY (RED-on-bad AND GREEN-on-good): the real round-trip invariant kills every
     non-equivalent mutant of its reference (GREEN); a deliberately VACUOUS invariant (a relation
     that holds trivially) is caught by the SAME gate as survivors (RED). The gate is not forked -
     run_mutation_gate proves an invariant oracle non-vacuous exactly as it does a value oracle.
  3. SWEEP: the gate-GREEN invariant, run against the REAL hyperlink library, reports the input
     where the round-trip invariant fails - `http://h/#`, whose empty fragment hyperlink drops on
     to_text() (`from_text('http://h/#').to_text() == 'http://h/'`). That is a round-trip-CLASS
     candidate the single-call value oracles structurally cannot see; it is a CANDIDATE, triaged
     like any divergence (crash-vs-value rules from A05 still apply), not an auto-asserted bug.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_invariant.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import author  # noqa: E402
from adapters import _REPO_SRC  # noqa: E402 - vendored hyperlink path (puts it on sys.path)
from sweep import run_sweep  # noqa: E402

INV_ENTRY = {
    "qualname": "URL.from_text", "signature": "(cls, text)", "auditability": "invariant",
    "intent": "parse a URL string into its components",
    "auditability_why": "round-trip: re-serializing a parsed canonical URL yields the input",
    "doc": "Parse an absolute URL scheme:[//host][/path][?query][#fragment]. For a canonical "
           "input, re-serializing the parsed URL reproduces the input exactly (round-trip "
           "identity), and re-parsing is idempotent.",
}

# --- the independent REFERENCE (a correct parse+serialize transform) ---------------------------
# A minimal but real canonical-URL round-trip: parse into components and join them back. The gate
# mutates THIS; breaking any step breaks round-trip identity on a probe that exercises it.
GOOD_REF = '''
def ref_from_text(text):
    def split_once(s, sep):
        i = s.find(sep)
        if i < 0:
            return s, None
        return s[:i], s[i + 1:]
    if ":" not in text:
        raise ValueError("no scheme")
    scheme, rest = split_once(text, ":")
    if not scheme:
        raise ValueError("empty scheme")
    fragment = None
    if "#" in rest:
        rest, fragment = split_once(rest, "#")
    query = None
    if "?" in rest:
        rest, query = split_once(rest, "?")
    host = None
    if rest.startswith("//"):
        rest = rest[2:]
        slash = rest.find("/")
        if slash < 0:
            host, path = rest, ""
        else:
            host, path = rest[:slash], rest[slash:]
    else:
        path = rest
    out = scheme + ":"
    if host is not None:
        out += "//" + host
    out += path
    if query is not None:
        out += "?" + query
    if fragment is not None:
        out += "#" + fragment
    return out

REFERENCE_FUNC = ref_from_text
REFERENCE_NAME = "ref_from_text"
'''

# --- the independent METAMORPHIC battery (relations, not a value table) -------------------------
# check_impl asserts ROUND-TRIP IDENTITY (canonical input re-serializes to itself) AND IDEMPOTENCE
# (re-applying is stable). Both are relations over fn - never a hard-coded input->output value. The
# two relations together have teeth: identity kills value-corrupting mutants idempotence is blind to
# (a const_return mutant is idempotent but breaks identity). PROBE_INPUTS include `http://h/#`,
# whose empty fragment the reference preserves - the input that later exposes the real-library bug.
GOOD_BATTERY = '''
PROBE_INPUTS = [
    "http://example.com/", "https://example.com/a/b", "http://example.com/a/b?x=y",
    "http://example.com/a#frag", "https://h/p?a=b&c=d", "http://h/", "ftp://h/x",
    "https://example.com/a/b?x=y#z", "http://h/a/b/c", "mailto:a@b.com",
    "http://h/p?q", "http://h/#",
]

def check_impl(fn):
    out = []
    for text in PROBE_INPUTS:
        try:
            once = fn(text)
            identity = (once == text)                 # round-trip identity on canonical input
            idempotent = (fn(once) == once)           # metamorphic: re-applying is stable
            ok = identity and idempotent
            out.append((ok, "" if ok else f"{text!r}: once={once!r}"))
        except Exception as exc:
            out.append((False, f"{text!r} raised {type(exc).__name__}: {exc}"))
    return out
'''

# --- a VACUOUS invariant (a relation that holds trivially) - the gate MUST catch it -------------
# `fn(x) == fn(x)` is always true and errors are tolerated, so it passes its own reference (no
# broken-ref RED) yet admits every wrong mutant. The mutation gate flags it RED via survivors -
# the same non-vacuity proof that protects value oracles, applied to an invariant.
VACUOUS_BATTERY = '''
PROBE_INPUTS = [
    "http://example.com/", "https://example.com/a/b", "http://example.com/a/b?x=y",
    "http://h/", "ftp://h/x", "http://h/a/b/c", "mailto:a@b.com", "http://h/#",
]

def check_impl(fn):
    out = []
    for text in PROBE_INPUTS:
        try:
            v = fn(text)
            out.append((v == v, ""))                  # trivially true => no teeth
        except Exception:
            out.append((True, "tolerated"))
    return out
'''

# self-describing bridge to the REAL hyperlink library for the sweep: the round-trip is
# from_text(text).to_text(). The vendored path is injected so the oracle imports hyperlink in any
# process (in-proc gate AND the sweep's worker pool). GEN_INPUTS stay canonical (they round-trip
# cleanly) so the ONLY surviving divergence is the mutation-proven empty-fragment probe.
ADAPTER_BLOCK = f'''
import sys as _sys
_REPO = {_REPO_SRC!r}
if _REPO not in _sys.path:
    _sys.path.insert(0, _REPO)
from hyperlink import URL as _URL

def ADAPTER(text):
    return _URL.from_text(text).to_text()

GEN_INPUTS = ["http://a/", "https://b/c", "http://d/e?f=g"]
'''


def _stub(ref_code: str, battery_code: str):
    """Prompt-aware authoring stub: the battery prompt carries 'BATTERY'; the reference prompt
    does not. Zero spend, deterministic - the two independent calls assemble into one oracle."""
    def fake(model, system, user, **kw):
        code = battery_code if "BATTERY" in user else ref_code
        return {"code": code, "raw": code, "in_tok": 100, "out_tok": 200,
                "cost": 0.001, "elapsed": 0.0}
    return fake


def _author(entry, ref, battery, run, *, qual, attempts=1):
    author.call_model = _stub(ref, battery)
    return author.author_and_gate({**entry, "qualname": qual}, "stub-model", run,
                                  attempts=attempts, gate_cap=40, shape="invariant")


def test_author_and_gate_invariant():
    """AUTHOR (shape='invariant') + GATE: GREEN on the real round-trip invariant, RED on a vacuous
    one - both through the unmodified cynthia-core mutation gate."""
    real = author.call_model
    try:
        with tempfile.TemporaryDirectory() as td:
            run = Path(td)

            # GREEN - the metamorphic invariant kills every non-equivalent mutant of its reference.
            rec = _author(INV_ENTRY, GOOD_REF, GOOD_BATTERY, run, qual="URL.from_text")
            assert rec.green and not rec.spec_disagreement, rec.to_dict()
            assert rec.gate["kill_rate"] == 1.0 and rec.gate["non_equivalent"] > 0, rec.gate
            assert not rec.gate["survivors"], rec.gate
            json.dumps(rec.to_dict())  # serializable
            print(f"GREEN ok: invariant killed {rec.gate['killed']}/{rec.gate['non_equivalent']} "
                  "non-equivalent mutants (round-trip identity + idempotence)")

            # RED - the SAME gate catches a vacuous (always-true) invariant as survivors.
            rec_v = _author({**INV_ENTRY, "auditability_why": "vacuous"}, GOOD_REF, VACUOUS_BATTERY,
                            run, qual="URL.from_text_vac")
            assert not rec_v.green and rec_v.gate["survivors"], rec_v.gate
            assert rec_v.gate["ref_passes"] and not rec_v.spec_disagreement, rec_v.gate
            print(f"RED ok: vacuous invariant left {len(rec_v.gate['survivors'])} survivors "
                  "(non-vacuity proof generalizes to the invariant shape)")
    finally:
        author.call_model = real


def test_reference_satisfies_invariant():
    """Pass-count proof (testing-canon §4): the reference satisfies its OWN metamorphic battery on
    every probe - 0 failures, and a meaningful number of passes (not a degenerate empty battery)."""
    ns: dict = {}
    exec(compile(GOOD_REF + "\n" + GOOD_BATTERY, "<good_oracle>", "exec"), ns)
    graded = ns["check_impl"](ns["REFERENCE_FUNC"])
    failed = sum(1 for ok, _ in graded if not ok)
    passed = sum(1 for ok, _ in graded if ok)
    assert failed == 0 and passed >= 10, (failed, passed, graded)
    print(f"reference satisfies its invariant: {passed} pass / {failed} fail")


def test_sweep_reports_invariant_failure():
    """SWEEP the gate-GREEN invariant against the REAL hyperlink library; it must surface the input
    where round-trip identity fails. `http://h/#` -> hyperlink drops the empty fragment on to_text,
    so from_text('http://h/#').to_text() == 'http://h/' != 'http://h/#'. Reported as a divergence
    candidate (a round-trip-class finding the value oracles can't see), triaged downstream."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        odir, rdir = root / "oracles", root / "records"
        odir.mkdir()
        rdir.mkdir()
        oracle_src = GOOD_REF + "\n" + GOOD_BATTERY + "\n" + ADAPTER_BLOCK
        opath = odir / "url_from_text_roundtrip.py"
        opath.write_text(oracle_src)
        # a non-registry qualname => the sweep uses the oracle's self-described ADAPTER + GEN_INPUTS
        (rdir / "url_from_text_roundtrip.json").write_text(json.dumps(
            {"qualname": "URL.from_text~roundtrip", "green": True, "oracle_path": str(opath)}))

        s = run_sweep(root, root / "sweep", cap=400, max_record=25, workers=2)

        # the adapter reproduces enough mutation-proven probes to be a valid bridge (mappable),
        # and the ONE probe it fails is the empty-fragment round-trip.
        assert s["green_oracles"] == 1 and s["swept_mappable"] == 1, s
        assert s["excluded_unmappable"] == 0, s
        assert s["surviving_divergences"] == 1, s
        assert s["divergences_probe_strong"] == 1, s          # the probe is mutation-proven
        assert s["divergence_qualnames"] == ["URL.from_text~roundtrip"], s

        cands = json.loads((root / "sweep" / "candidates.json").read_text())
        div = [c for c in cands if c["classification"] == "divergence"]
        assert len(div) == 1, div
        c = div[0]
        assert c["input"] == repr("http://h/#"), c
        assert c["real_result"] == repr("http://h/") and c["source"] == "probe", c
        print(f"sweep ok: round-trip invariant flagged {c['input']} - real library returns "
              f"{c['real_result']} (empty fragment dropped); 1 candidate, triaged downstream")


def main() -> None:
    test_author_and_gate_invariant()
    test_reference_satisfies_invariant()
    test_sweep_reports_invariant_failure()
    print("test_invariant: OK")


if __name__ == "__main__":
    main()
