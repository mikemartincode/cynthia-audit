"""Self-contained proof for auditor/differential.py - the REAL-vs-REAL parser differential.
No network and no model: it runs the actual hyperlink (vendored), urllib.parse (stdlib), and
rfc3986 (installed) parsers against each other over a deterministic input set.

What it demonstrates, end to end (the E02 done-criteria):
  1. COMPARE: the same url through ≥2 independent real parsers, with a per-component diff.
  2. CLASSIFY: spec-pinned (candidate) vs spec-permitted (ambiguity), each with an RFC basis -
     not asserted blindly; the verdict follows whether the diff survives RFC-permitted canon.
  3. SECURITY SURFACE: authority-boundary disagreements (host/userinfo/port) are flagged
     distinctly from the rest.
  4. HONEST HANDLING: a spec-PERMITTED divergence (scheme/host case folding) is correctly NOT
     promoted, and a clean URL with only default-port/representation differences is not either.

The strongest findings (the corroborated host-boundary and the host-VALUE split) require the
THIRD independent parser - that is the cross-parser-corroboration design working as intended
(≥2 reals must agree on a host for it to be promoted), so this test requires rfc3986 present.

Run: ~/projects/cynthia-core/.venv/bin/python auditor/test_differential.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from differential import (  # noqa: E402
    AUTHORITY_PROBES, _classify_validity, _canon, compare, parsers, run_differential,
)
from strategies import URL_POOL  # noqa: E402


def _pinned(rec, component):
    return [cd for cd in rec["component_diffs"]
            if cd["component"] == component and cd["classification"] == "spec-pinned"]


def _permitted(rec, component):
    return [cd for cd in rec["component_diffs"]
            if cd["component"] == component and cd["classification"] == "spec-permitted"]


def test_parsers_present():
    """≥2 independent real implementations, and the 3rd voice (rfc3986) the strong corroborated
    findings depend on. urllib is stdlib; hyperlink is the vendored target."""
    ps = parsers()
    assert {"hyperlink", "urllib"} <= set(ps), ps
    assert "rfc3986" in ps, ("rfc3986 not installed - the corroborated host-boundary findings "
                             "need a 3rd independent parser; `pip install rfc3986`")
    print(f"parsers present: {sorted(ps)} (3-way differential)")


def test_corroborated_host_boundary():
    """`http://a@b@c/`: two independent reals (urllib + rfc3986) resolve host `c`; hyperlink
    rejects the authority. The canonical SSRF-bypass shape - promoted, security-relevant, with
    the §3.2 authority-grammar basis. NOT dressed as a CVE (note present, severity per field)."""
    ps = parsers()
    rec = compare("http://a@b@c/", ps)
    assert rec is not None and rec["promoted"] and rec["security_relevant"], rec
    v = rec["validity"]
    assert v and v["classification"] == "spec-pinned", v
    assert v["resolved_host"] == "c" and v["corroborating_parsers"] >= 2, v
    assert "hyperlink" in rec["rejected"], rec
    assert "§3.2" in v["rfc_basis"] and "CVE" in v["note"], v  # cites RFC, disclaims CVE
    json.dumps(rec)  # serializable
    print(f"corroborated: {v['corroborating_parsers']} parsers resolve host {v['resolved_host']!r}, "
          f"hyperlink rejects - promoted security-relevant")


def test_host_value_split():
    r"""`http://evil.com\@good.com/`: ALL three parse it, but they DISAGREE on the host -
    hyperlink + urllib read `good.com`, rfc3986 reads `evil.com`. A real host-VALUE differential
    (RFC vs WHATWG backslash handling), promoted as a spec-pinned authority-boundary candidate."""
    ps = parsers()
    rec = compare(r"http://evil.com\@good.com/", ps)
    assert rec is not None and rec["promoted"] and rec["security_relevant"], rec
    host = _pinned(rec, "host")
    assert host, rec["component_diffs"]
    raw = host[0]["raw"]
    assert host[0]["authority_boundary"] and "§3.2.2" in host[0]["rfc_basis"], host[0]
    # the three parsers genuinely split on the host value
    assert "good.com" in str(raw) and "evil.com" in str(raw), raw
    print(f"host-value split: {raw} - spec-pinned authority-boundary candidate")


def test_agreement_is_no_finding():
    """Control: `http://example.com@evil.com/` is a scary-LOOKING userinfo URL, but all three
    parsers agree host=evil.com, userinfo=example.com - so it is NOT promoted and shows no
    authority-boundary disagreement (only benign default-port/representation diffs remain). No
    false positive on a single-`@` authority every parser reads identically."""
    ps = parsers()
    rec = compare("http://example.com@evil.com/", ps)
    assert rec is None or not rec["promoted"], rec
    if rec is not None:
        assert not _pinned(rec, "host") and not _pinned(rec, "userinfo"), rec["component_diffs"]
        for comp in ("host", "userinfo"):  # parsers genuinely agree on the boundary
            assert not (_pinned(rec, comp) or _permitted(rec, comp)), (comp, rec["component_diffs"])
    print("agreement control: example.com@evil.com - all parsers agree on host/userinfo, no finding")


def test_permitted_not_promoted():
    """HONEST HANDLING (criterion 4): `HTTP://H/PaTh` raw-differs on scheme + host (urllib
    lowercases, the others preserve), but the difference VANISHES under RFC case-folding (§3.1,
    §3.2.2). It is recorded as spec-permitted and NOT promoted."""
    ps = parsers()
    rec = compare("HTTP://H/PaTh", ps)
    assert rec is not None, "expected a recorded (raw) difference"
    assert not rec["promoted"] and not rec["security_relevant"], rec
    assert _permitted(rec, "scheme") and _permitted(rec, "host"), rec["component_diffs"]
    assert not any(cd["classification"] == "spec-pinned" for cd in rec["component_diffs"]), rec
    print("permitted-not-promoted: HTTP://H/PaTh case-fold is spec-permitted, correctly not promoted")


def test_default_port_not_a_candidate():
    """A clean `http://example.com/` differs only by representation (hyperlink fills the default
    port 80, urllib/rfc3986 leave it absent) - elided under §6.2.3 and never promoted."""
    ps = parsers()
    rec = compare("http://example.com/", ps)
    assert rec is None or not rec["promoted"], rec
    if rec is not None:
        assert not _pinned(rec, "port"), rec["component_diffs"]
    print("default-port: http://example.com/ port 80-vs-absent elided, not a candidate")


def test_validity_requires_corroboration():
    """The accept/reject promotion rule's NEGATIVE branch: when accepting parsers disagree among
    themselves on the host (no ≥2 corroboration), the split is spec-permitted, not promoted."""
    accepted = {
        "a": {"scheme": "http", "host": "x", "userinfo": None, "port": None,
              "path": "/", "query": "", "fragment": ""},
        "b": {"scheme": "http", "host": "y", "userinfo": None, "port": None,
              "path": "/", "query": "", "fragment": ""},
    }
    v = _classify_validity(accepted, {"c": "ValueError: rejected"})
    assert v["classification"] == "spec-permitted", v
    # and the POSITIVE branch: two accepting parsers agreeing on a host => promoted
    accepted["b"]["host"] = "x"
    v2 = _classify_validity(accepted, {"c": "ValueError: rejected"})
    assert v2["classification"] == "spec-pinned" and v2["resolved_host"] == "x", v2
    print("corroboration rule: disagreeing hosts => permitted; ≥2 agreeing => spec-pinned")


def test_canon_folds_only_permitted():
    """The canonicalizer folds EXACTLY the RFC-permitted variation and no more: scheme/host case,
    percent-hex case, IP-literal brackets, default-port - but NOT a genuinely different host."""
    assert _canon("scheme", "HTTP", "HTTP") == "http"            # §3.1
    assert _canon("host", "H", "http") == "h"                    # §3.2.2 case
    assert _canon("host", "[::1]", "http") == "::1"              # §3.2.2 brackets
    assert _canon("query", "%2f", None) == "%2F"                 # §6.2.2.1 hex case
    assert _canon("port", None, "http") == 80                    # §6.2.3 default
    assert _canon("host", "good.com", "http") != _canon("host", "evil.com", "http")
    print("canon: folds case/hex/brackets/default-port only; distinct hosts stay distinct")


def test_run_differential_full():
    """END TO END over the full input set (URL_POOL + the authority probes): a summary, a
    per-disagreement record file, and a markdown report - with ≥1 promoted security-relevant
    candidate and a non-empty spec-permitted ambiguity table."""
    inputs = list(URL_POOL) + AUTHORITY_PROBES
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "diff"
        s = run_differential(inputs, out)

        assert s["promoted_candidates"] >= 1 and s["security_relevant_candidates"] >= 1, s
        assert s["spec_permitted_ambiguities"] >= 1 and s["ambiguity_classes"], s
        assert "http://a@b@c/" in s["promoted_urls"] and "http://a@b@c/" in s["security_urls"], s
        # a case-fold URL from the pool must be a recorded ambiguity, never promoted
        assert "HTTP://H/" not in s["promoted_urls"], s

        for f in ("summary.json", "disagreements.json", "report.md"):
            assert (out / f).exists(), f
        report = (out / "report.md").read_text()
        assert "Security-relevant candidates" in report and "host-boundary" in report, report[:400]
        assert "Spec-permitted ambiguities (correctly NOT promoted)" in report, report[-400:]

        disagreements = json.loads((out / "disagreements.json").read_text())
        promoted = [d for d in disagreements if d["promoted"]]
        assert len(promoted) == s["promoted_candidates"], (len(promoted), s["promoted_candidates"])
        print(f"full run: {s['disagreements']} disagreements -> {s['promoted_candidates']} promoted "
              f"({s['security_relevant_candidates']} security-relevant), "
              f"{s['spec_permitted_ambiguities']} permitted; report + records written")


def main() -> None:
    test_parsers_present()
    test_corroborated_host_boundary()
    test_host_value_split()
    test_agreement_is_no_finding()
    test_permitted_not_promoted()
    test_default_port_not_a_candidate()
    test_validity_requires_corroboration()
    test_canon_folds_only_permitted()
    test_run_differential_full()
    print("test_differential: OK")


if __name__ == "__main__":
    main()
