#!/usr/bin/env python3
"""auditor/fuzz_obligations.py - STEP 3: hunt REAL property violations in shipped libraries.

The obligations are proven to BITE (fold step 2). Now run them on inputs FAR beyond the doctests,
against the REAL shipped code, and look for a genuine violation = a bug candidate. Heavy on Unicode,
because that is where normalization-idempotence and round-trip bugs actually live (NFC/NFD, casefold
vs lower, Turkish dotted-I, Kelvin sign, ligatures, zero-width/format chars, full-width).

A violation is a CANDIDATE, not a verdict - every hit is hand-triaged: real bug vs misclassification
vs invalid-input (f raising is fine). No false claims; only a survivor that I read counts.

Each obligation: a real callable (+ sibling for round-trip), a property checker (reused from
intent_obligation's trusted templates), run over the fuzz corpus. Stdlib + the trusted checkers."""

from __future__ import annotations

import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from intent_obligation import check_idempotent, check_case_lower, check_inverse  # noqa: E402 trusted templates


# ---------------------------------------------------------------- the fuzz corpus (Unicode-heavy)


def fuzz_corpus(seeds: list[str]) -> list[str]:
    """A diverse input set: ascii edges + the Unicode classes where normalizers/round-trips break."""
    base = [
        "", " ", "  ", "\t", "a", "A", "aA", "Ab.Cd", "a_b-c.d", "a..b", "--a--", "__a__",
        "a" * 200, "A.B_C-D.e", "1.2.3", "foo bar", ".leading", "trailing.", "MiXeD",
    ]
    unicode_tricky = [
        "café", "café",            # NFC 'é' vs NFD 'e'+combining-acute (same look, diff bytes)
        "naïve", "naïve",
        "日本語", "한국어", "Ｆｕｌｌｗｉｄｔｈ",   # CJK + full-width latin
        "ß", "ẞ", "straße", "STRASSE",    # German sharp-s (lower vs casefold: ß->ss)
        "İstanbul", "ı", "I", "i",        # Turkish dotted/dotless I (lower() locale trap)
        "K", "K",                    # 'K' vs Kelvin sign U+212A (casefolds/lowers to 'k')
        "ﬁle", "ﬀ",                       # ligatures fi / ff (compatibility)
        "a​b", "a‍b", "﻿", # zero-width space / joiner / BOM
        "Ω", "Ω",                    # Greek omega vs ohm sign U+2126
        "²", "½", "Ⅻ",                    # superscript/fraction/roman-numeral (compat)
        "AB­CD",                     # soft hyphen
        "  Spaces  ", "\n", "a\nb",
    ]
    out, seen = [], set()
    for x in list(seeds) + base + unicode_tricky:
        if x not in seen:
            seen.add(x); out.append(x)
    # NFC/NFD variants of every seed - the highest-yield normalization probe
    for s in list(seeds):
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            v = unicodedata.normalize(form, s)
            if v not in seen:
                seen.add(v); out.append(v)
    return out


# ---------------------------------------------------------------- the obligations to hunt (proven + high-yield)


def _imp(stmt, name):
    ns = {}
    exec(stmt, ns)  # noqa: S102 - trusted import string
    return ns[name]


def load_obligations() -> list[dict]:
    """Verified obligations (from the slice/fold) + high-yield round-trips. Resolve real callables."""
    obls = []

    def add(label, prop, getter, *, sibling=None, seeds):
        try:
            f = getter()
            sib = sibling() if sibling else None
        except Exception as e:  # noqa: BLE001
            print(f"  [skip {label}: {type(e).__name__}: {e}]"); return
        obls.append({"label": label, "prop": prop, "f": f, "sibling": sib, "seeds": seeds})

    from packaging.utils import canonicalize_name, canonicalize_version  # noqa: E402
    add("packaging.canonicalize_name", "idempotent", lambda: canonicalize_name,
        seeds=["Django", "oslo.concurrency", "Foo.Bar_baz", "A--B__C"])
    add("packaging.canonicalize_name", "case_lower", lambda: canonicalize_name,
        seeds=["Django", "REQUESTS", "MiXeD.Name"])
    add("packaging.canonicalize_version", "idempotent", lambda: canonicalize_version,
        seeds=["1.0.1", "1.0.0", "1.0.0-alpha.1", "1.0.0+local"])
    try:
        from packaging.utils import canonicalize_license_expression  # newer packaging
        add("packaging.canonicalize_license_expression", "idempotent",
            lambda: canonicalize_license_expression, seeds=["MIT", "mit and apache-2.0"])
    except Exception:  # noqa: BLE001
        pass
    # idna round-trip - prime Unicode bug territory (decode(encode(x)) == x)
    add("idna.encode/decode", "inverse", lambda: _imp("import idna; f=idna.encode", "f"),
        sibling=lambda: _imp("import idna; f=idna.decode", "f"),
        seeds=["bücher.de", "example.com", "日本.jp", "xn--bcher-kva.de"])
    # also idna single-label round-trip
    add("idna.alabel/ulabel", "inverse", lambda: _imp("import idna; f=idna.alabel", "f"),
        sibling=lambda: _imp("import idna; f=idna.ulabel", "f"),
        seeds=["bücher", "example", "日本"])
    return obls


# ---------------------------------------------------------------- hunt


def hunt() -> dict:
    obls = load_obligations()
    checkers = {"idempotent": check_idempotent, "case_lower": check_case_lower, "inverse": check_inverse}
    findings = []
    total_checks = 0
    print(f"\nhunting {len(obls)} proven obligations over a Unicode-heavy fuzz corpus...\n")
    for o in obls:
        corpus = fuzz_corpus(o["seeds"])
        checker = checkers[o["prop"]]
        viol = []
        for x in corpus:
            total_checks += 1
            r = checker(o["f"], [x], sibling=o["sibling"])
            if r["n_violated"] > 0:
                viol.append({"input": repr(x), "detail": r["results"][0]["detail"]})
        status = f"{len(viol)} VIOLATION(s)" if viol else "clean"
        print(f"  {o['label']:42s} [{o['prop']:10s}]  {len(corpus):3d} inputs -> {status}")
        if viol:
            findings.append({"obligation": f"{o['label']} [{o['prop']}]", "violations": viol[:8]})
    return {"obligations": len(obls), "total_checks": total_checks, "findings": findings}


def main() -> int:
    import json
    res = hunt()
    print(f"\n=== {res['total_checks']} checks across {res['obligations']} obligations ===")
    if not res["findings"]:
        print("No property violations - the audited functions are conformant on the fuzz corpus.")
        print("(Honest artifact: a calibrated prover that ran broadly and found conformance.)")
    else:
        print(f"⚠ {len(res['findings'])} obligation(s) with VIOLATIONS - candidates for triage:\n")
        for f in res["findings"]:
            print(f"  {f['obligation']}:")
            for v in f["violations"]:
                print(f"      input={v['input'][:60]}  {v['detail'][:80]}")
    Path("results").mkdir(exist_ok=True)
    Path("results/fuzz_findings.json").write_text(json.dumps(res, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
