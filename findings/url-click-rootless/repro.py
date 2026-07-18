#!/usr/bin/env python3
"""Standalone reproduction — hyperlink.URL.click() crashes resolving an absolute-URI reference
with a rootless path (mailto:, tel:, urn:, and RFC 3986 5.4.1's own first example "g:h").

Dependencies: hyperlink only.   Reproduce:
    python -m venv /tmp/v && /tmp/v/bin/pip install hyperlink && /tmp/v/bin/python repro.py
Tested against hyperlink 21.0.0 (PyPI) and commit 978f2e6455 (2026-03-20). No auditor code.

What the spec says
------------------
URL.click() documents itself as RFC 3986 section 5 reference resolution ("Resolve the given URL
relative to this URL ... For more information, see RFC 3986 section 5").

RFC 3986 5.2.1 (Transform References): when the reference R has a scheme, the resolved target is
R itself (T.scheme = R.scheme, T.path = remove_dot_segments(R.path), ...). A reference that is
already an absolute URI resolves to that absolute URI, regardless of whether its path is rootless.

RFC 3986 5.4.1 (Normal Examples), base = "http://a/b/c/d;p?q":
    "g:h"  ->  "g:h"     (the FIRST listed normal example)

The discrepancy (and its disposition)
-------------------------------------
hyperlink raises NotImplementedError("absolute URI with rootless path: ...") for every such
reference instead of returning the reference. That raise is EXPLICIT and DELIBERATE in hyperlink's
own source (the maintainer named the unimplemented RFC 3986 5.2.1 scheme-present case rather than
resolving it), so this is a documented, intentional limitation -- not a latent defect. It is kept
as a recorded NON-FINDING: the auditor surfaced a genuine spec-vs-implementation gap; triage
correctly declined to report a deliberately-unimplemented, clearly-erroring case upstream.
"""

import sys

from hyperlink import URL

RFC_BASE = "http://a/b/c/d;p?q"  # the canonical base used throughout RFC 3986 section 5.4

# (reference, RFC-correct resolved result, why it's a valid reference)
CASES = [
    ("g:h", "g:h", "RFC 3986 5.4.1 first normal example"),
    ("mailto:fred@example.com", "mailto:fred@example.com", "RFC 6068 mailto URI (rootless path)"),
    ("tel:+1-555-0100", "tel:+1-555-0100", "RFC 3966 tel URI (rootless path)"),
    ("urn:isbn:0451450523", "urn:isbn:0451450523", "RFC 8141 urn URI (rootless path)"),
]


def main() -> int:
    print(f"hyperlink reference-resolution repro — base = {RFC_BASE!r}\n")
    base = URL.from_text(RFC_BASE)
    crashed = 0

    for ref, rfc_expected, why in CASES:
        # The reference is itself a well-formed URL hyperlink parses without complaint:
        parsed = URL.from_text(ref).to_text()
        assert parsed == ref, f"sanity: {ref!r} should round-trip, got {parsed!r}"

        try:
            got = base.click(ref).to_text()
        except NotImplementedError as exc:
            crashed += 1
            print(f"  FAIL  click({ref!r})")
            print(f"        raised   : NotImplementedError: {exc}")
            print(f"        RFC 3986 : {rfc_expected!r}   ({why})")
        else:
            ok = "ok" if got == rfc_expected else "WRONG VALUE"
            print(f"  {ok}  click({ref!r}) = {got!r}  (RFC expects {rfc_expected!r})")
        print()

    print(f"{crashed}/{len(CASES)} valid references raised in click() instead of resolving.")
    if crashed:
        print("DISCREPANCY REPRODUCED (documented as intentional in hyperlink): click() documents "
              "RFC 3986 section 5 but deliberately raises NotImplementedError on absolute-URI "
              "references with a rootless path (5.2.1 says resolve to the reference itself). "
              "Recorded as a non-finding -- not filed upstream.")
        # exit 0: the script ran and demonstrated the divergence. (A future fixed hyperlink would
        # print 'ok' for every case and crashed==0 — i.e. the repro self-checks whether it still
        # reproduces.)
    else:
        print("Not reproduced on this hyperlink version — click() resolved every case.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
