# hyperlink `URL.click()` raises `NotImplementedError` resolving an absolute-URI reference with a rootless path

**Component:** `hyperlink.URL.click` (`src/hyperlink/_url.py`, the `NotImplementedError` at line 1627)
**Affected:** hyperlink 21.0.0 (current PyPI release) and commit `978f2e6455` (2026-03-20). Long-standing.
**Class:** correctness / robustness (crash on a valid input). **Not** a security vulnerability — see Impact.
**Status:** reproduced standalone and hand-verified against RFC 3986. Reported as a correctness bug; no fix submitted.

## Summary

`URL.click(href)` documents itself as RFC 3986 §5 reference resolution. When `href` is an absolute
URI whose path is *rootless* (does not begin with `/`) — e.g. `mailto:`, `tel:`, `urn:`, or RFC
3986 §5.4.1's own first worked example `g:h` — it raises
`NotImplementedError: absolute URI with rootless path: <href>` instead of resolving the reference.

Per RFC 3986 §5.2.1, a reference that already carries a scheme resolves to *itself*; a rootless
path is explicitly legal for such a URI. The correct result is the reference, not a crash.

## Reproduce

```
python -m venv /tmp/v && /tmp/v/bin/pip install hyperlink
/tmp/v/bin/python repro.py
```

`repro.py` depends only on `hyperlink`. Observed output (hyperlink 21.0.0):

```
  FAIL  click('g:h')
        raised   : NotImplementedError: absolute URI with rootless path: 'g:h'
        RFC 3986 : 'g:h'   (RFC 3986 5.4.1 first normal example)
  FAIL  click('mailto:fred@example.com')   ... raised NotImplementedError
  FAIL  click('tel:+1-555-0100')           ... raised NotImplementedError
  FAIL  click('urn:isbn:0451450523')       ... raised NotImplementedError
4/4 valid references crashed click() instead of resolving.
```

Each reference is itself well-formed — `URL.from_text('mailto:fred@example.com').to_text()`
round-trips fine. hyperlink can *parse* these URIs; it only fails to *resolve* to them.

## Root cause

`URL.click` (docstring: *"Resolve the given URL relative to this URL ... For more information,
see RFC 3986 section 5"*) reaches a branch for a reference that has a scheme but a rootless path
and gives up:

```python
raise NotImplementedError("absolute URI with rootless path: %r" % (href,))
```

RFC 3986 §5.2.1 (Transform References) — when `defined(R.scheme)`:

```
T.scheme = R.scheme;  T.authority = R.authority;
T.path   = remove_dot_segments(R.path);  T.query = R.query;
```

i.e. the target is the reference itself. RFC 3986 §5.4.1 (Normal Examples), base
`http://a/b/c/d;p?q`, lists `"g:h" = "g:h"` as the first example. The documented contract (RFC 3986
§5) and the actual behavior (raise on a documented §5.4.1 case) disagree — that gap is the bug.

## Impact (honest)

Correctness and robustness, not security. Any code that resolves a clicked/linked target against
a base URL with `URL.click()` — a feed reader, a crawler, an HTML link rewriter, an email/anchor
normalizer — raises an unhandled `NotImplementedError` the moment it meets an ordinary `mailto:`,
`tel:`, or `urn:` link, rather than resolving it. That is a real availability/robustness defect
(an exception on valid, common input). It is **not** a parser differential, an SSRF, or an
authorization bypass, and is not represented as one. The worst realistic consequence is a crash in
a service that resolves attacker-or-user-supplied link targets; severity depends entirely on the
caller's error handling.

## Provenance (tool-assisted — disclosed)

Found by the cynthia differential bug-auditor, then hand-verified:

- An oracle for `URL.click` was authored by `deepseek-v4-pro` and **mechanically validated by the
  mutation gate** — it killed 4/4 single-site AST mutants of its reference implementation
  (`kill_rate = 1.0`, 0 survivors), i.e. proven non-vacuous before use.
- A differential sweep ran the real library against that oracle over adversarial inputs and
  surfaced the `NotImplementedError` divergence on `g:`/`h:`/`o:`/`n:` (one root cause).
- Triage corroborated cross-family: an independent `minimax-m3` second oracle (gate-GREEN,
  different model family from the deepseek author) plus a deepseek spec re-derivation that agreed
  the operation should resolve. The per-input cross-family *vote* was inconclusive, so promotion
  rested on the spec re-derivation — which is why the auditor rated this **medium**, not high.
- **A human (this write-up) then confirmed it against RFC 3986 §5.2.1 and §5.4.1 directly** and
  reproduced it standalone on the PyPI release. The RFC citation, not the model agreement, is the
  load-bearing evidence here.

The auditor's value was finding the input and flagging it non-vacuously; the confirmation is the
spec citation above.

## Channel — decision pending (not auto-submitted)

No PR or issue has been filed. AI-assisted bug reports are easy to get wrong and unwelcome when
fired blindly at maintainers. Options, to decide deliberately:
1. OSS issue to `python-hyper/hyperlink` with this repro + RFC citation (no PR, let maintainers fix).
2. OSS issue **and** a small PR implementing the §5.2.1 scheme-present case.
3. Local verification only — record as a verified spec-conformance finding without filing upstream.

Recommend (1): a clean, RFC-cited issue with a standalone repro is genuinely useful and low-risk;
a PR touching reference-resolution semantics deserves more care than an unsolicited drive-by.
