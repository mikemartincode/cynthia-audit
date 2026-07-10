# hyperlink `URL.click()` raises `NotImplementedError` resolving an absolute-URI reference with a rootless path

**Component:** `hyperlink.URL.click` (`src/hyperlink/_url.py`, the `NotImplementedError` at line 1627)
**Affected:** hyperlink 21.0.0 (current PyPI release) and commit `978f2e6455` (2026-03-20). Long-standing.
**Class:** correctness / robustness (crash on a valid input). **Not** a security vulnerability - see Impact.
**Status:** ⚠ **Withdrawn as a bug - the raise is intentional** (see the Correction section, next). Reproduced standalone and hand-verified against RFC 3986; the divergence is real, but the source raises by design under a maintainer comment, so it reclassifies to a deliberate, documented limitation. Not filed upstream.

## ⚠ Correction - the raise is intentional (read this first)

The behavior documented below is **deliberate**, not an oversight. `URL.click` guards the scheme+rootless
case explicitly and raises with a descriptive message under a maintainer comment that cites the RFC
(`src/hyperlink/_url.py`, the `click` body):

```python
if clicked.scheme and not clicked.rooted:
    # Schemes with relative paths are not well-defined.  RFC 3986 calls
    # them a "loophole in prior specifications" that should be avoided,
    # or supported only for backwards compatibility.
    raise NotImplementedError(
        "absolute URI with rootless path: %r" % (href,)
    )
```

This is a **known, source-documented limitation**, so the finding is **not a reportable correctness
bug**. Two honest nuances, neither of which restores it to one:

- The comment justifies via RFC 3986 **§5.4.2** (the same-scheme "loophole", e.g. base `http:…` + ref
  `http:g`). But even §5.4.2's *strict* answer is `"http:g" = "http:g"` (resolve to self), and §5.4.1's
  first *normal* example is `"g:h" = "g:h"` - §5 does define an output; the maintainers simply chose to
  raise rather than implement either branch.
- The raise also catches §5.4.1-*normal* references whose scheme differs from the base (`g:h`, `mailto:`),
  which the loophole reasoning doesn't strictly cover - so the limitation is slightly broader than its
  stated justification. That is a *scoping/feature* observation, not a correctness defect: the code
  intends to decline all scheme+rootless resolution and says so.

The only arguably-fileable residue is a **docstring-completeness nit** - `click()`'s docstring cites
"RFC 3986 section 5" without noting the scheme+rootless-path case it intentionally declines. Too minor
to warrant an unsolicited report.

**This finding's real value is now as evidence for the project's own thesis** (`WRITEUP.md`): an
LLM-authored oracle plus a spec re-derivation asserted full §5 resolution as the contract; the library
deliberately, knowingly scoped it narrower, and only reading the *source* (not the docstring + RFC)
caught that - the same human-source-read step the writeup argues is load-bearing.

## Summary

`URL.click(href)` documents itself as RFC 3986 §5 reference resolution. When `href` is an absolute
URI whose path is *rootless* (does not begin with `/`) - e.g. `mailto:`, `tel:`, `urn:`, or RFC
3986 §5.4.1's own first worked example `g:h` - it raises
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

Each reference is itself well-formed - `URL.from_text('mailto:fred@example.com').to_text()`
round-trips fine. hyperlink can *parse* these URIs; it only fails to *resolve* to them.

## Root cause

`URL.click` (docstring: *"Resolve the given URL relative to this URL ... For more information,
see RFC 3986 section 5"*) reaches a branch for a reference that has a scheme but a rootless path
and **deliberately** raises (the maintainers' choice - see the Correction section above):

```python
raise NotImplementedError("absolute URI with rootless path: %r" % (href,))
```

RFC 3986 §5.2.1 (Transform References) - when `defined(R.scheme)`:

```
T.scheme = R.scheme;  T.authority = R.authority;
T.path   = remove_dot_segments(R.path);  T.query = R.query;
```

i.e. the target is the reference itself. RFC 3986 §5.4.1 (Normal Examples), base
`http://a/b/c/d;p?q`, lists `"g:h" = "g:h"` as the first example. The documented contract (RFC 3986
§5) and the actual behavior (raise on a documented §5.4.1 case) disagree - that gap is the bug.

## Impact (honest)

Correctness and robustness, not security. Any code that resolves a clicked/linked target against
a base URL with `URL.click()` - a feed reader, a crawler, an HTML link rewriter, an email/anchor
normalizer - raises an unhandled `NotImplementedError` the moment it meets an ordinary `mailto:`,
`tel:`, or `urn:` link, rather than resolving it. That is a real availability/robustness defect
(an exception on valid, common input). It is **not** a parser differential, an SSRF, or an
authorization bypass, and is not represented as one. The worst realistic consequence is a crash in
a service that resolves attacker-or-user-supplied link targets; severity depends entirely on the
caller's error handling. Per the Correction above, this is *intended* library behavior, so handling it
is the caller's responsibility by design - not a defect the library would "fix"; `click()` signals
"unsupported" loudly via the exception.

## Provenance (tool-assisted - disclosed)

Found by the cynthia differential bug-auditor, then hand-verified:

- An oracle for `URL.click` was authored by `deepseek-v4-pro` and **mechanically validated by the
  mutation gate** - it killed 4/4 single-site AST mutants of its reference implementation
  (`kill_rate = 1.0`, 0 survivors), i.e. proven non-vacuous before use.
- A differential sweep ran the real library against that oracle over adversarial inputs and
  surfaced the `NotImplementedError` divergence on `g:`/`h:`/`o:`/`n:` (one root cause).
- Triage corroborated cross-family: an independent `minimax-m3` second oracle (gate-GREEN,
  different model family from the deepseek author) plus a deepseek spec re-derivation that agreed
  the operation should resolve. The per-input cross-family *vote* was inconclusive, so promotion
  rested on the spec re-derivation - which is why the auditor rated this **medium**, not high.
- **A human (this write-up) then confirmed it against RFC 3986 §5.2.1 and §5.4.1 directly** and
  reproduced it standalone on the PyPI release. The RFC citation, not the model agreement, is the
  load-bearing evidence here.

The auditor's value was finding the input and flagging it non-vacuously; the confirmation is the
spec citation above.

## Channel - decision pending (not auto-submitted)

No PR or issue has been filed. AI-assisted bug reports are easy to get wrong and unwelcome when
fired blindly at maintainers. Options, to decide deliberately:
1. OSS issue to `python-hyper/hyperlink` with this repro + RFC citation (no PR, let maintainers fix).
2. OSS issue **and** a small PR implementing the §5.2.1 scheme-present case.
3. Local verification only - record as a verified spec-conformance finding without filing upstream.

**Superseded by the Correction above** - the limitation is deliberate and documented in the source, so
there is no correctness bug to file. Recommend **(3), local-only**: retain this as a verified example of
the auditor's doc-vs-source divergence mode, and of why the human source-read (not docstring + spec
alone) is the load-bearing step. The lone fileable residue - a docstring that omits the intentional
limitation - is too minor to be worth an unsolicited report.
