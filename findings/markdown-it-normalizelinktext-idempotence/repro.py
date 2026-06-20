#!/usr/bin/env python3
"""markdown-it-py normalizeLinkText is not idempotent on percent-encoded whitespace.

Found by the auto-obligation prover (auditor/intent_obligation.py + fuzz_obligations.py): the
docstring-derived IDEMPOTENT obligation, fuzzed over a Unicode/URL corpus against the real shipped
code. A normalizer is expected to be idempotent (re-normalizing normalized input is a no-op);
normalizeLinkText is not.

  normalizeLinkText('%20') -> ' '   (percent-decodes to a space)
  normalizeLinkText(' ')   -> ''    (a literal space is stripped)
  => f(f('%20')) = '' != ' ' = f('%20')

SEVERITY: low. normalizeLinkText produces autolink DISPLAY text and is applied once in practice;
idempotence is not a documented contract. The security-relevant href path (normalizeLink) IS
idempotent (clean over the same corpus). Reported as an FYI inconsistency, not a critical bug.
"""
from markdown_it import MarkdownIt
md = MarkdownIt()
a = md.normalizeLinkText("%20")
b = md.normalizeLinkText(a)
print(f"normalizeLinkText('%20') = {a!r}")
print(f"normalizeLinkText({a!r}) = {b!r}")
assert a == " " and b == "", "repro shape changed"
print(f"NOT IDEMPOTENT: f(f('%20'))={b!r} != f('%20')={a!r}")
print("normalizeLink (href path) clean:",
      md.normalizeLink("http://h/%20") == md.normalizeLink(md.normalizeLink("http://h/%20")))
