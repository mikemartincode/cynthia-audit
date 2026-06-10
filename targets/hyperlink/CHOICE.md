# Target: hyperlink

**Repo:** https://github.com/python-hyper/hyperlink (shallow clone in `repo/`, gitignored)
**Pinned commit:** 978f2e645578aad856fe5e03e2e2c017c8c0f7ca (2026-03-20)
**License:** MIT — permits cloning, analysis, and quoting source in a write-up.

## Why this target

- **Security-relevant CVE class.** URL-parser differentials are a real vulnerability family
  (SSRF, auth bypass, normalization confusion). A divergence between hyperlink's parse /
  normalize / to_uri behavior and an independently-authored RFC 3986 oracle is exactly the
  shape of finding this auditor exists to surface.
- **Famous enough to matter.** hyperlink is the URL library underneath Twisted. A real finding
  here is credible; a clean pass over it is also a meaningful negative result.
- **Pure Python.** The mutation gate is Python-AST; C-backed parsers (e.g. yarl's quoting
  extension) would leave the gate mutating code that isn't what ships. hyperlink's core is one
  2,472-line pure-Python module (`_url.py`).
- **Edge-case-rich.** IDNA hosts, percent-encoding per-component, scheme registries, rooted vs
  relative paths, IPv6 literals — dense spec surface where bugs plausibly survive.
- Runtime dep: `idna` (third-party). The sweep environment must install it; the indexer does not
  need it.

## Manifest summary (from `auditor/index.py`, rerunnable)

- 61 public functions; 34 basis=`spec`, 2 basis=`invariant`, **25 basis=`none`** (no substantive
  docstring, no recognized universal invariant — honestly out of scope for oracle authoring).
- 60/61 deterministic; the exception is `register_scheme` (writes three module-level registries).
- **35 auditable** (deterministic AND spec|invariant).

## Classifier limitations (recorded, not hidden)

- Only statically-unconditional module-level defs are indexed. Defs inside `try:`/`if` import
  guards are environment-conditional and excluded — this drops `hypothesis.py`'s test-support
  strategies and `_socket.py`'s Windows-py2.7 ctypes fallback, both correctly out of audit scope.
- Determinism is judged on *writes* to enclosing-scope state plus known-impure calls
  (time/random/IO/env), propagated transitively through the package call graph. *Reads* of
  mutable module state (e.g. `scheme_uses_netloc` consulting the scheme registry) are treated as
  deterministic; the sweep runs each function in a fresh process with default registry state, so
  this is sound for the audit but would not be for long-lived processes.
- Unresolvable external calls (e.g. `idna.encode`) are assumed pure. The differential sweep
  re-checks determinism empirically (same input twice) before trusting any divergence.
- `datetime.datetime.now()`-style two-level attribute chains are not resolved (only
  alias-to-module bases); hyperlink does not use datetime.
