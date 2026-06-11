# Target: idna

**Repo:** https://github.com/kjd/idna (shallow clone in `repo/`, gitignored)
**Pinned commit:** 862150e12779792900343b48a1223beb5e2b62f7 (2026-06-02)
**License:** BSD-3-Clause — permits cloning, analysis, and quoting source in a write-up.

## Why this target

- **Security-relevant bug class.** IDNA is the internationalized-domain-name boundary: the
  encode/decode and A-label/U-label (punycode) conversions are exactly where homograph,
  normalization-confusion, and label-validation bugs live. A divergence between idna's shipping
  behavior and an independently-authored RFC 5890/5891 + UTS-46 oracle is the shape of finding
  this auditor exists to surface — the same family as the hyperlink URL-parser differential, in a
  different domain (a genuinely new test of the harness, not a re-run of the same surface).
- **Famous enough to matter.** idna is the IDNA library underneath requests and httpx. A real
  finding here is credible; a clean pass is also a meaningful negative result.
- **Pure Python.** The mutation gate is Python-AST; idna's core (`core.py`) is pure Python with
  table-driven data (`idnadata.py`, `uts46data.py`), so the gate mutates the code that actually
  ships.
- **Edge-case-rich, with an inverse pair.** label-length / bidi / contextj / contexto / hyphen
  validation, NFC checks, std3 remapping — a dense spec surface. `encode`/`decode` and
  `Codec.encode`/`Codec.decode` are inverse pairs, so the indexer also assigns the round-trip
  invariant basis (exercises the E01 invariant-oracle path, not only spec oracles).

## Manifest summary (from `auditor/index.py`, rerunnable)

- 23 public functions; 20 basis=`spec`, 2 basis=`invariant`, **1 basis=`none`** (no substantive
  docstring, no recognized universal invariant — honestly out of scope for oracle authoring).
- 22/23 deterministic.
- **21 auditable** (deterministic AND spec|invariant).

## Classifier limitations (recorded, not hidden)

- Only statically-unconditional module-level defs (and methods of module-level classes) are
  indexed; defs inside import guards are excluded as environment-conditional.
- Determinism is judged on writes to enclosing-scope state plus known-impure calls
  (time/random/IO/env), propagated transitively through the package call graph. Reads of the
  large static IDNA data tables are deterministic; the sweep runs each function in a fresh process,
  so this is sound for the audit.
- The table-driven validators consult module-level frozensets/dicts (`idnadata`); these are
  read-only data, treated as deterministic — correct for a per-process sweep.
