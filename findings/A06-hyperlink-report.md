# Audit report - hyperlink

- **Target:** `hyperlink` @ commit `978f2e6455`
- **Authored by:** `deepseek-v4-pro`  ·  **Cross-family vote:** `minimax-m3`  ·  **Spec arbiter:** `deepseek-v4-pro`
- **Functions:** 61 public  ·  35 auditable (deterministic + spec/invariant basis)
- **Oracles gate-GREEN:** 32 / 35 authored (the mutation gate proved each non-vacuous)
- **Sweep candidates:** 707 (from 1875 raw disagreements, −474 invalid-input filtered)
- **Triaged:** real-bug **5** · bad-oracle 327 · invalid-input 267 · spec-ambiguity 108
- **Cross-family-verified real-bug findings:** **4** {'high': 0, 'medium': 4, 'low': 0}
- **Human-review queue (spec-ambiguity, not asserted bugs):** 16
- **Spend:** $3.1643 total (authoring $2.4726 + triage $0.6917); cap $12.0, stopped=False
- **Wall-clock:** 928s (author 0s + sweep 0s + triage 928s); sweep fanned across 4 worker processes

## Real-bug findings (library crashes on a valid input - A07 must reproduce)

> **Post-hoc human correction (2026-06-24):** the `URL.click` rows below are **NOT a confirmed bug.**
> On source inspection the `NotImplementedError` is raised *intentionally*, under a maintainer comment
> citing RFC 3986 §5.4.2's "loophole in prior specifications" (`src/hyperlink/_url.py`, the `click`
> body). It is a deliberate, documented limitation. These rows are retained as the **raw run output**
> (what the tool emitted, flagged "medium pending repro"); the human characterization and reclassification
> live in `findings/url-click-rootless/REPORT.md` -> *Correction*. This is itself an instance of the
> doc-vs-source divergence mode the project's `WRITEUP.md` is about.

4 finding(s) across 1 function(s): `URL.click`×4. Multiple inputs under one function are the SAME root cause shown by different minimal triggers - count findings by function, not by row.

Each promotion required a CRASH divergence on a VALID input (never a value disagreement) plus corroboration from the cross-family second oracle and/or the independent spec re-derivation (`evidence` records which fired; an inconclusive cross-family vote still needs spec agreement to promote). Confidence is medium pending an independent A07 repro - none is asserted as a confirmed bug here.

### `URL.click`  (medium)
- **Minimal input:** `('p:', 'g:')`
- **Library result:** `RAISED NotImplementedError: absolute URI with rootless path: 'g:'`
- **Oracle expected:** `'g:'`
- **Evidence:** cross-oracle vote `inconclusive` · spec re-derive `oracle` · crash-divergence `True`

### `URL.click`  (medium)
- **Minimal input:** `('p:', 'h:')`
- **Library result:** `RAISED NotImplementedError: absolute URI with rootless path: 'h:'`
- **Oracle expected:** `'h:'`
- **Evidence:** cross-oracle vote `inconclusive` · spec re-derive `oracle` · crash-divergence `True`

### `URL.click`  (medium)
- **Minimal input:** `('p:', 'o:')`
- **Library result:** `RAISED NotImplementedError: absolute URI with rootless path: 'o:'`
- **Oracle expected:** `'o:'`
- **Evidence:** cross-oracle vote `inconclusive` · spec re-derive `oracle` · crash-divergence `True`

### `URL.click`  (medium)
- **Minimal input:** `('p:', 'n:')`
- **Library result:** `RAISED NotImplementedError: absolute URI with rootless path: 'n:'`
- **Oracle expected:** `'n:'`
- **Evidence:** cross-oracle vote `inconclusive` · spec re-derive `oracle` · crash-divergence `True`

## Method note

Every number above traces to this run's artifacts: `records/*.json` (authoring + gate), `sweep/summary.json` (differential sweep), `triage/summary.json` + `triage/findings.json` (classification). The gate's non-vacuity guarantee is what lets a cheap model's oracle be trusted without a human reading it; the cross-family split is what keeps a shared spec-misreading from becoming a false finding.

_Serial author estimate ~8468s vs 0s parallel; sweep + triage fan across process pools._
