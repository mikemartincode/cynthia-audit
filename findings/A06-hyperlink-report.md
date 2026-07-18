# Audit report — hyperlink

- **Target:** `hyperlink` @ commit `978f2e6455`
- **Authored by:** `deepseek-v4-pro`  ·  **Cross-family vote:** `minimax-m3`  ·  **Spec arbiter:** `deepseek-v4-pro`
- **Functions:** 61 public  ·  35 auditable (deterministic + spec/invariant basis)
- **Oracles gate-GREEN:** 32 / 35 authored (the mutation gate proved each non-vacuous)
- **Sweep candidates:** 707 (from 1875 raw disagreements, −474 invalid-input filtered)
- **Triaged:** crash-flagged **5** · bad-oracle 327 · invalid-input 267 · spec-ambiguity 108
- **Cross-family-verified crash-flag candidates:** **4** {'high': 0, 'medium': 4, 'low': 0}  (disposition below)
- **Human-review queue (spec-ambiguity, not asserted bugs):** 16
- **Spend:** $3.1643 total (authoring $2.4726 + triage $0.6917); cap $12.0, stopped=False
- **Wall-clock:** 928s (author 0s + sweep 0s + triage 928s); sweep fanned across 4 worker processes

## Crash-flag candidates (raise on a valid input) — disposition: documented-intentional non-finding

4 candidate(s) across 1 function(s): `URL.click`×4. Multiple inputs under one function are the SAME root cause shown by different minimal triggers — count by function, not by row.

**Disposition:** all four rows are one root cause — hyperlink's deliberate `NotImplementedError` for the RFC 3986 §5.2.1 scheme-present rootless-path case (full analysis in `findings/url-click-rootless/`). That raise is explicit in the library's own source, so this is a documented, intentional limitation — recorded as a **non-finding** and NOT reported upstream. What the pipeline demonstrates here is the auditor surfacing a genuine spec-vs-implementation gap non-vacuously; the human triage's job was to decline to escalate a deliberately-unimplemented case.

Each promotion required a CRASH divergence on a VALID input (never a value disagreement) plus corroboration from the cross-family second oracle and/or the independent spec re-derivation (`evidence` records which fired; an inconclusive cross-family vote still needs spec agreement to promote). Confidence is medium pending an independent A07 repro — none is asserted as a confirmed bug here.

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
