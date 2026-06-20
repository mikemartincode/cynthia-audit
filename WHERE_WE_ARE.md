# MASTER HANDOFF — Coverage-Recall experiment + M3 author/speed work

Single handoff doc for everything in `~/projects/cynthia-audit` (the experiment) plus the M3 author +
gate-safety work that grew out of it. Self-contained; a cold context should be able to continue from
here. Companion: `~/projects/cynthiaV3/M3_SPEED_HANDOFF.md` (the focused M3 inference-speed sweep).

---

## 0. State in one paragraph
We built a rigorous harness to test whether **"recall" lifts an LLM bug-auditor's oracle COVERAGE**
(= fraction of functions whose authored oracle passes the cynthia-core **mutation gate** = non-vacuity,
NOT correctness). The harness works; ~$43 of deepseek-v4-pro spent. **Proven:** the multi-shape
strategy *ladder* lifts coverage +60%; best-of-N *doubles the ceiling* (coverage was authoring-limited,
not fundamental). **Open (the actual thesis):** the version of recall that was BUILT is only a strategy
*selector* (reorders which oracle shape to try) — it's ceiling-capped and showed a small,
directionally-consistent-but-underpowered lift (+0.015, 4/4 repos, within noise). The version that was
*intended* — recall as **augmented generation** (inject past successful oracles as exemplars so the
model authors past its own ceiling) — has **not been built or tested**. A parallel thread found **M3
think-OFF best-of-N ≈ paid deepseek at $0**, which (if scaled) makes the whole experiment free — but an
M3 best-of-N spike OOM-killed the box (now fixed). Decision pending: build the real (exemplar) recall,
test recall-with-headroom, scale for significance, or move M3 onto the experiment.

---

## 1. The two threads
- **Thread A — coverage-recall experiment** (the original goal). Paused at a decision point.
- **Thread B — M3 as a free author + M3 speed** (grew out of "deepseek is expensive"). M3 parity shown;
  speed sweep not yet run (see `M3_SPEED_HANDOFF.md`).

---

## 2. What's PROVEN (measured findings)
1. **Ladder works: +60% coverage.** Pooled deterministic held-out coverage baseline 0.091 → blind
   retry (value→invariant→property) 0.146 (+0.055), beyond the Arm-1 noise band on 3/4 repos.
2. **Recall (SELECTION version) is directionally positive but underpowered.** Arm3 (recall-ordered) >
   Arm2 (blind) on 4/4 held-out repos, pooled +0.015 (~+10% over blind), sign-test p≈0.06, but WITHIN
   the reps=3 noise bands → not significant.
3. **best-of-N doubles the ceiling: 0.193 → 0.395 pooled** (packaging 4×, dateutil 5×, markdown 1.75×,
   bleach flat). ⇒ low coverage is **authoring-limited, not fundamental**.
4. **Why coverage is low:** 73% of attempts fail the gate's step-0 cross-acceptance (`spec_disagreement`
   — the independent battery rejects the independent reference). Sub-types: 60% domain/error-boundary,
   23% value/logic, 17% convention/input-shape. Single-call coupling recovers only ~25% on the hardest
   repo ⇒ mostly the model's one-shot oracle-authoring ceiling, not the cross-check.
5. **What recall LEARNED (qualitative, encouraging):** real, sensible rules — `arity=2`: value
   collapses 0.03 vs property 0.14 (n=36, routes around the multi-arg convention failure); `inv=True`:
   invariant 0.40 vs value 0.20 (n=5, the round-trip insight). BUT the dominant `arity=1` shape (n=47)
   shows no preference (~0.15 all) → dilutes the aggregate. The mechanism is real *where shape predicts
   strategy*; the coarse key + low ceiling cap the measurable effect.
6. **Cost is reasoning-OUTPUT-bound, not cache.** 49.3M output tokens = 97% of the ~$43 bill; input is
   3.5M (82% cached — the cache fires fine, it just barely matters). best-of-N is ~5.4×/cell because it
   multiplies output. ⇒ the cost lever is fewer drafts / capped reasoning / a cheaper author, NOT cache.
7. **M3 parity (Thread B):** M3 think-OFF best-of-8 = 6/23 GREEN on dateutil = ties deepseek best-of-5
   (6/23) at **$0**. Author DIVERSITY is the real lever: M3 & deepseek GREEN sets near-disjoint → union
   ~2× either. (n=23, one repo — small; the disjoint-sets finding is the robust one.) See memory
   `project_m3_oracle_author_parity`.

**CLAIM BOUNDARY (always state):** coverage = gate-GREEN = non-vacuity, NOT correctness. No model ever
*approves* an oracle; the gate decides. strict-GREEN (memorizer-killing) recorded alongside, rarer.

---

## 3. Bugs found & fixed (harness hardening — all verified)
1. **Budget rail false-drop** — `reserve()` ran before the semaphore, booking all N cells' $0.20
   estimate up-front → tripped the cap on estimates. Fixed: reserve INSIDE the sem.
2. **M3 non-stream timeout** — reasoning buffered past the 300s read timeout (15/30 bake-off cells).
   Fixed: `_wants_stream` → minimax streams; deepseek stays non-stream (keeps its cache).
3. **Gate hang** — a non-terminating authored reference hung the in-process ref-check forever (wedged
   the run). Fixed: gate in a hard-kill subprocess (`gate_subprocess.py` → `_gate_runner.py`), 90s
   process-group SIGKILL.
4. **OOM (the box/tmux crash)** — a memory-bomb reference (allocating loop) in an IN-PROCESS best-of-N
   gate grew a python proc to **29GB** → OOM-killed the box / its tmux pane. Fixed: `RLIMIT_AS` cap
   (4GB, env `GATE_MEM_CAP_GB`) in `_gate_runner.py` — bomb dies at the cap, box survives.
5. **gate-failed ≠ RED** — timeout/OOM/crash were being counted as RED (polluting coverage). Fixed:
   `gate_failed=True` flag on no-verdict gates; such cells bucket as `error`, EXCLUDED from coverage +
   recall (a crashed gate is not a verdict that the oracle is bad).
6. **m3_speedab wired onto the capped gate** — extracted the subprocess gate into `gate_subprocess.py`
   (stdlib-only, no circular import) and pointed `author_best_of_n`'s in-process gate at it, so
   `m3_speedab.py` is now memory-safe to re-run. Verified: bomb → no OOM; good → GREEN.

Full suite: **51 passed, 0 failed** (incl. the previously-failing triage salvage test, fixed as a
side-effect of subprocess gating).

---

## 4. Tested ✅ vs Open ❓
**✅ verified (code):** 51 unit tests; recall statelessness (exclude≡delete); gate hardening (timeout
/ mem-bomb / cap / good-still-GREEN); best-of-N bomb-safety; engine checkpoint/resume/budget-wall;
arm simulation; prefix cache fires.
**✅ determined (runs):** bake-off → deepseek primary; corpus (5 repos); LOO held-out (4 repos); ceiling
doubling; spec-disagreement diagnosis; M3 parity (1 repo); OOM root cause.
**❓ open (not run):**
- **#1 (headline) Exemplar-injection recall** — the REAL idea (author past the ceiling). Not built.
- **#2 Recall-with-headroom** — does selection-recall beat blind retry once best-of-N gives room? Not run.
- **#3 Significance at scale** — 15-repo leave-one-out (4/4-direction → real p-value). Not run.
- **#4 M3 as the fixed author end-to-end** — scale beyond 23 fns; M3 `property` shape; M3 corpus/holdout.
- **#5 M3 speed settings sweep** — thinking/max_tokens/streaming/shim/routing matrix (`M3_SPEED_HANDOFF.md`).
- **#6 Re-run validation** of the fixed m3_speedab under real load.
- **#7 Correctness beyond non-vacuity** — differential sweep + human (out of scope so far).

---

## 5. Decision — what to do next (ranked)
- **A (recommended, ~$3–5): build + run the exemplar-injection A/B (#1).** Make `recall_strategy.py`
  also retrieve the GREEN oracle *code* for the nearest same-shape function (other repos, LOO-clean),
  inject it into `_author_independent`'s prompt, and A/B ~15–20 deepseek-failed functions (with vs
  without exemplar). One decisive number on the actual thesis. Tiny spend.
- **B (free): finalize honest v1.** Ladder +60% + best-of-N doubles ceiling + selection-recall
  directionally-positive-within-noise + the cost/diagnosis. Credible under-claimed artifact.
- **C: recall-with-headroom (#2)** — best-of-N holdout, but on M3 (free) not deepseek (else expensive).
- **D: M3 speed sweep (#5)** — hand to fresh context per `M3_SPEED_HANDOFF.md`; a fast+good M3 makes
  B/C/#3 all free.
- NOT recommended: scaling the *selection* recall on deepseek (expensive, tests the weak version).

---

## 6. Harness map + how to run + invariants
**Interpreter:** `~/projects/cynthia-core/.venv/bin/python` (editable cynthia_core + pytest; stdlib
sqlite3). **cynthia-core is NOT modified — do not.**
**Env (never write the key to a file):**
`export LITELLM_KEY=$(grep ^LITELLM_KEY= ~/projects/cynthiaV3/.env | cut -d= -f2-);
 export LITELLM_GATEWAY=http://192.168.1.110:4000` (M3 cache shim live on :4100).
**Author model FIXED across corpus + all arms** (no Opus; M3 is the free candidate, deepseek the paid).

`auditor/` modules:
- `author.py` — 4 oracle shapes (value/invariant/property/stubbed_seam); static-first prompts (prefix
  cache); strict-GREEN; `_author_independent` (where exemplar injection goes for #1); `author_best_of_n`
  (M3 path, now gates via the capped subprocess); `gate_authored` (in-process gate, used INSIDE the
  subprocess runner).
- `gate_subprocess.py` — **the shared safe gate** (hard-kill timeout + memory cap). Use this, not
  in-process `gate_authored`, for any new gating.
- `_gate_runner.py` — the subprocess entry (sets `RLIMIT_AS`).
- `coverage_exp.py` — async author+gate engine: `run_cells(best_of_n=…)`, budget rail, atomic
  checkpoint, resume, heartbeat, gate_failed handling.
- `recall_strategy.py` — stateless sqlite shape→strategy store (for #1: add GREEN-oracle-code retrieval).
- `corpus.py` (durable repo queue) · `holdout.py` (pure 3-arm leave-one-out simulation) ·
  `report_loo.py` (per-repo + pooled + SVG + RESULTS.md) · `bakeoff.py` · `acquire_targets.py` ·
  `m3_speedab.py` (M3 best-of-N speed/quality A/B — safe to re-run now).
**Run:** `corpus.py --create-from <queue_seed> --recall-db results/corpus/recall.db --best-of-n N` (add
the flag where threaded) → `holdout.py`/loop → `report_loo.py`. Re-run `report_loo.py` any time (pure).

**Invariants (never break):** gate is the sole authority (no model approves, incl. a retrieved
exemplar); leave-one-out excludes the held-out repo's rows (recall stateless aggregation); author model
fixed across arms (only the retry/recall policy varies); coverage = gate-GREEN ≠ correctness.

---

## 7. Data on disk (`results/`)
- `corpus/recall.db` — recall corpus (5 repos, single-draft).
- `ceiling_bon/` — best-of-5 ceiling data (4 repos).
- `holdout/<repo>/` — held-out v1 cells (4 repos, reps=3).
- `RESULTS/` — v1 deliverables (RESULTS.md + 2 SVG charts + loo_summary.json).
- `bakeoff/`, `_derisk/`, `_sstest/` — earlier phases.
- `targets/` — 10 indexed eligible repos (packaging, dateutil, markdown-it-py, bleach, more-itertools,
  toolz, boltons, semver, validators, humanize) + idna (train-only). hyperlink = calibration.

## 8. Spend
~$43 real deepseek (est tracks real within ~7%; output-bound). M3 work ~$0. Whole-experiment estimate
if continued: exemplar A/B ~$3–5; full best-of-N×15-repo on deepseek ~$200+ (don't — use M3).

## 9. Memory + cross-refs
Memory (`~/.claude/projects/-home-mike-projects-cynthiaV3/memory/`): `project_coverage_recall_experiment`
· `project_m3_oracle_author_parity` · `project_m3_bestofn_oom`. M3 speed sweep: `cynthiaV3/M3_SPEED_HANDOFF.md`.
