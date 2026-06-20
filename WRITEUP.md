# Auditing third-party code with LLM-proposed, execution-judged oracles

A study of where large language models can and cannot be trusted in automated bug-finding for
real Python libraries, with a working pipeline, measured findings, and a comparison against the
current published state of the art.

## The problem

Finding *correctness* bugs — code that runs fine but returns the wrong answer — requires a **test
oracle**: an independent source of truth for what "correct" is. Static analysis and fuzzing find
*broken* (crashes, leaks, undefined behaviour) without an oracle, and are mature, well-funded fields.
They cannot find *wrong*, because "wrong" is defined relative to intent, and intent lives in natural
language (docstrings, names, specs) that pre-LLM tools could not read.

LLMs can read that intent. The question this work investigates is narrow and load-bearing: **can an
LLM supply the oracle?** — and if not directly, in what role is it trustworthy.

## Trust model

The invariant throughout: **the LLM proposes; execution disposes.** No model output is ever a verdict.
Every accept/reject is decided by running code. Concretely the pipeline uses three execution gates,
all from the mutation-testing substrate in `cynthia-core`:

- **Faithfulness** — a candidate oracle/property must hold on the function's *own documented examples*
  (its doctests). An oracle that contradicts the docs is rejected.
- **Teeth (non-vacuity)** — it must kill mutants of the reference/real function. An oracle that passes
  a wrong implementation is vacuous and rejected.
- **Cross-acceptance** — reference and battery are authored *independently* from the spec; if the
  independent battery rejects the independent reference, that is a spec-disagreement to escalate, not a
  silent retry into agreement.

## Pipeline (`auditor/`)

- `coverage_exp.py` / `corpus.py` — async author+gate engine; durable per-cell checkpointing, hard
  budget rail, resume. Builds a corpus of gate-GREEN oracles (= non-vacuous, the coverage metric).
- `recall_strategy.py` — stateless shape→strategy store; leave-one-out-clean exemplar retrieval
  (`nearest_exemplar`) with a deterministic role-split so an injected exemplar never re-couples the
  two independent spec reads.
- `intent_obligation.py` — the obligation **front-end**: a docstring is classified (cheap model) into a
  **library of trusted, hand-written property checkers** (idempotent, case-lower, inverse), anchored to
  the function's doctests; the trusted checker — never LLM-authored logic — renders the verdict.
- `fold_to_frontier.py` — emits the obligations as `cynthia/services/frontier` gates and validates them
  through frontier's own `run_gate` (pass the real function, kill a directed mutant).
- `fuzz_obligations.py` — runs validated obligations on the real shipped code over a Unicode-heavy
  corpus to hunt doc-vs-code violations.
- `slam_dunk.py` — the contrasting design: the LLM **authors** a bespoke property per function (gated by
  faithfulness + teeth + consensus). Included because its failure is the central result.
- `combine_filter.py` — applies the precision signal over an external dataset (below).

## Findings

### 1. Recall lifts coverage, but the corpus must be matured to measure it

A multi-shape strategy ladder lifts gate-GREEN coverage ~60% over a single shape; best-of-N roughly
doubles the ceiling — coverage was authoring-limited, not fundamental. Shape→strategy *recall* is
directionally positive but underpowered on a 42-green corpus. A 6-hour free run of MiniMax-M3
(think-off, best-of-6, doctest front-load) across new repositories produced **208 gate-GREEN oracles
(5× the prior corpus), 24 of them memorizer-defeating (24×)**, deepening exactly the shape bucket where
recall previously had no signal. A memorization-hardened rescue test (cross-domain exemplars only,
behavioural anti-copy, hand-read) showed genuine method-transfer rescues — the exemplar transfers
*how to author*, not the answer.

### 2. An LLM cannot be trusted to *author* the oracle (the central result)

When the LLM authors a bespoke property, it **systematically hallucinates the specification** —
asserting guarantees the docs never make:

| Function | LLM-asserted property | Reality |
|---|---|---|
| `packaging.canonicalize_name` | strips whitespace | it does not; output keeps spaces |
| `packaging.canonicalize_version` | strips pre/post/dev/local | PEP 440 keeps them: `1.0.0a1`→`1a1` |
| `packaging.is_normalized_name` | returns `True` for all inputs | it is a validating predicate |

Critically, **faithfulness + teeth + same-model consensus all fail to catch these.** The hallucinated
rule is not exercised by the doctest inputs (so faithfulness passes), the property still kills mutants
on doctest inputs (so teeth pass), and **same-model consensus fails because the bias is shared** —
K samples from one model hallucinate the *same* rule, so majority voting confirms the false positive.

The fix follows from the structure of the failure. Two kinds of shared bias, two mechanisms:

- **Idiosyncratic-across-models** (different families read an ambiguous spec differently): broken by
  **diverse-model consensus** — author one property per distinct family and require a cross-family
  majority. Measured: `canonicalize_name` and `canonicalize_version` flip from false-positive VIOLATION
  to CONFORMANT, because MiniMax-M3's hallucination is outvoted by DeepSeek and Gemini.
- **Model-universal** (every family makes the same intuitive misreading — the clear case is a bool
  predicate, where all models assume "should return True"): voting cannot break it. Handled by a
  structural **predicate guard** — a bool-returning function is refused (it needs its documented
  *condition*, the boolean-template's job, not a free-form property). Measured: `is_normalized_name`
  moves from VIOLATION to a refusal.

Together these take the five packaging functions the same-model gate false-positived on (3 of 5) down
to **0 false positives**. The general lesson stands: free-form LLM-authored oracles need both a
cross-family vote and structural refusal of the cases where the misreading is universal — and even
then, the high-precision path remains the classifier-over-trusted-templates design below.

### 3. The trustworthy designs keep the LLM out of the oracle seat

- **Classifier over trusted templates** (`intent_obligation.py`): the LLM only chooses which
  hand-written checker applies; execution + doctests judge. On the idempotent slice this produced **6
  verified obligations across two templates with 0 false claims**, correctly *refusing* parsers and a
  bool predicate. The obligations validate as sound frontier gates (3/3: pass real code, kill mutants).
- **Cross-implementation differential** (`differential.py`): corroborate ≥2 real implementations of one
  spec; a disagreement among real, battle-tested code is high-signal. No LLM oracle involved.

### 4. Fuzzing the validated obligations on real code

Over a Unicode-heavy corpus (NFC/NFD, casefold, dotted-I, Kelvin sign, ligatures, zero-width):
`packaging` canonicalizers and `idna` are conformant. `idna`'s `encode`/`decode` produced 14 apparent
round-trip violations — **all triaged as expected case-canonicalization** (`encode` is a canonicalizing
codec, not an inverse; its `decode∘encode` is idempotent, 25/25). `markdown-it-py.normalizeLinkText` has
a **genuine idempotence violation** (`f('%20')=' '`, `f(' ')=''` — percent-decode yields whitespace a
second pass strips); low severity (display-text path, one-shot, idempotence undocumented), and the
security-relevant `normalizeLink` href path is clean. Repro: `findings/markdown-it-normalizelinktext-idempotence/`.

## Comparison with the state of the art

Anthropic's *Finding bugs with Claude and property-based testing* (2026) — arXiv 2510.09907, *Agentic
Property-Based Testing: Finding Bugs Across the Python Ecosystem* — has Claude **author** properties from
docstrings, run Hypothesis tests, reflect, rank, and human-triage. Reported: **Claude Opus 4.1, 2.21
billion tokens, 100+ packages, 984 reports, 56% valid / 32% reportable** (top-21: 86%). Their stated
limitation — *"deriving properties from code with subtle or complex semantics remains difficult... the
agent struggles when code embeds implicit assumptions that only maintainers understand"* — is finding #2
above, **observed at the frontier tier**. This indicates oracle hallucination is a design property, not a
model-quality artifact: it appears on Opus 4.1 with billions of tokens, and on a free small model.

Their released dataset (`github.com/mmaaz-git/agentic-pbt`) carries 21 human validity labels (18 valid,
3 invalid). Wiring the precision signal from finding #3 over their reports (`combine_filter.py`):

- **Caught 3/3 of their released false positives** — each is the same LLM-invented-contract mode
  (`scipy.cumulative_simpson` "monotonicity" — false for the quadrature method; `FibonacciRetry`
  "statelessness" — it is stateful by design; `awkward.ListForm` universal postcondition).
- Kept-set precision rose from 86% → **100% (10/10 kept are valid)**.
- Honest cost: recall 10/18 — as a hard filter it over-rejects (it conflates *assumed-and-false* with
  *assumed-but-reasonable*), so it belongs as a re-ranking signal, with an execution-faithfulness
  variant the path to recovering recall. n = 21 (3 invalid): a signal, not a proof.

## Conclusion

For automated bug-finding on third-party code, the LLM's trustworthy roles are **classifying intent into
trusted checkers** and **aiming inputs** — both gated by execution. Letting it **author the oracle**
reintroduces the test-oracle problem: it hallucinates the specification on inputs the anchoring evidence
does not cover, and the dominant mitigation (consensus) does not catch it because the bias is shared.
This holds from a free small model up to a frontier model at billions of tokens.

## Reproduction

Interpreter `~/projects/cynthia-core/.venv/bin/python` (frontier fold needs the cynthiaV3 venv for
`pydantic_ai`). Env: `LITELLM_KEY`, `LITELLM_GATEWAY` (never written to a file). Target clones are
reproducible from each `targets/<repo>/CHOICE.md` (URL + pinned commit); manifests are tracked, clones
are git-ignored. Frontier workers use direct vendor APIs (`DEEPSEEK_API_KEY` / `MINIMAX_API_KEY`), not
the gateway.

## References

- Anthropic, *Finding bugs with Claude and property-based testing* (2026): https://www.anthropic.com/research/property-based-testing
- *Agentic Property-Based Testing: Finding Bugs Across the Python Ecosystem*, arXiv:2510.09907; code: https://github.com/mmaaz-git/agentic-pbt
- *Hallucination to Consensus: Multi-Agent LLMs for End-to-End JUnit Test Generation* (CANDOR), arXiv:2506.02943
- Google Project Zero / DeepMind, *Big Sleep* — agentic vulnerability discovery (memory/security bugs)
