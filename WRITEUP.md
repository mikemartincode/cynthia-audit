# A shared-bias failure in agentic property-based testing, and a fix

Characterizing why a large fraction of LLM-authored property-test bug reports are invalid, why the
standard mitigation (consensus) does not fix it, and what does - evaluated against the released labels
of the current published state of the art.

## Summary

Agentic property-based testing - an LLM authors properties from a function's documentation, runs them,
and reports counterexamples - is the current approach to finding *correctness* bugs in real code at
scale. The published state of the art (Anthropic, *Finding bugs with Claude and property-based testing*,
2026; arXiv:2510.09907) reports that **44% of its generated reports are invalid** (56% valid, 32%
reportable), using **Claude Opus 4.1 across 2.21 billion tokens on 100+ Python packages**.

This work makes four claims, each backed by execution:

1. **The invalid reports share one root cause** - the LLM asserts a contract the specification never
   makes (a *spec hallucination*): monotonicity a numerical method does not guarantee, statelessness on
   an object documented as stateful, a universal postcondition that holds only for valid inputs. All 3
   false positives in the SOTA's released label set are this mode, and it reproduces independently.
2. **It is a design problem, not a model-quality one** - the same failure appears at the frontier tier
   (Opus 4.1, billions of tokens) and on a free small model. More/better model does not remove it.
3. **Consensus does not fix it.** Same-model voting shares the model's bias; even diverse-model voting
   cannot catch a misreading every model family makes.
4. **A fix that does** (for the cases it can): diverse-model consensus for biases idiosyncratic to one
   family, plus a structural guard for the model-universal cases - taking the false positives to zero on
   the evaluated set, and catching 3/3 of the SOTA's released false positives as a precision filter.

The governing principle: **an LLM may classify intent and aim inputs; execution and trusted checkers
render the verdict. The LLM must never author the oracle** - that reintroduces the test-oracle problem.

## Background: the false-positive rate is the bottleneck

In agentic PBT the LLM *is* the oracle: it decides what "correct" means by authoring the property. The
SOTA manages the resulting invalid reports with a ranking rubric and human triage (top-21 reach 86%
valid). Its own stated limitation: *"deriving properties from code with subtle or complex semantics
remains difficult... the agent struggles when code embeds implicit assumptions that only maintainers
understand."* That sentence is the failure mode this work characterizes - observed at the frontier tier.

## The failure mode: LLM-invented-contract hallucination

The three false positives in the SOTA's released labels, each an asserted contract the spec never makes:

| Report (their false positive) | Asserted property | Why it is wrong |
|---|---|---|
| `scipy.integrate.cumulative_simpson` | result is monotonic for non-negative input | Simpson's rule fits parabolas; non-monotonic on non-uniform spacing **by construction** |
| `aiohttp_retry.FibonacciRetry.get_timeout` | deterministic / stateless in `attempt` | a **stateful** retry generator by design |
| `awkward.forms.ListForm.length_one_array` | `len == 1` for any constructed form | crashes on a malformed form - invalid construction, not a bug |

Reproduced independently on `packaging` (free model): authored properties claimed `canonicalize_name`
strips whitespace (it does not), `canonicalize_version` strips pre/post/dev/local (PEP 440 keeps them:
`1.0.0a1`->`1a1`), and `is_normalized_name` returns `True` for all inputs (it is a validating predicate).

Critically, the standard gates do not catch these. **Faithfulness** (the property holds on the
function's own doctest inputs) passes, because the hallucinated rule is not exercised by the documented
examples. **Teeth** (the property kills mutants) passes, because it still discriminates on those inputs.
The error lives in the region the anchoring evidence does not cover.

## Why consensus does not fix it

The intuitive mitigation - author the property K times and require agreement - fails in a measurable way.
Same-model K-sampling shares the model's bias: three samples from one model hallucinate the *same* rule,
so the majority *confirms* the false positive (measured: 3 of 5 `packaging` functions). Voting only
suppresses error that is *idiosyncratic*; spec hallucination is *systematic*.

There are two systematic kinds, and they need different mechanisms:

- **Idiosyncratic across model families** - different models read an ambiguous spec differently.
- **Model-universal** - every family makes the same intuitive misreading (the clear case: a boolean
  predicate, where all models assume "should return `True`").

## The fix

- **Diverse-model consensus** - author one property per *distinct* model family (MiniMax-M3, DeepSeek,
  Gemini) and require a cross-family majority. This breaks idiosyncratic-across-models bias. Measured:
  `canonicalize_name` and `canonicalize_version` move from false-positive VIOLATION to CONFORMANT,
  because one model's hallucination is outvoted.
- **Structural predicate guard** - a bool-returning function is refused (its correctness needs the
  documented *condition*, not a free-form property; the misreading is universal so voting cannot help).
  Measured: `is_normalized_name` moves from VIOLATION to a refusal.

Together these take the five `packaging` functions the same-model gate false-positived on (3 of 5) to
**zero false positives**.

As a *precision filter over the SOTA's released reports*: classify each report's violated property as
*documented* vs *assumed-contract*. This **caught 3/3 of the released false positives** (kept-set
precision 86%->100%). Honest cost: recall 10/18 - as a hard filter it over-rejects, conflating
*assumed-and-false* with *assumed-but-reasonable*, so it belongs as a re-ranking signal with an
execution-faithfulness variant as the path to recovering recall. n = 21 (3 invalid): a signal, not a proof.

## The principle, and the high-precision alternative

The reliable design keeps the LLM out of the oracle seat entirely: it **classifies** a docstring into a
library of **trusted, hand-written property checkers** (idempotent, case-lower, inverse) anchored to the
function's doctests; the trusted checker - never LLM-authored logic - renders the verdict. On an
idempotent slice this produced **6 verified obligations with 0 false claims**, correctly *refusing*
parsers and predicates, and the obligations validate as sound gates in an external verification service
(pass the real function, kill a directed mutant). Where two real implementations of one spec exist, a
**cross-implementation differential** finds genuine divergences with no LLM oracle at all.

## What this is not

- **Not a new bug-finder.** The base agentic-PBT system is Anthropic's published work; the contribution
  here is the characterization, the why-consensus-fails result, and the fix - on top of it.
- **Not a bug count.** The high-precision path was run over 67 single-argument functions across four
  mature libraries (more-itertools, semver, humanize, boltons): **0 false positives and 0 reportable
  bugs.** Well-maintained code on the tool's precise surface is conformant; the tool correctly reports
  that good code is good. Finding real bugs at volume requires a different target profile
  (mid-maturity, serialization-heavy libraries - where the SOTA's real findings clustered) and
  multi-argument support, which the present single-argument tooling lacks. That is future work, stated
  plainly rather than implied.
- **Not statistically powered.** The released label set is 21 reports (3 invalid); the independent
  reproduction is 5 functions. The results are directional and reproducible, not significance claims.

## Method / apparatus

The experiments are produced by a small pipeline (`auditor/`): an async author-and-gate engine over the
`cynthia-core` mutation gate with durable checkpointing; a stateless shape->strategy recall store with
leave-one-out-clean exemplar retrieval; the obligation front-end (`intent_obligation.py`) and its
validation through an external verification service (`fold_to_frontier.py`); the free-form authoring path
with the diverse-vote + predicate-guard gate (`authored_oracle.py`); and the precision filter over the external
dataset (`combine_filter.py`).

## Reproduction

Interpreter `~/projects/cynthia-core/.venv/bin/python` (the verification-service fold needs the cynthiaV3
environment for `pydantic_ai`). Configuration is environment-only (`LITELLM_KEY`, `LITELLM_GATEWAY`;
direct vendor keys `DEEPSEEK_API_KEY` / `MINIMAX_API_KEY` for the diverse panel), never written to a
file. Target clones are reproducible from the pinned commit in each `targets/<repo>/CHOICE.md`; manifests
are tracked, clones are git-ignored.

## References

- Anthropic, *Finding bugs with Claude and property-based testing* (2026): https://www.anthropic.com/research/property-based-testing
- *Agentic Property-Based Testing: Finding Bugs Across the Python Ecosystem*, arXiv:2510.09907; code: https://github.com/mmaaz-git/agentic-pbt
- *Hallucination to Consensus: Multi-Agent LLMs for End-to-End JUnit Test Generation* (CANDOR), arXiv:2506.02943
