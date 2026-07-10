# cynthia-audit

**LLM-authored spec oracles you never have to trust: a mutation gate is the sole authority.**

A cheap model authors an independent spec oracle for each auditable function of a real shipping
library. The oracle only counts if it passes on the real code AND kills mutants of the function
it claims to specify - vacuous, wrong, or hallucinated specs die mechanically, not by review.
Divergences that survive are triaged with cross-family voting and structural guards before
anything is called a finding.

This builds on the agentic property-based-testing line of work
([arXiv:2510.09907](https://arxiv.org/abs/2510.09907)), which reports a large invalid-report
rate when the model is allowed to judge its own work. The governing rule here: **the model
proposes, mutants dispose.**

## Read first

- **[WRITEUP.md](WRITEUP.md)** - the main findings: four claims, each execution-backed, plus an
  honest "what this is not."
- **[results/RESULTS/RESULTS.md](results/RESULTS/RESULTS.md)** - the coverage-recall A/B:
  leave-one-out across 4 target repos, pre-committed held-out choice, variance bands - and a
  near-null result reported as such.
- **[findings/](findings/)** - reports from real targets, including post-hoc corrections where
  the first analysis turned out wrong.

## Pipeline

Index a pinned real repository -> a cheap model authors an independent spec oracle per function
-> the mutation gate mechanically proves each oracle non-vacuous (it must kill mutants) -> the
real shipping code runs against gate-passing oracles -> divergences are triaged. The LLM is never
the judge of its own output at any step.

## Reproducing

The model-authoring paths need an OpenAI-compatible gateway (env below) and the mutation-gate
library from a private codebase, so they don't run standalone. The model-free components do:
`auditor/differential.py` (parser differential), `auditor/complexity.py` (growth/ReDoS probe),
and `auditor/trace.py` (the pipeline trace layer) need only the stdlib (+ optional `rfc3986`).
Target repos are pinned by URL + commit in `targets/*/CHOICE.md`; gateway/key config is env-only
and no key is ever written to a file.

## Config (env only)

    LITELLM_GATEWAY   gateway base URL          (required)
    LITELLM_KEY       bearer token              (required)

## The proven seed

`seed/deepseek_author.py` - the single-function pipeline, measured working 2026-06:
DeepSeek-pro authored a gate-GREEN semver oracle (29/29 mutants killed) for ~$0.032; DeepSeek-flash
authored an inconsistent one the gate caught for ~$0.0008. Run `python seed/deepseek_author.py
deepseek-v4-pro` to reproduce. `seed/semver_oracle.py` is the hand-written reference oracle.

## Budget

Hard cap: **$50 of DeepSeek** for the first full repo pass. Realistic spend for one repo is
$1-5 (pro authoring ~$0.03/function); the cap is iteration headroom, enforced by the harness
spend tracker (A03), which stops dispatching before the cap.

## Real-vs-real differential (auditor/differential.py)

A second comparison mode that needs no model and no oracle: run the same URL through 2+
INDEPENDENT real implementations of RFC 3986 and flag where they disagree, with a field-level
diff on the security-relevant authority components (scheme, userinfo, host, port). Where the
oracle sweep is bounded by oracle quality, this is bounded only by the agreement of independent
real code - its sweet spot is the parser-differential class (SSRF / request-smuggling / filter
bypass), where two parsers reading the same authority boundary differently IS the bug.

A raw difference is detected first, then a canonicalization folding EXACTLY the RFC-permitted
variation (scheme/host case §3.1/§3.2.2, percent-hex case §6.2.2.1, default-port elision §6.2.3,
IP-literal brackets §3.2.2). Differences that survive on an authority component are promoted as
spec-pinned candidates; those that vanish are spec-permitted ambiguities and are never promoted.
An accept/reject split is promoted only when ≥2 independent reals resolve the SAME host a third
rejects (cross-parser corroboration). Nothing is dressed as a confirmed CVE - the disagreement
is shown, the RFC clause cited, severity follows the field.

Comparison libraries:
  - urllib.parse - Python stdlib (always present)
  - rfc3986       - OPTIONAL third voice; `pip install rfc3986`. Absent => 2-way. The strongest
                    (corroborated) findings need this third independent parser.

    python auditor/differential.py [--out results/e02-differential] [--cap N]
    ~/projects/cynthia-core/.venv/bin/python auditor/test_differential.py   # proof, no network

## Assertable value bugs (auditor/spec_vectors.py + triage)

Triage used to punt every wrong-VALUE divergence to a human queue - only library crashes
auto-promoted, because cross-model agreement on a subtle value proved correlated (the first
all-deepseek run manufactured a 100% false-positive rate on default-port / normalization
semantics). E03 makes a value divergence assertable when the evidence is strong enough, by two
paths kept explicitly distinct in the finding's evidence:

  - GROUND TRUTH (`spec_vectors.py`): the spec's OWN canonical vectors (RFC 3986 §5.4.1/§5.4.2
    reference-resolution table) are the truth, not a model. A spec-vector SWEEP runs the real
    library over every published vector; a divergence is a real-bug/high anchored to the RFC's
    own example, with the citation. On hyperlink it is correct on 40/41 vectors - the one
    divergence is `URL.click('http://a/b/c/d;p?q','g:h')`, re-confirming the A06 divergence with no
    model in the loop. (That divergence is real and RFC-table-anchored, but it is an *intentional*,
    source-documented limitation in hyperlink - a spec-conformance gap, not a reportable bug; see
    `findings/url-click-rootless/REPORT.md` -> Correction.)
  - CROSS-FAMILY MAJORITY: a value divergence promotes only when ≥3 DISTINCT model families side
    with the oracle (≥2 cross-family GREEN oracles + a cross-family blind arbiter). 2 families
    alone (the production deepseek+minimax config) stays in the human-review queue - the
    correlated-error trap stays closed by construction, proven by re-classifying the real A06
    findings: 0 false value promotions.

Model agreement is corroboration; only the spec's own vectors are proof, and the evidence record
keeps that line bright.

    ~/projects/cynthia-core/.venv/bin/python auditor/test_value_bugs.py     # proof, no network

## Grammar-based + coverage-guided inputs (auditor/grammar.py, E04)

The sweep's pre-E04 generator draws from a fixed, hand-authored `URL_POOL` - finite and static,
so a valid-but-unusual URI the author didn't write is never reached. E04 raises RECALL on three
axes, each feeding the SAME sweep so the lift is measured, not asserted:

  - GRAMMAR - structurally-valid URIs straight from the RFC 3986 ABNF (Appendix A): every
    authority form (reg-name / IPv4 / IPv6 / IPvFuture / empty), rootless vs //-authority paths,
    dot-segments, ports, query, fragment, percent-encoding. Deterministic; every emitted URI is
    validated to parse, so it exercises post-parse code, not just the reject path.
  - SEED - the target's OWN test fixtures (AST-extracted, not regex) ∪ a known edge-case
    dictionary (the RFC §1.1.2 examples, percent-encoding edge cases, Unicode normalization).
  - COVERAGE - a bounded greybox loop (AFL/libFuzzer core idea, no atheris): mutate the corpus,
    keep a mutant only if it reaches a target line not yet covered. Coverage measured with
    `sys.settrace` over the vendored source (no `coverage` dep). HARD-CAPPED by mutation budget;
    the cap is logged, never silent.

Measured on hyperlink (`measure_e04.py`, deterministic): driving the same operation battery, the
baseline pool reaches 393 distinct target lines; baseline ∪ E04 reaches 411 (+18, +4.6%). Over the
14 url-convention gate-GREEN oracles the E04 corpus surfaces proportionally more candidate
divergences for triage (generated-diff, weak evidence). This RAISES recall - more branches
reached, more candidates surfaced - it is NOT exhaustive: no symbolic execution, bounded by the
stated caps. A bug behind a branch none of the three axes reaches is still missed.

    python auditor/measure_e04.py [--records results/a06-final] [--out results/e04-recall]
    AUDITOR_E04=1 python auditor/sweep.py ...   # opt-in: append the E04 corpus to the sweep
    ~/projects/cynthia-core/.venv/bin/python auditor/test_grammar.py   # proof, no network

## Cost/complexity probe (auditor/complexity.py, E05)

Every other probe compares VALUES; this one measures COST - a bug class the correctness
pipeline structurally cannot see. Two probes, both bounded and both honest about timing noise:

  - GROWTH - time a function across geometrically scaled input sizes (n, 2n, 4n, 8n), median-of-k
    on distinct payloads, fit a log-log slope + R^2, and flag superlinear ONLY when the clean fit
    repeats in every independent trial. Constant-factor noise has no slope and cannot trip it.
    Reported as MEASURED growth over the probed range, never an asymptotic proof.
  - REDOS - throw catastrophic-backtracking attack shapes at the regex-bearing parser entry
    point and flag runaway time against a same-length benign baseline (abs threshold x ratio,
    or the wall bound itself dying). The baseline comparison separates "this shape backtracks"
    from "this function is slow on every large input" (which is the growth probe's business).

Every measurement runs in a forked child that STREAMS per-size results; the parent kills it at a
wall bound, so a genuinely-exponential function is a logged `bound-hit`, never a hung run. The
planted controls in the test prove both directions: a quadratic function and a `(a+)+$` regex are
flagged; linear/constant functions and a safe regex are not.

Measured on hyperlink (results/e05-complexity): all 6 size-scalable axes (parse/normalize/
to_uri/to_text/click) fit linear (slopes 0.66-1.02), and 8 attack shapes produce no runaway -
0 complexity candidates, a valid recorded outcome for a well-built library.

    python auditor/complexity.py [--out results/e05-complexity] [--base-n 128] [--trials 3]
    ~/projects/cynthia-core/.venv/bin/python auditor/test_complexity.py   # proof, no network

## Layout

    seed/            proven single-function pattern (author -> gate) + reference oracle
    targets/         per-repo target manifests + cloned source (gitignored)
    results/         per-function result records + the findings report (gitignored)
    auditor/         the parallel harness (built by Phase 4) + differential (E02) + grammar/coverage inputs (E04) + complexity probe (E05)
