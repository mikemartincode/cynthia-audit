# cynthia-audit — parallel real-repo bug auditor (built on cynthia-core)

**Status:** scaffold + proven seed. The parallel harness is built by coreship Phase 4 (A01–A06).

## What this is

A separate application that uses the `cynthia-core` mutation gate to audit a real, famous
repository for bugs: index its functions, have a cheap model (DeepSeek) author an independent
spec oracle per auditable function, mechanically prove each oracle non-vacuous with the mutation
gate, run the real shipping code against the gate-passing oracles, and triage the divergences.

## Why it lives OUTSIDE cynthia-core

`cynthia-core` is curated to be secret-free, infra-free, stdlib-core (see its `CLAIMS.md` and the
coreship EXCLUDE list). This auditor uses the LiteLLM gateway + DeepSeek + a bearer key — exactly
the proprietary coupling cynthia-core deliberately excludes. So the auditor imports `cynthia_core`
as a **library** and keeps all gateway/key config in env. **Nothing here ever gets committed into
cynthia-core, and no key is ever written to a file.**

## Config (env only)

    LITELLM_GATEWAY   gateway base URL          (required)
    LITELLM_KEY       bearer token              (required)

## The proven seed

`seed/deepseek_author.py` — the single-function pipeline, measured working 2026-06:
DeepSeek-pro authored a gate-GREEN semver oracle (29/29 mutants killed) for ~$0.032; DeepSeek-flash
authored an inconsistent one the gate caught for ~$0.0008. Run `python seed/deepseek_author.py
deepseek-v4-pro` to reproduce. `seed/semver_oracle.py` is the hand-written reference oracle.

## Budget

Hard cap: **$50 of DeepSeek** for the first full repo pass. Realistic spend for one repo is
$1–5 (pro authoring ~$0.03/function); the cap is iteration headroom, enforced by the harness
spend tracker (A03), which stops dispatching before the cap.

## Real-vs-real differential (auditor/differential.py)

A second comparison mode that needs no model and no oracle: run the same URL through 2+
INDEPENDENT real implementations of RFC 3986 and flag where they disagree, with a field-level
diff on the security-relevant authority components (scheme, userinfo, host, port). Where the
oracle sweep is bounded by oracle quality, this is bounded only by the agreement of independent
real code — its sweet spot is the parser-differential class (SSRF / request-smuggling / filter
bypass), where two parsers reading the same authority boundary differently IS the bug.

A raw difference is detected first, then a canonicalization folding EXACTLY the RFC-permitted
variation (scheme/host case §3.1/§3.2.2, percent-hex case §6.2.2.1, default-port elision §6.2.3,
IP-literal brackets §3.2.2). Differences that survive on an authority component are promoted as
spec-pinned candidates; those that vanish are spec-permitted ambiguities and are never promoted.
An accept/reject split is promoted only when ≥2 independent reals resolve the SAME host a third
rejects (cross-parser corroboration). Nothing is dressed as a confirmed CVE — the disagreement
is shown, the RFC clause cited, severity follows the field.

Comparison libraries:
  - urllib.parse — Python stdlib (always present)
  - rfc3986       — OPTIONAL third voice; `pip install rfc3986`. Absent => 2-way. The strongest
                    (corroborated) findings need this third independent parser.

    python auditor/differential.py [--out results/e02-differential] [--cap N]
    ~/projects/cynthia-core/.venv/bin/python auditor/test_differential.py   # proof, no network

## Assertable value bugs (auditor/spec_vectors.py + triage)

Triage used to punt every wrong-VALUE divergence to a human queue — only library crashes
auto-promoted, because cross-model agreement on a subtle value proved correlated (the first
all-deepseek run manufactured a 100% false-positive rate on default-port / normalization
semantics). E03 makes a value divergence assertable when the evidence is strong enough, by two
paths kept explicitly distinct in the finding's evidence:

  - GROUND TRUTH (`spec_vectors.py`): the spec's OWN canonical vectors (RFC 3986 §5.4.1/§5.4.2
    reference-resolution table) are the truth, not a model. A spec-vector SWEEP runs the real
    library over every published vector; a divergence is a real-bug/high anchored to the RFC's
    own example, with the citation. On hyperlink it is correct on 40/41 vectors — the one
    divergence is `URL.click('http://a/b/c/d;p?q','g:h')`, re-confirming the A06 finding with no
    model in the loop.
  - CROSS-FAMILY MAJORITY: a value divergence promotes only when ≥3 DISTINCT model families side
    with the oracle (≥2 cross-family GREEN oracles + a cross-family blind arbiter). 2 families
    alone (the production deepseek+minimax config) stays in the human-review queue — the
    correlated-error trap stays closed by construction, proven by re-classifying the real A06
    findings: 0 false value promotions.

Model agreement is corroboration; only the spec's own vectors are proof, and the evidence record
keeps that line bright.

    ~/projects/cynthia-core/.venv/bin/python auditor/test_value_bugs.py     # proof, no network

## Layout

    seed/            proven single-function pattern (author -> gate) + reference oracle
    targets/         per-repo target manifests + cloned source (gitignored)
    results/         per-function result records + the findings report (gitignored)
    auditor/         the parallel harness (built by Phase 4) + differential mode (E02)
