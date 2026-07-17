# cynthia-audit

**LLM-authored spec oracles you never have to trust: a mutation gate is the sole authority.**

A cheap model authors an independent spec oracle for each function of a real, shipping library.
An oracle only counts if it passes on the real code **and** kills mutants of the function it claims
to specify — vacuous, wrong, or hallucinated specs die mechanically, not by human review. Surviving
divergences are triaged with cross-family voting and spec-vector ground truth before anything is
called a finding. This attacks the known failure mode of agentic bug-finding (models reporting a
high rate of invalid bugs when allowed to judge their own work; cf.
[arXiv:2510.09907](https://arxiv.org/abs/2510.09907)). The rule: **the model proposes, mutants dispose.**

Built as a standalone auditor on top of a private mutation-gate library. The model-authoring paths
need an LLM gateway; the differential and cost auditors below need nothing but the standard library.

## See it work (30 seconds, stdlib only, no API key)

```bash
python auditor/differential.py   # run several real URL/RFC-3986 parsers on the same inputs -> JSON divergences
python -m pytest auditor/test_differential.py auditor/test_complexity.py auditor/test_grammar.py -q   # 23 passing
```

`differential.py` is the model-free core of the same divergence-hunting the full pipeline does:
where two independent real parsers read the same authority boundary differently, that disagreement
*is* the bug class (SSRF / request-smuggling / filter-bypass). RFC-permitted variation is folded out
first, so only spec-pinned divergences survive.

## The proven seed

`seed/deepseek_author.py` — the single-function pipeline, measured working 2026-06:
DeepSeek-pro authored a gate-GREEN semver oracle (29/29 mutants killed) for ~$0.032; DeepSeek-flash
authored an inconsistent one the gate caught for ~$0.0008. Run `python seed/deepseek_author.py
deepseek-v4-pro` to reproduce. `seed/semver_oracle.py` is the hand-written reference oracle.

## Budget

Hard cap: **$50 of DeepSeek** for the first full repo pass. Realistic spend for one repo is
$1–5 (pro authoring ~$0.03/function); the cap is iteration headroom, enforced by the harness
spend tracker (A03), which stops dispatching before the cap.

## Layout

    seed/            proven single-function pattern (author -> gate) + reference oracle
    targets/         per-repo target manifests + cloned source (gitignored)
    results/         per-function result records + the findings report (gitignored)
    auditor/         the parallel harness (built by Phase 4)
