# cynthia-audit

[![ci](https://github.com/mikemartincode/cynthia-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/mikemartincode/cynthia-audit/actions/workflows/ci.yml)

**LLM-authored spec oracles you never have to trust: a mutation gate is the sole authority.**

A cheap model authors an independent spec oracle for each function of a real, shipping library.
An oracle only counts if it passes on the real code **and** kills mutants of the function it claims
to specify - vacuous, wrong, or hallucinated specs die mechanically, not by human review. The model
never grades its own output: the mutation gate is the sole authority, and surviving divergences are
triaged with cross-family voting and spec-vector ground truth before anything is called a finding.
This attacks the known failure mode of agentic bug-finding (models reporting a high rate of invalid
bugs when allowed to judge their own work; cf. [arXiv:2510.09907](https://arxiv.org/abs/2510.09907)).
The rule: **the model proposes, mutants dispose.**

Built as a standalone auditor on top of the
[mutation-gate](https://github.com/mikemartincode/mutation-gate) library. The model-authoring paths
need an LLM gateway; the harness and its test suite need only the `hyperlink` package (a target the
auditor runs against) and no API key.

## See it work (30 seconds, no API key)

The harness and its unit suite run against a real target with no gateway and no key:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt   # hyperlink (a target library) + pytest
pytest auditor/ -q                 # 10 passed
```

That exercises the auditor's indexing, authoring-plumbing, sweep, run, and triage stages end to end
against synthetic and real inputs. To run the model-authoring pipeline itself, add an LLM gateway
(`.env`, see `.env.example`) and use the seed below.

## The proven seed

`seed/deepseek_author.py` - the single-function pipeline, measured working 2026-06:
DeepSeek-pro authored a gate-GREEN semver oracle (29/29 mutants killed) for ~$0.032; DeepSeek-flash
authored an inconsistent one the gate caught for ~$0.0008. Run `python seed/deepseek_author.py
deepseek-v4-pro` to reproduce. `seed/semver_oracle.py` is the hand-written reference oracle.

## Honest negative results

Surfacing a spec-discrepancy is not the same as finding a bug - triage decides, and the record keeps
the corrections visible. `findings/url-click-rootless/` documents one such discrepancy the auditor
flagged: `hyperlink.URL.click()` raises `NotImplementedError` on an absolute-URI reference with a
rootless path (`mailto:`, `tel:`, `urn:`), while its docstring points at RFC 3986 section 5 reference
resolution. On investigation, that `NotImplementedError` is a documented, deliberate limitation in
hyperlink's own source - so it is kept as a recorded non-finding, not reported upstream.
`python findings/url-click-rootless/repro.py` reproduces the discrepancy standalone. Keeping results
like this visible is the point: the gate stops the model from grading its own work, and triage stops
the pipeline from inflating a documented limitation into a claimed defect.

## Companion writeup

The gate here only means something if the gate itself cannot be fooled.
[`docs/red-teaming-the-verifier.md`](docs/red-teaming-the-verifier.md) is an honest account of
adversarially reviewing a verifier and finding three ways to force a false pass -- a forgeable pass
signal, an under-specified job that skipped safety stages, and an unsandboxed judge -- and making each
one structurally impossible.

## Budget

Hard cap: **$50 of DeepSeek** for the first full repo pass. Realistic spend for one repo is
$1-5 (pro authoring ~$0.03/function); the cap is iteration headroom, enforced by the harness
spend tracker, which stops dispatching before the cap.

## Layout

    seed/            proven single-function pattern (author -> gate) + reference oracle
    targets/         per-repo target manifests + cloned source (gitignored)
    results/         per-function result records + the findings report (gitignored)
    auditor/         the parallel harness
    findings/        discrepancy records + a standalone repro per entry (see: honest negative results)
