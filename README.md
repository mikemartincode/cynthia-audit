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

## Layout

    seed/            proven single-function pattern (author -> gate) + reference oracle
    targets/         per-repo target manifests + cloned source (gitignored)
    results/         per-function result records + the findings report (gitignored)
    auditor/         the parallel harness (built by Phase 4)
