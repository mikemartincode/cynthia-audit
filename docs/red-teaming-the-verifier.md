# Red-teaming the verifier: three ways a code-checker can be tricked into approving wrong code

cynthia-audit is built on one rule: the model never grades its own work -- a
mutation gate, not the model, decides whether an authored oracle counts. That
rule only means something if the gate itself cannot be fooled. This is a short,
honest account of reviewing a verifier adversarially -- specifically the
certification layer of the larger platform this research feeds, which takes
model-authored code, runs it against gates, and returns GREEN (ship) or BLOCKED
(fix) with no human and no model in the judging loop.

I sat down and tried to cheat it. I found three ways to force a false GREEN.
Each is written up here with the fix, because a verifier's only real property is
that it cannot be fooled -- including by the person who built it.

## 1. The pass signal was forgeable

A gate "passed" if its run exited 0 with the literal string `GATE_OK` on stdout.
The untrusted, model-written code was spliced into the harness *before* the gate
ran. So a submission could simply:

```python
print("GATE_OK")
raise SystemExit(0)
```

and exit before the gate ever executed. The code under judgment could sign its
own approval.

**Fix:** the pass token is now a per-run cryptographic nonce delivered
out-of-band (over stdin, never on a path the child process can read), and the
submitted code is reconstructed from only its inert top-level definitions via
the AST -- so no top-level statement in a completion runs before the gate, and
the code cannot learn or print the token. The pass signal is unforgeable by
construction.

**Principle:** the verdict signal must be unforgeable by the thing being judged,
and the judged code must not run before the judge.

## 2. An under-specified job silently skipped safety stages

The certification "plan" was an untyped dictionary. If it omitted the
independent oracle or the distinguishing probe inputs, whole verification stages
quietly no-op'd and the system greened on weaker evidence -- the most dangerous
class of bug, because nothing looks wrong.

**Fix:** the plan is now a typed contract that forbids unknown or missing
fields. An under-specified plan is *unrepresentable*: you cannot reach GREEN
without the mandatory oracle and a non-empty set of mutants for the adequacy
check.

**Principle:** make the invalid state impossible to express. Don't
validate-and-hope. (This is the same idea as the `shape-contracts` library: a
typed boundary where the untrusted side can never be laxer than the trusted
side.)

## 3. The judge ran adversarial code with full privileges

The gate executed model-authored code in a subprocess that inherited the
parent's entire environment (including API keys), its working directory, and no
resource limits.

**Fix:** a scrubbed environment, a throwaway working directory, hard memory and
CPU limits, and an isolated interpreter.

**Principle:** you are running adversarial-by-default code. Treat it that way.

## The deeper one: parts that pass alone can be wrong together

Two functions can each satisfy their own contract and kill every one of their
own mutants, and still compose into a live defect that belongs to the *pair*,
not to either unit. So nothing certifies GREEN without a composition check over
the assembled system. Per-unit proof is necessary, never sufficient.

## Why this matters

Every fix here turns a runtime hope into a structural guarantee: unforgeable by
construction, unrepresentable, isolated by default. That is the whole game of
verification engineering -- you don't catch bugs, you make them impossible to
express. And a fix only counts if the attack is encoded as a regression test: a
submission that prints the old token and exits early, an under-specified plan, an
over-allocating submission that must hit the memory limit.

"It passes" is worth nothing until you have proven the pass cannot be forged.

The public pieces of this approach live in adjacent repos:
[`mutation-gate`](https://github.com/mikemartincode/mutation-gate) (a test that
cannot kill its mutant cannot merge) and
[`shape-contracts`](https://github.com/mikemartincode/shape-contracts) (the typed
boundary from #2).
