#!/usr/bin/env python3
"""auditor/grammar.py — E04 input generation: grammar-based, seed-corpus, and coverage-guided.

The pre-E04 sweep (auditor/strategies.py) draws from a fixed, hand-authored `URL_POOL`. That
is fuzzing-adjacent but finite and static: a bug hiding behind a structurally-unusual-yet-valid
URI the author didn't think to write is simply never reached. This module raises RECALL along
three independent axes, each of which feeds the SAME differential sweep so the lift is measured,
not asserted:

  1. GRAMMAR  — generate structurally-valid-but-weird URIs straight from RFC 3986's ABNF
     (Appendix A): every authority form (reg-name / IPv4 / IPv6 / IPvFuture / empty), rootless
     vs //-authority paths, dot-segments, ports (incl. degenerate), query, fragment, and
     percent-encoded octets. Deterministic (seeded), and every emitted URI is validated to
     parse (so it exercises the post-parse code paths, not just the reject path).

  2. SEED     — the target's OWN test fixtures (the maintainers' adversarial corpus, extracted
     from the test modules by AST) UNION a dictionary of known edge-case values (Unicode
     normalization, the RFC's own §1.1.2 examples, percent-encoding edge cases). A library's
     regression suite is the single densest source of inputs that touch real edge branches.

  3. COVERAGE — a bounded greybox loop (the AFL/libFuzzer core idea, no atheris dependency):
     mutate the corpus, keep only a mutant that executes a target line not yet covered, repeat.
     Coverage is measured with `sys.settrace` over the vendored target source — pure stdlib, no
     `coverage` package. The loop is HARD-CAPPED by iteration budget and the cap is logged, never
     silent: coverage-guided fuzzing is unbounded by nature and this is deliberately not.

HONEST LIMITS (stated wherever the lift is reported): this raises recall — more distinct target
lines reached and more candidate divergences surfaced — it does NOT make the search exhaustive.
There is no symbolic execution and no constraint solving; a bug behind a branch none of these
three axes happens to reach is still missed. "More branches / more candidates," never "complete."

Determinism: all randomness is a seeded `random.Random` (default seed 0), so a run is
reproducible and any input that expands coverage can be re-found.
"""

from __future__ import annotations

import argparse
import ast
import json
import random
import sys
from pathlib import Path

# the vendored target, imported by absolute path (never an installed hyperlink) — identical to
# the convention adapters.py uses, so coverage is measured against the exact code the sweep runs.
_REPO_SRC = (Path(__file__).resolve().parent.parent / "targets/hyperlink/repo/src")
_TARGET_FILE = str(_REPO_SRC / "hyperlink/_url.py")
_TEST_DIR = _REPO_SRC / "hyperlink/test"
if str(_REPO_SRC) not in sys.path:
    sys.path.insert(0, str(_REPO_SRC))

from hyperlink import URL  # noqa: E402


# ====================================================================== 1. GRAMMAR (RFC 3986)
#
# Component pools, each a small set of values that are VALID for the production but chosen to be
# unusual. Composition follows RFC 3986 §3: URI = scheme ":" hier-part [ "?" query ] [ "#" frag ];
# hier-part is either "//" authority path-abempty (absolute) or path-rootless (no authority).

_SCHEME = ["http", "https", "ftp", "a", "a1", "x+y-z.w", "HtTp", "urn", "tel"]

# userinfo = *( unreserved / pct-encoded / sub-delims / ":" )   §3.2.1
_USERINFO = ["", "u", "u:p", "u:", ":p", "%41:%42", "a.b-c~d", "!$&'()*+,;=", "user%40name"]

# host: reg-name / IPv4address / IP-literal("[" IPv6 / IPvFuture "]") / empty   §3.2.2
_HOST = [
    "example.com", "xn--80ak6aa92e.com", "ex%41mple.com", "a.b.c", "localhost", "",
    "0.0.0.0", "192.168.0.1", "255.255.255.255",                     # IPv4address
    "[::1]", "[2001:db8::1]", "[::ffff:1.2.3.4]", "[v1.fe80::a]",    # IP-literal (IPv6 / IPvFuture)
    "reg-name.host;x",                                              # reg-name with a sub-delim
]

# port = *DIGIT   §3.2.3   (the empty port and leading-zero/long forms are all grammatical)
_PORT = ["", "0", "80", "000", "8080", "65535", "99999", "8"]

# path segments — pchar = unreserved / pct-encoded / sub-delims / ":" / "@"   §3.3
_SEG = ["", "a", "b", "a%2Fb", ".", "..", "seg;param", "%C3%A9", "x:y", "p@q", "long-segment"]

# query = *( pchar / "/" / "?" )   §3.4 ; fragment likewise §3.5
_QUERY = ["", "a=b", "a=b&c=d", "q=%26", "a", "=v", "&&", "k=%C3%A9&z=/?"]
_FRAGMENT = ["", "frag", "%41", "/p?x", "sec:tion"]


def _abempty_path(rng: random.Random) -> str:
    """path-abempty = *( "/" segment ) — used WITH an authority. Always starts with '/' or empty."""
    n = rng.choice([0, 1, 1, 2, 3])
    return "".join("/" + rng.choice(_SEG) for _ in range(n))


def _rootless_path(rng: random.Random) -> str:
    """path-rootless = segment-nz *( "/" segment ) — used WITHOUT an authority. Non-empty first."""
    first = rng.choice([s for s in _SEG if s]) or "a"
    rest = "".join("/" + rng.choice(_SEG) for _ in range(rng.choice([0, 0, 1, 2])))
    return first + rest


def _authority(rng: random.Random) -> str:
    ui = rng.choice(_USERINFO)
    host = rng.choice(_HOST)
    port = rng.choice(_PORT)
    s = ""
    if ui:
        s += ui + "@"
    s += host
    if port:
        s += ":" + port
    return s


def _compose(rng: random.Random) -> str:
    """One grammatical URI. ~70% absolute (//authority), ~30% rootless, both with optional
    query/fragment — so the generated set spans both hier-part forms of §3.3."""
    scheme = rng.choice(_SCHEME)
    if rng.random() < 0.7:
        uri = f"{scheme}://{_authority(rng)}{_abempty_path(rng)}"
    else:
        uri = f"{scheme}:{_rootless_path(rng)}"
    if rng.random() < 0.6:
        q = rng.choice(_QUERY)
        if q:
            uri += "?" + q
    if rng.random() < 0.5:
        f = rng.choice(_FRAGMENT)
        if f:
            uri += "#" + f
    return uri


def generate_grammar_uris(limit: int = 300, seed: int = 0) -> tuple[list[str], dict]:
    """Deterministically emit up to `limit` DISTINCT, parse-VALID URIs from the RFC 3986 ABNF.

    Returns (uris, stats). `stats` records how many raw compositions were tried, how many were
    kept (deduped + parse-valid), and how many were dropped as unparseable — so the
    "structurally valid" guarantee is auditable, not assumed."""
    rng = random.Random(seed)
    seen: set[str] = set()
    kept: list[str] = []
    tried = dropped = 0
    # cap the attempt budget so a pathological dedup-collision rate can't spin forever.
    attempt_budget = limit * 20
    while len(kept) < limit and tried < attempt_budget:
        tried += 1
        uri = _compose(rng)
        if uri in seen:
            continue
        seen.add(uri)
        try:
            URL.from_text(uri)  # structural validity = the target's own parser accepts it
        except Exception:  # noqa: BLE001 — an unparseable composition is dropped, not a finding
            dropped += 1
            continue
        kept.append(uri)
    stats = {"requested": limit, "tried": tried, "kept": len(kept), "dropped_unparseable": dropped,
             "attempt_budget": attempt_budget, "attempt_budget_hit": tried >= attempt_budget}
    return kept, stats


# ====================================================================== 2. SEED CORPUS
#
# The target's own test fixtures (extracted by AST, not regex — so we get every string constant
# the maintainers wrote, including the gnarly ones) UNION a curated edge-case dictionary.

# Known edge-case values: Unicode normalization/confusables, the RFC's §1.1.2 example URIs, and
# percent-encoding edge cases. Each is a recognised edge-case family for URI parsers; every entry
# is a benign string whose value is purely the structure it exercises.
NASTY_DICTIONARY = [
    # RFC 3986 §1.1.2 worked examples
    "ftp://ftp.is.co.za/rfc/rfc1808.txt",
    "http://www.ietf.org/rfc/rfc2396.txt",
    "ldap://[2001:db8::7]/c=GB?objectClass?one",
    "mailto:John.Doe@example.com",
    "news:comp.infosystems.www.servers.unix",
    "tel:+1-816-555-1212",
    "telnet://192.0.2.16:80/",
    "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
    # percent-encoding edge cases
    "http://h/%2e%2e%2f%2e%2e%2f",     # encoded dot-segments
    "http://h/%00",                    # encoded NUL
    "http://h/%ff%fe",                 # encoded non-UTF8 octets
    "http://h/%E2%80%8B",              # encoded zero-width space
    "http://%41%42@h/",                # percent-encoded userinfo
    # Unicode normalization / confusables
    "http://exа́mple.com/",       # Cyrillic 'а' + combining acute
    "http://example．com/",        # fullwidth full stop
    "http://Ⅿ.example/",               # Roman-numeral confusable in the host
    # structural degeneracies
    "http://h:000080/",                # leading-zero port
    "http://[::ffff:192.168.0.1]/",    # IPv4-mapped IPv6
    "http:///triple-slash-empty-auth", # empty authority, rooted path
    "http://h/a//b///c",               # collapsed empty segments
]


def _looks_like_uri(s: str) -> bool:
    """A string fixture is URI-ish if it carries a scheme, an authority marker, or is a path
    reference — the shapes URL.from_text is meant to consume. Plain words/names are dropped."""
    if not s or len(s) > 2048:
        return False
    if "://" in s or s.startswith(("//", "/")):
        return True
    # scheme ":" ...   (RFC 3986 §3.1: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ))
    head, sep, _ = s.partition(":")
    if sep and head and head[0].isalpha() and all(c.isalnum() or c in "+-." for c in head):
        return True
    return False


def extract_test_fixtures(test_dir: Path = _TEST_DIR, cap: int = 600) -> tuple[list[str], dict]:
    """AST-walk the target's test modules, collect every URI-ish string constant. Capped; the cap
    is reported. Returns (fixtures, stats)."""
    seen: set[str] = set()
    fixtures: list[str] = []
    files_read = 0
    capped = False
    for path in sorted(test_dir.glob("test_*.py")):
        files_read += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if _looks_like_uri(s) and s not in seen:
                    seen.add(s)
                    fixtures.append(s)
                    if len(fixtures) >= cap:
                        capped = True
                        break
        if capped:
            break
    stats = {"files_read": files_read, "extracted": len(fixtures), "cap": cap, "cap_hit": capped}
    return fixtures, stats


def load_seed_corpus(cap: int = 600) -> tuple[list[str], dict]:
    """Target test fixtures UNION the edge-case dictionary, deduped. Returns (corpus, stats)."""
    fixtures, fstats = extract_test_fixtures(cap=cap)
    seen = set(fixtures)
    corpus = list(fixtures)
    added_nasty = 0
    for v in NASTY_DICTIONARY:
        if v not in seen:
            seen.add(v)
            corpus.append(v)
            added_nasty += 1
    stats = {"from_tests": fstats, "edge_dictionary": len(NASTY_DICTIONARY),
             "edge_added": added_nasty, "total": len(corpus)}
    return corpus, stats


# ====================================================================== 3. COVERAGE (sys.settrace)
#
# Distinct executable lines reached in the vendored target source — a standard, dependency-free
# coverage proxy. The global tracer fires on every 'call'; we install a line tracer only for
# frames whose code lives in the target file, so non-target frames cost nothing.

# The battery of operations one URL string drives. Identical for every input set, so a line-count
# delta is attributable to the INPUTS alone, never to a different battery.
def _drive(text: str) -> None:
    try:
        u = URL.from_text(text)
    except Exception:  # noqa: BLE001 — a reject still executed the parse/validate lines up to it
        return
    for op in (
        lambda: u.to_text(), lambda: u.to_uri().to_text(), lambda: u.to_iri().to_text(),
        lambda: u.normalize().to_text(), lambda: (u.scheme, u.host, u.port, u.path),
        lambda: (u.rooted, u.absolute, u.query, u.fragment), lambda: u.child("x"),
        lambda: u.sibling("y"), lambda: u.click("g"), lambda: u.replace(port=1),
    ):
        try:
            op()
        except Exception:  # noqa: BLE001 — every op's executed lines count, success or raise
            pass


def _make_tracer(target_file: str, hit: set[int]):
    def _line(frame, event, _arg):
        if event == "line":
            hit.add(frame.f_lineno)
        return _line

    def _global(frame, event, _arg):
        if event == "call" and frame.f_code.co_filename == target_file:
            return _line
        return None
    return _global


def lines_hit(inputs, target_file: str = _TARGET_FILE) -> set[int]:
    """The set of distinct line numbers executed in `target_file` while driving every input
    through the fixed battery. settrace is thread-local; this measures the calling thread."""
    hit: set[int] = set()
    tracer = _make_tracer(target_file, hit)
    old = sys.gettrace()
    sys.settrace(tracer)
    try:
        for text in inputs:
            _drive(text)
    finally:
        sys.settrace(old)
    return hit


# ---- the bounded greybox loop ----------------------------------------------------------------

_INTERESTING = list("/%:@[]?#.&=") + ["%2F", "%00", "..", "//", "．", "0"]


def _mutate(text: str, rng: random.Random) -> str:
    """One small structural mutation, biased toward URI-interesting tokens. Deterministic for a
    given rng state."""
    if not text:
        return "/"
    op = rng.randint(0, 4)
    i = rng.randrange(len(text))
    tok = rng.choice(_INTERESTING)
    if op == 0:                                   # insert an interesting token
        return text[:i] + tok + text[i:]
    if op == 1:                                   # delete a char
        return text[:i] + text[i + 1:]
    if op == 2:                                   # replace a char with an interesting token
        return text[:i] + tok + text[i + 1:]
    if op == 3:                                   # duplicate a span (length growth)
        j = min(len(text), i + rng.randint(1, 4))
        return text[:j] + text[i:j] + text[j:]
    return text[i:] + text[:i]                    # rotate


def coverage_guided(seeds, budget: int = 2000, seed: int = 0,
                    target_file: str = _TARGET_FILE) -> tuple[list[str], dict]:
    """AFL-style loop: keep a mutant only if it reaches a target line the corpus hasn't yet.
    HARD-CAPPED at `budget` mutations; the cap is returned in stats (logged, never silent).

    Returns (newly_kept_inputs, stats)."""
    rng = random.Random(seed)
    corpus = [s for s in seeds if s]
    if not corpus:
        corpus = ["http://h/"]
    covered: set[int] = set()
    tracer = _make_tracer(target_file, covered)
    old = sys.gettrace()
    sys.settrace(tracer)
    kept: list[str] = []
    iterations = 0
    baseline = 0
    try:
        # establish the seed baseline coverage inside the same trace session
        for s in corpus:
            _drive(s)
        baseline = len(covered)
        while iterations < budget:
            iterations += 1
            parent = corpus[rng.randrange(len(corpus))]
            mutant = _mutate(parent, rng)
            before = len(covered)
            _drive(mutant)                        # updates `covered` via the active tracer
            if len(covered) > before:             # the mutant reached a new line => keep it
                corpus.append(mutant)
                kept.append(mutant)
    finally:
        sys.settrace(old)
    stats = {"budget": budget, "iterations": iterations, "budget_hit": iterations >= budget,
             "seeds": len(corpus) - len(kept), "kept_expanding": len(kept),
             "baseline_lines": baseline, "final_lines": len(covered),
             "lines_gained_by_fuzzing": len(covered) - baseline}
    return kept, stats


# ====================================================================== assembled E04 corpus

def build_e04_inputs(*, grammar_limit: int = 300, seed_cap: int = 600, fuzz_budget: int = 2000,
                     seed: int = 0) -> tuple[list[str], dict]:
    """The full E04 URL-string corpus: grammar ∪ seed-corpus ∪ coverage-guided, deduped and
    stable-ordered. Returns (inputs, stats) — every cap/budget surfaced in stats."""
    grammar_uris, gstats = generate_grammar_uris(limit=grammar_limit, seed=seed)
    corpus, sstats = load_seed_corpus(cap=seed_cap)
    fuzz_seeds = grammar_uris + corpus
    fuzz_kept, fstats = coverage_guided(fuzz_seeds, budget=fuzz_budget, seed=seed)

    seen: set[str] = set()
    inputs: list[str] = []
    for src in (grammar_uris, corpus, fuzz_kept):
        for s in src:
            if s not in seen:
                seen.add(s)
                inputs.append(s)
    stats = {"grammar": gstats, "seed_corpus": sstats, "coverage_guided": fstats,
             "total_distinct": len(inputs)}
    return inputs, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="E04 input generation (grammar + seed + coverage)")
    ap.add_argument("--grammar-limit", type=int, default=300)
    ap.add_argument("--seed-cap", type=int, default=600)
    ap.add_argument("--fuzz-budget", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    inputs, stats = build_e04_inputs(grammar_limit=args.grammar_limit, seed_cap=args.seed_cap,
                                     fuzz_budget=args.fuzz_budget, seed=args.seed)
    print(json.dumps(stats, indent=2))
    print(f"\nE04 corpus: {len(inputs)} distinct inputs "
          f"(grammar {stats['grammar']['kept']} + seed {stats['seed_corpus']['total']} + "
          f"coverage-guided {stats['coverage_guided']['kept_expanding']})")
    if stats["coverage_guided"]["budget_hit"]:
        print(f"  NOTE: coverage-guided loop hit its {args.fuzz_budget}-mutation budget cap (logged)")
    if args.out:
        args.out.write_text(json.dumps({"inputs": inputs, "stats": stats}, indent=2) + "\n")
        print(f"  wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
