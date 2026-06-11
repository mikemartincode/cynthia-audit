#!/usr/bin/env python3
"""auditor/differential.py — REAL-vs-REAL differential testing of URL parsers.

Where auditor/sweep.py compares the target library against a model-authored, mutation-gated
oracle (the verify-the-verifier path — strong, but bounded by oracle quality), this mode runs
the SAME input through 2+ INDEPENDENT REAL implementations of the same spec and flags where
they disagree. There is no model and no oracle here: the ground truth is the agreement of
independent real code on the shared spec surface. Its sweet spot is the security-relevant
PARSER-DIFFERENTIAL class (SSRF / request-smuggling / filter-bypass), which exists precisely
because two real parsers read the SAME url's authority boundary differently — a class the
single-call value oracle structurally cannot see.

A separate module, not a `--mode` on sweep_one, on purpose: sweep_one is built around the
oracle calling-convention, the fidelity gate against PROBE_INPUTS, and the mutation record —
none of which apply when both sides are real libraries. Forcing real-vs-real through that
machinery would obscure both. This module reuses the generated input pool (strategies.URL_POOL)
and nothing else.

THREE PARSERS (each an independent implementation of RFC 3986):
  - hyperlink   — the audit target (vendored under targets/hyperlink/repo/src)
  - urllib.parse — Python stdlib (always present)
  - rfc3986      — the `rfc3986` package, OPTIONAL (a third independent voice; absent => 2-way)

THE HONEST CLASSIFICATION LINE. A raw value difference is detected first, then a
canonicalization that embodies EXACTLY the variation RFC 3986 PERMITS is applied per component
(scheme/host case-folding §3.1/§3.2.2, percent-hex case §6.2.2.1, default-port elision §6.2.3,
IP-literal brackets §3.2.2). If the values agree AFTER that canonicalization, the difference is
spec-PERMITTED — an ambiguity, never promoted. If an AUTHORITY component (scheme/host/port/
userinfo) still disagrees, it is a spec-PINNED candidate, because RFC 3986 §3.2 pins the
authority structure tightly. Residual path/query/fragment differences are conservatively
treated as spec-PERMITTED: §6.2.2 makes their normalization OPTIONAL, so two parsers may
legitimately differ — promoting them would be the same trap as same-family agreement (the A05
rule), one layer up. Under-promotion here is deliberate; a false CVE is worse than a missed one.

ACCEPT-vs-REJECT (validity divergence). When some parsers accept a url and others reject it,
the promotion rule is CROSS-PARSER CORROBORATION: it is promoted only when ≥2 independent reals
resolve the SAME host that ≥1 real rejected — two voices agreeing a host exists in a string a
third refuses is the canonical SSRF-bypass shape (e.g. `http://a@b@c/`: urllib + rfc3986 both
read host `c`, hyperlink rejects the authority outright). If the accepting parsers disagree
among themselves on the host, it is recorded as an ambiguity, not promoted.

"0 promoted candidates" is a valid, recorded outcome. The disagreement is shown, the RFC clause
is cited, and severity follows the field — nothing is dressed as a confirmed vulnerability.

Usage:
    python auditor/differential.py [--out results/e02-differential] [--cap 0]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strategies import URL_POOL  # noqa: E402

# Authority-confusion payloads — the parser-differential corpus the broad URL_POOL doesn't
# carry. These are the classic SSRF/filter-bypass shapes whose whole point is that independent
# parsers read the authority's host boundary differently. Kept here (not folded into the shared
# URL_POOL, which the oracle sweep also consumes) so the differential's targeted surface is
# explicit. Each is benign per se — the value is purely WHERE the parsers place the host.
AUTHORITY_PROBES = [
    "http://a@b@c/",                    # double '@': lenient parsers read host=c, strict rejects
    "http://a:b@c:d@e/",                # multi '@' with colons: host=e or reject
    r"http://evil.com\@good.com/",      # backslash: RFC vs WHATWG read a different host
    "http://example.com@evil.com/",     # single userinfo '@' — all should agree host=evil.com
    "http://good.com#@evil.com/",       # '#' must terminate authority — all should agree good.com
    "https://expected@evil.com/",       # plain userinfo — control, all agree host=evil.com
]

# the target lives under the vendored repo, imported by absolute path (never an installed copy).
_REPO_SRC = str((Path(__file__).resolve().parent.parent / "targets/hyperlink/repo/src"))
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

import urllib.parse as _ulib  # noqa: E402
from hyperlink import URL as _HL  # noqa: E402

try:
    import rfc3986 as _rfc  # noqa: E402
    _HAVE_RFC = True
except ImportError:  # pragma: no cover - rfc3986 is an optional third voice
    _HAVE_RFC = False

# RFC 3986 components in authority-first order. AUTHORITY is the security-relevant boundary.
COMPONENTS = ("scheme", "userinfo", "host", "port", "path", "query", "fragment")
AUTHORITY = ("scheme", "userinfo", "host", "port")          # §3.2 — tightly pinned by grammar
BOUNDARY = ("userinfo", "host", "port")                     # the SSRF / smuggling surface
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}  # §6.2.3


# ---------------------------------------------------------------- parse adapters (real code)
#
# Each returns a {component: raw_value} dict or raises. Values are kept RAW (no spec
# normalization) so the canonicalization step below is the ONLY place permitted variation is
# folded — a difference that survives it is real. `userinfo` is derived from the authority's
# last '@' split (RFC 3986 §3.2.1: userinfo is everything before the final '@'); urllib's
# `.username` is NOT used because it drops the password after the first ':'.

def parse_hyperlink(url: str) -> dict:
    u = _HL.from_text(url)
    path = ("/" if u.rooted else "") + "/".join(u.path)
    query = "&".join(k if v is None else f"{k}={v}" for k, v in u.query)
    return {"scheme": u.scheme, "userinfo": u.userinfo, "host": u.host,
            "port": u.port, "path": path, "query": query, "fragment": u.fragment}


def parse_urllib(url: str) -> dict:
    s = _ulib.urlsplit(url)
    netloc = s.netloc
    userinfo = netloc.rsplit("@", 1)[0] if "@" in netloc else None
    # `.hostname` (lowercased, brackets stripped) and `.port` are urllib's REAL outputs; .port
    # validates lazily and may raise — accessed here so a bad port is an honest reject.
    return {"scheme": s.scheme, "userinfo": userinfo, "host": s.hostname,
            "port": s.port, "path": s.path, "query": s.query, "fragment": s.fragment}


def parse_rfc3986(url: str) -> dict:
    u = _rfc.urlparse(url)
    return {"scheme": u.scheme, "userinfo": u.userinfo, "host": u.host,
            "port": u.port, "path": u.path, "query": u.query, "fragment": u.fragment}


def parsers() -> dict:
    p = {"hyperlink": parse_hyperlink, "urllib": parse_urllib}
    if _HAVE_RFC:
        p["rfc3986"] = parse_rfc3986
    return p


# ---------------------------------------------------------------- permitted-variation canon
#
# Each canonicalizer embodies one RFC 3986 clause that makes a difference PERMITTED. A value
# difference that vanishes under these is spec-permitted; one that survives is real.

_PCT = re.compile(r"%([0-9a-fA-F]{2})")


def _fold_pct(v: str) -> str:
    return _PCT.sub(lambda m: "%" + m.group(1).upper(), v)            # §6.2.2.1


def _canon(component: str, value, scheme):
    """Canonical form for equality, folding ONLY RFC-permitted variation.

    Every non-port component is string-valued, and a parser spells "not present" as either
    `None` or `''` — that is a pure representation choice (rfc3986 uses None, hyperlink ''),
    not a spec disagreement, so both collapse to ''. The absent-vs-empty distinction (e.g. a
    bare `#` fragment) is E01's round-trip concern, not this cross-parser authority concern."""
    if component == "port":
        if value is None and isinstance(scheme, str):
            return DEFAULT_PORTS.get(scheme.lower())                  # §6.2.3 default-port
        return value
    if value is None:
        value = ""
    if not isinstance(value, str):
        return value
    if component == "scheme":
        return value.lower()                                         # §3.1 scheme case-insensitive
    if component == "host":
        v = value.lower()                                            # §3.2.2 host case-insensitive
        if v.startswith("[") and v.endswith("]"):
            v = v[1:-1]                                              # §3.2.2 IP-literal brackets
        return _fold_pct(v)
    if component in ("userinfo", "path", "query", "fragment"):
        return _fold_pct(value)
    return value


# The governing grammar clause for each component PLUS the permitted-variation canonicalization
# applied before comparison. Phrased neutrally so it reads correctly whether the difference
# VANISHED under canon (spec-permitted) or SURVIVED it (spec-pinned).
_CLAUSE = {
    "scheme": "RFC 3986 §3.1 — scheme grammar; compared case-insensitively (lowercased)",
    "host": "RFC 3986 §3.2.2 — host grammar; compared case-insensitively, IP-literal brackets stripped",
    "port": "RFC 3986 §3.2.3 — port = *DIGIT; scheme default-port elided (§6.2.3) before comparison",
    "userinfo": "RFC 3986 §3.2.1 — userinfo grammar; percent-hex folded (§6.2.2.1)",
    "path": "RFC 3986 §3.3 / §6.2.2 — path; dot-segment & percent-hex normalization is OPTIONAL",
    "query": "RFC 3986 §3.4 / §6.2.2.1 — query; percent-hex folded",
    "fragment": "RFC 3986 §3.5 / §6.2.2.1 — fragment; percent-hex folded",
}


# ---------------------------------------------------------------- per-input comparison

def _call(fn, url):
    try:
        return True, fn(url), None
    except Exception as exc:  # noqa: BLE001 — every failure mode is data for classification
        return False, None, f"{type(exc).__name__}: {exc}"


def compare(url: str, ps: dict) -> dict | None:
    """Run url through every parser and return a disagreement record, or None if all parsers
    that accepted it agree on every component (after permitted-variation canonicalization) and
    none rejected it."""
    accepted, rejected = {}, {}
    for name, fn in ps.items():
        ok, comps, err = _call(fn, url)
        (accepted if ok else rejected)[name] = comps if ok else err

    component_diffs = []
    if len(accepted) >= 2:
        for comp in COMPONENTS:
            raw = {n: c[comp] for n, c in accepted.items()}
            canon = {n: _canon(comp, c[comp], c["scheme"]) for n, c in accepted.items()}
            raw_agree = len({_hashable(v) for v in raw.values()}) == 1
            if raw_agree:
                continue  # no difference at all on this component
            canon_agree = len({_hashable(v) for v in canon.values()}) == 1
            if canon_agree:
                verdict, sec = "spec-permitted", False
            elif comp in AUTHORITY:
                verdict, sec = "spec-pinned", True
            else:
                verdict, sec = "spec-permitted", False  # §6.2.2 optional => conservative
            component_diffs.append({
                "component": comp, "raw": {n: _short(v) for n, v in raw.items()},
                "canonical_agree": canon_agree, "classification": verdict,
                "authority_boundary": comp in BOUNDARY, "security_relevant": sec,
                "rfc_basis": _CLAUSE[comp],
            })

    validity = None
    if accepted and rejected:
        validity = _classify_validity(accepted, rejected)

    promoted = any(d["classification"] == "spec-pinned" for d in component_diffs) or \
        (validity is not None and validity["classification"] == "spec-pinned")
    if not component_diffs and validity is None:
        return None
    return {
        "url": url, "promoted": promoted,
        "accepted": sorted(accepted), "rejected": {n: rejected[n] for n in sorted(rejected)},
        "component_diffs": component_diffs, "validity": validity,
        "security_relevant": any(d["security_relevant"] for d in component_diffs)
        or (validity is not None and validity["security_relevant"]),
    }


def _classify_validity(accepted: dict, rejected: dict) -> dict:
    """An accept/reject split. PROMOTE only when ≥2 independent reals resolve the SAME host that
    ≥1 real rejected (cross-parser corroboration — the SSRF-bypass shape). If accepting parsers
    disagree on the host, it is an ambiguity, not a bug."""
    hosts = {n: (_canon("host", c["host"], c["scheme"]) or "") for n, c in accepted.items()}
    resolved = [h for h in hosts.values() if h]
    counts = Counter(resolved)
    corroborated = counts.most_common(1)[0] if counts else (None, 0)
    host, agree_n = corroborated
    if host and agree_n >= 2:
        return {
            "kind": "accept-vs-reject", "classification": "spec-pinned",
            "security_relevant": True, "resolved_host": host, "corroborating_parsers": agree_n,
            "accepting_hosts": hosts, "rejected": {n: rejected[n] for n in sorted(rejected)},
            "rfc_basis": "RFC 3986 §3.2 (authority = [userinfo '@'] host [':' port]); "
                         f"{agree_n} independent parsers resolve host {host!r} from a string "
                         "another rejects — a host-boundary disagreement on the SSRF surface",
            "note": "lenient parsers resolve a host where the strict parser rejects the "
                    "authority; severity follows the host field — shown, not asserted as a CVE",
        }
    return {
        "kind": "accept-vs-reject", "classification": "spec-permitted",
        "security_relevant": bool(resolved), "accepting_hosts": hosts,
        "rejected": {n: rejected[n] for n in sorted(rejected)},
        "rfc_basis": "RFC 3986 §3.2 authority grammar",
        "note": "accept/reject split without a corroborated host (parsers disagree among "
                "themselves or resolve no host) — recorded, not promoted",
    }


def _hashable(v):
    return v if isinstance(v, (str, int, type(None), bool)) else repr(v)


def _short(v, n: int = 120):
    s = repr(v)
    return s if len(s) <= n else s[:n] + "…"


# ---------------------------------------------------------------- driver + report

def run_differential(inputs, out_dir: Path) -> dict:
    ps = parsers()
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs = list(inputs)  # materialize: iterated twice (sweep + count), generator-safe

    disagreements = [d for d in (compare(u, ps) for u in inputs) if d is not None]
    promoted = [d for d in disagreements if d["promoted"]]
    ambiguities = [d for d in disagreements if not d["promoted"]]
    security = [d for d in promoted if d["security_relevant"]]

    # ambiguities aggregated by (component, clause) — these are pervasive (default ports, case
    # folding) and listing each would bury the signal; candidates are listed individually.
    amb_index = Counter()
    for d in ambiguities:
        for cd in d["component_diffs"]:
            if cd["classification"] == "spec-permitted":
                amb_index[(cd["component"], cd["rfc_basis"])] += 1
        if d["validity"] and d["validity"]["classification"] == "spec-permitted":
            amb_index[("validity", d["validity"]["rfc_basis"])] += 1

    summary = {
        "parsers": sorted(ps),
        "rfc3986_present": _HAVE_RFC,
        "inputs": len(inputs),
        "disagreements": len(disagreements),
        "promoted_candidates": len(promoted),
        "security_relevant_candidates": len(security),
        "spec_permitted_ambiguities": len(ambiguities),
        "promoted_urls": [d["url"] for d in promoted],
        "security_urls": [d["url"] for d in security],
        "ambiguity_classes": [{"component": k[0], "rfc_basis": k[1], "count": n}
                              for k, n in sorted(amb_index.items(), key=lambda kv: -kv[1])],
    }
    (out_dir / "disagreements.json").write_text(json.dumps(disagreements, indent=2) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out_dir / "report.md").write_text(_render_report(summary, promoted, security))
    return summary


def _render_report(summary: dict, promoted: list, security: list) -> str:
    L = []
    L.append("# Real-vs-real URL parser differential\n")
    L.append(f"Parsers compared: {', '.join(summary['parsers'])}"
             + ("" if summary["rfc3986_present"] else " (rfc3986 absent — 2-way)") + ".\n")
    L.append(f"{summary['disagreements']} inputs produced a disagreement: "
             f"{summary['promoted_candidates']} promoted spec-pinned candidate(s) "
             f"({summary['security_relevant_candidates']} security-relevant), "
             f"{summary['spec_permitted_ambiguities']} spec-permitted (not promoted).\n")

    L.append("\n## Security-relevant candidates (authority boundary)\n")
    if security:
        for d in security:
            L.append(_render_one(d))
    else:
        L.append("_None._\n")

    other = [d for d in promoted if not d["security_relevant"]]
    if other:
        L.append("\n## Other spec-pinned candidates\n")
        for d in other:
            L.append(_render_one(d))

    L.append("\n## Spec-permitted ambiguities (correctly NOT promoted)\n")
    L.append("Differences that vanish under the permitted-variation canonicalization the RFC "
             "allows. Aggregated by class; severity none.\n\n")
    if summary["ambiguity_classes"]:
        L.append("| Component | Count | RFC basis |\n|---|---|---|\n")
        for a in summary["ambiguity_classes"]:
            L.append(f"| {a['component']} | {a['count']} | {a['rfc_basis']} |\n")
    else:
        L.append("_None._\n")
    return "".join(L)


def _render_one(d: dict) -> str:
    L = [f"\n### `{d['url']}`\n"]
    if d["rejected"]:
        L.append(f"- rejected by: {', '.join(f'{n} ({e})' for n, e in d['rejected'].items())}\n")
    if d["validity"] and d["validity"]["classification"] == "spec-pinned":
        v = d["validity"]
        L.append(f"- **host-boundary disagreement**: {v['corroborating_parsers']} parsers "
                 f"resolve host `{v['resolved_host']}`; another rejects.\n")
        L.append(f"  - hosts: {v['accepting_hosts']}\n")
        L.append(f"  - basis: {v['rfc_basis']}\n")
        L.append(f"  - note: {v['note']}\n")
    for cd in d["component_diffs"]:
        if cd["classification"] != "spec-pinned":
            continue
        tag = " (authority boundary)" if cd["authority_boundary"] else ""
        L.append(f"- **{cd['component']}**{tag}: {cd['raw']}\n")
        L.append(f"  - basis: {cd['rfc_basis']}\n")
    return "".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description="real-vs-real URL parser differential")
    ap.add_argument("--out", type=Path, default=Path("results/e02-differential"))
    ap.add_argument("--cap", type=int, default=0,
                    help="limit the URL_POOL slice (0 = full); authority probes always included")
    args = ap.parse_args()
    pool = URL_POOL[: args.cap] if args.cap else URL_POOL
    inputs = list(pool) + AUTHORITY_PROBES
    s = run_differential(inputs, args.out)
    print(json.dumps(s, indent=2))
    print(f"\nparsers: {', '.join(s['parsers'])} | {s['disagreements']} disagreements -> "
          f"{s['promoted_candidates']} promoted ({s['security_relevant_candidates']} "
          f"security-relevant), {s['spec_permitted_ambiguities']} permitted (not promoted)")
    if s["security_urls"]:
        print(f"security-relevant host-boundary disagreement in: {', '.join(s['security_urls'])}")
    else:
        print("0 security-relevant candidates (a valid, recorded outcome)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
