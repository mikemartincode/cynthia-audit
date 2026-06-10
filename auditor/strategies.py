#!/usr/bin/env python3
"""auditor/strategies.py — adversarial input generators, one per oracle calling convention.

The generated set is where bugs that the oracle author's hand-picked probes missed can fall
out, so the pools below are deliberately HOSTILE: degenerate ports (leading zeros, overflow,
non-numeric), unicode hosts/paths, percent-encoding both valid and malformed, IPv6 literals,
userinfo with/without password, dot-segment paths, mixed-case schemes, schemeless/relative
refs, very long components, and empty/edge strings. The semver sweep that found nothing did
so partly on a gentle generator — these are not gentle.

Generation is DETERMINISTIC (fixed pools, `itertools.product`, stable order) so a run is
reproducible and a candidate can be re-found. Each convention caps its product so the sweep
terminates; the cap is surfaced (strategy_for returns the cap actually applied) and the sweep
logs when a cap truncates the cartesian coverage.

A convention maps an oracle's one-argument shape to an iterator of those arguments:
  url            -> a single URL string
  url_href       -> (base_url, href)
  url_segments   -> (base_url, *segments)
  url_segment    -> (url, segment)
  url_bool       -> (url, with_password)
  url_opt_bool   -> (url,) or (url, with_password)
  url_name       -> (url, name)
  url_name_optval -> (url, name) or (url, name, value)
  url_name_value -> (url, name, value)
  url_remove     -> (url, name) | (url, name, value) | (url, name, value, limit)
  url_remove4    -> (url, name, value, limit)   (DecodedURL.remove — fixed arity)
  parse_triple   -> (url, decoded, lazy)
"""

from __future__ import annotations

import itertools

# ---------------------------------------------------------------- value pools

URL_POOL = [
    # ordinary
    "http://example.com/", "https://example.com/a/b?x=y#f", "http://example.com",
    # ports: leading zeros, overflow, non-numeric, empty
    "http://h:0080/", "http://h:80/", "http://h:99999/", "http://h:abc/", "http://h:/",
    "http://h:0/", "http://h:000/",
    # unicode host + path
    "http://exämple.com/café", "http://例え.テスト/路径", "http://h/föö/bär",
    # percent-encoding: valid, malformed, double, reserved
    "http://h/%41%42", "http://h/%2e%2e/x", "http://h/%2F", "http://h/%zz",
    "http://h/%", "http://h/%2", "http://h/a%2Fb", "http://ex%61mple.com/",
    "http://h/?q=%C3%A9", "http://h/?a=%2F&b=%26",
    # IPv6 + brackets
    "http://[::1]/", "http://[::1]:80/", "http://[garbage]/", "http://[::ffff:1.2.3.4]/",
    # userinfo
    "http://u:p@h/", "http://u:@h/", "http://u@h/", "http://:p@h/", "http://@h/",
    # dot segments
    "http://h/a/../b", "http://h/./a", "http://h/../../x", "http://h/a/b/../../c",
    # case
    "HTTP://H/", "Http://Example.COM/PaTh", "hTTps://H/",
    # multiple/empty query + fragments
    "http://h/?a=1&a=2&b=", "http://h/?&&=", "http://h/#", "http://h/?#frag",
    # degenerate / relative / schemeless
    "", "http://", "//h/p", "h:", ":", "?q", "#f", "/abs/path", "rel/path", "../up",
    "g:h", "mailto:a@b.com", "urn:isbn:0451450523", "file:///etc/hosts",
    # length
    "http://h/" + "a" * 300, "http://" + "h" * 200 + "/",
    # whitespace + control-ish
    "http://h/a b", "http://h/a\tb", " http://h/", "http://h/ ",
]

NAME_POOL = [
    "", "x", "name", "a b", "a/b", "a%2Fb", "café", "?q", "#f", "a=b", "..", ".",
    "key" * 50, "naïve", ":/?#[]@", "+plus", "%41", "a&b",
]

VALUE_POOL = [None, "", "v", "a b", "café", "%2F", "a&b=c", "1"]

SEGMENT_POOL = [
    "", "seg", "a b", "a/b", "café", "%2F", "..", ".", "?x", "#y",
    ":/?#[]@", "long" * 80,
]

BOOL_POOL = [True, False]


# ---------------------------------------------------------------- convention generators
#
# Each generator is a thunk -> iterator. Caps are applied with itertools.islice in
# strategy_for; the generators themselves are honest cartesian products in stable order.

def _gen_url():
    return (u for u in URL_POOL)

def _gen_url_href():
    return ((u, h) for u in URL_POOL for h in URL_POOL)

def _gen_url_segments():
    # 1-3 segments, plus a couple multi-seg cases
    one = ((u, s) for u in URL_POOL for s in SEGMENT_POOL)
    two = ((u, s1, s2) for u in URL_POOL[:20] for s1 in SEGMENT_POOL[:6] for s2 in SEGMENT_POOL[:6])
    return itertools.chain(one, two)

def _gen_url_segment():
    return ((u, s) for u in URL_POOL for s in SEGMENT_POOL)

def _gen_url_bool():
    return ((u, b) for u in URL_POOL for b in BOOL_POOL)

def _gen_url_opt_bool():
    no_bool = ((u,) for u in URL_POOL)
    with_bool = ((u, b) for u in URL_POOL for b in BOOL_POOL)
    return itertools.chain(no_bool, with_bool)

def _gen_url_name():
    return ((u, n) for u in URL_POOL for n in NAME_POOL)

def _gen_url_name_optval():
    two = ((u, n) for u in URL_POOL for n in NAME_POOL)
    three = ((u, n, v) for u in URL_POOL[:25] for n in NAME_POOL[:8] for v in VALUE_POOL[:5])
    return itertools.chain(two, three)

def _gen_url_name_value():
    return ((u, n, v) for u in URL_POOL for n in NAME_POOL[:10] for v in VALUE_POOL)

def _gen_url_remove():
    two = ((u, n) for u in URL_POOL for n in NAME_POOL)
    three = ((u, n, v) for u in URL_POOL[:20] for n in NAME_POOL[:6] for v in VALUE_POOL[:5])
    four = ((u, n, v, lim) for u in URL_POOL[:15] for n in NAME_POOL[:4]
            for v in VALUE_POOL[:3] for lim in (None, 0, 1, 2))
    return itertools.chain(two, three, four)

def _gen_url_remove4():
    return ((u, n, v, lim) for u in URL_POOL for n in NAME_POOL[:8]
            for v in (None, "", "v", "café") for lim in (None, 0, 1, 2))

def _gen_parse_triple():
    return ((u, d, lz) for u in URL_POOL for d in BOOL_POOL for lz in BOOL_POOL)


_GENERATORS = {
    "url": _gen_url,
    "url_href": _gen_url_href,
    "url_segments": _gen_url_segments,
    "url_segment": _gen_url_segment,
    "url_bool": _gen_url_bool,
    "url_opt_bool": _gen_url_opt_bool,
    "url_name": _gen_url_name,
    "url_name_optval": _gen_url_name_optval,
    "url_name_value": _gen_url_name_value,
    "url_remove": _gen_url_remove,
    "url_remove4": _gen_url_remove4,
    "parse_triple": _gen_parse_triple,
}


# ---------------------------------------------------------------- qualname -> convention

CONVENTION = {
    "URL.scheme": "url",
    "URL.host": "url",
    "URL.port": "url",
    "URL.query": "url",
    "URL.fragment": "url",
    "URL.rooted": "url",
    "URL.absolute": "url",
    "URL.uses_netloc": "url",
    "URL.normalize": "url",
    "URL.to_uri": "url",
    "URL.to_iri": "url",
    "URL.from_text": "url",
    "parse_host": "url",
    "scheme_uses_netloc": "url",
    "URL.click": "url_href",
    "URL.child": "url_segments",
    "DecodedURL.child": "url_segments",
    "URL.sibling": "url_segment",
    "DecodedURL.sibling": "url_segment",
    "URL.authority": "url_bool",
    "DecodedURL.to_text": "url_bool",
    "URL.to_text": "url_opt_bool",
    "URL.get": "url_name",
    "URL.add": "url_name_optval",
    "URL.set": "url_name_value",
    "URL.remove": "url_remove",
    "DecodedURL.remove": "url_remove4",
    "parse": "parse_triple",
    # URL.path, URL.replace, iter_pairs, make_sentinel are representation-mismatch
    # (unmappable) oracles — the sweep gates them out before generation, so no
    # convention is registered.
}

DEFAULT_CAP = 400


def strategy_for(qualname: str, cap: int = DEFAULT_CAP):
    """(inputs_list, total_available_or_None, capped_bool) for one oracle's convention.

    total_available is None when the generator is an unbounded/expensive product we don't
    fully enumerate (we still report whether the cap truncated by peeking one past it)."""
    conv = CONVENTION.get(qualname)
    if conv is None:
        return [], 0, False
    gen = _GENERATORS[conv]()
    taken = list(itertools.islice(gen, cap + 1))
    capped = len(taken) > cap
    return taken[:cap], (None if capped else len(taken)), capped
