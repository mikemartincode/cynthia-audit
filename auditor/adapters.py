#!/usr/bin/env python3
"""auditor/adapters.py - faithful bridges from the REAL hyperlink API to each oracle's
invented one-argument calling convention.

Each A03 oracle reimplemented a hyperlink behavior as a pure function `ref_<leaf>(arg)`
with a self-chosen input convention (a URL string, or a tuple the ref unpacks) and a
self-chosen output representation (URL text, a scalar, a tuple). To differential-test the
REAL library against a mutation-proven oracle we need, per function, an adapter with the
SAME one-argument convention that calls the real code and returns the SAME output shape.

The adapter is the unavoidable bridge in any "library vs independent spec oracle" diff. It
is kept deliberately THIN: parse the real object, call the real method, return its native
result (or `.to_text()` for URL-valued methods - the representation every URL-valued oracle
chose). An adapter must NOT re-encode spec semantics; where the oracle's chosen output
representation differs structurally from the real API's (e.g. a path tuple with vs without a
leading empty segment), that adapter is left faithful to the REAL shape and the sweep's
empirical fidelity check (adapter vs REFERENCE_FUNC over the mutation-proven PROBE_INPUTS)
flags it as an unmappable bridge - it is NOT silently normalized into agreement, which would
manufacture or mask divergences.

Inputs are passed straight through (the convention is the oracle's); a real call that raises
propagates so the sweep can apply its invalid-input filter.
"""

from __future__ import annotations

import sys
from pathlib import Path

# the target lives under the vendored repo, imported by absolute path so the sweep never
# depends on an installed hyperlink (and never picks up a different version on the box).
_REPO_SRC = str((Path(__file__).resolve().parent.parent / "targets/hyperlink/repo/src"))
if _REPO_SRC not in sys.path:
    sys.path.insert(0, _REPO_SRC)

import hyperlink._url as _M  # noqa: E402
from hyperlink import URL, DecodedURL  # noqa: E402

_UNSET = _M._UNSET  # the library's own "argument omitted" sentinel for remove()


# ---------------------------------------------------------------- helpers

class BridgeInapplicable(Exception):
    """The argument doesn't fit this oracle's tuple convention (e.g. a bare string where a
    tuple is required). Raised BEFORE the real call so the sweep classifies it as a bridge
    artifact, never as a real-code divergence. The oracle's non-tuple-rejection probes test
    the oracle's own invented input validation, which has no counterpart in the real method -
    silently char-splitting a string via `a, *b = "str"` would manufacture a false finding."""


def _astuple(arg):
    if not isinstance(arg, tuple):
        raise BridgeInapplicable(f"convention requires a tuple, got {type(arg).__name__}")
    return arg


def _u(text):
    return URL.from_text(text)


def _du(text):
    return DecodedURL.from_text(text)


# ---------------------------------------------------------------- URL scalars (arg = str)

def _scheme(arg):
    return _u(arg).scheme

def _host(arg):
    return _u(arg).host

def _port(arg):
    return _u(arg).port

def _path(arg):
    return _u(arg).path

def _query(arg):
    return _u(arg).query

def _fragment(arg):
    return _u(arg).fragment

def _rooted(arg):
    return _u(arg).rooted

def _absolute(arg):
    return _u(arg).absolute

def _uses_netloc(arg):
    return _u(arg).uses_netloc


# ---------------------------------------------------------------- URL transforms -> text

def _normalize(arg):
    return _u(arg).normalize().to_text()

def _to_uri(arg):
    return _u(arg).to_uri().to_text()

def _to_iri(arg):
    return _u(arg).to_iri().to_text()

def _click(arg):
    arg = _astuple(arg)
    base, href = arg
    return _u(base).click(href).to_text()

def _child(arg):
    arg = _astuple(arg)
    base, *segs = arg
    return _u(base).child(*segs).to_text()

def _sibling(arg):
    arg = _astuple(arg)
    url, seg = arg
    return _u(url).sibling(seg).to_text()

def _authority(arg):
    arg = _astuple(arg)
    url, with_password = arg
    return _u(url).authority(with_password)

def _to_text(arg):
    arg = _astuple(arg)
    url = arg[0]
    with_password = arg[1] if len(arg) > 1 else False
    return _u(url).to_text(with_password=with_password)

def _add(arg):
    arg = _astuple(arg)
    if len(arg) == 2:
        url, name = arg
        value = None
    else:
        url, name, value = arg
    return _u(url).add(name, value).to_text()

def _set(arg):
    arg = _astuple(arg)
    url, name, value = arg
    return _u(url).set(name, value).to_text()

def _get(arg):
    arg = _astuple(arg)
    url, name = arg
    return _u(url).get(name)

def _remove(arg):
    arg = _astuple(arg)
    url, name = arg[0], arg[1]
    value = arg[2] if len(arg) > 2 else _UNSET
    limit = arg[3] if len(arg) > 3 else None
    kw = {}
    if value is not _UNSET and value is not None:
        kw["value"] = value
    if limit is not None:
        kw["limit"] = limit
    return _u(url).remove(name, **kw).to_text()

def _from_text(arg):
    # the oracle's check_impl calls out.to_text(); the real URL provides it.
    return _u(arg)


# ---------------------------------------------------------------- DecodedURL -> text

def _du_child(arg):
    arg = _astuple(arg)
    base, *segs = arg
    return _du(base).child(*segs).to_text()

def _du_remove(arg):
    arg = _astuple(arg)
    url, name, value, limit = arg
    kw = {}
    if value is not None:
        kw["value"] = value
    if limit is not None:
        kw["limit"] = limit
    return _du(url).remove(name, **kw).to_text()

def _du_sibling(arg):
    arg = _astuple(arg)
    url, seg = arg
    return _du(url).sibling(seg).to_text()

def _du_to_text(arg):
    arg = _astuple(arg)
    url, with_password = arg
    return _du(url).to_text(with_password=with_password)


# ---------------------------------------------------------------- module-level functions

def _iter_pairs(arg):
    return list(_M.iter_pairs(arg))

def _make_sentinel(arg):
    # oracle convention: arg is a tuple of 0-2 positional args (name, var_name).
    if not isinstance(arg, tuple):
        raise ValueError("make_sentinel adapter expects a tuple")
    return _M.make_sentinel(*arg)

def _parse(arg):
    arg = _astuple(arg)
    url, decoded, lazy = arg
    return _M.parse(url, decoded, lazy)

def _parse_host(arg):
    return _M.parse_host(arg)

def _scheme_uses_netloc(arg):
    return _M.scheme_uses_netloc(arg)


# ---------------------------------------------------------------- URL.replace (9-tuple)

# The oracle represents a URL as a 9-tuple
# (scheme, host, path, query, fragment, port, rooted, userinfo, uses_netloc)
# and replace() as: build that URL, apply the non-"__UNSET__" kwargs, return the 9-tuple.
_REPLACE_FIELDS = ("scheme", "host", "path", "query", "fragment",
                   "port", "rooted", "userinfo", "uses_netloc")
_REPLACE_UNSET = "__UNSET__"


def _url_from_9tuple(t):
    scheme, host, path, query, fragment, port, rooted, userinfo, uses_netloc = t
    return URL(scheme=scheme, host=host, path=tuple(path), query=tuple(query),
               fragment=fragment, port=port, rooted=rooted, userinfo=userinfo,
               uses_netloc=uses_netloc)


def _url_to_9tuple(u):
    return (u.scheme, u.host, tuple(u.path), tuple(u.query), u.fragment,
            u.port, u.rooted, u.userinfo, u.uses_netloc)


def _replace(arg):
    if not isinstance(arg, tuple) or len(arg) != 10:
        raise ValueError("replace adapter expects a 10-tuple")
    cur = arg[0]
    repls = arg[1:]
    u = _url_from_9tuple(cur)
    kw = {}
    for field, val in zip(_REPLACE_FIELDS, repls):
        if val == _REPLACE_UNSET:
            continue
        if field == "path":
            val = tuple(val)
        elif field == "query":
            val = tuple(val.items()) if isinstance(val, dict) else tuple(val)
        kw[field] = val
    return _url_to_9tuple(u.replace(**kw))


# ---------------------------------------------------------------- registry

ADAPTERS = {
    "URL.scheme": _scheme,
    "URL.host": _host,
    "URL.port": _port,
    "URL.path": _path,
    "URL.query": _query,
    "URL.fragment": _fragment,
    "URL.rooted": _rooted,
    "URL.absolute": _absolute,
    "URL.uses_netloc": _uses_netloc,
    "URL.normalize": _normalize,
    "URL.to_uri": _to_uri,
    "URL.to_iri": _to_iri,
    "URL.click": _click,
    "URL.child": _child,
    "URL.sibling": _sibling,
    "URL.authority": _authority,
    "URL.to_text": _to_text,
    "URL.add": _add,
    "URL.set": _set,
    "URL.get": _get,
    "URL.remove": _remove,
    "URL.from_text": _from_text,
    "URL.replace": _replace,
    "DecodedURL.child": _du_child,
    "DecodedURL.remove": _du_remove,
    "DecodedURL.sibling": _du_sibling,
    "DecodedURL.to_text": _du_to_text,
    "iter_pairs": _iter_pairs,
    "make_sentinel": _make_sentinel,
    "parse": _parse,
    "parse_host": _parse_host,
    "scheme_uses_netloc": _scheme_uses_netloc,
}


# Per-oracle "observable" extractor for the differential-generation path: when an oracle's
# REFERENCE_FUNC and the adapter both return an OPAQUE object (a URL-like wrapper, a
# generator), reduce both to the comparable value the oracle's own check_impl observes -
# `.to_text()` for URL-valued wrappers, `list()` for the iter_pairs generator. Scalars and
# text need no extraction (absent from this map). This is NOT spec normalization: it picks
# the same projection the mutation-proven check_impl already grades on.
OBSERVABLE = {
    "URL.from_text": lambda o: o.to_text(),
    "parse": lambda o: o.to_text(),
    "iter_pairs": list,
}
