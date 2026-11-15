"""The quantum-safe proof page at /r/{domain}/proof, rendered on the server.

Complete HTML in the first response, like the record at /r/{domain}: a link unfurler, a crawler and
a reader with scripting blocked all get the full statement. /r is on the strict CSP list, so there
is no inline script, no inline handler and no style attribute. One script of this origin
(/ui/make-safe-proof.js, with the vendored verifier /ui/vendor/morrow-pq-verify.js) lets a visitor
check both signatures in their own browser; without it the page still says how to check offline.
"""

from __future__ import annotations

from typing import Any, Dict

from services import registry_page as _registry
from services.registry_page import esc

_STYLE = "/ui/make-safe.css?v=20261115"
_SCRIPTS = ("/ui/vendor/morrow-pq-verify.js", "/ui/make-safe-proof.js?v=20261115")


def _day(value: Any) -> str:
    return str(value or "")[:10] or "-"


def _when(value: Any) -> str:
    text = str(value or "")
    return text.replace("T", " ").replace("Z", " UTC") if text else "-"


def _row(label: str, value: Any) -> str:
    return f"<tr><td>{esc(label)}</td><td class=\"value\">{esc(value)}</td></tr>"


def _head(title: str, description: str, canonical: str, noindex: bool = False) -> str:
    head = _registry._head(title, description, canonical, noindex=noindex)
    extra = f'<link rel="stylesheet" href="{_STYLE}">\n' + "".join(
        f'<script src="{src}" defer></script>\n' for src in _SCRIPTS)
    return head.replace("</head>", extra + "</head>")


def _owner_line(owner: Dict[str, Any]) -> str:
    if owner.get("claimed_by_dns"):
        return f"Claimed by its owner with a DNS record since {_day(owner.get('claimed_since'))}"
    return "Not claimed by its owner on Morrow"


def render_proof(envelope: Dict[str, Any], origin: str) -> str:
    doc = envelope.get("document") or {}
    domain = str(doc.get("domain") or "")
    base = origin.rstrip("/")
    safe = doc.get("status") == "quantum_safe"
    title = (f"{domain}: quantum-safe since {_day(doc.get('safe_since'))} | Morrow" if safe
             else f"{domain}: no longer quantum-safe | Morrow")
    sigs = envelope.get("signatures") or []
    parts = [
        _head(title, str(doc.get("statement") or ""), f"{base}/r/{domain}/proof"),
        _registry._chrome_open(),
        f'  <section class="record-head accent-{"ok" if safe else "warn"} proof-head" id="record" data-proof="/r/{esc(domain)}/proof.json">',
        '    <p class="eyebrow">Signed proof</p>',
        f"    <h1>{esc(domain)}</h1>",
    ]
    if safe:
        parts.append(f'    <p class="proof-status" data-state="safe">Quantum-safe since {esc(_day(doc.get("safe_since")))}</p>')
    else:
        parts.append('    <p class="proof-status" data-state="lapsed">No longer quantum-safe</p>')
    parts.append(f'    <p class="lede">{esc(doc.get("statement"))}</p>')
    if not safe:
        parts.append(f'    <p class="notice">Since {esc(_when(doc.get("lapsed_at")))} this host negotiates '
                     f'{esc(doc.get("lapsed_key_exchange") or "a classical key exchange")}. The fix for its stack is '
                     f'on <a href="/{esc(domain)}#make-safe">its page</a>.</p>')
    parts.append(
        f'    <p class="actions"><a class="btn" href="/{esc(domain)}#make-safe">'
        f'{"See it live" if safe else "Make it safe again"}</a> '
        f'<a href="/r/{esc(domain)}/proof.json">Download the signed proof</a> '
        f'<a href="/r/{esc(domain)}">Public record</a></p>')
    parts.append("  </section>")

    parts.append('  <section class="panel"><h2>What was observed</h2><table class="facts"><tbody>')
    parts.append(_row("Key exchange", doc.get("key_exchange") or "-"))
    parts.append(_row("First observed post-quantum", _when(doc.get("safe_since"))))
    parts.append(_row("Last confirmed post-quantum", _when(doc.get("last_confirmed_safe"))))
    parts.append(_row("Checks in a row", doc.get("checks_in_run")))
    if not safe:
        parts.append(_row("Classical again from", _when(doc.get("lapsed_at"))))
    parts.append(_row("Newest check", _when(doc.get("last_checked"))))
    parts.append(_row("Owner", _owner_line(doc.get("owner") or {})))
    parts.append(_row("Signed", _when(doc.get("issued_at"))))
    parts.append("</tbody></table>")
    parts.append(f'<p class="fine">{esc(doc.get("method"))} Morrow re-checks a host when someone opens its page, '
                 "re-checks it after a fix, or watches it. A later classical check changes this page and its "
                 "signed statement on the next view.</p></section>")

    parts.append('  <section class="panel" id="verify"><h2>Check it yourself</h2>')
    parts.append(f"<p>Signed with {len(sigs)} key{'s' if len(sigs) != 1 else ''}: "
                 + ", ".join(esc(s.get("alg")) for s in sigs) + ". Both must verify.</p>")
    parts.append('<p><button type="button" class="btn" id="proof-verify" hidden>Check the signatures in this browser</button></p>')
    parts.append('<p class="verify-out" id="proof-verify-out" role="status" aria-live="polite"></p>')
    parts.append("<p class=\"fine\">Offline: the signed bytes are the line <code>"
                 f"{esc(doc.get('signing_context'))}</code> and a newline, followed by the <code>document</code> of "
                 f"<a href=\"/r/{esc(domain)}/proof.json\">proof.json</a> as canonical JSON (keys sorted, no spaces, "
                 "UTF-8). Check each signature with the public key of the same <code>kid</code> from "
                 f"<a href=\"{esc(base)}/.well-known/morrow-proof-keys.json\">morrow-proof-keys.json</a>: "
                 "Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204, empty context).</p></section>")
    parts.append('  <section class="panel"><h2>Embed it</h2>')
    snippet = f"[![quantum-readiness grade]({base}/api/public/badge/{domain}.svg)]({base}/r/{domain}/proof)"
    parts.append(f'<pre class="snippet">{esc(snippet)}</pre></section>')
    parts.append(_registry._chrome_close())
    return "\n".join(parts)


def render_unsigned(domain: str, record: Dict[str, Any], origin: str, reason: str) -> str:
    base = origin.rstrip("/")
    safe = record.get("status") == "safe"
    parts = [
        _head(f"{domain}: quantum-safe record | Morrow", "Unsigned: this server cannot sign proofs right now.",
              f"{base}/r/{domain}/proof", noindex=True),
        _registry._chrome_open(),
        f'  <section class="record-head accent-{"ok" if safe else "warn"} proof-head" id="record">',
        '    <p class="eyebrow">Proof (unsigned)</p>',
        f"    <h1>{esc(domain)}</h1>",
        (f'    <p class="proof-status" data-state="safe">Quantum-safe since {esc(_day(record.get("safe_since")))}</p>'
         if safe else '    <p class="proof-status" data-state="lapsed">No longer quantum-safe</p>'),
        f'    <p class="notice">Not signed: {esc(reason)} What follows is the stored record, with nothing to '
        "verify it by.</p>",
        f'    <p class="actions"><a class="btn" href="/{esc(domain)}#make-safe">Its live grade</a></p>',
        "  </section>",
        _registry._chrome_close(),
    ]
    return "\n".join(parts)


def render_missing(domain: str, origin: str, reason: str) -> str:
    base = origin.rstrip("/")
    text = {
        "not_safe_yet": (f"No check of {domain} has seen post-quantum key exchange yet, so there is no proof to show. "
                         "Make it safe first: its page has the exact change for its server."),
        "refused_optout": f"{domain} has asked not to be checked by this service.",
        "not_a_domain": "That is not a hostname this service checks.",
    }.get(reason, "There is no proof here.")
    parts = [
        _head(f"No proof for {domain} | Morrow", text, f"{base}/r/{domain}/proof", noindex=True),
        _registry._chrome_open(),
        '  <section class="record-head accent-none" id="record">',
        '    <p class="eyebrow">Signed proof</p>',
        f"    <h1>{esc(domain)}</h1>",
        f'    <p class="lede">{esc(text)}</p>',
    ]
    if reason == "not_safe_yet":
        parts.append(f'    <p class="actions"><a class="btn" href="/{esc(domain)}#make-safe">Make it safe</a></p>')
    parts += ["  </section>", _registry._chrome_close()]
    return "\n".join(parts)

