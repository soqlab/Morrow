"""Server-rendered pages and badges for the public registry at ``/r/{domain}``.

Why this is rendered on the server
----------------------------------
``static/check.html`` is a tool: a form, and JavaScript that fetches a result. That is right for
somebody running a check and useless for a record. A record has to survive being shared, which
means it has to be readable by things that do not run JavaScript -- a search crawler, a link
unfurler in Slack or LinkedIn, a reader with scripting blocked, an archiver. So the record page
is complete HTML in the first response, built from stored data, and touches no network at all.

What it may not do
------------------
``/r`` is on the strict CSP list (``script-src 'self'``, no ``unsafe-inline``), so nothing here
emits an inline ``<script>``, an inline event handler or a ``style=`` attribute. There is no
JavaScript on this page in the first place: every control is a link or a form. The one exception
is the JSON-LD block in ``<head>``, which is a data block rather than executable script -- CSP
does not stop it, and the crawlers it exists for parse the HTML without enforcing CSP anyway.

The badge
---------
Hand-built SVG, as ``services/qr_svg.py`` already does, with no new dependency and no font
metrics library: the width comes from a per-character table, which is what shields.io does.
Rules that matter more than the drawing are in ``badge_svg``.
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple  # noqa: F401

from services import public_check as _check

#: The chrome every public document on this site shares, so a record page does not look like it
#: came from somewhere else. Deliberately without fabric.js/motion.js: a record is read, not
#: animated, and this page's whole point is to be fast and complete on first paint.
# Only two sheets. static/check.css once rendered black text on a black ground because its token
# names collided with another sheet's; the fix that lasts is to load the one sheet that defines the
# page shell and then one sheet of our own, with a literal fallback on every token we read.
_STYLES = (
    "/ui/public.css?v=7",
    "/ui/registry.css?v=20261004",
)

_NAV = (
    ("/", "Platform"),
    ("/security", "Security"),
    ("/pricing", "Pricing"),
    ("/check", "Free check"),
    ("/support", "Contact"),
)

_FOOTER_LINKS = (
    ("/public-check/terms", "Terms of use"),
    ("/public-check/acceptable-use", "Acceptable use"),
    ("/abuse", "Abuse &amp; opt-out"),
    ("/public-check/privacy", "Checker privacy"),
    ("/scanner", "Scanner identity"),
    ("/support", "Support"),
)

#: posture -> (badge fill, page accent class). Green for both post-quantum outcomes, amber for
#: classical, grey for the two cases where nothing was established.
_POSTURE_STYLE = {
    _check.POSTURE_PQC_READY: ("#1a7f37", "ok"),
    _check.POSTURE_HYBRID: ("#2ea043", "part"),
    _check.POSTURE_CLASSICAL: ("#bf8700", "warn"),
    _check.POSTURE_UNREACHABLE: ("#6e7681", "none"),
    _check.POSTURE_UNKNOWN: ("#6e7681", "none"),
}

_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def esc(value: Any) -> str:
    """Escape for HTML text and for quoted attributes alike."""
    return html.escape("" if value is None else str(value), quote=True)


# ── Badge ────────────────────────────────────────────────────────────────────

#: Widths at an 11px sans font, in units of 1/10 px, for the characters that can appear in a
#: badge label. Measured text would need a font metrics library the image does not carry; this is
#: the same approximation shields.io ships, and the badge only has to not clip.
_CHAR_WIDTH = {
    " ": 35, "-": 41, ".": 35, "/": 46, ":": 35,
    "0": 63, "1": 63, "2": 63, "3": 63, "4": 63, "5": 63, "6": 63, "7": 63, "8": 63, "9": 63,
    "a": 61, "b": 63, "c": 55, "d": 63, "e": 60, "f": 36, "g": 63, "h": 63, "i": 27, "j": 27,
    "k": 57, "l": 27, "m": 97, "n": 63, "o": 62, "p": 63, "q": 63, "r": 41, "s": 53, "t": 38,
    "u": 63, "v": 57, "w": 83, "x": 57, "y": 57, "z": 53,
}
_CHAR_WIDTH_DEFAULT = 70

_BADGE_LABEL = "post-quantum"
_BADGE_HEIGHT = 20
_BADGE_PAD = 6


def _text_width(text: str) -> int:
    """Approximate rendered width in px, rounded up."""
    total = sum(_CHAR_WIDTH.get(ch, _CHAR_WIDTH.get(ch.lower(), _CHAR_WIDTH_DEFAULT))
                for ch in text)
    return (total + 9) // 10


def badge_svg(posture: Optional[str]) -> str:
    """The badge for a posture, or the neutral one when there is nothing to report.

    Three rules, each of which has a reason that is not aesthetic:

    1. No cookies, no ``Vary``, no auth. GitHub serves README images through its Camo proxy;
       anything that varies per viewer is cached wrongly or not cached at all.
    2. ``None`` -- an opted-out domain *and* a domain nobody has ever checked -- renders the same
       grey ``unknown`` badge. A 403 would break the README it sits in and would confirm that the
       domain asked to be left out; identical output leaks neither the posture nor the opt-out.
    3. It renders from the argument only. Nothing here can start a check, so a popular README
       cannot turn into traffic against somebody's endpoint.
    """
    key = posture if posture in _POSTURE_STYLE else _check.POSTURE_UNKNOWN
    value = _check.POSTURE_LABEL.get(key, "unknown")
    fill = _POSTURE_STYLE[key][0]

    label_w = _text_width(_BADGE_LABEL) + _BADGE_PAD * 2
    value_w = _text_width(value) + _BADGE_PAD * 2
    total = label_w + value_w
    # Text is placed at 10x scale and scaled down, which is how shields keeps sub-pixel centring
    # stable across renderers.
    label_x = label_w * 5
    value_x = (label_w + value_w / 2) * 10
    alt = f"post-quantum: {value}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="{_BADGE_HEIGHT}" '
        f'role="img" aria-label="{esc(alt)}">'
        f"<title>{esc(alt)}</title>"
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="{_BADGE_HEIGHT}" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{label_w}" height="{_BADGE_HEIGHT}" fill="#30363d"/>'
        f'<rect x="{label_w}" width="{value_w}" height="{_BADGE_HEIGHT}" fill="{fill}"/>'
        f'<rect width="{total}" height="{_BADGE_HEIGHT}" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,Geneva,sans-serif" '
        f'font-size="110" transform="scale(.1)">'
        f'<text x="{label_x}" y="140" fill="#010101" fill-opacity=".3">{esc(_BADGE_LABEL)}</text>'
        f'<text x="{label_x}" y="130">{esc(_BADGE_LABEL)}</text>'
        f'<text x="{value_x:.0f}" y="140" fill="#010101" fill-opacity=".3">{esc(value)}</text>'
        f'<text x="{value_x:.0f}" y="130">{esc(value)}</text>'
        f"</g></svg>"
    )


def badge_size(posture: Optional[str]) -> Tuple[int, int]:
    """The badge's (width, height), so an <img> can reserve the right box and not reflow."""
    key = posture if posture in _POSTURE_STYLE else _check.POSTURE_UNKNOWN
    value = _check.POSTURE_LABEL.get(key, "unknown")
    width = (_text_width(_BADGE_LABEL) + _BADGE_PAD * 2) + (_text_width(value) + _BADGE_PAD * 2)
    return width, _BADGE_HEIGHT


def badge_markdown(domain: str, origin: str) -> str:
    """The snippet somebody pastes into a README."""
    base = origin.rstrip("/")
    return f"[![post-quantum]({base}/r/{domain}/badge.svg)]({base}/r/{domain})"


# ── Page ─────────────────────────────────────────────────────────────────────


def _head(title: str, description: str, canonical: str, *,
          noindex: bool = False, json_ld: Optional[Dict[str, Any]] = None) -> str:
    tags = [
        "<!DOCTYPE html>", '<html lang="en">', "<head>",
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"<title>{esc(title)}</title>",
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">',
        f'<meta name="description" content="{esc(description)}">',
        f'<link rel="canonical" href="{esc(canonical)}">',
        # An unfurl shows the title and the description; there is no og:image because generating
        # a per-domain card needs a TTF and static/fonts/ ships woff2, which Pillow cannot read.
        # A five-way static card would add nothing the title does not already say.
        '<meta property="og:type" content="article">',
        f'<meta property="og:title" content="{esc(title)}">',
        f'<meta property="og:description" content="{esc(description)}">',
        f'<meta property="og:url" content="{esc(canonical)}">',
        '<meta name="twitter:card" content="summary">',
    ]
    if noindex:
        # /r/{anything} is unbounded crawl space: any string is a URL. A page with no record must
        # never be indexable, or a crawler will mine the namespace forever.
        tags.append('<meta name="robots" content="noindex, follow">')
    for href in _STYLES:
        tags.append(f'<link rel="stylesheet" href="{href}">')
    if json_ld is not None:
        # A data block, not a script: CSP does not execute it, and the crawlers it is for read the
        # HTML without enforcing CSP. json.dumps escapes "<" as < via ensure_ascii, so this
        # cannot close the element early.
        payload = json.dumps(json_ld, ensure_ascii=True, separators=(",", ":"))
        tags.append('<script type="application/ld+json">' + payload.replace("<", "\\u003c")
                    + "</script>")
    tags.append("</head>")
    return "\n".join(tags)


def _chrome_open() -> str:
    nav = "".join(f'<a href="{href}">{label}</a>' for href, label in _NAV)
    return (
        '<body class="public-document registry-page">\n'
        '<a class="skip-link" href="#record">Skip to the record</a>\n'
        '<main class="doc-shell">\n'
        '  <header class="topbar">\n'
        '    <a class="brand" href="/launch"><span class="brand-mark" aria-hidden="true"></span>'
        "<span>Airlock Command</span></a>\n"
        f'    <nav class="nav" aria-label="Public navigation">{nav}'
        '<a class="nav-cta" href="/ui/">Open console &#8599;</a></nav>\n'
        "  </header>\n"
    )


def _chrome_close() -> str:
    links = " / ".join(f'<a href="{href}">{label}</a>' for href, label in _FOOTER_LINKS)
    return (
        '  <footer>\n'
        "    <span>Airlock Command / Public registry</span>\n"
        f"    <nav>{links}</nav>\n"
        "  </footer>\n"
        "</main>\n</body>\n</html>\n"
    )


def _row(label: str, value: Any, note: str = "") -> str:
    # Only None and "" count as absent. A zero is a fact: "0 certificates seen" is worth printing,
    # and `value in (None, "", 0)` would also swallow False.
    if (value is None or value == "") and not note:
        return ""
    extra = f'<span class="note">{esc(note)}</span>' if note else ""
    return f'<tr><td>{esc(label)}</td><td class="value">{esc(value)}{extra}</td></tr>'


def _algorithm_cards(algorithms: Iterable[Dict[str, Any]]) -> str:
    cards: List[str] = []
    ordered = sorted(algorithms or [],
                     key=lambda a: _RISK_ORDER.get(str(a.get("risk") or "").lower(), 4))
    for algo in ordered:
        status = str(algo.get("status") or "unknown")
        name = str(algo.get("algorithm") or algo.get("resolved_as") or "unknown")
        observed_as = str(algo.get("observed_as") or "")
        standards = ", ".join(str(s) for s in (algo.get("standards") or []))
        action = str(algo.get("action") or "")
        cards.append(
            f'<article class="algo algo-{esc(status)}">'
            f'<h3>{esc(name)}</h3>'
            f'<p class="role">{esc(algo.get("role") or "")}</p>'
            f'<p class="verdict-line">{esc(status.replace("_", " "))}</p>'
            f'<p>{esc(algo.get("details") or "")}</p>'
            + (f'<p class="fine">Observed as <code>{esc(observed_as)}</code>.</p>'
               if observed_as and observed_as != name else "")
            + (f'<p class="fine">Standards: {esc(standards)}</p>' if standards else "")
            + (f'<p class="action">{esc(action)}</p>'
               if action and action.lower() != "none" else "")
            + "</article>"
        )
    if not cards:
        return ('<p class="empty">No algorithm could be identified, so none is listed. That is '
                "not the same as none being present.</p>")
    return f'<div class="algo-grid">{"".join(cards)}</div>'


def _history_table(history: List[Dict[str, Any]], domain: str) -> str:
    if len(history) <= 1:
        return ('<p class="empty">One observation so far. When this endpoint\'s cryptography '
                "changes, the change appears here with its date.</p>")
    rows: List[str] = []
    for item in history:
        posture = str(item.get("posture") or _check.POSTURE_UNKNOWN)
        label = _check.POSTURE_LABEL.get(posture, "unknown")
        link = f'/r/{esc(domain)}/at/{int(item.get("observation_id") or 0)}'
        rows.append(
            f"<tr><td><a href=\"{link}\">{esc(_short_date(item.get('observed_at')))}</a></td>"
            f'<td><span class="pill pill-{esc(_POSTURE_STYLE.get(posture, ("", "none"))[1])}">'
            f"{esc(label)}</span></td>"
            f"<td>{esc(item.get('summary') or '')}</td>"
            f"<td>{esc(_short_date(item.get('last_seen_at')))}</td></tr>"
        )
    return (
        '<table class="history"><thead><tr><th>First seen</th><th>Posture</th>'
        "<th>What was negotiated</th><th>Last confirmed</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        '<p class="fine">A row is added when the cryptography changes, not when the check runs. '
        "An unchanged endpoint moves its &#8220;last confirmed&#8221; date instead, so this list "
        "is a history of changes rather than a log of visits.</p>"
    )


def _short_date(value: Any) -> str:
    text = str(value or "")
    return text[:10] if len(text) >= 10 else text


def _deadline_table(deadlines: Iterable[Dict[str, Any]]) -> str:
    rows: List[str] = []
    for item in deadlines or []:
        reference = str(item.get("reference") or "")
        name = esc(item.get("name") or item.get("framework") or "")
        name_cell = (f'<a href="{esc(reference)}" rel="nofollow noopener">{name}</a>'
                     if reference.startswith("https://") else name)
        rows.append(
            f"<tr><td>{name_cell}<span class=\"note\">{esc(item.get('authority') or '')}</span></td>"
            f"<td>{esc(item.get('soft_deadline') or '--')}</td>"
            f"<td>{esc(item.get('hard_deadline') or '--')}</td></tr>"
        )
    if not rows:
        return ""
    return (
        '<table class="deadlines"><thead><tr><th>Published deadline</th><th>First milestone</th>'
        f"<th>Final</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
        '<p class="fine">Quoted from the issuing authority. Whether a deadline binds this domain '
        "depends on who operates it, which this check cannot know.</p>"
    )


def _list_block(title: str, items: Iterable[Any]) -> str:
    entries = [str(i) for i in (items or []) if str(i).strip()]
    if not entries:
        return ""
    body = "".join(f"<li>{esc(item)}</li>" for item in entries)
    return f"<h2>{esc(title)}</h2><ul class=\"plain\">{body}</ul>"


def _json_ld(domain: str, canonical: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    result = entry.get("result") or {}
    verdict = result.get("verdict") or {}
    return {
        "@context": "https://schema.org",
        "@type": "Dataset",
        "name": f"Post-quantum readiness record for {domain}",
        "description": str(verdict.get("explanation") or "")[:800],
        "url": canonical,
        "dateModified": str(entry.get("last_observed_at") or ""),
        "datePublished": str(entry.get("first_seen_at") or ""),
        "isAccessibleForFree": True,
        "license": "https://opensource.org/licenses/MIT",
        "creator": {"@type": "Organization", "name": "Airlock Command"},
        "about": {"@type": "WebSite", "url": f"https://{domain}/"},
        "measurementTechnique": "TLS handshake observation and Certificate Transparency",
        "variableMeasured": _check.POSTURE_LABEL.get(str(entry.get("posture") or ""), "unknown"),
    }


def render_record(entry: Dict[str, Any], history: List[Dict[str, Any]], origin: str,
                  *, observation: Optional[Dict[str, Any]] = None) -> str:
    """The record page. ``observation`` renders one historical observation instead of the latest."""
    shown = observation or entry
    domain = str(entry.get("domain") or "")
    result = shown.get("result") or {}
    verdict = result.get("verdict") or {}
    observed = result.get("observed") or {}
    cert = observed.get("certificate") or {}
    hndl = result.get("harvest_now_decrypt_later") or {}
    ct = result.get("certificate_transparency") or {}
    posture = str(shown.get("posture") or entry.get("posture") or _check.POSTURE_UNKNOWN)
    accent = _POSTURE_STYLE.get(posture, ("", "none"))[1]
    is_historical = observation is not None

    base = origin.rstrip("/")
    canonical = (f"{base}/r/{domain}/at/{int(shown.get('observation_id') or 0)}"
                 if is_historical else f"{base}/r/{domain}")
    title = f"{domain} -- post-quantum readiness | Airlock Command"
    description = (str(verdict.get("headline") or "") + ". "
                   + str(verdict.get("explanation") or ""))[:300]

    parts: List[str] = [
        _head(title, description, canonical,
              noindex=is_historical,
              json_ld=None if is_historical else _json_ld(domain, canonical, entry)),
        _chrome_open(),
        f'  <section class="record-head accent-{esc(accent)}" id="record">',
        '    <p class="eyebrow">Public post-quantum record</p>',
        f"    <h1>{esc(domain)}</h1>",
        f'    <p class="posture-line"><span class="pill pill-{esc(accent)}">'
        f'{esc(_check.POSTURE_LABEL.get(posture, "unknown"))}</span> '
        f'{esc(_check.POSTURE_MEANING.get(posture, ""))}</p>',
        f"    <h2 class=\"headline\">{esc(verdict.get('headline') or '')}</h2>",
        f"    <p class=\"lede\">{esc(verdict.get('explanation') or '')}</p>",
        '    <dl class="meta">',
        f"      <dt>Observed</dt><dd>{esc(shown.get('observed_at') or '')}</dd>",
        f"      <dt>Last confirmed</dt><dd>{esc(shown.get('last_seen_at') or '')}</dd>",
        f"      <dt>First recorded</dt><dd>{esc(entry.get('first_seen_at') or '')}</dd>",
        f"      <dt>Observations</dt><dd>{esc(entry.get('observations') or 1)}</dd>",
        "    </dl>",
    ]

    if is_historical:
        parts.append(
            '    <p class="notice">This is a past observation, kept so it can be cited. '
            f'The current record is at <a href="{esc(base)}/r/{esc(domain)}">/r/{esc(domain)}</a>.</p>')

    # The one control on the page, and it is a link: the record stays complete with no JavaScript.
    parts.append(
        f'    <p class="actions"><a class="btn" href="/check?domain={esc(domain)}">Run this check '
        f'again</a> <a href="/r/{esc(domain)}/export.json">Download JSON</a> '
        f'<a href="/r/{esc(domain)}/cbom.json">Download CBOM</a></p>')
    parts.append("  </section>")

    # ── What was measured
    parts.append('  <section class="panel"><h2>What was measured</h2>')
    parts.append('<table class="facts"><tbody>')
    parts.append(_row("Reachable", "yes" if observed.get("reachable") else "no",
                      "" if observed.get("reachable")
                      else "Nothing was measured, so nothing here is a clean result."))
    parts.append(_row("TLS version", observed.get("tls_version")))
    parts.append(_row("Cipher", observed.get("cipher_name")))
    if observed.get("key_exchange_observed"):
        parts.append(_row("Key exchange", observed.get("key_exchange")))
    elif observed.get("reachable"):
        parts.append(_row("Key exchange", "not observed",
                          str(observed.get("key_exchange_unobservable_reason") or
                              "It was not observable from outside, so it is reported as not "
                              "observed -- never as absent.")))
    parts.append(_row("Certificate key", (f"{cert.get('key_type')}"
                                          + (f"-{cert.get('key_bits')}" if cert.get("key_bits") else "")
                                          + (f" ({cert.get('key_curve')})" if cert.get("key_curve") else ""))
                      if cert.get("key_type") else ""))
    parts.append(_row("Certificate signature", cert.get("sig_algorithm")))
    parts.append(_row("Issuer", cert.get("issuer")))
    parts.append(_row("Certificate expires", cert.get("not_after")))
    parts.append(_row("Port", observed.get("port") or 443))
    parts.append(_row("Connections made", observed.get("connections_made"),
                      "One handshake, plus one ClientHello offering post-quantum groups."))
    if not observed.get("reachable") and observed.get("error"):
        parts.append(_row("Why it failed", observed.get("error")))
    parts.append("</tbody></table></section>")

    # ── Algorithms
    parts.append('  <section class="panel"><h2>Algorithms this endpoint depends on</h2>')
    parts.append(_algorithm_cards(result.get("algorithms") or []))
    parts.append("</section>")

    # ── HNDL
    if hndl.get("rationale"):
        parts.append('  <section class="panel"><h2>Harvest now, decrypt later</h2>')
        parts.append(f"<p>{esc(hndl.get('rationale'))}</p>")
        parts.append('<table class="facts"><tbody>')
        parts.append(_row("Algorithm class", hndl.get("algorithm_class")))
        parts.append(_row("Risk tier", hndl.get("risk_tier")))
        probability = hndl.get("break_probability_by_q_day")
        if probability is not None:
            parts.append(_row("Break probability by the modelled Q-Day", probability,
                              f"Model, not forecast. Q-Day year used: "
                              f"{hndl.get('q_day_year_used')} "
                              f"({hndl.get('q_day_year_source')})."))
        parts.append("</tbody></table></section>")

    # ── Deadlines
    deadline_block = _deadline_table(result.get("deadlines") or [])
    if deadline_block:
        parts.append(f'  <section class="panel"><h2>Published deadlines</h2>{deadline_block}</section>')

    # ── History
    parts.append(f'  <section class="panel"><h2>History</h2>{_history_table(history, domain)}</section>')

    # ── Certificate Transparency
    if str(ct.get("status") or "") == "ok":
        issuers = ", ".join(str(i.get("issuer") or "") for i in (ct.get("issuers") or [])[:4])
        parts.append('  <section class="panel"><h2>From public certificate logs</h2>')
        parts.append('<table class="facts"><tbody>')
        parts.append(_row("Certificates seen", ct.get("certificate_count"),
                          "Read from public Certificate Transparency logs. The domain was not "
                          "contacted for this."))
        parts.append(_row("Issuers", issuers))
        parts.append(_row("Earliest", _short_date(ct.get("earliest_not_before"))))
        parts.append(_row("Latest expiry", _short_date(ct.get("latest_not_after"))))
        parts.append(f'</tbody></table><p class="fine">Source: '
                     f'{esc(ct.get("provider") or "")}.</p></section>')

    # ── Badge
    snippet = badge_markdown(domain, base)
    parts.append(
        '  <section class="panel"><h2>Badge</h2>'
        f'<p><img src="/r/{esc(domain)}/badge.svg" alt="post-quantum: '
        f'{esc(_check.POSTURE_LABEL.get(posture, "unknown"))}" '
        f'width="{badge_size(posture)[0]}" height="{badge_size(posture)[1]}"></p>'
        "<p>Paste this into a README. It renders the current posture, not this snapshot, and it "
        "is served from stored data -- showing the badge never starts a check.</p>"
        f"<pre><code>{esc(snippet)}</code></pre></section>")

    # ── Limits, honestly
    limits = _list_block("What this does not tell you", result.get("limits") or [])
    adds = _list_block("What a full assessment adds", result.get("what_a_full_assessment_adds") or [])
    if limits or adds:
        parts.append(f'  <section class="panel limits">{limits}{adds}</section>')

    parts.append(
        '  <section class="panel fine-print">'
        "<p>This record is a point-in-time observation of one public endpoint on port 443, built "
        "from public data. It is not an audit, and it says nothing about anything else the "
        "operator runs. If this is your domain and you want it gone, "
        '<a href="/abuse">opt out</a>: the record is hidden and the domain is refused before DNS. '
        'If you saw the handshake in your logs, <a href="/scanner">this is what connected to '
        "you</a>.</p></section>")
    parts.append(_chrome_close())
    return "\n".join(p for p in parts if p)


def render_missing(domain: str, origin: str) -> str:
    """For a domain with no record. Returned with 404 and noindex, never as a blank record."""
    base = origin.rstrip("/")
    title = f"No record yet for {domain} | Airlock Command"
    description = (f"{domain} has not been checked by the public post-quantum readiness "
                   "checker, so there is no record to show.")
    return "\n".join([
        _head(title, description, f"{base}/r/{domain}", noindex=True),
        _chrome_open(),
        '  <section class="record-head accent-none" id="record">',
        '    <p class="eyebrow">Public post-quantum record</p>',
        f"    <h1>{esc(domain)}</h1>",
        '    <p class="lede">There is no record for this domain: nobody has run the free check '
        "on it yet.</p>",
        f'    <p class="actions"><a class="btn" href="/check?domain={esc(domain)}">'
        "Run the check</a></p>",
        '    <p class="fine">Running it contacts this endpoint once on port 443, the way a '
        'browser does. The <a href="/public-check/acceptable-use">acceptable-use policy</a> '
        "applies: check hosts you own, a supplier you are assessing, or a domain you are "
        "researching in good faith.</p>",
        "  </section>",
        _chrome_close(),
    ])


def render_refused(domain: str, covered: str, origin: str) -> str:
    """For an opted-out domain, in the wording /abuse already promises.

    /abuse states that a check on an opted-out domain is "refused with a message saying the domain
    asked not to be checked and that nothing was contacted", and that the exports answer the same
    way. The API already does exactly that, so the record page says it too: hiding the refusal here
    while the API discloses it would protect nothing and contradict a published page. The badge is
    the one exception, for the reason given in badge_svg.
    """
    base = origin.rstrip("/")
    title = f"{domain} has opted out | Airlock Command"
    description = f"{domain} has asked not to be checked by this service."
    return "\n".join([
        _head(title, description, f"{base}/r/{domain}", noindex=True),
        _chrome_open(),
        '  <section class="record-head accent-none" id="record">',
        '    <p class="eyebrow">Public post-quantum record</p>',
        f"    <h1>{esc(domain)}</h1>",
        f'    <p class="lede">{esc(covered)} has asked not to be checked by this service, so '
        f"there is no record here and {esc(domain)} was not contacted. Nothing was resolved and "
        "no connection was made.</p>",
        '    <p class="fine">If you operate this domain and want that reversed, or you reached '
        'this page by accident, <a href="/abuse">the opt-out page</a> explains both directions. '
        'What the service does and does not send is described on <a href="/scanner">scanner '
        "identity</a>.</p>",
        "  </section>",
        _chrome_close(),
    ])
