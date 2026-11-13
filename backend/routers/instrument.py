"""The instrument: Morrow's public, no-account views, and their plain, script-free twins.

  GET /                      the one input, your own connection, live counts
  GET /<domain>              that domain's grade (the address is the interface: /example.com)
  GET /league                sector averages and their weekly trend; no site is named
  GET /atlas                 retired: forwards to /estate when signed in, /league otherwise
  GET /estate[/scan/<id>|/asset/<key>]  your estate through time, one scan, one endpoint (signed in)
  GET /algorithms[/<id>]     the algorithm reference and the dated history of internet cryptography
  GET /trust                 which commit runs here, checked against the signed manifest and deploy log
  GET /plain[...]            the same answers as plain HTML: no script, no stylesheet

Every page view above is the same static file (static/instrument.html); the views read the
public API under /api/public. The plain pages are rendered here from the same services, so they
quote the same numbers. All of it is unauthenticated (app._auth_public_path asks
:func:`is_public_path`) and served under :data:`CSP`, which allows nothing but this origin: no
third-party script, style, font, image or connection, and no inline script or style.
"""

from __future__ import annotations

import html
import os
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

#: The policy for every instrument and plain page. Stricter than the app's strict policy: images
#: only from this origin or data: URIs, styles only from files on this origin, fonts the same.
CSP = ("default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; "
       "object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'none'")
#: The plain pages run no script at all.
CSP_PLAIN = CSP.replace("script-src 'self'", "script-src 'none'")

VIEW_PREFIXES = ("/league", "/atlas", "/algorithms", "/trust", "/estate")
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
#: Last labels that are file extensions, not top-level domains: /wp-login.php is a probe, not a site.
#: (.zip and .mov are real TLDs and stay allowed.)
_FILE_SUFFIXES = frozenset("""php php3 php5 phtml html htm shtml xhtml txt xml json js mjs map css svg png jpg jpeg gif ico
    webp avif woff woff2 ttf otf eot env ini cfg conf config yml yaml toml md asp aspx ashx jsp jspx cgi pl py rb sh bat
    cmd exe dll bak old orig swp tmp log sql sqlite db gz tgz bz2 rar 7z tar csv tsv xls xlsx doc docx pdf ps1 lock pem
    key crt cer der p12 pfx jks git svn htaccess htpasswd well-known action do""".split())
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def domain_segment(segment: str) -> Optional[str]:
    """The hostname a single path segment names, or None. Lower-cased, trailing dot dropped."""
    text = str(segment or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(text):
        return None
    if text.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
        return None
    return text


def page_path(static_dir: str) -> str:
    return os.path.join(static_dir, "instrument.html")


_LITERAL_CACHE: Dict[int, Any] = {}


def _app_literal_paths(app: Any) -> set:
    routes = getattr(app, "routes", []) or []
    cached = _LITERAL_CACHE.get(id(app))
    if cached and cached[0] == len(routes):
        return cached[1]
    paths = {getattr(r, "path", "") for r in routes if getattr(r, "path", "") and "{" not in getattr(r, "path", "")}
    _LITERAL_CACHE[id(app)] = (len(routes), paths)
    return paths


def is_public_path(path: str, app: Any = None) -> bool:
    """True for every path this router answers, so the auth gate and the CSP agree with it."""
    p = str(path or "")
    if p == "/":
        return True
    if any(p == pre or p.startswith(pre + "/") for pre in VIEW_PREFIXES + ("/plain",)):
        return True
    segs = [s for s in p.split("/") if s]
    if len(segs) == 1 and domain_segment(segs[0]):
        # A route of the app's own with a dotted name (/cbom.csv, /robots.txt) is never a domain view.
        return app is None or p not in _app_literal_paths(app)
    return False


def csp_for(path: str, app: Any = None) -> Optional[str]:
    p = str(path or "")
    if p == "/plain" or p.startswith("/plain/"):
        return CSP_PLAIN
    if is_public_path(p, app):
        return CSP
    return None


# ── plain pages ──────────────────────────────────────────────────────────────

def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
           f"<title>{_e(title)} - Morrow, plain</title></head><body>"
           "<p><a href=\"/plain\">Morrow, plain version</a> | <a href=\"/plain/league\">Sector averages</a> | "
           "<a href=\"/\">Full version</a></p><hr>"
           f"{body}<hr><p>No script, no stylesheet, no tracking. The same answers as the full version, "
           "from the same server.</p></body></html>")
    return HTMLResponse(doc, status_code=status, headers={"Cache-Control": "no-store"})


def _form(value: str = "") -> str:
    return ("<form method=\"get\" action=\"/plain/go\"><p><label for=\"d\">Domain to check</label><br>"
            f"<input id=\"d\" name=\"d\" type=\"text\" value=\"{_e(value)}\" autocomplete=\"off\" spellcheck=\"false\">"
            " <button type=\"submit\">Check</button></p></form>")


def _plain_result(result: Dict[str, Any], history_rows: List[Dict[str, Any]]) -> str:
    d = result.get("domain")
    kx = result.get("key_exchange") or {}
    tls = result.get("tls") or {}
    cert = result.get("certificate") or {}
    ex = result.get("exposure") or {}
    summaries = result.get("summaries") or {}
    versions = ", ".join(v for v in ("1.3", "1.2", "1.1", "1.0") if (tls.get("versions") or {}).get(v)) or "-"
    out = [f"<h1>{_e(d)}: grade {_e(result.get('grade'))}</h1>",
           f"<p>{_e(summaries.get('executive') or result.get('summary'))}</p>"]
    if ex.get("recorded_traffic_at_risk") and ex.get("decrypt_year_low"):
        out.append(f"<p><strong>Traffic recorded today could be read from about {_e(ex.get('decrypt_year_low'))} "
                   f"to {_e(ex.get('decrypt_year_high'))}.</strong> Source: <a href=\"{_e(ex.get('source_url'))}\">"
                   f"{_e(ex.get('source_url'))}</a></p>")
    else:
        out.append(f"<p>{_e(ex.get('basis'))}</p>")
    out.append("<h2>What was measured</h2><dl>")
    for label, value in (("Key exchange", kx.get("group") or "not observed"),
                         ("Post-quantum", "yes" if kx.get("post_quantum") else "no"),
                         ("Protocol", tls.get("negotiated") or "-"), ("Versions accepted", versions),
                         ("Forward secrecy", "yes" if result.get("forward_secrecy") else "no"),
                         ("Certificate", f"{cert.get('key_type') or '-'} {cert.get('key_bits') or ''}, expires "
                                         f"{str(cert.get('not_after') or '-')[:10]}"),
                         ("Served by", result.get("server_software") or "not disclosed"),
                         ("Checked", f"{result.get('scanned_at')} (rubric {result.get('rubric_version')})")):
        out.append(f"<dt>{_e(label)}</dt><dd>{_e(value)}</dd>")
    out.append("</dl>")
    reasons = result.get("reasons") or []
    if reasons:
        out.append("<h2>Why this grade</h2><ul>" + "".join(f"<li>{_e(r)}</li>" for r in reasons) + "</ul>")
    fixes = result.get("fixes") or []
    out.append("<h2>The fix</h2>")
    if not fixes:
        out.append("<p>Nothing to change.</p>")
    for fix in fixes:
        out.append(f"<h3>{_e(fix.get('title'))}</h3><pre>{_e(fix.get('snippet'))}</pre>"
                   f"<p>{_e(fix.get('notes'))}</p><p>Needs: {_e(fix.get('requires'))}</p>")
    out.append(f"<form method=\"get\" action=\"/plain/{_e(d)}\"><input type=\"hidden\" name=\"fresh\" value=\"1\">"
               "<button type=\"submit\">Re-check now</button></form>")
    if history_rows:
        out.append("<h2>Earlier checks</h2><table><thead><tr><th>Checked</th><th>Grade</th><th>Key exchange</th>"
                   "</tr></thead><tbody>")
        for row in history_rows:
            out.append(f"<tr><td>{_e(row.get('scanned_at'))}</td><td>{_e(row.get('grade'))}</td>"
                       f"<td>{_e(row.get('group') or '-')}</td></tr>")
        out.append("</tbody></table>")
    out.append(f"<p><a href=\"/api/public/grade/{_e(d)}.txt\">As text</a> | "
               f"<a href=\"/api/public/history/{_e(d)}.atom\">Feed of grade changes</a> | "
               f"<a href=\"/{_e(d)}\">Full version</a></p>")
    return "".join(out)


def create_instrument_router(deps: Any) -> APIRouter:
    """deps: static_dir, client_ip(request) -> str."""
    router = APIRouter(include_in_schema=False)
    page = page_path(deps.static_dir)

    def _view() -> FileResponse:
        if not os.path.exists(page):
            raise HTTPException(status_code=404, detail="instrument.html not found")
        return FileResponse(page, media_type="text/html; charset=utf-8",
                            headers={"Cache-Control": "public, max-age=0, must-revalidate"})

    def _ip(request: Request) -> str:
        try:
            return str(deps.client_ip(request) or "")
        except Exception:
            return str(request.client.host if request.client else "")

    @router.api_route("/league", methods=["GET", "HEAD"])
    @router.api_route("/atlas", methods=["GET", "HEAD"])
    @router.api_route("/algorithms", methods=["GET", "HEAD"])
    @router.api_route("/trust", methods=["GET", "HEAD"])
    def instrument_view():
        return _view()

    # Your estate, a scan, an endpoint: the page is static; the data comes from your own signed-in
    # API calls (/scans, /search), so the page itself is public and shows nothing without them.
    @router.api_route("/estate", methods=["GET", "HEAD"])
    @router.api_route("/estate/{rest:path}", methods=["GET", "HEAD"])
    def instrument_estate(rest: str = ""):
        return _view()

    @router.api_route("/algorithms/{algorithm_id}", methods=["GET", "HEAD"])
    def instrument_algorithm(algorithm_id: str):
        if not _ID_RE.match(algorithm_id.lower()):
            raise HTTPException(status_code=404, detail="no such algorithm")
        return _view()

    @router.get("/plain")
    def plain_home():
        from services import public_grade

        try:
            s = public_grade.stats()
            stats = (f"<p>This server has run {s['public_checks_total']:,} checks of {s['domains_checked']:,} domains; "
                     f"in the last 7 days {s['public_checks_7d']:,}, of which {round(s['pq_share_7d'] * 100, 1)}% "
                     "used a post-quantum key exchange.</p>")
        except Exception:
            stats = "<p>The counts are not available right now.</p>"
        body = ("<h1>Is a website safe from future quantum computers?</h1>"
                "<p>Type a domain. Morrow connects to it once over HTTPS and tells you its grade, from which year "
                "recorded traffic could be read, and the exact configuration change that fixes it.</p>"
                + _form() + stats +
                "<p><a href=\"/plain/league\">Sector averages</a></p>")
        return _page("Check a domain", body)

    @router.get("/plain/go")
    def plain_go(d: str = ""):
        host = domain_segment(d.strip().split("://")[-1].split("/")[0])
        if not host:
            return _page("Check a domain", "<p>That is not a domain name. Try something like example.com.</p>"
                         + _form(d), status=400)
        return RedirectResponse(f"/plain/{host}", status_code=303)

    @router.get("/plain/league")
    def plain_league():
        from services import league

        data = league.sector_averages()
        rows = "".join(
            f"<tr><td>{_e(s['name'])}</td><td>{s['graded']}</td>"
            + "".join(f"<td>{_e(s['grades'].get(g, 0))}</td>" for g in "ABCDEF")
            + f"<td>{_e('-' if s['pq_share'] is None else str(round(s['pq_share'] * 100, 1)) + '%')}</td></tr>"
            for s in data.get("sectors") or [] if s.get("graded"))
        table = ("<table><thead><tr><th>Sector</th><th>Graded</th><th>A</th><th>B</th><th>C</th><th>D</th><th>E</th>"
                 "<th>F</th><th>Post-quantum</th></tr></thead><tbody>" + rows + "</tbody></table>")
        body = ("<h1>Sector averages</h1><p>How each sector's well-known sites are spread over the grades. "
                "No site is named or ranked; any single domain can be checked above.</p>"
                + (table if rows else "<p>Nothing graded yet.</p>"))
        from services import pq_ready

        ready = pq_ready.public_list("name")
        body += ("<h2>Post-quantum ready, by choice</h2><p>" + _e(ready["about"]) + "</p>"
                 + ("<ul>" + "".join(f"<li><a href=\"/plain/{_e(e['domain'])}\">{_e(e['domain'])}</a>: {_e(e['sector_name'])}, "
                                     f"grade {_e(e['grade'])}, checked {_e(e['checked_at'][:10])}</li>" for e in ready["entries"])
                    + "</ul>" if ready["entries"] else "<p>No organisation has listed itself yet.</p>"))
        return _page("Sector averages", body)

    @router.get("/plain/{domain}")
    async def plain_domain(request: Request, domain: str, fresh: str = ""):
        from services import public_grade

        host = domain_segment(domain)
        if not host:
            raise HTTPException(status_code=404, detail="not a domain")
        try:
            result = await run_in_threadpool(public_grade.check, host, _ip(request), fresh == "1")
        except public_grade.GradeError as exc:
            return _page(host, f"<h1>{_e(host)}</h1><p>{_e(exc.detail)}</p>" + _form(host),
                         status=exc.status_code)
        rows = await run_in_threadpool(public_grade.history, host, 30)
        return _page(f"{host}: grade {result.get('grade')}", _plain_result(result, rows) + _form())

    # Last: a single dotted segment is a domain view, unless the app has a route of that name.
    @router.api_route("/{domain}", methods=["GET", "HEAD"])
    def instrument_domain(domain: str):
        if not domain_segment(domain):
            raise HTTPException(status_code=404, detail="Not Found")
        return _view()

    return router
