"""The header and footer every public Morrow page shares, written once.

The instrument views (static/instrument.html), the record and proof pages rendered on the server
(services/registry_page.py, services/make_safe_page.py), the documents (/legal, /abuse, the
policies) and the 404 page all wear the same frame as the front page: the MORROW wordmark, one way
to check a domain, a light/dark switch, and one footer with the same links in the same order,
Sign in among them. The static documents carry a copy of these strings; test_site_feel.py checks
that every copy is byte-for-byte this one, so the frame cannot drift page by page.

Everything here is markup only: no inline script, no inline style, so it fits the strictest CSP any
of those pages is served with. The switch is hidden until static/feel.js shows it (without
JavaScript it could not work, and the page follows the device's own setting anyway).
"""

from __future__ import annotations

#: Stylesheets and the one script, in the order every server-rendered page loads them.
#: feel.js is not deferred: it sets the visitor's chosen theme before the first paint.
ASSET_VERSION = "20261119-one"
STYLES = (
    f"/ui/instrument.css?v={ASSET_VERSION}",
    f"/ui/feel.css?v={ASSET_VERSION}",
)
SCRIPT = f"/ui/feel.js?v={ASSET_VERSION}"

THEME_TOGGLE = ('<button type="button" class="i-theme" data-theme-toggle hidden>'
                '<span class="i-theme-ic" aria-hidden="true"></span><span class="i-theme-t">Theme</span></button>')

#: The header of a page that is not the instrument: the wordmark, the one input's address, the switch.
HEADER = (
    '<header class="i-top">\n'
    '  <div class="i-top-in">\n'
    '    <a class="i-mark" href="/">MORROW</a>\n'
    '    <div class="i-top-right">\n'
    '      <a class="i-cmd-btn i-cmd-link" href="/"><span aria-hidden="true">&rsaquo;</span>'
    '<span class="t">Check a domain</span></a>\n'
    f"      {THEME_TOGGLE}\n"
    "    </div>\n"
    "  </div>\n"
    "</header>\n"
)

#: The footer's links, the same everywhere (the instrument's footer lists exactly these).
FOOTER_LINKS = (
    ("/plain", "Plain version"),
    ("/trust", "No tracking: checked live"),
    ("/legal", "Legal &amp; trust"),
    ("/abuse", "Opt a domain out"),
    ("/about-scanner", "What connects to your server"),
    ("/watching", "Watching"),
    ("/support", "Support"),
    ("/ui/", "Sign in"),
)

FOOTER_LINKS_HTML = "".join(f'    <a href="{href}">{label}</a>\n' for href, label in FOOTER_LINKS)

#: The footer of a page that is not the instrument. The build line names the running commit once
#: static/feel.js has read /api/public/build; without JavaScript it is a link to where that is shown.
FOOTER = (
    '<footer class="i-foot">\n'
    '  <div class="i-foot-in">\n'
    '    <span id="i-build" data-build><a href="/trust">Which commit this server runs</a></span>\n'
    + FOOTER_LINKS_HTML +
    "  </div>\n"
    "</footer>\n"
)


def head_assets() -> str:
    """The <link> and <script> tags for a server-rendered page's <head>."""
    return "".join(f'<link rel="stylesheet" href="{href}">\n' for href in STYLES) + f'<script src="{SCRIPT}"></script>\n'
