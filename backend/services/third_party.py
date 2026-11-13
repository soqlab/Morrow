"""Who else is exposing you: the outside services a domain depends on, and their key exchange.

A site can switch its own edge to a post-quantum key exchange and still send its visitors' card
numbers to a payment provider, or their passwords to a sign-in provider, over a classical one. A
recording of that traffic is exposed exactly as if the site had not switched. This module finds
those services and asks each one the same question the public grade asks the site itself.

Discovery (``discover``; the parsing is pure and tested without a network)
---------------------------------------------------------------------------
  * the homepage: one ``GET /`` over TLS to the domain's pinned address (and at most
    ``MAX_REDIRECTS`` redirects, each re-validated and re-pinned), at most ``MAX_HTML_BYTES``;
    every ``script``/``link``/``img``/``iframe``/``source``/``form action`` origin in it;
  * DNS: the CNAME chain of the domain and of ``www.``, read for a known CDN or host; the MX hosts;
    and a fixed list of common sign-in and payment subdomains (``login.``, ``checkout.`` ...),
    counted only when their CNAME points at another organisation's name;
  * a name is classified by suffix (``KNOWN``): payment, sign-in, analytics and so on.

What is contacted, and the guard
--------------------------------
Every discovered host goes through the same guard as the public grade
(services/public_grade.resolve_pinned): resolved once, refused if any answer is private, loopback,
link-local, CGNAT, reserved, this server's own address, or wrapped inside IPv6, and then contacted
only on that pinned address with SNI set to the name. The public-check opt-out list is honoured
for every host. Per host: one ClientHello probe (scanner._probe_key_exchange_group, the existing
key-exchange check) and, only when it could not read the group, one ordinary handshake. A host
with a stored public grade from the last hour is not contacted at all.

Bounds: at most ``max_hosts()`` hosts probed (the rest are listed as not checked), ``workers()``
at a time, a per-connection timeout and a whole-run deadline. Results are cached per host and per
domain. Rate limits: per client IP, per target domain, and a global hourly budget, through
services/org_rate_limits.py, like the public grade.

Mail is listed but not graded: it is delivered over SMTP on port 25, which this check never opens.

Settings
--------
``MORROW_EXPOSURE_MAX_HOSTS``      12    hosts probed per domain
``MORROW_EXPOSURE_WORKERS``        4     hosts probed at once
``MORROW_EXPOSURE_TIMEOUT``        4     per-connection timeout, seconds
``MORROW_EXPOSURE_DEADLINE``       30    whole-run deadline, seconds
``MORROW_EXPOSURE_CACHE_SECONDS``  3600  per-domain and per-host cache
``MORROW_EXPOSURE_IP_PER_MINUTE``  6     requests per client IP per minute
``MORROW_EXPOSURE_DOMAIN_PER_HOUR`` 6    uncached runs for one domain per hour
``MORROW_EXPOSURE_GLOBAL_PER_HOUR`` 120  uncached runs per hour, whole service
"""

from __future__ import annotations

import logging
import os
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from services import decrypt_window as _decrypt_window
from services import public_grade as _grade

logger = logging.getLogger(__name__)

PORT = 443
MAX_HTML_BYTES = 512 * 1024
MAX_REDIRECTS = 3
MAX_CANDIDATES = 60
MAX_SAME_SITE_LOOKUPS = 10
CNAME_HOPS = 4
DNS_LIFETIME = 2.5

#: Subdomains where sign-in and payment pages usually live. Counted only when the name is a CNAME
#: to another organisation (a hosted checkout or login), never merely because it exists.
COMMON_SUBDOMAINS: Tuple[Tuple[str, str], ...] = (
    ("login", "auth"), ("auth", "auth"), ("sso", "auth"), ("id", "auth"), ("accounts", "auth"),
    ("account", "auth"), ("checkout", "payment"), ("pay", "payment"), ("payments", "payment"),
    ("billing", "payment"), ("shop", "shop"), ("store", "shop"),
)

#: (name suffix, role, vendor). The first match wins, so exact hosts come before their parent.
KNOWN: Tuple[Tuple[str, str, str], ...] = (
    # payment
    ("stripe.com", "payment", "Stripe"), ("stripe.network", "payment", "Stripe"),
    ("paypal.com", "payment", "PayPal"), ("paypalobjects.com", "payment", "PayPal"),
    ("braintreegateway.com", "payment", "Braintree"), ("braintree-api.com", "payment", "Braintree"),
    ("adyen.com", "payment", "Adyen"), ("adyenpayments.com", "payment", "Adyen"),
    ("checkout.com", "payment", "Checkout.com"), ("squareup.com", "payment", "Square"),
    ("squarecdn.com", "payment", "Square"), ("klarna.com", "payment", "Klarna"),
    ("klarnaservices.com", "payment", "Klarna"), ("razorpay.com", "payment", "Razorpay"),
    ("mollie.com", "payment", "Mollie"), ("worldpay.com", "payment", "Worldpay"),
    ("authorize.net", "payment", "Authorize.net"), ("paddle.com", "payment", "Paddle"),
    ("recurly.com", "payment", "Recurly"), ("chargebee.com", "payment", "Chargebee"),
    ("pay.google.com", "payment", "Google Pay"), ("apple-pay-gateway.apple.com", "payment", "Apple Pay"),
    ("myshopify.com", "shop", "Shopify"), ("shopify.com", "shop", "Shopify"),
    # sign-in
    ("login.microsoftonline.com", "auth", "Microsoft Entra ID"), ("b2clogin.com", "auth", "Azure AD B2C"),
    ("accounts.google.com", "auth", "Google sign-in"), ("appleid.apple.com", "auth", "Sign in with Apple"),
    ("auth0.com", "auth", "Auth0"), ("okta.com", "auth", "Okta"), ("oktacdn.com", "auth", "Okta"),
    ("onelogin.com", "auth", "OneLogin"), ("amazoncognito.com", "auth", "Amazon Cognito"),
    ("pingidentity.com", "auth", "Ping Identity"), ("pingone.com", "auth", "Ping Identity"),
    ("duosecurity.com", "auth", "Duo"), ("clerk.accounts.dev", "auth", "Clerk"), ("clerk.com", "auth", "Clerk"),
    ("stytch.com", "auth", "Stytch"), ("workos.com", "auth", "WorkOS"), ("frontegg.com", "auth", "Frontegg"),
    # bot checks
    ("challenges.cloudflare.com", "captcha", "Cloudflare Turnstile"), ("hcaptcha.com", "captcha", "hCaptcha"),
    ("recaptcha.net", "captcha", "Google reCAPTCHA"),
    # forms and support
    ("hsforms.com", "form", "HubSpot"), ("hsforms.net", "form", "HubSpot"), ("hs-scripts.com", "support", "HubSpot"),
    ("hubspot.com", "support", "HubSpot"), ("list-manage.com", "form", "Mailchimp"),
    ("mailchimp.com", "form", "Mailchimp"), ("typeform.com", "form", "Typeform"),
    ("intercom.io", "support", "Intercom"), ("intercomcdn.com", "support", "Intercom"),
    ("zendesk.com", "support", "Zendesk"), ("zdassets.com", "support", "Zendesk"),
    ("drift.com", "support", "Drift"), ("crisp.chat", "support", "Crisp"), ("tawk.to", "support", "tawk.to"),
    ("livechatinc.com", "support", "LiveChat"), ("calendly.com", "embed", "Calendly"),
    # analytics, tags, errors, ads
    ("googletagmanager.com", "analytics", "Google Tag Manager"), ("google-analytics.com", "analytics", "Google Analytics"),
    ("segment.com", "analytics", "Segment"), ("segment.io", "analytics", "Segment"), ("hotjar.com", "analytics", "Hotjar"),
    ("mixpanel.com", "analytics", "Mixpanel"), ("amplitude.com", "analytics", "Amplitude"),
    ("plausible.io", "analytics", "Plausible"), ("clarity.ms", "analytics", "Microsoft Clarity"),
    ("fullstory.com", "analytics", "FullStory"), ("heap.io", "analytics", "Heap"),
    ("newrelic.com", "analytics", "New Relic"), ("nr-data.net", "analytics", "New Relic"),
    ("sentry.io", "analytics", "Sentry"), ("sentry-cdn.com", "analytics", "Sentry"),
    ("doubleclick.net", "ads", "Google Ads"), ("googlesyndication.com", "ads", "Google Ads"),
    ("googleadservices.com", "ads", "Google Ads"), ("facebook.net", "ads", "Meta"), ("facebook.com", "social", "Meta"),
    ("licdn.com", "social", "LinkedIn"), ("linkedin.com", "social", "LinkedIn"), ("twimg.com", "social", "X"),
    ("twitter.com", "social", "X"),
    # shared script and file hosts (a copy can be served from the site itself)
    ("cdnjs.cloudflare.com", "library", "cdnjs"), ("jsdelivr.net", "library", "jsDelivr"), ("unpkg.com", "library", "unpkg"),
    ("ajax.googleapis.com", "library", "Google Hosted Libraries"), ("code.jquery.com", "library", "jQuery CDN"),
    ("bootstrapcdn.com", "library", "BootstrapCDN"),
    ("fonts.googleapis.com", "fonts", "Google Fonts"), ("fonts.gstatic.com", "fonts", "Google Fonts"),
    ("typekit.net", "fonts", "Adobe Fonts"), ("use.fontawesome.com", "fonts", "Font Awesome"),
    ("kit.fontawesome.com", "fonts", "Font Awesome"),
    ("maps.googleapis.com", "maps", "Google Maps"), ("mapbox.com", "maps", "Mapbox"),
    ("youtube.com", "video", "YouTube"), ("youtube-nocookie.com", "video", "YouTube"), ("ytimg.com", "video", "YouTube"),
    ("vimeo.com", "video", "Vimeo"), ("vimeocdn.com", "video", "Vimeo"), ("wistia.com", "video", "Wistia"),
    # hosting and CDNs (also matched against CNAME targets)
    ("cdn.cloudflare.net", "cdn", "Cloudflare"), ("cloudfront.net", "cdn", "Amazon CloudFront"),
    ("elb.amazonaws.com", "cdn", "AWS load balancer"), ("akamaiedge.net", "cdn", "Akamai"),
    ("edgekey.net", "cdn", "Akamai"), ("edgesuite.net", "cdn", "Akamai"), ("akamai.net", "cdn", "Akamai"),
    ("akamaized.net", "cdn", "Akamai"), ("akamaihd.net", "cdn", "Akamai"), ("fastly.net", "cdn", "Fastly"),
    ("fastlylb.net", "cdn", "Fastly"), ("azureedge.net", "cdn", "Azure CDN"), ("azurefd.net", "cdn", "Azure Front Door"),
    ("trafficmanager.net", "cdn", "Azure Traffic Manager"), ("herokudns.com", "cdn", "Heroku"),
    ("vercel-dns.com", "cdn", "Vercel"), ("netlify.app", "cdn", "Netlify"), ("netlify.com", "cdn", "Netlify"),
    ("github.io", "cdn", "GitHub Pages"), ("b-cdn.net", "cdn", "Bunny CDN"), ("edgecastcdn.net", "cdn", "Edgio"),
    ("googlehosted.com", "cdn", "Google"), ("wixdns.net", "cdn", "Wix"), ("squarespace.com", "cdn", "Squarespace"),
    ("cloudinary.com", "images", "Cloudinary"), ("imgix.net", "images", "imgix"), ("wixstatic.com", "images", "Wix"),
    ("squarespace-cdn.com", "images", "Squarespace"), ("wp.com", "images", "WordPress.com"),
    # mail (MX targets)
    ("google.com", "mail", "Google Workspace"), ("googlemail.com", "mail", "Google Workspace"),
    ("protection.outlook.com", "mail", "Microsoft 365"), ("outlook.com", "mail", "Microsoft 365"),
    ("pphosted.com", "mail", "Proofpoint"), ("mimecast.com", "mail", "Mimecast"),
    ("messagingengine.com", "mail", "Fastmail"), ("zoho.com", "mail", "Zoho Mail"), ("zoho.eu", "mail", "Zoho Mail"),
    ("icloud.com", "mail", "iCloud Mail"), ("amazonaws.com", "cdn", "Amazon Web Services"),
)

#: Two-label public suffixes, so example.co.uk is one organisation, not "co.uk".
_TWO_LABEL_SUFFIXES = frozenset("""co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk com.au net.au org.au edu.au gov.au
    co.nz org.nz co.jp ne.jp or.jp co.kr com.br com.cn com.hk com.sg com.mx com.tr com.ar co.in co.za co.il
    com.tw com.my com.ph com.pl com.ua com.vn co.id""".split())

#: Where a role sits in the worst-first list, after status: the more sensitive the data, the higher.
ROLE_ORDER = {"payment": 0, "auth": 1, "form": 2, "shop": 3, "captcha": 4, "support": 5, "analytics": 6,
              "script": 7, "library": 8, "embed": 9, "video": 10, "maps": 11, "ads": 12, "social": 13,
              "styles": 14, "fonts": 15, "images": 16, "cdn": 17, "mail": 18, "other": 19}
#: How a role reads in a sentence: "your payment provider isn't".
ROLE_LABEL = {"payment": "your payment provider", "auth": "your sign-in provider",
              "form": "the service your forms post to", "shop": "your shop platform",
              "captcha": "your bot check", "support": "your chat or support widget",
              "analytics": "your analytics", "script": "a script your homepage loads",
              "library": "a script library your homepage loads", "embed": "an embedded page",
              "video": "your video host", "maps": "your maps provider", "ads": "your ad network",
              "social": "a social widget", "styles": "a stylesheet host", "fonts": "your font host",
              "images": "your image host", "cdn": "your CDN", "mail": "your mail provider",
              "other": "an outside service"}
#: Worst first. "classical" and "no_tls" are the exposures; the rest say what could not be told.
STATUS_ORDER = {"classical": 0, "no_tls": 1, "unknown": 2, "unreachable": 3, "refused": 4, "pq": 5,
                "not_graded": 6, "not_checked": 7, "skipped": 8}
_EXPOSED = ("classical", "no_tls")
_GRADED = ("classical", "no_tls", "pq", "unknown")

_cache_lock = threading.Lock()
_domain_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_host_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_inflight_lock = threading.Lock()
_inflight: Dict[str, threading.Lock] = {}


# ── Settings ─────────────────────────────────────────────────────────────────


def _num(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(str(os.getenv(name, "") or default).strip())
    except ValueError:
        value = default
    return max(low, min(high, value))


def max_hosts() -> int:
    return int(_num("MORROW_EXPOSURE_MAX_HOSTS", 12, 1, 25))


def workers() -> int:
    return int(_num("MORROW_EXPOSURE_WORKERS", 4, 1, 8))


def connect_timeout() -> float:
    return _num("MORROW_EXPOSURE_TIMEOUT", 4.0, 0.5, 15.0)


def deadline_seconds() -> float:
    return _num("MORROW_EXPOSURE_DEADLINE", 30.0, 2.0, 90.0)


def cache_seconds() -> int:
    return int(_num("MORROW_EXPOSURE_CACHE_SECONDS", 3600, 0, 7 * 24 * 3600))


def ip_per_minute() -> int:
    return int(_num("MORROW_EXPOSURE_IP_PER_MINUTE", 6, 1, 10_000))


def domain_per_hour() -> int:
    return int(_num("MORROW_EXPOSURE_DOMAIN_PER_HOUR", 6, 1, 1_000))


def global_per_hour() -> int:
    return int(_num("MORROW_EXPOSURE_GLOBAL_PER_HOUR", 120, 1, 100_000))


# ── Names ────────────────────────────────────────────────────────────────────


def site_of(host: str) -> str:
    """The organisation-level name of a host: www.shop.example.co.uk -> example.co.uk."""
    labels = [p for p in str(host or "").lower().rstrip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(a: str, b: str) -> bool:
    return bool(a) and site_of(a) == site_of(b)


def classify(host: str) -> Tuple[Optional[str], Optional[str]]:
    """(role, vendor) for a known name, else (None, None)."""
    h = str(host or "").lower().rstrip(".")
    for suffix, role, vendor in KNOWN:
        if h == suffix or h.endswith("." + suffix):
            return role, vendor
    return None, None


def clean_host(value: Any) -> Optional[str]:
    """A bare public hostname from a URL's host part, or None. IP literals are never hosts here."""
    from services import public_check

    raw = str(value or "").strip().lower().rstrip(".")
    if not raw or len(raw) > 253 or not re.match(r"^[a-z0-9.-]+$", raw):
        return None
    try:
        host = public_check.normalize_domain(raw)
    except Exception:
        return None
    return host if "." in host else None


# ── Discovery: the homepage ─────────────────────────────────────────────────

#: tag -> (attributes holding a URL, the role a match gets when the name is not a known service)
_TAG_ATTRS = {
    "script": (("src",), "script"), "iframe": (("src",), "embed"), "frame": (("src",), "embed"),
    "img": (("src", "srcset"), "images"), "source": (("src", "srcset"), "images"),
    "video": (("src", "poster"), "video"), "audio": (("src",), "video"), "embed": (("src",), "embed"),
    "object": (("data",), "embed"), "form": (("action",), "form"), "link": (("href",), "styles"),
}
#: <link rel=...> values that are references to another document, not resources the page loads.
_LINK_IGNORED = frozenset({"canonical", "alternate", "author", "me", "next", "prev", "help", "license",
                           "search", "bookmark", "nofollow", "noreferrer", "noopener", "external", "tag", "shortlink",
                           "pingback", "webmention", "edituri", "wlwmanifest"})


class _Refs(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.refs: List[Tuple[str, str, str]] = []  # (url, default role, how it was found)

    def handle_starttag(self, tag, attrs):
        if len(self.refs) >= 2000:
            return
        tag = tag.lower()
        a = {str(k).lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = urljoin(self.base, a["href"].strip())
            return
        spec = _TAG_ATTRS.get(tag)
        if not spec:
            return
        names, role = spec
        how = tag
        if tag == "link":
            rels = set(a.get("rel", "").lower().split())
            if not rels or rels & _LINK_IGNORED:
                return
            if rels & {"preconnect", "dns-prefetch"}:
                role, how = "script", "link rel=" + sorted(rels & {"preconnect", "dns-prefetch"})[0]
            elif rels & {"modulepreload"} or a.get("as", "").lower() == "script":
                role, how = "script", "link rel=preload"
            elif a.get("as", "").lower() == "font":
                role, how = "fonts", "link rel=preload"
            elif "stylesheet" in rels:
                how = "stylesheet"
            elif rels & {"icon", "apple-touch-icon", "shortcut", "manifest"}:
                role, how = "images", "icon"
        elif tag == "form":
            how = "form action"
        for name in names:
            value = a.get(name, "").strip()
            if not value:
                continue
            if name == "srcset":
                value = value.split(",")[0].strip().split(" ")[0]
            self.refs.append((value, role, how))


def parse_html(html: str, page_url: str) -> List[Dict[str, str]]:
    """Every outside origin the page loads or posts to: [{host, role, via}], first sighting kept.

    Pure. Only http(s) and protocol-relative URLs count; relative paths, data:, javascript: and
    mailto: are this page or nothing. Hosts are bare public names (no IP literals, no ports other
    than 443 noted as such).
    """
    parser = _Refs(page_url)
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    seen: Dict[str, Dict[str, str]] = {}
    for raw, role, how in parser.refs:
        if raw.lower().startswith(("data:", "javascript:", "mailto:", "tel:", "blob:", "about:", "#")):
            continue
        try:
            url = urlsplit(urljoin(parser.base, raw))
        except ValueError:
            continue
        if url.scheme not in ("http", "https"):
            continue
        host = clean_host(url.hostname or "")
        if not host:
            continue
        if host not in seen:
            seen[host] = {"host": host, "role": role, "via": how + (" (plain http)" if url.scheme == "http" else "")}
        elif ROLE_ORDER.get(role, 99) < ROLE_ORDER.get(seen[host]["role"], 99):
            seen[host]["role"] = role
            seen[host]["via"] = how
    return list(seen.values())


def _http_get(address: str, host: str, path: str, timeout: float, max_bytes: int = MAX_HTML_BYTES,
              deadline: Optional[float] = None) -> Dict[str, Any]:
    """One ``GET path`` over TLS to the pinned address, HTTP/1.0 so the body is never chunked."""
    ctx = _grade._context(verify=False, alpn=["http/1.1"])
    request = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {_grade.USER_AGENT}\r\n"
               "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.1\r\nAccept-Encoding: identity\r\n"
               "Connection: close\r\n\r\n").encode("ascii")
    end = min(deadline or float("inf"), time.monotonic() + 2 * timeout)
    data = b""
    sock = socket.create_connection((address, PORT), timeout=timeout)
    with sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(request)
            while len(data) < max_bytes and time.monotonic() < end:
                try:
                    chunk = ssock.recv(min(65536, max_bytes - len(data)))
                except (socket.timeout, ssl.SSLError):
                    break
                if not chunk:
                    break
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers.setdefault(name.strip().lower(), value.strip()[:2000])
    return {"status": int(match.group(1)) if match else 0, "headers": headers, "body": body}


def fetch_homepage(host: str, deadline: Optional[float] = None) -> Dict[str, Any]:
    """The homepage HTML of ``host``: {final_host, url, html, notes}. Never raises.

    Each hop (the first request and every redirect) is validated and pinned through
    public_grade.resolve_pinned, so a redirect to an internal name is refused, not followed.
    """
    notes: List[str] = []
    current, path = host, "/"
    for hop in range(MAX_REDIRECTS + 1):
        if deadline and time.monotonic() > deadline:
            notes.append("the homepage was not read: out of time")
            break
        try:
            address = _grade.resolve_pinned(current)
        except _grade.GradeError as exc:
            notes.append(f"the homepage was not read: {exc.detail}")
            break
        try:
            got = _http_get(address, current, path, connect_timeout(), deadline=deadline)
        except Exception as exc:
            notes.append(f"the homepage of {current} could not be read ({type(exc).__name__})")
            break
        status = got["status"]
        if status in (301, 302, 303, 307, 308) and got["headers"].get("location"):
            target = urlsplit(urljoin(f"https://{current}{path}", got["headers"]["location"]))
            nxt = clean_host(target.hostname or "")
            if target.scheme != "https" or not nxt or (target.port not in (None, PORT)):
                notes.append("the homepage redirects somewhere this check does not follow")
                break
            current, path = nxt, (target.path or "/") + (("?" + target.query) if target.query else "")
            if hop == MAX_REDIRECTS:
                notes.append(f"stopped after {MAX_REDIRECTS} redirects")
            continue
        ctype = got["headers"].get("content-type", "").lower()
        if status != 200 or ("html" not in ctype and ctype):
            notes.append(f"the homepage answered HTTP {status or '?'} {ctype or ''}".strip())
            break
        charset = (re.search(r"charset=([\w-]+)", ctype) or [None, "utf-8"])[1]
        try:
            text = got["body"].decode(charset, "replace")
        except LookupError:
            text = got["body"].decode("utf-8", "replace")
        if len(got["body"]) >= MAX_HTML_BYTES:
            notes.append(f"only the first {MAX_HTML_BYTES // 1024} KB of the homepage were read")
        return {"final_host": current, "url": f"https://{current}{path}", "html": text, "notes": notes}
    return {"final_host": current, "url": f"https://{current}{path}", "html": "", "notes": notes}


# ── Discovery: DNS ───────────────────────────────────────────────────────────


def _dns(name: str, rtype: str) -> List[str]:
    """Answers for one DNS question, as bare names; [] on any failure. Tests replace this."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_LIFETIME
        answers = resolver.resolve(name, rtype)
    except Exception:
        return []
    out = []
    for record in answers:
        if rtype == "MX":
            out.append(str(record.exchange).rstrip(".").lower())
        else:
            out.append(str(getattr(record, "target", record)).rstrip(".").lower())
    return out


def cname_chain(name: str) -> List[str]:
    chain, current = [], name
    for _ in range(CNAME_HOPS):
        nxt = _dns(current, "CNAME")
        if not nxt or nxt[0] in chain or nxt[0] == name:
            break
        chain.append(nxt[0])
        current = nxt[0]
    return chain


def dns_services(host: str, same_site_hosts: Iterable[Tuple[str, str]] = ()) -> List[Dict[str, Any]]:
    """Services seen in DNS: the CDN behind the domain, its mail, and hosted sign-in / checkout names."""
    found: List[Dict[str, Any]] = []
    apex_names = [host] + ([] if host.startswith("www.") else ["www." + host])
    candidates: List[Tuple[str, str, str]] = [(n, "edge", "") for n in apex_names]
    for prefix, role in COMMON_SUBDOMAINS:
        candidates.append((f"{prefix}.{host}", "common", role))
    for name, page_role in list(same_site_hosts)[:MAX_SAME_SITE_LOOKUPS]:
        if name not in apex_names and not any(c[0] == name for c in candidates):
            candidates.append((name, "page", page_role))

    def look(item: Tuple[str, str, str]) -> Tuple[Tuple[str, str, str], List[str]]:
        return item, cname_chain(item[0])

    with ThreadPoolExecutor(max_workers=8) as pool:
        chains = list(pool.map(look, candidates))
    mx = _dns(host, "MX")
    for (name, kind, hint), chain in chains:
        off_site = [c for c in chain if not same_site(c, host)]
        if not off_site:
            continue
        target = off_site[-1]
        role, vendor = None, None
        for c in reversed(chain):
            role, vendor = classify(c)
            if role:
                break
        if kind == "edge":
            # The domain itself is the edge its own grade measured; www. may be a different edge.
            found.append({"host": name, "role": "cdn", "vendor": vendor or site_of(target),
                          "via": "CNAME " + " > ".join(chain), "same_edge": name == host})
        else:
            # A name of the site's own that is really another company's server: probed under
            # the site's name (SNI), since that is the name visitors' browsers use.
            found.append({"host": name, "role": hint or (role if role not in (None, "cdn") else "other"),
                          "vendor": vendor or site_of(target), "via": "CNAME " + " > ".join(chain),
                          "hosted_name": True})
    # One row per mail provider, not per MX host: five Google MX names are one dependency.
    by_vendor: Dict[str, Dict[str, Any]] = {}
    for exchange in sorted(set(mx))[:10]:
        host_name = clean_host(exchange)
        if not host_name:
            continue
        role, vendor = classify(host_name)
        vendor = vendor if role == "mail" else site_of(host_name)
        if vendor in by_vendor:
            by_vendor[vendor]["mx_hosts"].append(host_name)
            continue
        by_vendor[vendor] = {"host": host_name, "role": "mail", "vendor": vendor, "mx_hosts": [host_name],
                             "self_hosted_mail": same_site(host_name, host)}
    for item in by_vendor.values():
        n = len(item["mx_hosts"])
        item["via"] = "MX" + (f" ({n} hosts)" if n > 1 else "")
        found.append(item)
    return found


def discover(host: str, html: str = "", page_url: str = "", same_site_dns: bool = True) -> List[Dict[str, Any]]:
    """Every outside service of ``host``: from the homepage HTML and from DNS, merged by host."""
    page = parse_html(html, page_url or f"https://{host}/") if html else []
    own_hosts = [(r["host"], r["role"]) for r in page if same_site(r["host"], host) and r["host"] != host]
    entries: Dict[str, Dict[str, Any]] = {}
    for ref in page:
        h = ref["host"]
        if same_site(h, host):
            continue
        role, vendor = classify(h)
        entries[h] = {"host": h, "role": role if role and role not in ("cdn", "mail") else ref["role"],
                      "vendor": vendor or site_of(h), "via": ref["via"] + " on the homepage"}
        if len(entries) >= MAX_CANDIDATES:
            break
    for item in dns_services(host, own_hosts if same_site_dns else ()):
        existing = entries.get(item["host"])
        if existing:
            existing["via"] += "; " + item["via"]
            continue
        entries[item["host"]] = item
    return list(entries.values())


# ── Grading each service ─────────────────────────────────────────────────────


def _cached_host(host: str) -> Optional[Dict[str, Any]]:
    ttl = cache_seconds()
    with _cache_lock:
        hit = _host_cache.get(host)
    if hit and ttl and time.monotonic() - hit[0] < ttl:
        return dict(hit[1])
    return None


def _store_host(host: str, value: Dict[str, Any]) -> None:
    with _cache_lock:
        if len(_host_cache) > 2000:
            _host_cache.clear()
        _host_cache[host] = (time.monotonic(), dict(value))


def probe_host(host: str, deadline: Optional[float] = None) -> Dict[str, Any]:
    """The key exchange one outside host negotiates: {status, key_exchange, post_quantum, ...}.

    ``status``: pq, classical, no_tls, unknown, unreachable, refused (the SSRF guard said no) or
    skipped (opted out, or out of time). Never raises, never contacts a non-public address.
    """
    import scanner
    from services import public_check

    cached = _cached_host(host)
    if cached is not None:
        return cached
    out: Dict[str, Any] = {"status": "unknown", "key_exchange": None, "post_quantum": False, "tls_version": None,
                           "detail": "", "source": "probe"}
    if public_check.opted_out(host):
        out.update(status="skipped", detail=f"{host} has asked not to be checked by this service.")
        return out
    try:
        stored = _grade.latest(host, _grade.cache_seconds())
    except Exception:
        stored = None
    if stored:
        kx = stored.get("key_exchange") or {}
        out.update(status="pq" if kx.get("post_quantum") else "classical", key_exchange=kx.get("group") or None,
                   post_quantum=bool(kx.get("post_quantum")), tls_version=(stored.get("tls") or {}).get("negotiated"),
                   source="stored public grade", grade=stored.get("grade"))
        _store_host(host, out)
        return out
    if deadline and time.monotonic() > deadline - 1:
        out.update(status="skipped", detail="not checked: the run ran out of time")
        return out
    try:
        address = _grade.resolve_pinned(host)
    except _grade.GradeError as exc:
        out.update(status="refused" if exc.error == "refused_target" else "unreachable", detail=exc.detail)
        _store_host(host, out)
        return out
    timeout = connect_timeout()
    if deadline:
        timeout = max(0.5, min(timeout, deadline - time.monotonic()))
    kx = scanner._probe_key_exchange_group(host, PORT, timeout=timeout, address=address)
    if kx.get("key_exchange_observed"):
        family = str(kx.get("key_exchange_family") or "")
        pq = family in _decrypt_window.PQ_FAMILIES
        out.update(status="pq" if pq else "classical", key_exchange=str(kx.get("key_exchange") or "") or None,
                   post_quantum=pq, tls_version="TLSv1.3")
        _store_host(host, out)
        return out
    # The group could not be read (a TLS 1.2-only server, or a refusal of the probe's hello):
    # one ordinary handshake tells TLS 1.2 (classical by definition) from no TLS at all.
    try:
        got = _grade._handshake(address, host, _grade._context(verify=False, low="1.0", ciphers=_grade._LEGACY_CIPHERS), timeout)
        version = got.get("version") or ""
        out["tls_version"] = version or None
        if version and version != "TLSv1.3":
            out.update(status="classical", detail=f"{version} only: no post-quantum key exchange exists below TLS 1.3")
        else:
            out.update(status="unknown", detail=str(kx.get("key_exchange_unobservable_reason") or "")[:200])
    except _grade._Unreachable:
        out.update(status="unreachable", detail=f"no connection on port {PORT} in time")
    except (ssl.SSLError, OSError) as exc:
        out.update(status="no_tls", detail=f"no TLS handshake completed: {type(exc).__name__}")
    _store_host(host, out)
    return out


def _fix(entry: Dict[str, Any]) -> str:
    host, vendor, role, status = entry["host"], entry.get("vendor") or entry["host"], entry["role"], entry["status"]
    if status == "pq":
        return "Nothing to ask for."
    if status == "refused":
        return "Not contacted: it resolves to an address that is not on the public internet. A public page should not load from it."
    if status == "skipped":
        return entry.get("detail") or "Not checked."
    if status == "not_checked":
        return f"Not checked: over this check's limit of {max_hosts()} hosts."
    if status == "unreachable":
        return "No answer on port 443 in time. Re-check later."
    if status == "not_graded":
        if entry.get("self_hosted_mail"):
            return "Your own mail server: mail travels over SMTP on port 25, which this check does not open."
        return f"Mail travels over SMTP on port 25, which this check does not open. Ask {vendor} about post-quantum TLS for mail."
    if entry.get("same_edge"):
        return "This is the edge your own grade measured: the fix above applies here too."
    if entry.get("hosted_name"):
        return f"{host} is your name, served by {vendor}: turn on post-quantum key exchange in its settings, or ask {vendor} to."
    if role in ("library", "fonts"):
        return f"Serve the file from your own site, which you can fix yourself, instead of from {host}."
    if vendor and vendor != site_of(host):
        return f"Ask {vendor} when {host} will offer X25519MLKEM768, or switch to an endpoint of theirs that does."
    return f"Ask whoever runs {host} to turn on X25519MLKEM768, or stop loading it."


def rank(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(entries, key=lambda e: (STATUS_ORDER.get(e["status"], 9), ROLE_ORDER.get(e["role"], 99), e["host"]))


def _pick_for_probing(entries: List[Dict[str, Any]], cap: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    gradable = [e for e in entries if e["role"] != "mail" and not e.get("same_edge")]
    gradable.sort(key=lambda e: (ROLE_ORDER.get(e["role"], 99), e["host"]))
    return gradable[:cap], gradable[cap:]


def summaries(domain: str, own_pq: Optional[bool], services: List[Dict[str, Any]]) -> Dict[str, str]:
    """The answer, in three depths. ``services`` is ranked worst first."""
    exposed = [s for s in services if s["status"] in _EXPOSED]
    graded = [s for s in services if s["status"] in _GRADED]
    first = exposed[0] if exposed else None
    more = len(exposed) - 1
    tail = f" and {more} more" if more > 0 else ""
    if not services:
        line = f"{domain}'s homepage loads nothing from outside services that Morrow could find."
        return {"plain": line, "standard": line, "expert": line + " (homepage HTML, CNAME, MX and common sign-in/checkout names)."}
    if first:
        label = ROLE_LABEL.get(first["role"], "an outside service")
        who = f"{label} isn't ({first['host']}){tail}"
        if own_pq is None:
            plain = f"{label[0].upper() + label[1:]} isn't ready ({first['host']}){tail}."
            standard = (f"{len(exposed)} of {len(graded)} outside services checked use a classical key exchange, "
                        f"worst first {label} ({first['host']}).")
        elif own_pq:
            plain = f"You're ready, but {who}."
            standard = (f"Your own connection uses a post-quantum key exchange, but {who}: "
                        f"{len(exposed)} of {len(graded)} outside services checked can be recorded today and read later.")
        else:
            plain = f"You're not ready yet, and neither is {label} ({first['host']}){tail}."
            standard = (f"Neither your own connection nor {label} ({first['host']}) uses a post-quantum key exchange; "
                        f"{len(exposed)} of {len(graded)} outside services checked are classical.")
        expert = (f"{len(exposed)}/{len(graded)} graded third-party hosts negotiate classical key exchange; worst: "
                  f"{first['host']} ({first['role']}, {first.get('key_exchange') or first.get('tls_version') or first['status']}).")
        return {"plain": plain, "standard": standard, "expert": expert}
    if not graded:
        line = f"Morrow found {len(services)} outside services but could grade none of them."
        return {"plain": line, "standard": line, "expert": line}
    if own_pq:
        plain = f"You're ready, and so are all {len(graded)} outside services Morrow could check."
    elif own_pq is None:
        plain = f"All {len(graded)} outside services Morrow could check use a post-quantum key exchange."
    else:
        plain = f"The {len(graded)} outside services Morrow could check are ready; your own connection is the one left to fix."
    return {"plain": plain, "standard": plain,
            "expert": plain + " Every graded host negotiated an ML-KEM hybrid group."}


# ── The guarded run, as the API calls it ─────────────────────────────────────


def _domain_lock(domain: str) -> threading.Lock:
    with _inflight_lock:
        if len(_inflight) > 1024:
            for key in [k for k, v in _inflight.items() if not v.locked()]:
                _inflight.pop(key, None)
        return _inflight.setdefault(domain, threading.Lock())


def _cached_domain(host: str) -> Optional[Dict[str, Any]]:
    ttl = cache_seconds()
    with _cache_lock:
        hit = _domain_cache.get(host)
    if hit and ttl and time.monotonic() - hit[0] < ttl:
        out = dict(hit[1])
        out["cached"] = True
        return out
    return None


def clear_cache() -> None:
    with _cache_lock:
        _domain_cache.clear()
        _host_cache.clear()


def _own_grade(host: str, client_ip: str) -> Dict[str, Any]:
    cached = _grade.latest(host, _grade.cache_seconds())
    if cached is not None:
        return cached
    return _grade.check(host, client_ip, charge=False)


def exposure(domain: Any, client_ip: str = "", fresh: bool = False) -> Dict[str, Any]:
    """Discover and grade the outside services of one public domain. Raises public_grade.GradeError."""
    from services import public_check

    if not _grade.enabled():
        raise _grade.GradeError(503, "disabled", "The public grade is switched off on this server.")
    host = _grade.normalize(domain)
    covered = public_check.opted_out(host)
    if covered:
        raise _grade.GradeError(403, "refused_optout", f"{covered} has asked not to be checked by this service.")
    ip_hash = public_check.hash_ip(client_ip)
    _grade._limit("public_exposure_ip", ip_hash, ip_per_minute(), 60.0,
                  f"More than {ip_per_minute()} outside-service checks a minute from your address. Wait a moment.")
    if not fresh:
        cached = _cached_domain(host)
        if cached is not None:
            return cached
    with _domain_lock(host):
        if not fresh:
            cached = _cached_domain(host)
            if cached is not None:
                return cached
        _grade._limit("public_exposure_domain", host, domain_per_hour(), 3600.0,
                      f"The outside services of {host} have been checked {domain_per_hour()} times this hour.")
        _grade._limit("public_exposure_global", "all", global_per_hour(), 3600.0,
                      "The outside-service check is at its hourly limit for everyone. Try again shortly.")
        own = _own_grade(host, client_ip)
        started = time.monotonic()
        result = run(host, own)
        public_check.log_check(host, ip_hash, "exposure_ok",
                               f"{len(result['services'])} services, {result['probed']} probed",
                               int((time.monotonic() - started) * 1000))
        with _cache_lock:
            if len(_domain_cache) > 500:
                _domain_cache.clear()
            _domain_cache[host] = (time.monotonic(), dict(result))
        return result


def run(host: str, own: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Discovery plus bounded, guarded probing for an already-validated host. No rate limits here."""
    end = time.monotonic() + deadline_seconds()
    page = fetch_homepage(host, deadline=end)
    entries = discover(host, page["html"], page["url"])
    own = own or {}
    own_kx = own.get("key_exchange") or {}
    own_pq = bool(own_kx.get("post_quantum")) if own else None
    cap = max_hosts()
    to_probe, over = _pick_for_probing(entries, cap)
    results: Dict[str, Dict[str, Any]] = {}
    if to_probe:
        pool = ThreadPoolExecutor(max_workers=workers())
        futures = {pool.submit(probe_host, e["host"], end): e["host"] for e in to_probe}
        done, pending = wait(list(futures), timeout=max(0.1, end - time.monotonic()))
        for f in done:
            try:
                results[futures[f]] = f.result()
            except Exception as exc:  # a probe never raises; this is belt and braces
                results[futures[f]] = {"status": "unknown", "detail": type(exc).__name__}
        for f in pending:
            f.cancel()
            results[futures[f]] = {"status": "skipped", "detail": "not checked: the run ran out of time"}
        pool.shutdown(wait=False, cancel_futures=True)
    services: List[Dict[str, Any]] = []
    for e in entries:
        item = dict(e)
        if e["host"] in results:
            item.update(results[e["host"]])
        elif e.get("same_edge"):
            item.update(status="pq" if own_pq else "classical", key_exchange=own_kx.get("group") or None,
                        post_quantum=bool(own_pq), source="your own grade")
        elif e["role"] == "mail":
            item.update(status="not_graded", key_exchange=None, post_quantum=False)
        else:
            item.update(status="not_checked", key_exchange=None, post_quantum=False)
        item["readable_from"] = _decrypt_window.DECRYPT_YEAR_LOW if item["status"] in _EXPOSED else None
        item["fix"] = _fix(item)
        services.append(item)
    services = rank(services)
    exposed = [s for s in services if s["status"] in _EXPOSED]
    return {
        "domain": host,
        "checked_at": _grade.iso(_grade.now_utc()),
        "cached": False,
        "homepage": {"url": page["url"], "read": bool(page["html"]), "notes": page["notes"]},
        "own": {"grade": own.get("grade"), "post_quantum": own_pq, "key_exchange": own_kx.get("group") or None},
        "services": services,
        "counts": {"found": len(services), "probed": len(to_probe), "exposed": len(exposed),
                   "graded": len([s for s in services if s["status"] in _GRADED]), "over_cap": len(over)},
        "probed": len(to_probe),
        "limits": {"max_hosts": cap, "timeout_seconds": connect_timeout(), "deadline_seconds": deadline_seconds()},
        "summaries": summaries(host, own_pq, services),
        "basis": _decrypt_window.EXPOSURE_BASIS,
        "source_url": _decrypt_window.EXPOSURE_SOURCE_URL,
    }
