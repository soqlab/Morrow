"""Make it safe: from "this host is not quantum-safe" to the fix, the watch and the proof.

Three parts, each built on what Morrow already has:

1. **The fix.** ``detect`` names the stack that terminates TLS for a host -- a CDN, a cloud load
   balancer or a server -- from what the public grade already read (the ``Server`` header and the
   fingerprinting headers kept in ``edge_headers``, the certificate issuer) and from public DNS (the
   CNAME chain and whether the address sits in a CDN's published ranges). ``recipe`` returns the
   change for that stack from ``data/make_safe_recipes.json``, where every snippet and version claim
   carries the vendor URL it was checked against and the date. A stack that cannot be named gets
   no invented setting: the "unknown" recipe says so and gives the honest next step.

2. **The watch.** After the change, the page asks for a re-check. ``recheck`` runs an ordinary
   fresh grade (services/public_grade.check: the SSRF guard, the opt-out list, the per-IP,
   per-domain and global budgets, the honest scanner User-Agent) and spaces the re-checks out per
   domain with a backoff (``BACKOFF_SECONDS``), so no page left open can turn into a probe loop.
   A request before the next slot is answered 429 with Retry-After, without contacting anything.

3. **The proof.** Once a check sees post-quantum key exchange, ``proof_envelope`` issues a signed
   "quantum-safe since <date>" statement with the deployment's proof keys (services/proof_signing:
   Ed25519 and ML-DSA-65, published at /.well-known/morrow-proof-keys.json). It is derived from the
   stored grade history, never from a request, so it cannot claim more than was observed: when a
   later check sees a classical handshake, the statement becomes "no longer quantum-safe" with the
   date it changed. When the domain is claimed by DNS (services/watch), the proof says so and since
   when -- never by whom, the same rule as every other public page.

Tables (no organisation column: nothing here belongs to a tenant): ``make_safe_watches`` (one row
per domain: the re-check session) and ``make_safe_proofs`` (the last signed statement per domain,
reused until the history changes).
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)

RECIPES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data",
                            "make_safe_recipes.json")
PROOF_FORMAT = "morrow.quantum-safe-proof/v1"
ENVELOPE_FORMAT = "morrow.quantum-safe-proof-envelope/v1"
#: Prefixed to every signed statement (services/proof_signing.sign), so a quantum-safe proof's
#: signature can never be replayed as a migration proof's, or the reverse.
PROOF_CONTEXT = b"morrow.quantum-safe-proof.v1\n"

#: Seconds before the next re-check of the same domain, by attempt. Doubles to fifteen minutes.
BACKOFF_SECONDS = (30, 60, 120, 240, 480, 900)
#: After this many re-checks in one session the page stops asking by itself; a person can still ask.
MAX_AUTO_ATTEMPTS = 10
#: A session older than this starts over when someone says they made the change again.
SESSION_SECONDS = 2 * 3600
#: Detection reads DNS; one answer per domain is reused for this long.
DETECT_CACHE_SECONDS = 600

STATUS_WAITING = "waiting"
STATUS_LIVE = "live"
STATUS_ERROR = "error"

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()
_recipes_cache: Dict[str, Any] = {}
_detect_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_detect_lock = threading.Lock()


class MakeSafeError(Exception):
    def __init__(self, status_code: int, error: str, detail: str, retry_after: Optional[float] = None,
                 state: Optional[Dict[str, Any]] = None):
        super().__init__(detail)
        self.status_code = status_code
        self.error = error
        self.detail = detail
        self.retry_after = retry_after
        self.state = state

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"error": self.error, "detail": self.detail}
        if self.retry_after:
            out["retry_after"] = int(max(1, self.retry_after))
        if self.state is not None:
            out["watch"] = self.state
        return out


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        out = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


# ── Recipes (data/make_safe_recipes.json) ───────────────────────────────────


def recipes() -> Dict[str, Any]:
    path = RECIPES_PATH
    mtime = os.path.getmtime(path)
    cached = _recipes_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    _recipes_cache[path] = (mtime, data)
    return data


def stack_ids() -> List[str]:
    return [k for k in recipes()["recipes"] if k != "unknown"]


def recipe(stack: str) -> Dict[str, Any]:
    """The recipe for a stack id, with its id; the honest "unknown" one for anything else."""
    table = recipes()["recipes"]
    key = stack if stack in table else "unknown"
    out = copy.deepcopy(table[key])
    out["id"] = key
    out["checked_on"] = recipes().get("checked_on")
    return out


def stack_menu() -> List[Dict[str, str]]:
    """Every stack a person can pick when detection is wrong or missing."""
    table = recipes()["recipes"]
    return [{"id": k, "name": table[k]["name"], "kind": table[k]["kind"]} for k in stack_ids()]


# ── Detection ────────────────────────────────────────────────────────────────

#: Published edge ranges, embedded because a lookup per check would be a dependency on the vendor
#: being up. Cloudflare: https://www.cloudflare.com/ips-v4 and /ips-v6; Fastly:
#: https://api.fastly.com/public-ip-list. Both fetched 2026-11-15.
IP_RANGES_CHECKED = "2026-11-15"
IP_RANGES: Dict[str, Tuple[str, ...]] = {
    "cloudflare": (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
    ),
    "fastly": (
        "23.235.32.0/20", "43.249.72.0/22", "90.98.0.0/17", "90.98.128.0/18", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20",
        "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16", "2a04:4e40::/32", "2a04:4e42::/31", "2a04:4e44::/32",
    ),
}
_NETWORKS = {k: tuple(ipaddress.ip_network(n) for n in v) for k, v in IP_RANGES.items()}

#: CNAME suffixes that name the edge a host points at.
CNAME_SUFFIXES: Tuple[Tuple[str, str], ...] = (
    (".cdn.cloudflare.net", "cloudflare"),
    (".cloudfront.net", "cloudfront"),
    (".elb.amazonaws.com", "aws_elb"),
    (".execute-api.amazonaws.com", "aws_apigateway"),
    (".azurefd.net", "azure_front_door"),
    (".t-msedge.net", "azure_front_door"),
    (".cloudapp.azure.com", "azure_app_gateway"),
    (".fastly.net", "fastly"),
    (".fastlylb.net", "fastly"),
    (".edgekey.net", "akamai"),
    (".edgesuite.net", "akamai"),
    (".akamaiedge.net", "akamai"),
    (".akamaized.net", "akamai"),
)

#: Points per signal. A header, a CNAME or a published range each name the edge outright; a
#: certificate issuer only narrows it down.
STRONG, WEAK = 3, 1
_EDGE_KINDS = ("cdn", "cloud_lb")


def _kind(stack: str) -> str:
    table = recipes()["recipes"]
    return str((table.get(stack) or {}).get("kind") or "unknown")


def from_headers(server: Optional[str], headers: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Signals in the response headers the grade kept. Pure."""
    s = str(server or "").lower()
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    via = h.get("via", "").lower()
    out: List[Dict[str, Any]] = []

    def hit(stack: str, detail: str, points: int = STRONG) -> None:
        out.append({"stack": stack, "signal": "header", "detail": detail, "points": points})

    if "cloudflare" in s or "cf-ray" in h:
        hit("cloudflare", "Server: cloudflare" if "cloudflare" in s else "a CF-Ray response header")
    if "cloudfront" in s or "x-amz-cf-id" in h or "x-amz-cf-pop" in h or "cloudfront" in via:
        hit("cloudfront", "CloudFront response headers (X-Amz-Cf-Id / Via)")
    if s.startswith("awselb"):
        hit("aws_elb", f"Server: {server}")
    if "x-amz-apigw-id" in h:
        hit("aws_apigateway", "an X-Amz-Apigw-Id response header")
    if "x-azure-ref" in h:
        hit("azure_front_door", "an X-Azure-Ref response header")
    if "microsoft-azure-application-gateway" in s:
        hit("azure_app_gateway", f"Server: {server}")
    if "x-fastly-request-id" in h or (h.get("x-served-by", "").lower().startswith("cache-") and "varnish" in via):
        hit("fastly", "Fastly response headers (X-Served-By / Via: varnish)")
    if "akamaighost" in s or "akamainetstorage" in s or "x-akamai-transformed" in h or "akamai-grn" in h:
        hit("akamai", "Akamai response headers")
    if "google" in via or s in ("gws", "gfe", "google frontend", "esf"):
        # Google's front end also serves Cloud Run, App Engine and Firebase without a load balancer.
        hit("google_lb", f"Google front-end headers ({'Via: ' + h.get('via', '') if 'google' in via else 'Server: ' + str(server)})",
            STRONG - 1)
    if any(tok in s for tok in ("nginx", "openresty", "tengine")):
        hit("nginx", f"Server: {server}")
    if "apache" in s:
        hit("apache", f"Server: {server}")
    if "caddy" in s:
        hit("caddy", f"Server: {server}")
    if "haproxy" in s:
        hit("haproxy", f"Server: {server}")
    if "traefik" in s:
        hit("traefik", f"Server: {server}")
    if "microsoft-iis" in s or "microsoft-httpapi" in s:
        hit("iis", f"Server: {server}")
    return out


def from_cname(chain: Iterable[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for name in chain or ():
        text = "." + str(name or "").lower().rstrip(".")
        for suffix, stack in CNAME_SUFFIXES:
            if text.endswith(suffix) or (suffix == ".execute-api.amazonaws.com" and ".execute-api." in text
                                         and text.endswith(".amazonaws.com")):
                out.append({"stack": stack, "signal": "cname", "detail": f"CNAME to {str(name).rstrip('.')}",
                            "points": STRONG})
                break
    return out


def from_addresses(addresses: Iterable[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for addr in addresses or ():
        try:
            ip = ipaddress.ip_address(str(addr).strip())
        except ValueError:
            continue
        for stack, nets in _NETWORKS.items():
            if stack in seen:
                continue
            if any(ip.version == n.version and ip in n for n in nets):
                seen.add(stack)
                out.append({"stack": stack, "signal": "address",
                            "detail": f"{ip} is in {recipes()['recipes'][stack]['name']}'s published ranges "
                                      f"(as of {IP_RANGES_CHECKED})", "points": STRONG})
    return out


def from_issuer(issuer: Optional[str]) -> List[Dict[str, Any]]:
    text = str(issuer or "")
    low = text.lower()
    out: List[Dict[str, Any]] = []
    if "o=amazon" in low.replace(" ", "") or "amazon rsa" in low or "amazon ecdsa" in low:
        # AWS Certificate Manager certificates are only served by AWS's own endpoints.
        for stack in ("cloudfront", "aws_elb", "aws_apigateway"):
            out.append({"stack": stack, "signal": "certificate",
                        "detail": "the certificate is issued by Amazon (AWS Certificate Manager)", "points": WEAK})
    elif "microsoft azure" in low:
        for stack in ("azure_front_door", "azure_app_gateway"):
            out.append({"stack": stack, "signal": "certificate",
                        "detail": "the certificate is issued by a Microsoft Azure CA", "points": WEAK})
    return out


def combine(signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Name the stack from the signals. Pure.

    An edge (CDN or cloud load balancer) beats a server: a CDN in front of nginx can pass the origin's
    ``Server: nginx`` through, but the visitor's TLS ends at the CDN. Confidence is "high" only for one
    strong signal (or more) with no rival edge; anything weaker is said to be weaker, and a weak signal
    alone (a certificate issuer) names no stack at all -- it only offers candidates.
    """
    scores: Dict[str, int] = {}
    evidence: Dict[str, List[str]] = {}
    for sig in signals:
        scores[sig["stack"]] = scores.get(sig["stack"], 0) + int(sig["points"])
        evidence.setdefault(sig["stack"], [])
        if sig["detail"] not in evidence[sig["stack"]]:
            evidence[sig["stack"]].append(sig["detail"])
    if not scores:
        return {"stack": "unknown", "confidence": "none", "evidence": [], "alternatives": []}

    def rank(stack: str) -> Tuple[int, int]:
        return (1 if _kind(stack) in _EDGE_KINDS else 0, scores[stack])

    ordered = sorted(scores, key=lambda k: (rank(k), k), reverse=True)
    top = ordered[0]
    if scores[top] < STRONG - 1:
        return {"stack": "unknown", "confidence": "none", "evidence": [],
                "alternatives": [{"stack": k, "evidence": evidence[k]} for k in ordered]}
    rivals = [k for k in ordered[1:] if _kind(k) in _EDGE_KINDS and scores[k] >= STRONG - 1] \
        if _kind(top) in _EDGE_KINDS else [k for k in ordered[1:] if scores[k] >= STRONG]
    if scores[top] >= STRONG and not rivals:
        confidence = "high"
    else:
        confidence = "medium"
    origin = [k for k in ordered if _kind(k) == "server" and k != top] if _kind(top) in _EDGE_KINDS else []
    return {"stack": top, "confidence": confidence, "evidence": evidence[top],
            "alternatives": [{"stack": k, "evidence": evidence[k]} for k in ordered[1:]],
            "origin_server": origin[0] if origin else None}


def _dns_lookup(host: str) -> Dict[str, List[str]]:
    """CNAME chain and addresses from public DNS. Lookups only: the host itself is not contacted."""
    from services import third_party

    try:
        chain = third_party.cname_chain(host)
    except Exception:
        chain = []
    addresses: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            addresses.extend(third_party._dns(host, rtype))
        except Exception:
            pass
    return {"cname": chain, "addresses": addresses[:16]}


def detect(host: str, result: Optional[Dict[str, Any]] = None,
           lookup: Optional[Callable[[str], Dict[str, List[str]]]] = None, use_cache: bool = True) -> Dict[str, Any]:
    """What terminates TLS for host, with the evidence for it."""
    if use_cache and lookup is None:
        with _detect_lock:
            hit = _detect_cache.get(host)
        if hit and time.monotonic() - hit[0] < DETECT_CACHE_SECONDS and hit[1].get("_basis") == _basis(result):
            return {k: v for k, v in hit[1].items() if k != "_basis"}
    dns = (lookup or _dns_lookup)(host)
    result = result or {}
    signals = (from_headers(result.get("server_software"), result.get("edge_headers"))
               + from_cname(dns.get("cname") or [])
               + from_addresses(dns.get("addresses") or [])
               + from_issuer((result.get("certificate") or {}).get("issuer")))
    out = combine(signals)
    out["dns"] = {"cname": list(dns.get("cname") or []), "addresses": list(dns.get("addresses") or [])}
    if use_cache and lookup is None:
        with _detect_lock:
            if len(_detect_cache) > 2048:
                _detect_cache.clear()
            _detect_cache[host] = (time.monotonic(), {**out, "_basis": _basis(result)})
    return out


def _basis(result: Optional[Dict[str, Any]]) -> str:
    return str((result or {}).get("scanned_at") or "")


def plan(host: str, result: Dict[str, Any], chosen: str = "",
         lookup: Optional[Callable[[str], Dict[str, List[str]]]] = None) -> Dict[str, Any]:
    """The whole "Make it safe" answer for a graded host: already safe, or the stack and its fix."""
    kx = result.get("key_exchange") or {}
    safe = bool(kx.get("post_quantum"))
    detected = detect(host, result, lookup=lookup)
    stack = chosen if chosen in stack_ids() else detected["stack"]
    names = recipes()["recipes"]
    out: Dict[str, Any] = {
        "domain": host,
        "safe": safe,
        "graded_at": result.get("scanned_at"),
        "grade": result.get("grade"),
        "key_exchange": kx.get("group") or None,
        "detected": {
            "stack": detected["stack"],
            "name": names.get(detected["stack"], names["unknown"])["name"],
            "confidence": detected["confidence"],
            "evidence": detected["evidence"],
            "alternatives": [{"stack": a["stack"], "name": names[a["stack"]]["name"], "evidence": a["evidence"]}
                             for a in detected.get("alternatives") or [] if a["stack"] in names],
            "origin_server": detected.get("origin_server"),
            "dns": detected.get("dns"),
        },
        "chosen": stack if chosen in stack_ids() else None,
        "recipe": recipe(stack),
        "stacks": stack_menu(),
        "other_fixes": [f for f in (result.get("fixes") or []) if f.get("id") == "certificate-renew"],
        "proof_url": f"/r/{host}/proof",
    }
    if detected.get("origin_server") and stack == detected["stack"]:
        out["origin_recipe"] = recipe(detected["origin_server"])
    return out


# ── Tables ───────────────────────────────────────────────────────────────────


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        with feature_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS make_safe_watches (
                    domain          TEXT PRIMARY KEY,
                    started_at      TEXT NOT NULL,
                    last_checked_at TEXT NOT NULL DEFAULT '',
                    next_allowed_at TEXT NOT NULL DEFAULT '',
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'waiting',
                    last_group      TEXT NOT NULL DEFAULT '',
                    last_error      TEXT NOT NULL DEFAULT ''
                )
                """)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS make_safe_proofs (
                    domain        TEXT PRIMARY KEY,
                    basis_hash    TEXT NOT NULL,
                    issued_at     TEXT NOT NULL,
                    envelope_json TEXT NOT NULL
                )
                """)
            conn.commit()
        _TABLES_READY.add(identity)


# ── The watch: re-checks, spaced out ─────────────────────────────────────────


def backoff(attempts: int) -> int:
    """Seconds to wait after the given number of re-checks in a session."""
    i = max(0, min(len(BACKOFF_SECONDS) - 1, int(attempts) - 1))
    return BACKOFF_SECONDS[i]


def new_session(now: datetime) -> Dict[str, Any]:
    return {"started_at": iso(now), "last_checked_at": "", "next_allowed_at": iso(now), "attempts": 0,
            "status": STATUS_WAITING, "last_group": "", "last_error": ""}


def advance(state: Dict[str, Any], outcome: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """The session after one re-check. Pure.

    outcome: {"post_quantum": bool, "group": str} for a completed check, or {"error": str,
    "retry_after": seconds} for one that did not complete (rate limited, unreachable, refused).
    """
    out = dict(state)
    out["attempts"] = int(state.get("attempts") or 0) + 1
    out["last_checked_at"] = iso(now)
    delay = backoff(out["attempts"])
    if outcome.get("error"):
        out["status"] = STATUS_ERROR
        out["last_error"] = str(outcome["error"])[:300]
        delay = max(delay, int(outcome.get("retry_after") or 0))
    elif outcome.get("post_quantum"):
        out["status"] = STATUS_LIVE
        out["last_error"] = ""
        out["last_group"] = str(outcome.get("group") or "")
    else:
        out["status"] = STATUS_WAITING
        out["last_error"] = ""
        out["last_group"] = str(outcome.get("group") or "")
    out["next_allowed_at"] = iso(now + timedelta(seconds=delay))
    return out


def public_state(state: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """What the page needs: the status, when it may ask again, and whether it should ask by itself."""
    now = now or now_utc()
    nxt = _parse(state.get("next_allowed_at")) or now
    wait = max(0, int((nxt - now).total_seconds() + 0.999))
    attempts = int(state.get("attempts") or 0)
    status = state.get("status") or STATUS_WAITING
    return {"status": status, "attempts": attempts, "started_at": state.get("started_at") or None,
            "last_checked_at": state.get("last_checked_at") or None, "next_check_in": wait,
            "key_exchange": state.get("last_group") or None, "last_error": state.get("last_error") or None,
            "auto": status != STATUS_LIVE and attempts < MAX_AUTO_ATTEMPTS,
            "max_auto_attempts": MAX_AUTO_ATTEMPTS}


def load_state(domain: str) -> Optional[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT started_at, last_checked_at, next_allowed_at, attempts, status, last_group, "
                           "last_error FROM make_safe_watches WHERE domain = ?", (domain,)).fetchone()
    return dict(row) if row else None


def save_state(domain: str, state: Dict[str, Any]) -> None:
    init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM make_safe_watches WHERE domain = ?", (domain,))
        conn.execute("INSERT INTO make_safe_watches (domain, started_at, last_checked_at, next_allowed_at, attempts, "
                     "status, last_group, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (domain, state["started_at"], state.get("last_checked_at") or "",
                      state.get("next_allowed_at") or "", int(state.get("attempts") or 0),
                      state.get("status") or STATUS_WAITING, state.get("last_group") or "",
                      state.get("last_error") or ""))
        conn.commit()


def session_for(domain: str, start: bool, now: datetime) -> Dict[str, Any]:
    """The current session, or a new one when asked to start and the old one is over.

    Starting again never resets the spacing of a session still running: saying "I've made the change"
    twice in a minute is the same session, and the next slot stays where it was.
    """
    state = load_state(domain)
    if state is None:
        return new_session(now)
    started = _parse(state.get("started_at")) or now
    over = (now - started).total_seconds() > SESSION_SECONDS or state.get("status") == STATUS_LIVE
    if start and over:
        fresh = new_session(now)
        nxt = _parse(state.get("next_allowed_at"))
        if nxt and nxt > now:
            fresh["next_allowed_at"] = iso(nxt)
        return fresh
    return state


_domain_locks: Dict[str, threading.Lock] = {}
_domain_locks_guard = threading.Lock()


def _lock_for(domain: str) -> threading.Lock:
    with _domain_locks_guard:
        if len(_domain_locks) > 1024:
            for key in [k for k, v in _domain_locks.items() if not v.locked()]:
                _domain_locks.pop(key, None)
        return _domain_locks.setdefault(domain, threading.Lock())


def recheck(domain: Any, client_ip: str = "", start: bool = False,
            grade: Optional[Callable[..., Dict[str, Any]]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """One spaced re-check through the public grade. Raises MakeSafeError(429) before the next slot."""
    from services import public_grade

    host = public_grade.normalize(domain)
    run = grade or public_grade.check
    lock = _lock_for(host)
    if not lock.acquire(timeout=1.0):
        raise MakeSafeError(429, "busy", f"{host} is being re-checked right now.", retry_after=10)
    try:
        now = now or now_utc()
        state = session_for(host, start, now)
        nxt = _parse(state.get("next_allowed_at"))
        if nxt and nxt > now:
            wait = (nxt - now).total_seconds()
            save_state(host, state)
            raise MakeSafeError(429, "too_soon",
                                f"Morrow re-checks {host} at most once every {backoff(int(state.get('attempts') or 1))} "
                                f"seconds while you wait, so the check never becomes a load on your server.",
                                retry_after=wait, state=public_state(state, now))
        result: Optional[Dict[str, Any]] = None
        try:
            result = run(host, client_ip, fresh=True)
            kx = result.get("key_exchange") or {}
            state = advance(state, {"post_quantum": bool(kx.get("post_quantum")), "group": kx.get("group")}, now)
        except public_grade.GradeError as exc:
            if exc.error in ("refused_optout", "refused_target", "invalid", "disabled"):
                raise MakeSafeError(exc.status_code, exc.error, exc.detail) from None
            state = advance(state, {"error": exc.detail, "retry_after": exc.retry_after or 0}, now)
        save_state(host, state)
    finally:
        lock.release()
    out: Dict[str, Any] = {"domain": host, "watch": public_state(state, now)}
    if result is not None:
        kx = result.get("key_exchange") or {}
        out["result"] = {"grade": result.get("grade"), "scanned_at": result.get("scanned_at"),
                         "key_exchange": kx.get("group") or None, "post_quantum": bool(kx.get("post_quantum")),
                         "summary": result.get("summary")}
    if state["status"] == STATUS_LIVE:
        out["proof_url"] = f"/r/{host}/proof"
    return out


# ── The proof ────────────────────────────────────────────────────────────────


def derive(history_newest_first: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The quantum-safe record from stored checks (newest first). Pure.

    status "safe": the newest check saw post-quantum key exchange; ``safe_since`` is the first check of
    the unbroken post-quantum run that ends with it. "lapsed": an earlier check saw it and the newest
    did not; ``lapsed_at`` is the first classical check after the last post-quantum one. "never": no
    check has seen it.
    """
    rows = [r for r in history_newest_first if r.get("scanned_at")]
    if not rows:
        return {"status": "never", "checks": 0}
    newest = rows[0]
    if newest.get("post_quantum"):
        run = []
        for r in rows:
            if not r.get("post_quantum"):
                break
            run.append(r)
        return {"status": "safe", "safe_since": run[-1]["scanned_at"], "last_confirmed": newest["scanned_at"],
                "key_exchange": newest.get("group") or "", "checks_in_run": len(run), "checks": len(rows),
                "last_checked": newest["scanned_at"], "lapsed_at": None, "lapsed_key_exchange": None}
    last_pq = next((i for i, r in enumerate(rows) if r.get("post_quantum")), None)
    if last_pq is None:
        return {"status": "never", "checks": len(rows), "last_checked": newest["scanned_at"]}
    run = []
    for r in rows[last_pq:]:
        if not r.get("post_quantum"):
            break
        run.append(r)
    lapse = rows[last_pq - 1]
    return {"status": "lapsed", "safe_since": run[-1]["scanned_at"], "last_confirmed": rows[last_pq]["scanned_at"],
            "key_exchange": rows[last_pq].get("group") or "", "checks_in_run": len(run), "checks": len(rows),
            "last_checked": newest["scanned_at"], "lapsed_at": lapse["scanned_at"],
            "lapsed_key_exchange": lapse.get("group") or "", "current_key_exchange": newest.get("group") or ""}


def _owner(domain: str) -> Dict[str, Any]:
    try:
        from services import watch

        claim = watch.public_claim(domain)
        return {"claimed_by_dns": bool(claim.get("claimed")), "claimed_since": claim.get("since") or None}
    except Exception:
        return {"claimed_by_dns": False, "claimed_since": None}


def document(domain: str, record: Dict[str, Any], owner: Dict[str, Any], base_url: str,
             keys: List[Dict[str, Any]], issued_at: str) -> Dict[str, Any]:
    from services import proof_signing, public_grade

    safe = record["status"] == "safe"
    return {
        "format": PROOF_FORMAT,
        "domain": domain,
        "status": "quantum_safe" if safe else "no_longer_quantum_safe",
        "statement": (f"{domain} has negotiated post-quantum key exchange in every check since "
                      f"{record['safe_since'][:10]}." if safe else
                      f"{domain} negotiated post-quantum key exchange from {record['safe_since'][:10]} until "
                      f"{record['last_confirmed'][:10]}; a check on {record['lapsed_at'][:10]} saw "
                      f"{record.get('lapsed_key_exchange') or 'a classical key exchange'} instead."),
        "safe_since": record["safe_since"],
        "last_confirmed_safe": record["last_confirmed"],
        "key_exchange": record.get("key_exchange") or None,
        "checks_in_run": int(record.get("checks_in_run") or 0),
        "lapsed_at": record.get("lapsed_at"),
        "lapsed_key_exchange": record.get("lapsed_key_exchange"),
        "last_checked": record.get("last_checked"),
        "owner": owner,
        "method": (f"Morrow's public grade (rubric {public_grade.RUBRIC_VERSION}): TLS handshakes to port 443 of "
                   "the host, offering post-quantum key-exchange groups, recording which group the server chose. "
                   "One public endpoint at the moments listed; not an audit of anything behind it."),
        "issued_at": issued_at,
        "issuer": {"product": "Morrow", "keys_url": base_url + proof_signing.WELL_KNOWN_PATH},
        "page": f"{base_url}/r/{domain}/proof",
        "signing_context": PROOF_CONTEXT.decode("ascii").strip(),
        "signing_keys": [proof_signing.public_descriptor(k) for k in keys],
    }


def _basis_hash(doc: Dict[str, Any]) -> str:
    from services import proof_signing

    basis = {k: v for k, v in doc.items() if k != "issued_at"}
    return hashlib.sha256(proof_signing.canonical_bytes(basis)).hexdigest()


def sign_document(doc: Dict[str, Any], keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    from services import proof_signing

    message = proof_signing.canonical_bytes(doc)
    signatures = proof_signing.sign(message, keys, context=PROOF_CONTEXT)
    by_kid = {k["kid"]: k for k in keys}
    for sig in signatures:  # never hand out a proof this server cannot itself verify
        if not proof_signing.verify_signature(sig["alg"], by_kid[sig["kid"]]["public_key_b64"], sig["signature"],
                                              message, context=PROOF_CONTEXT):
            raise MakeSafeError(500, "self_check_failed", "The proof's signature did not verify on this server.")
    return {"format": ENVELOPE_FORMAT, "document": doc, "signatures": signatures}


def verify_envelope(envelope: Dict[str, Any], published: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Check every signature of an envelope against the published keys. What anyone can do offline."""
    from services import proof_signing

    published = published or proof_signing.published_keys()
    keys = {k["kid"]: k for k in published.get("keys") or []}
    doc = envelope.get("document") or {}
    message = proof_signing.canonical_bytes(doc)
    checks = []
    for sig in envelope.get("signatures") or []:
        key = keys.get(sig.get("kid"))
        ok = bool(key) and key.get("alg") == sig.get("alg") and proof_signing.verify_signature(
            sig.get("alg"), key["public_key"], sig.get("signature") or "", message, context=PROOF_CONTEXT)
        checks.append({"kid": sig.get("kid"), "alg": sig.get("alg"), "ok": ok})
    valid = bool(checks) and all(c["ok"] for c in checks) and doc.get("format") == PROOF_FORMAT
    return {"valid": valid, "checks": checks}


def proof_envelope(domain: str, base_url: str, history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """The signed statement for domain: issued when a check first sees it safe, truthful after.

    Raises MakeSafeError 404 when no check has seen post-quantum key exchange, 503 when this server
    has no signing key (the vault key is not configured).
    """
    from services import proof_signing, public_grade

    rows = history if history is not None else public_grade.history_all(domain, 1000)
    record = derive(rows)
    if record["status"] == "never":
        raise MakeSafeError(404, "not_safe_yet",
                            f"No check of {domain} has seen post-quantum key exchange yet, so there is nothing to prove.")
    try:
        keys = proof_signing.active_key_set(create=True)
    except proof_signing.SigningUnavailable as exc:
        raise MakeSafeError(503, "signing_unavailable", f"This server cannot sign proofs: {exc}") from None
    if not keys:
        raise MakeSafeError(503, "signing_unavailable", "This server has no proof signing key.")
    owner = _owner(domain)
    doc = document(domain, record, owner, base_url.rstrip("/"), keys, iso(now_utc()))
    basis = _basis_hash(doc)
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT basis_hash, envelope_json FROM make_safe_proofs WHERE domain = ?",
                           (domain,)).fetchone()
    if row and row["basis_hash"] == basis:
        try:
            return json.loads(row["envelope_json"])
        except (TypeError, ValueError):
            pass
    try:
        envelope = sign_document(doc, keys)
    except proof_signing.SigningUnavailable as exc:
        raise MakeSafeError(503, "signing_unavailable", f"This server cannot sign proofs: {exc}") from None
    with feature_conn() as conn:
        conn.execute("DELETE FROM make_safe_proofs WHERE domain = ?", (domain,))
        conn.execute("INSERT INTO make_safe_proofs (domain, basis_hash, issued_at, envelope_json) VALUES (?, ?, ?, ?)",
                     (domain, basis, doc["issued_at"], json.dumps(envelope, separators=(",", ":"), sort_keys=True)))
        conn.commit()
    return envelope
