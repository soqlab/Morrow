"""Paste anything: the home page's one input, for more than a domain.

Whatever is pasted, dropped or picked is recognised and answered on one page:

  domain or URL          -> /r/<domain>, exactly as before (the browser goes there without asking us)
  list of domains        -> the vendor check (/vendors), which grades a list
  X.509 certificate      -> PEM (one or a chain) or DER: key, signature, expiry, quantum verdict
  (or a CSR, public key)    (services/cert_inventory.classify) and what it means for the harvest clock
  configuration file     -> nginx, Apache httpd, HAProxy, Caddy, Traefik, openssl.cnf, sshd_config /
                            ssh_config, java.security, Windows Schannel (.reg export or the
                            PowerShell TLS cmdlets): the protocols, key-exchange groups and ciphers it
                            enables, whether hybrid X25519MLKEM768 is on, and the Make it safe recipe
                            for that stack (data/make_safe_recipes.json via services/make_safe)
  CycloneDX CBOM (JSON)  -> algorithms by quantum risk (services/sbom_import's CBOM reader, nothing stored)
  repository link        -> honest: scanning code needs a connected code host; where to do it
  traffic capture        -> .pcap / .pcapng: the key exchange of each TLS connection (services/pcap_tls)

Rules, all enforced here and tested in test_paste_anything.py:
  * Processed in memory and discarded. Nothing pasted is written to a database, a file or a log, and
    no answer quotes a line of it back except the TLS settings it was asked about.
  * A private key is never processed. Any input that carries one (PEM, OpenSSH, PuTTY, PKCS#8 DER,
    PKCS#12, a JWK with "d") is refused before anything else looks at it, with a plain warning that
    the key must be treated as exposed.
  * Size limits per type (LIMITS) and a cap on lines, nesting, certificates and components.
  * Nothing is decompressed (zip, gzip and friends are refused), XML is never parsed (no external
    entities), JSON is depth-capped (services/json_limits), regular expressions are linear and run on
    lines of bounded length, and nothing is executed or fetched: a paste never makes Morrow connect
    anywhere.
  * Anonymous use spends the same per-IP budget as the public grade (charge()).
"""

from __future__ import annotations

import base64
import binascii
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

KB = 1024
MB = 1024 * 1024
LIMITS = {
    "line": 2 * KB,           # a domain, URL or repository link
    "certificate": 256 * KB,
    "config": 1 * MB,
    "cbom": 5 * MB,
    "capture": 10 * MB,
    "text": 1 * MB,           # anything else that is text
}
MAX_INPUT_BYTES = LIMITS["capture"]
#: The JSON body around a base64 capture: 4/3 of the largest input plus room for the field names.
MAX_BODY_BYTES = (MAX_INPUT_BYTES * 4) // 3 + 64 * KB
MAX_LINES = 20_000
MAX_LINE_CHARS = 8 * KB
MAX_CERTS = 20
MAX_DOMAINS_IN_LIST = 200
#: Captures are the expensive kind: two read at a time per process, the rest are told to retry.
CAPTURE_CONCURRENCY = 2
_capture_slots = threading.BoundedSemaphore(CAPTURE_CONCURRENCY)

NOT_STORED = ("Read in memory on this server and discarded when the answer was sent. Nothing you pasted "
              "is stored or logged, and Morrow connected to nothing to answer it.")

CONFIG_STACKS = {
    "nginx": "nginx", "apache": "Apache httpd", "haproxy": "HAProxy", "caddy": "Caddy (Caddyfile)",
    "traefik": "Traefik", "openssl_cnf": "OpenSSL configuration (openssl.cnf)",
    "openssh": "OpenSSH (sshd_config / ssh_config)", "java": "Java security properties (java.security)",
    "iis": "Windows Schannel / IIS",
}
_AN = ("nginx", "apache", "haproxy", "openssl_cnf", "openssh")
AS_KINDS = ("certificate", "cbom", "capture") + tuple("config:" + k for k in CONFIG_STACKS)


class PasteError(Exception):
    def __init__(self, status_code: int, error: str, detail: str, retry_after: Optional[float] = None,
                 body: Optional[Dict[str, Any]] = None):
        super().__init__(detail)
        self.status_code = status_code
        self.error = error
        self.detail = detail
        self.retry_after = retry_after
        self.body = body

    def as_dict(self) -> Dict[str, Any]:
        out = {"error": self.error, "detail": self.detail}
        if self.body:
            out.update(self.body)
        return out


def _mb(n: int) -> str:
    return f"{n // MB} MB" if n >= MB else f"{n // KB} KB"


# ── Rate limits: the public grade's per-IP budget ────────────────────────────

def charge(client_ip: str, capture: bool = False) -> None:
    """Spend the anonymous budget: the public grade's per-IP limit, a tighter one for captures, and
    a global hourly ceiling. Raises PasteError(429)."""
    from services import org_rate_limits, public_check, public_grade

    ip_hash = public_check.hash_ip(client_ip)
    checks = [("paste_ip", ip_hash, public_grade.ip_per_minute(), 60.0,
               f"More than {public_grade.ip_per_minute()} pastes a minute from your address. Wait a moment."),
              ("paste_global", "all", public_grade.global_per_hour(), 3600.0,
               "This server has read as many pastes as it will this hour. Try again later.")]
    if capture:
        checks.append(("paste_capture_ip", ip_hash, public_grade.fresh_per_minute(), 60.0,
                       f"More than {public_grade.fresh_per_minute()} captures a minute from your address. Wait a moment."))
    for kind, key, limit, window, detail in checks:
        hit = org_rate_limits.hit(kind, key, limit, window)
        if not hit.get("allowed"):
            raise PasteError(429, "rate_limited", detail, retry_after=float(hit.get("retry_after") or window))


# ── The request ───────────────────────────────────────────────────────────────

def decode_request(payload: Any) -> Tuple[bytes, str, str]:
    """(bytes, file name, forced kind) from {"content", "encoding": "text"|"base64", "name", "as"}."""
    if not isinstance(payload, dict):
        raise PasteError(400, "bad_request", "Send JSON: {\"content\": \"...\"}.")
    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        raise PasteError(400, "empty", "Nothing was pasted.")
    encoding = str(payload.get("encoding") or "text").strip().lower()
    if encoding == "base64":
        try:
            data = base64.b64decode(content, validate=False)
        except (binascii.Error, ValueError):
            raise PasteError(400, "bad_request", "The file could not be read.")
    elif encoding == "text":
        data = content.encode("utf-8", "surrogatepass")
    else:
        raise PasteError(400, "bad_request", "encoding must be text or base64.")
    if len(data) > MAX_INPUT_BYTES:
        raise PasteError(413, "too_large", f"That is larger than {_mb(MAX_INPUT_BYTES)}, the most Morrow reads.")
    name = re.sub(r"[^A-Za-z0-9._ -]", "", str(payload.get("name") or ""))[:120]
    forced = str(payload.get("as") or "").strip().lower()
    if forced and forced not in AS_KINDS:
        raise PasteError(400, "bad_request", "Unknown type.")
    return data, name, forced


# ── Private keys: refused before anything reads the input ────────────────────

_PRIVATE_PEM = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----")
_PRIVATE_MARKERS = (b"PuTTY-User-Key-File-", b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----")
_KEYSTORE_SUFFIXES = (".p12", ".pfx", ".jks", ".jceks", ".keystore", ".bcfks", ".ppk", ".pvk", ".snk")
_PKCS12_DATA_OID = bytes.fromhex("06092a864886f70d010701")
PRIVATE_KEY_WARNING = (
    "This contains a private key. Morrow did not read it and has already discarded it. Treat the key as "
    "exposed: anything pasted into a web page may have passed through your clipboard, browser extensions "
    "or a proxy. Replace it (issue a new key and certificate, or a new SSH host key) and revoke the old "
    "certificate. Morrow never needs a private key: paste the certificate (the BEGIN CERTIFICATE block) instead.")


def _looks_like_pkcs8_or_pkcs12(data: bytes) -> bool:
    if len(data) < 16 or data[0] != 0x30 or len(data) > LIMITS["certificate"]:
        return False
    head = data[:40]
    if b"\x02\x01\x03\x30" in head and _PKCS12_DATA_OID in head:
        return True                                              # PFX: version 3, then pkcs7-data
    try:
        from cryptography.hazmat.primitives import serialization

        serialization.load_der_private_key(data, password=None)
        return True
    except TypeError:
        return True                                              # an encrypted private key
    except Exception:
        return False


def _jwk_private(obj: Any) -> bool:
    stack, seen = [obj], 0
    while stack and seen < 10_000:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            if "kty" in node and any(k in node for k in ("d", "p", "q", "k")):
                return True
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def private_key_in(data: bytes, name: str = "") -> bool:
    if _PRIVATE_PEM.search(data) or any(m in data for m in _PRIVATE_MARKERS):
        return True
    if name.lower().endswith(_KEYSTORE_SUFFIXES):
        return True
    return _looks_like_pkcs8_or_pkcs12(data)


def _refuse_private_key() -> PasteError:
    return PasteError(422, "private_key", PRIVATE_KEY_WARNING, body={
        "kind": "private_key", "what": "A private key. Morrow did not read it.", "refused": True,
        "next": [{"label": "What to paste instead: the certificate", "href": "/#paste"}], "stored": False})


# ── Text helpers ─────────────────────────────────────────────────────────────

_COMPRESSED = (b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
               b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18")


def _text(data: bytes) -> Optional[str]:
    """The input as text, or None when it is binary."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    else:
        if data[:3] == b"\xef\xbb\xbf":
            data = data[3:]
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if "\x00" in text:
        return None
    return text


def _clean(value: Any, limit: int = 200) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or "")).strip()
    return text[:limit]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Domains, URLs and repository links ───────────────────────────────────────

_REPO_RE = re.compile(
    r"^(?:(?:https?://)?(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)/|git@(github\.com|gitlab\.com|bitbucket\.org):)"
    r"([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?(?:[/#?][^\s]*)?$", re.I)


def as_domain(line: str) -> Optional[str]:
    from routers.instrument import domain_segment

    text = line.strip()
    if not text or len(text) > 300 or re.search(r"\s", text):
        return None
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text, flags=re.I)
    text = text.split("/")[0].split("?")[0].split("#")[0]
    text = text.rsplit("@", 1)[-1]
    if text.startswith("["):
        return None
    text = text.split(":")[0]
    return domain_segment(text)


def _repository(line: str) -> Optional[Dict[str, Any]]:
    m = _REPO_RE.match(line.strip())
    if not m:
        return None
    host = (m.group(1) or m.group(2)).lower()
    owner, repo = m.group(3), m.group(4)
    return _repository_answer(host, owner, repo)


def _repository_answer(host: str, owner: str, repo: str) -> Dict[str, Any]:
    name = f"{owner}/{repo}"
    where = {"github.com": "GitHub", "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket"}[host]
    return {
        "kind": "repository",
        "what": f"A {where} repository: {name}.",
        "headline": ("Scanning a repository's code needs a Morrow account with the code host connected. Morrow "
                     "does not fetch code for anonymous visitors, so nothing was read from " + host + "."),
        "details": {"host": host, "repository": name},
        "next": [
            {"label": "Sign in and connect " + where, "href": "/ui/code-hosts.html", "primary": True},
            {"label": "Or produce a CBOM in CI (CBOMkit) and paste the JSON here", "href": "https://github.com/cbomkit/cbomkit"},
        ],
        "notes": ["Once the code host is connected, the console scans the repository for RSA, elliptic-curve and other "
                  "quantum-vulnerable code and opens the fixes as pull requests you review."],
    }


# ── Certificates ─────────────────────────────────────────────────────────────

_PEM_BLOCK = re.compile(r"-----BEGIN ((?:TRUSTED |X509 |NEW )?CERTIFICATE(?: REQUEST)?|PUBLIC KEY)-----"
                        r"([A-Za-z0-9+/=\s]{1,262144}?)-----END \1-----")

_PQ_SIG_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65", "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
for _i, _n in enumerate(("SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f",
                         "SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f")):
    _PQ_SIG_OIDS[f"2.16.840.1.101.3.4.3.{20 + _i}"] = "SLH-DSA-" + _n


def _key_facts(key: Any) -> Dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    from services.cert_inventory import _curve

    if isinstance(key, rsa.RSAPublicKey):
        return {"key_algorithm": "RSA", "key_size": key.key_size, "curve": ""}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"key_algorithm": "EC", "key_size": key.curve.key_size, "curve": _curve(key.curve.name)}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"key_algorithm": "Ed25519", "key_size": 256, "curve": "Ed25519"}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"key_algorithm": "Ed448", "key_size": 456, "curve": "Ed448"}
    if isinstance(key, dsa.DSAPublicKey):
        return {"key_algorithm": "DSA", "key_size": key.key_size, "curve": ""}
    return {"key_algorithm": "", "key_size": None, "curve": ""}


def _public_key_facts(obj: Any) -> Dict[str, Any]:
    try:
        return _key_facts(obj.public_key())
    except Exception:
        oid = getattr(getattr(obj, "public_key_algorithm_oid", None), "dotted_string", "")
        name = _PQ_SIG_OIDS.get(oid, "")
        return {"key_algorithm": name.split("-", 2)[0] + "-" + name.split("-", 2)[1] if name else (oid or "unknown"),
                "key_size": None, "curve": "", "algorithm_detail": name}


def _sig_name(cert: Any) -> str:
    oid = getattr(cert.signature_algorithm_oid, "dotted_string", "")
    if oid in _PQ_SIG_OIDS:
        return _PQ_SIG_OIDS[oid]
    name = getattr(cert.signature_algorithm_oid, "_name", "") or oid
    return {"sha256WithRSAEncryption": "RSA with SHA-256", "sha384WithRSAEncryption": "RSA with SHA-384",
            "sha512WithRSAEncryption": "RSA with SHA-512", "sha1WithRSAEncryption": "RSA with SHA-1",
            "md5WithRSAEncryption": "RSA with MD5", "ecdsa-with-SHA256": "ECDSA with SHA-256",
            "ecdsa-with-SHA384": "ECDSA with SHA-384", "ecdsa-with-SHA512": "ECDSA with SHA-512",
            "ecdsa-with-SHA1": "ECDSA with SHA-1", "RSASSA-PSS": "RSA-PSS", "ed25519": "Ed25519",
            "ed448": "Ed448"}.get(name, name)


def _key_label(facts: Dict[str, Any]) -> str:
    alg, size, curve = facts.get("key_algorithm"), facts.get("key_size"), facts.get("curve")
    if facts.get("algorithm_detail"):
        return str(facts["algorithm_detail"])
    if alg == "RSA" and size:
        return f"RSA {size}-bit"
    if alg == "EC":
        return f"EC {curve}" if curve else "EC"
    return str(alg or "unknown")


def _verdict_words(v: Dict[str, Any]) -> Tuple[str, str]:
    if v.get("quantum_vulnerable"):
        return "bad", "Quantum-vulnerable: a large quantum computer could forge signatures with this key (Shor's algorithm)."
    if v.get("status") == "compliant" or v.get("risk") == "low":
        return "ok", "Quantum-safe signature algorithm."
    return "warn", "Not a known quantum-safe algorithm."


def _cert_entry(cert: Any, now: datetime) -> Dict[str, Any]:
    from cryptography import x509
    from services.cert_inventory import classify

    facts = _public_key_facts(cert)
    sig = _sig_name(cert)
    verdict = classify({**facts, "signature_algorithm": sig})
    try:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:                                       # cryptography < 42
        nb, na = cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)
    sans: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [_clean(n, 253) for n in ext.value.get_values_for_type(x509.DNSName)][:50]
    except Exception:
        pass
    is_ca = False
    try:
        is_ca = bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except Exception:
        pass
    tone, sentence = _verdict_words(verdict)
    days = (na - now).days
    return {
        "role": "certificate",
        "subject": _clean(cert.subject.rfc4514_string(), 300),
        "issuer": _clean(cert.issuer.rfc4514_string(), 300),
        "self_signed": cert.subject == cert.issuer,
        "is_ca": is_ca,
        "dns_names": sans[:10],
        "dns_names_total": len(sans),
        "key": _key_label(facts),
        "key_algorithm": facts.get("key_algorithm"),
        "key_size": facts.get("key_size"),
        "signature_algorithm": sig,
        "not_before": nb.strftime("%Y-%m-%d"),
        "not_after": na.strftime("%Y-%m-%d"),
        "days_left": days,
        "expired": days < 0,
        "quantum_vulnerable": bool(verdict.get("quantum_vulnerable")),
        "risk": verdict.get("risk"),
        "tone": tone,
        "verdict": sentence,
        "weak_signature": (verdict.get("signature") or {}).get("algorithm") or "",
        "_na": na,
    }


def _csr_entry(csr: Any) -> Dict[str, Any]:
    from services.cert_inventory import classify

    facts = _public_key_facts(csr)
    verdict = classify(facts)
    tone, sentence = _verdict_words(verdict)
    return {"role": "request", "subject": _clean(csr.subject.rfc4514_string(), 300), "key": _key_label(facts),
            "key_algorithm": facts.get("key_algorithm"), "key_size": facts.get("key_size"),
            "quantum_vulnerable": bool(verdict.get("quantum_vulnerable")), "risk": verdict.get("risk"),
            "tone": tone, "verdict": sentence}


def _pubkey_entry(key: Any) -> Dict[str, Any]:
    from services.cert_inventory import classify

    facts = _key_facts(key)
    verdict = classify(facts)
    tone, sentence = _verdict_words(verdict)
    return {"role": "public_key", "key": _key_label(facts), "key_algorithm": facts.get("key_algorithm"),
            "key_size": facts.get("key_size"), "quantum_vulnerable": bool(verdict.get("quantum_vulnerable")),
            "risk": verdict.get("risk"), "tone": tone, "verdict": sentence}


def _pem_blocks(text: str) -> List[Tuple[str, bytes]]:
    out = []
    for m in _PEM_BLOCK.finditer(text):
        if len(out) >= MAX_CERTS:
            break
        try:
            der = base64.b64decode(re.sub(r"\s", "", m.group(2)), validate=True)
        except (binascii.Error, ValueError):
            continue
        out.append((m.group(1), der))
    return out


def _certificates(blocks: List[Tuple[str, bytes]]) -> Dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from services import decrypt_window

    now = _now()
    entries: List[Dict[str, Any]] = []
    unreadable = 0
    for label, der in blocks[:MAX_CERTS]:
        try:
            if "REQUEST" in label:
                entries.append(_csr_entry(x509.load_der_x509_csr(der)))
            elif label == "PUBLIC KEY":
                entries.append(_pubkey_entry(serialization.load_der_public_key(der)))
            else:
                entries.append(_cert_entry(x509.load_der_x509_certificate(der), now))
        except Exception:
            unreadable += 1
    if not entries:
        raise PasteError(400, "unreadable", "That looks like a certificate, but it could not be read. Paste the whole "
                         "block, from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----.")
    certs = [e for e in entries if e["role"] == "certificate"]
    # A chain is in order when each certificate's issuer is the next one's subject.
    chain_ok = len(certs) > 1 and all(certs[i]["issuer"] == certs[i + 1]["subject"] for i in range(len(certs) - 1))
    leaf = certs[0] if certs else entries[0]
    vulnerable = [e for e in entries if e["quantum_vulnerable"]]
    if certs:
        what = ("A certificate chain of {} certificates".format(len(certs)) if len(certs) > 1 else "A certificate") + (
            f" for {leaf['dns_names'][0]}." if leaf.get("dns_names") else f": {leaf['subject'] or 'no subject'}.")
    elif leaf["role"] == "request":
        what = "A certificate signing request."
    else:
        what = "A public key."
    if vulnerable:
        headline = (f"{len(vulnerable)} of {len(entries)} {'keys' if len(entries) > 1 else 'key'} can be broken by a "
                    "large quantum computer. That matters for impersonation, not for recorded traffic.")
    else:
        headline = "No quantum-vulnerable key here."
    harvest: List[str] = [
        "The certificate does not decide whether recorded traffic can be read later; the key exchange does. "
        "A server with this certificate can still use X25519MLKEM768, so its recorded traffic stays private.",
    ]
    if certs:
        na = leaf["_na"]
        if leaf["quantum_vulnerable"] and na.year < decrypt_window.DECRYPT_YEAR_LOW:
            harvest.append(f"It expires on {leaf['not_after']}, before {decrypt_window.DECRYPT_YEAR_LOW} (the earliest "
                           "year in the expert range for a quantum computer that breaks RSA-2048), so forging this "
                           "certificate is not a realistic quantum risk. Its replacements are the ones to plan for.")
        elif leaf["quantum_vulnerable"]:
            harvest.append(f"It is valid until {leaf['not_after']}, inside the {decrypt_window.DECRYPT_YEAR_LOW}-"
                           f"{decrypt_window.DECRYPT_YEAR_HIGH} range, so a quantum computer could forge it while it "
                           "is still trusted. Shorten its lifetime or plan a post-quantum replacement.")
        if leaf.get("key_algorithm") == "RSA":
            harvest.append("RSA key: if the server still accepts RSA key transport (TLS 1.2 suites without ECDHE), anyone "
                           "who later obtains this key can read every recorded session that used it, with or without "
                           "a quantum computer.")
    for e in entries:
        e.pop("_na", None)
    next_actions: List[Dict[str, Any]] = []
    host = next((d for d in leaf.get("dns_names") or [] if not d.startswith("*.")), "") if certs else ""
    if host and as_domain(host):
        next_actions.append({"label": f"Check the key exchange of {host}", "href": f"/r/{as_domain(host)}", "primary": True})
    next_actions.append({"label": "Paste the server's configuration for its exact fix", "href": "/#paste"})
    expiring = [e for e in certs if 0 <= e["days_left"] <= 30]
    expired = [e for e in certs if e["expired"]]
    notes = []
    if expired:
        notes.append(f"{len(expired)} certificate{'s have' if len(expired) > 1 else ' has'} expired.")
    if expiring:
        notes.append(f"{len(expiring)} certificate{'s expire' if len(expiring) > 1 else ' expires'} within 30 days.")
    if len(certs) > 1 and not chain_ok:
        notes.append("The certificates are not in chain order (each one issued by the next).")
    if unreadable:
        notes.append(f"{unreadable} block{'s' if unreadable > 1 else ''} could not be read and {'were' if unreadable > 1 else 'was'} skipped.")
    return {"kind": "certificate", "what": what, "headline": headline, "tone": "bad" if vulnerable else "ok",
            "details": {"items": entries, "chain_in_order": chain_ok if len(certs) > 1 else None},
            "harvest": harvest, "notes": notes, "next": next_actions}


# ── Configuration files ──────────────────────────────────────────────────────

_SIGNALS: Dict[str, List[Tuple[str, int]]] = {
    "nginx": [(r"^\s*ssl_(?:protocols|ciphers|ecdh_curve|certificate|conf_command|prefer_server_ciphers)\b", 3),
              (r"^\s*(?:http|server|location|upstream|events)\b[^{\n]*\{", 1),
              (r"^\s*listen\s+[^;]*;", 1), (r"^\s*(?:proxy_pass|server_name|worker_processes)\s", 2)],
    "apache": [(r"^\s*SSL(?:Protocol|CipherSuite|Engine|OpenSSLConfCmd|CertificateFile|HonorCipherOrder)\b", 3),
               (r"^\s*</?(?:VirtualHost|Directory|IfModule|Location)\b", 2), (r"^\s*(?:ServerName|DocumentRoot|LoadModule)\s", 1)],
    "haproxy": [(r"^\s*ssl-default-(?:bind|server)-(?:options|ciphers|ciphersuites|curves)\b", 3),
                (r"^\s*(?:frontend|backend|listen)\s+\S+", 2), (r"^\s*bind[ \t][^\n]*\bssl\b", 3),
                (r"^\s*(?:global|defaults)\s*$", 1), (r"^\s*(?:mode\s+(?:http|tcp)|default_backend)\b", 1)],
    "caddy": [(r"^\s*(?:reverse_proxy|file_server|encode|respond|php_fastcgi)\b", 2),
              (r"^\s*tls\b[^{\n]*\{[ \t]*$", 1), (r"^\s*(?:curves|protocols)\s+(?:x25519|secp|tls1\.)", 3),
              (r"^\s*[a-z0-9*-]+(?:\.[a-z0-9*-]+)+(?::\d+)?[^{\n]*\{[ \t]*$", 1)],
    "traefik": [(r"\b(?:curvePreferences|minVersion|cipherSuites)\b\s*[:=]", 2), (r"VersionTLS1[0-3]", 2),
                (r"^\s*(?:entryPoints|certResolvers|routers|providers)\s*[:=]?\s*$", 1), (r"\[tls\.options", 3)],
    "openssl_cnf": [(r"^\s*\[\s*(?:system_default_sect|ssl_sect|openssl_init|req|req_distinguished_name|v3_ca|v3_req)\s*\]", 3),
                    (r"^\s*(?:openssl_conf|ssl_conf|system_default)\s*=", 3),
                    (r"^\s*(?:MinProtocol|MaxProtocol|CipherString|Ciphersuites)\s*=", 3),
                    (r"^\s*(?:default_bits|default_md|distinguished_name)\s*=", 2)],
    "openssh": [(r"^\s*(?:KexAlgorithms|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes)\s", 3),
                (r"^\s*(?:PermitRootLogin|PasswordAuthentication|ChallengeResponseAuthentication|UsePAM|AuthorizedKeysFile|"
                 r"HostKey|Subsystem|X11Forwarding|PubkeyAuthentication|StrictHostKeyChecking|IdentityFile)\s", 2),
                (r"^\s*(?:Ciphers|MACs)\s+[a-z0-9@.,+^-]+\s*$", 2), (r"^\s*(?:Match|Host)\s+\S", 1)],
    "java": [(r"^\s*jdk\.(?:tls|certpath|jar|security)\.[A-Za-z.]+\s*[=:]", 3), (r"^\s*security\.provider\.\d+\s*[=:]", 3),
             (r"^\s*(?:securerandom|keystore\.type|crypto\.policy|jdk\.tls\.namedGroups)\b", 2)],
    "iis": [(r"SCHANNEL", 3), (r"^\s*Windows Registry Editor Version", 2), (r"(?:Enable|Disable)-Tls(?:EccCurve|CipherSuite)\b", 3),
            (r"Cryptography\\Configuration\\(?:Local\\)?SSL", 3), (r"^\s*\"(?:Enabled|DisabledByDefault|EccCurves|Functions)\"=", 2)],
}
#: Every pattern is anchored to a line start and never lets whitespace cross a line, so the scan is linear.
_SIGNAL_RE = {k: [(re.compile(p.replace(r"^\s*", r"^[ \t]*"), re.M | re.I if k != "openssh" else re.M), w) for p, w in v]
              for k, v in _SIGNALS.items()}


def _score_configs(text: str) -> Dict[str, int]:
    sample = "\n".join(line[:MAX_LINE_CHARS] for line in text.splitlines()[:MAX_LINES] if line.strip())
    scores: Dict[str, int] = {}
    for stack, rules in _SIGNAL_RE.items():
        total = 0
        for rx, weight in rules:
            hits = len(rx.findall(sample))
            total += weight * min(hits, 5)
        if total:
            scores[stack] = total
    return scores


def _logical_lines(text: str, comment: str = "#", continuation: bool = False) -> List[Tuple[int, str]]:
    """(line number, text without comment) with bounded length and count."""
    out: List[Tuple[int, str]] = []
    pending, start = "", 0
    for n, raw in enumerate(text.splitlines()[:MAX_LINES], 1):
        line = raw[:MAX_LINE_CHARS]
        stripped = line.lstrip()
        if comment and stripped.startswith(tuple(comment)):
            line = ""
        elif comment and "#" in comment and " #" in line:
            line = line.split(" #", 1)[0]
        if continuation and line.rstrip().endswith("\\"):
            if not pending:
                start = n
            pending += line.rstrip()[:-1] + " "
            continue
        if pending:
            line, n2 = pending + line, start
            pending = ""
        else:
            n2 = n
        if line.strip():
            out.append((n2, line.strip()))
    if pending.strip():
        out.append((start, pending.strip()))
    return out


def _proto(token: str) -> str:
    """"TLSv1.2" for every spelling the supported stacks use (TLSv1.2, tls1.2, VersionTLS12, TLS 1.2), else ""."""
    t = token.strip().strip("\"';,").lower().replace("_", "").replace(" ", "")
    t = t.replace("versiontls", "tls").replace("tlsv", "tls")
    return {"sslv2": "SSLv2", "sslv3": "SSLv3", "ssl2": "SSLv2", "ssl3": "SSLv3", "ssl30": "SSLv3",
            "tls1": "TLSv1.0", "tls10": "TLSv1.0", "tls1.0": "TLSv1.0", "tls11": "TLSv1.1", "tls1.1": "TLSv1.1",
            "tls12": "TLSv1.2", "tls1.2": "TLSv1.2", "tls13": "TLSv1.3", "tls1.3": "TLSv1.3"}.get(t, "")


ALL_TLS = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
LEGACY = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")


def _between(low: str, high: str) -> List[str]:
    order = ["SSLv3"] + ALL_TLS
    lo = order.index(low) if low in order else order.index("TLSv1.0")
    hi = order.index(high) if high in order else len(order) - 1
    return order[lo:hi + 1]


def _split(value: str, seps: str = ":, ") -> List[str]:
    value = value.strip().strip(";").strip().strip("\"'")
    return [t for t in re.split("[" + re.escape(seps) + "]+", value) if t][:200]


class _Cfg:
    """What one configuration sets, as it is read."""

    def __init__(self, stack: str) -> None:
        self.stack = stack
        self.protocols: Optional[List[str]] = None
        self.group_lists: List[List[str]] = []
        self.ciphers: List[str] = []
        self.tls13_suites: List[str] = []
        self.ssh: Dict[str, List[str]] = {}
        self.evidence: List[Dict[str, Any]] = []
        self.notes: List[str] = []
        self.disabled_groups: List[str] = []

    def saw(self, line: int, setting: str, value: str) -> None:
        if len(self.evidence) < 60:
            self.evidence.append({"line": line, "setting": _clean(setting, 60), "value": _clean(value, 400)})


def _parse_nginx(text: str) -> _Cfg:
    c = _Cfg("nginx")
    for n, line in _logical_lines(text):
        m = re.match(r"^(ssl_protocols|ssl_ecdh_curve|ssl_ciphers|ssl_conf_command)\s+([^;{}]*);", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        c.saw(n, key, val)
        if key == "ssl_protocols":
            c.protocols = sorted({p for p in (_proto(t) for t in val.split()) if p}, key=_order)
        elif key == "ssl_ecdh_curve":
            if val.strip().lower() != "auto":
                c.group_lists.append(_split(val, ":"))
        elif key == "ssl_ciphers":
            c.ciphers += _split(val, ":")
        else:
            parts = val.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in ("groups", "curves"):
                c.group_lists.append(_split(parts[1], ":"))
            elif len(parts) == 2 and parts[0].lower() == "ciphersuites":
                c.tls13_suites += _split(parts[1], ":")
            elif len(parts) == 2 and parts[0].lower() in ("minprotocol", "maxprotocol"):
                _min_max(c, parts[0].lower(), parts[1])
    return c


def _order(p: str) -> int:
    order = ["SSLv2", "SSLv3"] + ALL_TLS
    return order.index(p) if p in order else 99


def _min_max(c: _Cfg, which: str, value: str) -> None:
    p = _proto(value)
    if not p:
        return
    cur = c.protocols or list(ALL_TLS)
    if which.startswith("min"):
        c.protocols = [x for x in cur if _order(x) >= _order(p)]
    else:
        c.protocols = [x for x in cur if _order(x) <= _order(p)]


def _parse_apache(text: str) -> _Cfg:
    c = _Cfg("apache")
    for n, line in _logical_lines(text, continuation=True):
        m = re.match(r"^(SSLProtocol|SSLCipherSuite|SSLOpenSSLConfCmd|SSLProxyProtocol)\s+(.+)$", line, re.I)
        if not m or m.group(1).lower() == "sslproxyprotocol":
            continue
        key, val = m.group(1), m.group(2).strip()
        c.saw(n, key, val)
        if key.lower() == "sslprotocol":
            enabled: set = set()
            for tok in val.split():
                sign = "-" if tok.startswith("-") else "+"
                name = tok.lstrip("+-")
                names = set(ALL_TLS) if name.lower() == "all" else {_proto(name)} - {""}
                enabled = enabled - names if sign == "-" else enabled | names
            c.protocols = sorted(enabled, key=_order)
        elif key.lower() == "sslciphersuite":
            parts = val.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in ("TLSV1.3", "SSL"):
                (c.tls13_suites if parts[0].upper() == "TLSV1.3" else c.ciphers).extend(_split(parts[1], ":"))
            else:
                c.ciphers += _split(val, ":")
        else:
            parts = val.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in ("groups", "curves"):
                c.group_lists.append(_split(parts[1], ":"))
            elif len(parts) == 2 and parts[0].lower() == "ciphersuites":
                c.tls13_suites += _split(parts[1], ":")
            elif len(parts) == 2 and parts[0].lower() in ("minprotocol", "maxprotocol"):
                _min_max(c, parts[0].lower(), parts[1])
    return c


def _parse_haproxy(text: str) -> _Cfg:
    c = _Cfg("haproxy")
    low, high, removed, forced = "", "", set(), ""
    for n, line in _logical_lines(text):
        words = line.split()
        head = words[0].lower()
        if head in ("ssl-default-bind-curves", "ssl-default-bind-ciphers", "ssl-default-bind-ciphersuites",
                    "ssl-default-bind-options") and len(words) > 1:
            val = " ".join(words[1:])
            c.saw(n, head, val)
            if head.endswith("curves"):
                c.group_lists.append(_split(val, ":"))
            elif head.endswith("ciphersuites"):
                c.tls13_suites += _split(val, ":")
            elif head.endswith("ciphers"):
                c.ciphers += _split(val, ":")
            opts = words[1:]
        elif head == "bind" and "ssl" in [w.lower() for w in words]:
            opts = words[2:]
            for i, w in enumerate(opts[:-1]):
                if w.lower() == "curves":
                    c.saw(n, "bind curves", opts[i + 1])
                    c.group_lists.append(_split(opts[i + 1], ":"))
                elif w.lower() == "ciphers":
                    c.saw(n, "bind ciphers", opts[i + 1])
                    c.ciphers += _split(opts[i + 1], ":")
                elif w.lower() == "ciphersuites":
                    c.tls13_suites += _split(opts[i + 1], ":")
        else:
            continue
        for i, w in enumerate(opts):
            wl = w.lower()
            if wl in ("ssl-min-ver", "ssl-max-ver") and i + 1 < len(opts):
                c.saw(n, wl, opts[i + 1])
                if wl == "ssl-min-ver":
                    low = _proto(opts[i + 1])
                else:
                    high = _proto(opts[i + 1])
            elif re.fullmatch(r"no-(sslv3|tlsv1[0-3])", wl):
                c.saw(n, wl, "")
                removed.add(_proto(wl[3:].replace("tlsv1", "tls1")))
            elif re.fullmatch(r"force-(sslv3|tlsv1[0-3])", wl):
                forced = _proto(wl[6:].replace("tlsv1", "tls1"))
    if forced:
        c.protocols = [forced]
    elif low or high or removed:
        # HAProxy 2.2 and newer default to TLS 1.2 as the minimum.
        c.protocols = [p for p in _between(low or "TLSv1.2", high or "TLSv1.3") if p not in removed]
    return c


def _parse_caddy(text: str) -> _Cfg:
    c = _Cfg("caddy")
    for n, line in _logical_lines(text):
        words = line.split()
        head = words[0].lower()
        if head == "protocols" and len(words) > 1:
            c.saw(n, "protocols", " ".join(words[1:]))
            low = _proto(words[1])
            high = _proto(words[2]) if len(words) > 2 else "TLSv1.3"
            c.protocols = _between(low or "TLSv1.2", high or "TLSv1.3")
        elif head == "curves" and len(words) > 1:
            c.saw(n, "curves", " ".join(words[1:]))
            c.group_lists.append(words[1:])
        elif head == "ciphers" and len(words) > 1:
            c.saw(n, "ciphers", " ".join(words[1:]))
            c.ciphers += words[1:]
    return c


def _parse_traefik(text: str) -> _Cfg:
    c = _Cfg("traefik")
    lines = _logical_lines(text)
    low = high = ""
    i = 0
    while i < len(lines):
        n, line = lines[i]
        m = re.match(r"^[\"']?(minVersion|maxVersion|curvePreferences|cipherSuites)[\"']?\s*[:=]\s*(.*)$", line)
        i += 1
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        items: List[str] = []
        if key in ("curvePreferences", "cipherSuites"):
            if val.startswith("["):
                items = [t.strip().strip("\"'") for t in val.strip("[]").split(",") if t.strip()]
            elif not val:
                while i < len(lines) and lines[i][1].startswith("-"):
                    items.append(lines[i][1].lstrip("-").strip().strip("\"'"))
                    i += 1
            c.saw(n, key, ", ".join(items))
            if key == "curvePreferences":
                c.group_lists.append(items)
            else:
                c.ciphers += items
        else:
            c.saw(n, key, val.strip("\"'"))
            if key == "minVersion":
                low = _proto(val)
            else:
                high = _proto(val)
    if low or high:
        c.protocols = _between(low or "TLSv1.2", high or "TLSv1.3")
    return c


def _parse_openssl_cnf(text: str) -> _Cfg:
    c = _Cfg("openssl_cnf")
    has_ssl = False
    for n, line in _logical_lines(text, continuation=True):
        m = re.match(r"^([A-Za-z_.]+)\s*=\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        kl = key.lower()
        if kl in ("minprotocol", "maxprotocol"):
            has_ssl = True
            c.saw(n, key, val)
            _min_max(c, kl, val)
        elif kl in ("groups", "curves"):
            has_ssl = True
            c.saw(n, key, val)
            c.group_lists.append(_split(val, ":"))
        elif kl == "cipherstring":
            has_ssl = True
            c.saw(n, key, val)
            c.ciphers += _split(val, ":")
        elif kl == "ciphersuites":
            has_ssl = True
            c.saw(n, key, val)
            c.tls13_suites += _split(val, ":")
        elif kl in ("default_bits", "default_md"):
            c.saw(n, key, val)
    if not has_ssl:
        c.notes.append("This file has no TLS settings (no system_default section with MinProtocol, Groups or "
                       "CipherString), so programs that load it use OpenSSL's built-in defaults.")
    return c


def _parse_openssh(text: str) -> _Cfg:
    c = _Cfg("openssh")
    for n, line in _logical_lines(text):
        parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key in ("kexalgorithms", "ciphers", "macs", "hostkeyalgorithms", "pubkeyacceptedalgorithms",
                   "pubkeyacceptedkeytypes", "hostkey"):
            c.saw(n, parts[0], parts[1])
            if key == "hostkey":
                c.ssh.setdefault("hostkey", []).append(parts[1].rsplit("/", 1)[-1][:80])
            else:
                c.ssh.setdefault(key, []).extend(_split(parts[1], ","))
    return c


def _parse_java(text: str) -> _Cfg:
    c = _Cfg("java")
    for n, line in _logical_lines(text, continuation=True):
        m = re.match(r"^(jdk\.tls\.disabledAlgorithms|jdk\.tls\.namedGroups|jdk\.tls\.server\.protocols|jdk\.tls\.client\.protocols)"
                     r"\s*[=:]\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        c.saw(n, key, val)
        items = [t.strip() for t in val.split(",") if t.strip()]
        if key == "jdk.tls.disabledAlgorithms":
            disabled = {_proto(t) for t in items} - {""}
            c.protocols = [p for p in ALL_TLS if p not in disabled]
            c.disabled_groups = [t for t in items if t.lower() in ("x25519mlkem768", "ecdh", "x25519")]
        elif key == "jdk.tls.namedGroups":
            c.group_lists.append(items)
        else:
            c.protocols = sorted({_proto(t) for t in items} - {""}, key=_order)
    return c


def _reg_multi_sz(hexdata: str) -> List[str]:
    try:
        raw = bytes(int(h, 16) for h in re.findall(r"[0-9a-fA-F]{2}", hexdata)[:8192])
        return [s for s in raw.decode("utf-16-le", "ignore").split("\x00") if s][:64]
    except ValueError:
        return []


def _parse_iis(text: str) -> _Cfg:
    c = _Cfg("iis")
    section = ""
    enabled: Dict[str, bool] = {}
    curves_on: List[str] = []
    curves_off: List[str] = []
    joined: List[Tuple[int, str]] = []
    for n, line in _logical_lines(text, comment=";", continuation=True):
        joined.append((n, line))
    for n, line in joined:
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        m = re.match(r"^\"(Enabled|DisabledByDefault)\"=dword:([0-9a-fA-F]{1,8})$", line)
        pm = re.search(r"SCHANNEL\\Protocols\\([^\\]+)\\Server", section, re.I)
        if m and pm:
            proto = _proto(pm.group(1).replace(" ", ""))
            if proto:
                on = int(m.group(2), 16) != 0
                c.saw(n, pm.group(1) + " " + m.group(1), "1" if on else "0")
                if m.group(1) == "Enabled":
                    enabled[proto] = on and enabled.get(proto, True)
                elif on:
                    enabled[proto] = False
            continue
        em = re.match(r"^\"EccCurves\"=hex\(7\):(.*)$", line, re.I)
        if em:
            curves = _reg_multi_sz(em.group(1))
            c.saw(n, "EccCurves", ", ".join(curves))
            c.group_lists.append(curves)
            continue
        cm = re.search(r"(Enable|Disable)-TlsEccCurve\b.*?-Name\s+[\"']?([A-Za-z0-9_]+)", line, re.I)
        if cm:
            c.saw(n, cm.group(1) + "-TlsEccCurve", cm.group(2))
            (curves_on if cm.group(1).lower() == "enable" else curves_off).append(cm.group(2))
            continue
        sm = re.search(r"(Enable|Disable)-TlsCipherSuite\b.*?-Name\s+[\"']?([A-Za-z0-9_]+)", line, re.I)
        if sm:
            c.saw(n, sm.group(1) + "-TlsCipherSuite", sm.group(2))
            c.ciphers.append(("" if sm.group(1).lower() == "enable" else "!") + sm.group(2))
    if enabled:
        defaults = {"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True}
        defaults.update(enabled)
        c.protocols = [p for p in ALL_TLS if defaults.get(p)]
        c.notes.append("Protocols not named in the export keep the Windows default for this version.")
    if curves_on and not c.group_lists:
        c.group_lists.append(curves_on)
    c.disabled_groups = curves_off
    return c


_PARSERS = {"nginx": _parse_nginx, "apache": _parse_apache, "haproxy": _parse_haproxy, "caddy": _parse_caddy,
            "traefik": _parse_traefik, "openssl_cnf": _parse_openssl_cnf, "openssh": _parse_openssh,
            "java": _parse_java, "iis": _parse_iis}

#: What applies when the file sets no key-exchange list: the stack's documented default.
_DEFAULT_GROUPS = {
    "nginx": "No ssl_ecdh_curve here, so OpenSSL's built-in list applies: OpenSSL 3.5 or newer offers X25519MLKEM768 by default; older OpenSSL does not.",
    "apache": "No Groups or Curves here, so OpenSSL's built-in list applies: OpenSSL 3.5 or newer offers X25519MLKEM768 by default; older OpenSSL does not.",
    "haproxy": "No curves here, so the TLS library's built-in list applies: AWS-LC builds and OpenSSL 3.5 or newer offer X25519MLKEM768; older OpenSSL does not.",
    "openssl_cnf": "No Groups or Curves here, so OpenSSL's built-in list applies: 3.5 or newer offers X25519MLKEM768 by default; older versions do not.",
    "caddy": "No curves here, so Caddy's default applies: Caddy 2.10 and newer offer X25519MLKEM768 by default.",
    "traefik": "No curvePreferences here, so Go's default applies: Traefik 3.5 and newer offer X25519MLKEM768 by default.",
    "java": "No jdk.tls.namedGroups here, so the JDK default applies: JDK 27 and newer put X25519MLKEM768 first; older JDKs have no hybrid group.",
    "iis": "No curve list here. Windows Schannel does not offer X25519_MLKEM768 until it is turned on (Windows Server 2025 or Windows 11 24H2 and newer).",
    "openssh": "No KexAlgorithms line, so OpenSSH's default applies: 10.0 and newer use mlkem768x25519-sha256, 9.0 and newer sntrup761x25519-sha512@openssh.com; both are hybrid post-quantum.",
}

_WEAK_CIPHER_TOKENS = ("RC4", "DES", "MD5", "NULL", "EXPORT", "EXP-", "ADH", "AECDH", "ANON")
_STATIC_RSA = re.compile(r"^(?:AES|CAMELLIA|SEED|IDEA|ARIA|RC4|DES-CBC3|NULL-)|^TLS_RSA_WITH_|^K?RSA$", re.I)


def _cipher_findings(ciphers: List[str]) -> Tuple[List[str], List[str]]:
    weak, static_rsa = [], []
    for t in ciphers:
        if t.startswith(("!", "-")) or t.startswith("@"):
            continue
        u = t.lstrip("+").upper()
        if any(w in u for w in _WEAK_CIPHER_TOKENS) and not u.startswith(("ECDHE-", "DHE-", "TLS_ECDHE")):
            weak.append(t)
        elif any(w in u for w in ("RC4", "3DES", "-DES-", "MD5", "NULL", "EXPORT")):
            weak.append(t)
        if _STATIC_RSA.search(u):
            static_rsa.append(t)
    return weak[:20], static_rsa[:20]


_SSH_PQ = ("mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com")
_SSH_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
                 "gss-group1-sha1-", "gss-gex-sha1-")


def _ssh_verdict(c: _Cfg) -> Tuple[str, List[str], Dict[str, Any]]:
    kex = c.ssh.get("kexalgorithms")
    findings: List[str] = []
    if kex is None:
        state = "default"
    else:
        first = kex[0][:1] if kex else ""
        names = [k.lstrip("+-^") for k in kex]
        if first == "-":
            removed_pq = [k for k in names if k in _SSH_PQ]
            state = "off" if len(set(removed_pq) & {"mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com"}) >= 2 else "default"
        elif first in ("+", "^"):
            state = "on" if any(k in _SSH_PQ for k in names) else "default"
        else:
            state = "on" if any(k in _SSH_PQ for k in names) else "off"
        weak = [k for k in names if k.startswith(_SSH_WEAK_KEX)]
        if weak:
            findings.append("Weak SHA-1 Diffie-Hellman key exchange is allowed: " + ", ".join(weak[:5]) + ".")
    ciphers = c.ssh.get("ciphers") or []
    weak_c = [x for x in ciphers if not x.startswith("-") and re.search(r"cbc|arcfour|3des|blowfish|cast128", x)]
    if weak_c:
        findings.append("Old ciphers are allowed: " + ", ".join(weak_c[:5]) + ".")
    macs = c.ssh.get("macs") or []
    weak_m = [x for x in macs if not x.startswith("-") and re.search(r"md5|-96|ripemd|umac-64", x)]
    if weak_m:
        findings.append("Weak MACs are allowed: " + ", ".join(weak_m[:5]) + ".")
    hostkeys = c.ssh.get("hostkey") or []
    if hostkeys:
        findings.append("Host keys (" + ", ".join(hostkeys[:4]) + ") are RSA, ECDSA or Ed25519: they only prove the "
                        "server's identity during a connection, so they do not put recorded sessions at risk.")
    details = {"key_exchange": kex, "ciphers": ciphers or None, "macs": macs or None,
               "host_key_algorithms": c.ssh.get("hostkeyalgorithms")}
    return state, findings, details


def _config(text: str, stack: str) -> Dict[str, Any]:
    from services import decrypt_window, make_safe
    from scanner import classify_key_exchange_group

    c = _PARSERS[stack](text)
    findings: List[str] = list(c.notes)
    if stack == "openssh":
        state, extra, ssh_details = _ssh_verdict(c)
        findings += extra
        groups_set = c.ssh.get("kexalgorithms") is not None
        details: Dict[str, Any] = {**ssh_details}
    else:
        pq_lists = [any(classify_key_exchange_group(g).startswith("pq") for g in lst) for lst in c.group_lists]
        if not c.group_lists:
            state = "default"
        elif all(pq_lists):
            state = "on"
        else:
            state = "off"
            if any(pq_lists):
                findings.append(f"{pq_lists.count(False)} of {len(pq_lists)} key-exchange lists leave X25519MLKEM768 out: "
                                "the hosts that use those stay classical.")
        if c.disabled_groups and any("mlkem" in g.lower().replace("_", "") for g in c.disabled_groups):
            state = "off"
            findings.append("The hybrid group is explicitly disabled: " + ", ".join(c.disabled_groups[:4]) + ".")
        groups_set = bool(c.group_lists)
        if c.protocols is not None and "TLSv1.3" not in c.protocols:
            if state != "off":
                findings.append("TLS 1.3 is not enabled, and hybrid post-quantum key exchange exists only in TLS 1.3.")
            state = "off"
        legacy = [p for p in (c.protocols or []) if p in LEGACY]
        if legacy:
            findings.append("Old protocol versions are enabled: " + ", ".join(legacy) + ". Turn them off.")
        weak, static_rsa = _cipher_findings(c.ciphers)
        if weak:
            findings.append("Weak cipher suites are allowed: " + ", ".join(weak[:6]) + ".")
        if static_rsa:
            findings.append(decrypt_window.STATIC_RSA_NOTE + " Allowed here: " + ", ".join(static_rsa[:4]) + ".")
        groups = [g for lst in c.group_lists for g in lst]
        details = {"protocols": c.protocols, "groups": list(dict.fromkeys(groups))[:40] or None,
                   "ciphers": c.ciphers[:40] or None, "tls13_suites": c.tls13_suites[:20] or None}
    if state == "on":
        headline = "Hybrid post-quantum key exchange is on in this file."
        tone = "ok"
    elif state == "off":
        headline = "Hybrid post-quantum key exchange is off: this configuration keeps the key exchange classical."
        tone = "bad"
    else:
        headline = "This file does not choose the key exchange, so the software's default decides."
        tone = "warn"
        findings.insert(0, _DEFAULT_GROUPS[stack])
    exposure = decrypt_window.exposure(True, state == "on")
    if state == "on":
        harvest = [exposure["basis"]]
    else:
        harvest = [f"Traffic recorded today from a classical key exchange could be read from about "
                   f"{exposure['decrypt_year_low']} to {exposure['decrypt_year_high']}. Source: "
                   f"{decrypt_window.EXPOSURE_SOURCE_LABEL}."]
        if state == "default":
            harvest[0] = "If the default is classical (older versions): " + harvest[0][0].lower() + harvest[0][1:]
    recipe = make_safe.config_recipe(stack) or make_safe.recipe(stack)
    if not c.evidence and stack != "openssl_cnf":
        findings.append("No TLS setting was found in what was pasted; it may live in an included file.")
    return {
        "kind": "config",
        "what": ("An " if stack in _AN else "A ") + CONFIG_STACKS[stack] + " configuration.",
        "stack": stack,
        "headline": headline,
        "tone": tone,
        "hybrid_pq": state,
        "groups_set": groups_set,
        "details": {**details, "settings": c.evidence},
        "findings": findings,
        "harvest": harvest,
        "recipe": recipe,
        "next": [{"label": "Make it safe: the change for " + recipe["name"], "href": "#paste-recipe", "primary": True},
                 {"label": "After the change, check the live server", "href": "/#paste"}],
    }


# ── CBOM ─────────────────────────────────────────────────────────────────────

_RISK_ORDER = ("critical", "high", "medium", "low", "unknown")


def _cbom(doc: Dict[str, Any], size: int) -> Dict[str, Any]:
    from services import sbom_import

    if size > LIMITS["cbom"]:
        raise PasteError(413, "too_large", f"CBOMs up to {_mb(LIMITS['cbom'])} are read here; this one is larger. "
                         "Signed in, the console imports larger ones.")
    components = sbom_import._flatten(doc.get("components"))
    if len(components) > sbom_import.MAX_IMPORT_COMPONENTS:
        raise PasteError(413, "too_large", f"This CBOM has more than {sbom_import.MAX_IMPORT_COMPONENTS:,} components, "
                         "the most read at once.")
    by_ref = {c["bom-ref"]: c for c in components if isinstance(c.get("bom-ref"), str) and c.get("bom-ref")}
    deps: Dict[str, List[str]] = {}
    for dep in doc.get("dependencies") or []:
        if isinstance(dep, dict) and isinstance(dep.get("ref"), str):
            deps[dep["ref"]] = [r for r in (dep.get("dependsOn") or []) + (dep.get("provides") or []) if isinstance(r, str)][:200]
    assets: Dict[str, Dict[str, Any]] = {}
    for comp in components:
        if comp.get("type") != "cryptographic-asset":
            continue
        try:
            asset = sbom_import._cbom_asset(comp, by_ref, deps)
        except Exception:
            asset = None
        if not asset:
            continue
        key = sbom_import._inventory_key(asset)
        if key in assets:
            assets[key]["occurrences"] += len(asset.get("occurrences") or [])
            continue
        assets[key] = {"name": _clean(asset.get("name"), 120), "type": asset["asset_type"],
                       "algorithm": _clean(asset.get("algorithm"), 80) or None,
                       "risk": asset.get("risk_level") or "unknown",
                       "quantum_vulnerable": bool(asset.get("quantum_vulnerable")), "pq_safe": bool(asset.get("pq_safe")),
                       "occurrences": len(asset.get("occurrences") or [])}
    rows = sorted(assets.values(), key=lambda a: (_RISK_ORDER.index(a["risk"]) if a["risk"] in _RISK_ORDER else 9, a["name"]))
    by_risk = {r: sum(1 for a in rows if a["risk"] == r) for r in _RISK_ORDER}
    vulnerable = [a for a in rows if a["quantum_vulnerable"]]
    safe = [a for a in rows if a["pq_safe"]]
    spec = _clean(doc.get("specVersion"), 10)
    schema = None
    if spec == "1.6" and size <= 1 * MB:
        try:
            sbom_import.validate_cyclonedx_16(doc)
            schema = True
        except sbom_import.SchemaInvalid:
            schema = False
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    comp = meta.get("component") if isinstance(meta.get("component"), dict) else {}
    subject = _clean(comp.get("name"), 120)
    if not rows:
        headline = "This CycloneDX document lists no cryptographic assets."
        tone = "warn"
    elif vulnerable:
        headline = (f"{len(vulnerable)} of {len(rows)} cryptographic assets are quantum-vulnerable"
                    + (f"; {len(safe)} are post-quantum." if safe else "; none is post-quantum yet."))
        tone = "bad"
    else:
        headline = f"None of the {len(rows)} cryptographic assets is quantum-vulnerable."
        tone = "ok"
    notes = []
    if schema is False:
        notes.append("The document does not validate against CycloneDX 1.6; it was summarised anyway.")
    if spec and spec not in ("1.4", "1.5", "1.6", "1.7"):
        notes.append(f"specVersion {spec} is not one Morrow knows; cryptographic assets arrived in 1.6.")
    return {
        "kind": "cbom",
        "what": f"A CycloneDX {spec or ''} cryptographic bill of materials".replace("  ", " ")
                + (f" for {subject}." if subject else "."),
        "headline": headline, "tone": tone,
        "details": {"components": len(components), "assets": len(rows), "by_risk": by_risk,
                    "by_type": {t: sum(1 for a in rows if a["type"] == t) for t in sorted({a["type"] for a in rows})},
                    "quantum_vulnerable": [a["name"] for a in vulnerable][:50],
                    "post_quantum": [a["name"] for a in safe][:50], "items": rows[:100],
                    "items_truncated": len(rows) > 100, "schema_valid": schema},
        "harvest": ["Key-establishment algorithms in this list (RSA encryption, ECDH, DH) are the ones a recording "
                    "today can be broken through later; signatures only matter while they are trusted."] if vulnerable else [],
        "notes": notes,
        "next": [{"label": "Signed in: import it into your inventory", "href": "/ui/#cbom", "primary": True}],
    }


# ── Captures ─────────────────────────────────────────────────────────────────

def _capture(data: bytes) -> Dict[str, Any]:
    from services import decrypt_window, pcap_tls

    if not _capture_slots.acquire(blocking=False):
        raise PasteError(503, "busy", "Morrow is reading other captures right now. Try again in a moment.", retry_after=10)
    try:
        try:
            r = pcap_tls.analyze(data)
        except pcap_tls.CaptureError as exc:
            raise PasteError(400, "unreadable", str(exc))
    finally:
        _capture_slots.release()
    seen, pq = r["negotiated_seen"], r["post_quantum"]
    if not r["tls_connections"]:
        headline = "No TLS handshake was found in this capture."
        tone = "warn"
    elif not seen:
        headline = f"{r['tls_connections']} TLS connections, but none shows the server's choice of key exchange."
        tone = "warn"
    elif pq == seen:
        headline = f"All {seen} connections with a visible key exchange used hybrid post-quantum key exchange."
        tone = "ok"
    else:
        headline = f"{seen - pq} of {seen} connections used a classical key exchange."
        tone = "bad"
    notes = []
    if r["quic_packets"]:
        notes.append(f"{r['quic_packets']:,} QUIC (HTTP/3) packets were not read: QUIC encrypts its handshake.")
    if r["stopped"]:
        notes.append("Reading " + r["stopped"] + ".")
    if r["unsupported_link_types"]:
        notes.append("Some packets use a link type Morrow does not read: " + ", ".join(map(str, r["unsupported_link_types"])) + ".")
    if r["connections_truncated"]:
        notes.append(f"Only the first {len(r['connections'])} connections are listed.")
    harvest = []
    if seen - pq:
        harvest.append(f"Those {seen - pq} sessions could be recorded and read from about {decrypt_window.DECRYPT_YEAR_LOW} to "
                       f"{decrypt_window.DECRYPT_YEAR_HIGH} ({decrypt_window.EXPOSURE_SOURCE_LABEL}).")
    servers = sorted({c["sni"] for c in r["connections"] if c["sni"] and not c["post_quantum"] and c["negotiated_group"]})
    nxt = [{"label": f"Check {s}", "href": f"/r/{as_domain(s)}"} for s in servers[:5] if as_domain(s)]
    if nxt:
        nxt[0]["primary"] = True
    return {"kind": "capture", "what": f"A traffic capture ({r['format']}, {r['packets']:,} packets).",
            "headline": headline, "tone": tone, "details": r, "harvest": harvest, "notes": notes, "next": nxt}


# ── Detection ────────────────────────────────────────────────────────────────

def _unknown(detail: str = "") -> Dict[str, Any]:
    return {"kind": "unknown", "what": "Morrow could not tell what this is.", "tone": "warn",
            "headline": detail or ("Paste a domain, a certificate (PEM), a server or SSH configuration file, a CycloneDX "
                                   "CBOM (JSON), a repository link, or drop a .pcap capture."),
            "next": []}


def _ambiguous(candidates: List[str]) -> Dict[str, Any]:
    return {"kind": "ambiguous", "what": "This could be more than one kind of file.", "tone": "warn",
            "headline": "Which is it? Morrow will read it as the one you pick.",
            "choices": [{"as": "config:" + k, "label": CONFIG_STACKS[k]} for k in candidates], "next": []}


def _too_big(kind: str, size: int) -> None:
    if size > LIMITS[kind]:
        raise PasteError(413, "too_large", f"{kind.capitalize()} input is limited to {_mb(LIMITS[kind])}; this is {_mb(size)}.")


def detect_and_analyze(data: bytes, name: str = "", forced: str = "") -> Dict[str, Any]:
    """Recognise the input and answer it. Raises PasteError for refusals and limits."""
    if private_key_in(data, name):
        raise _refuse_private_key()
    size = len(data)
    if data[:8].startswith(_COMPRESSED) or name.lower().endswith((".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst")):
        raise PasteError(415, "compressed", "Compressed files are not opened here. Unpack it and paste or drop the file inside.")
    from services import pcap_tls

    if forced == "capture" or pcap_tls.is_capture(data):
        if not pcap_tls.is_capture(data):
            raise PasteError(400, "unreadable", "This is not a pcap or pcapng capture.")
        _too_big("capture", size)
        return _capture(data)
    text = _text(data)
    if text is None:
        _too_big("certificate", size)
        try:
            from cryptography import x509

            x509.load_der_x509_certificate(data)
            return _certificates([("CERTIFICATE", data)])
        except PasteError:
            raise
        except Exception:
            return _unknown("This is a binary file Morrow does not read. Certificates (PEM or DER), configuration "
                            "files, CycloneDX JSON and .pcap / .pcapng captures are what it reads.")
    stripped = text.strip()
    if forced.startswith("config:"):
        _too_big("config", size)
        return _config(text, forced.split(":", 1)[1])
    if forced == "certificate" or ("-----BEGIN" in stripped and size <= LIMITS["certificate"]):
        _too_big("certificate", size)
        blocks = _pem_blocks(text)
        if blocks or forced == "certificate":
            if not blocks:
                raise PasteError(400, "unreadable", "No certificate block was found.")
            return _certificates(blocks)
    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    if len(lines) == 1 and size <= LIMITS["line"]:
        line = lines[0]
        repo = _repository(line)
        if repo:
            return repo
        host = as_domain(line)
        if host:
            return {"kind": "domain", "what": f"A domain: {host}.", "headline": "Opening its record.", "tone": "ok",
                    "details": {"domain": host}, "next": [{"label": f"Open {host}", "href": f"/r/{host}", "primary": True}],
                    "redirect": f"/r/{host}"}
        if re.fullmatch(r"[A-Za-z0-9+/=]{200,}", line):
            try:
                der = base64.b64decode(line, validate=True)
                from cryptography import x509

                x509.load_der_x509_certificate(der)
                return _certificates([("CERTIFICATE", der)])
            except Exception:
                pass
    if stripped.startswith("<"):
        if re.search(r"<bom[\s>]", stripped[:4096]) or "cyclonedx" in stripped[:4096].lower():
            return _unknown("This is CycloneDX XML. Morrow reads CycloneDX JSON only: export the CBOM as JSON and paste that.")
        if re.match(r"<\?xml|<configuration[\s>]", stripped[:200]):
            return _unknown("XML is not read here. If this is an IIS web.config, note that IIS keeps its TLS settings in "
                            "Windows Schannel, not in web.config: paste a .reg export of the SCHANNEL key or your "
                            "Enable-TlsEccCurve script instead.")
    if forced == "cbom" or stripped.startswith(("{", "[")):
        _too_big("cbom", size)
        from services import json_limits

        try:
            doc = json_limits.loads(stripped, max_depth=sbom_import_depth())
        except ValueError:
            if forced == "cbom":
                raise PasteError(400, "unreadable", "That is not valid JSON.")
            doc = None
        if doc is not None:
            if _jwk_private(doc):
                raise _refuse_private_key()
            if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
                return _cbom(doc, size)
            if forced == "cbom":
                raise PasteError(400, "unreadable", "This JSON is not a CycloneDX document (bomFormat is not \"CycloneDX\").")
            return _unknown("This is JSON, but not a CycloneDX CBOM. Morrow reads CycloneDX 1.6 cryptographic BOMs.")
    if 1 < len(lines) <= MAX_DOMAINS_IN_LIST and all(as_domain(ln) for ln in lines):
        hosts = list(dict.fromkeys(as_domain(ln) for ln in lines))
        return {"kind": "domain_list", "what": f"A list of {len(hosts)} domains.", "tone": "ok",
                "headline": "Grade them all at once with the vendor check.", "details": {"domains": hosts[:20], "count": len(hosts)},
                "next": [{"label": "Check them all", "href": "/vendors", "primary": True}]}
    _too_big("config", size)
    scores = _score_configs(text)
    if not scores or max(scores.values()) < 3:
        return _unknown()
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top, best = ranked[0]
    close = [k for k, v in ranked if v >= best * 0.75 and v >= 3]
    if len(close) > 1:
        return _ambiguous(close[:4])
    return _config(text, top)


def sbom_import_depth() -> int:
    from services import sbom_import

    return sbom_import.MAX_JSON_DEPTH


def analyze(data: bytes, name: str = "", forced: str = "") -> Dict[str, Any]:
    """The full answer for the page: detection, the analysis and the storage statement."""
    out = detect_and_analyze(data, name, forced)
    out.setdefault("notes", [])
    out.setdefault("harvest", [])
    out["stored"] = False
    out["privacy"] = NOT_STORED
    out["bytes"] = len(data)
    return out
