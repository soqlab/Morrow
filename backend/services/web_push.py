"""Browser Web Push for watched domains: VAPID (RFC 8292) and aes128gcm payload encryption (RFC 8291).

No third-party push library: the two RFCs need only ECDH on P-256, HKDF-SHA256 and AES-128-GCM,
which ``cryptography`` (already a dependency) provides.

Settings
--------
``MORROW_VAPID_PRIVATE_KEY``  the application server's P-256 private key: base64url of the 32-byte
                              scalar (what ``npx web-push generate-vapid-keys`` prints as the private
                              key) or a PEM block. Without it push is switched off, and the page and
                              the API say so in a sentence; every other channel still works.
``MORROW_VAPID_PUBLIC_KEY``   optional: base64url of the uncompressed public point. Derived from the
                              private key when absent; refused at startup-free read time if it does
                              not match.
``MORROW_VAPID_SUBJECT``      optional contact for push services (RFC 8292 "sub"): an https URL or a
                              mailto: address. Default: <MORROW_PUBLIC_BASE_URL>/about-scanner.
``MORROW_WEB_PUSH_HOSTS``     optional extra push-service host suffixes, comma separated.

Where a push goes
-----------------
A browser subscription names an endpoint URL, so it is a user-supplied URL. It must be https on
port 443 at a known push service (``PUSH_HOST_SUFFIXES``), every address it resolves to must be
public (services/alert_routing.validate_webhook_url, the platform's SSRF guard), and the connection
is pinned to the address that was checked. A 404 or 410 from the push service means the browser
dropped the subscription; the caller deletes it.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import struct
import time
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

RECORD_SIZE = 4096
DEFAULT_TTL = 24 * 3600
PUSH_HOST_SUFFIXES = (
    "fcm.googleapis.com",            # Chrome, Edge on Android, Opera, Samsung Internet
    "push.services.mozilla.com",     # Firefox
    "notify.windows.com",            # Edge on Windows (WNS)
    "push.apple.com",                # Safari (web.push.apple.com)
)


class PushError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: Any) -> bytes:
    s = str(text or "").strip().replace("+", "-").replace("/", "_").rstrip("=")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _private_key() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    raw = str(os.getenv("MORROW_VAPID_PRIVATE_KEY", "") or "").strip()
    if not raw:
        return None
    if "BEGIN" in raw:
        key = load_pem_private_key(raw.replace("\\n", "\n").encode("ascii"), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("not a P-256 key")
        return key
    scalar = unb64u(raw)
    if len(scalar) != 32:
        raise ValueError("a VAPID private key is 32 bytes")
    return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())


def _public_bytes(key: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def status() -> Dict[str, Any]:
    """{enabled, public_key, reason}. Never raises."""
    try:
        key = _private_key()
    except Exception:
        return {"enabled": False, "public_key": "",
                "reason": "Browser notifications are off on this server: MORROW_VAPID_PRIVATE_KEY is set but is not a "
                          "valid P-256 key."}
    if key is None:
        return {"enabled": False, "public_key": "",
                "reason": "Browser notifications are off on this server: the operator has not set VAPID keys "
                          "(MORROW_VAPID_PRIVATE_KEY). Your feed and webhooks still work."}
    public = b64u(_public_bytes(key))
    configured = str(os.getenv("MORROW_VAPID_PUBLIC_KEY", "") or "").strip().rstrip("=")
    if configured and configured.replace("+", "-").replace("/", "_") != public:
        return {"enabled": False, "public_key": "",
                "reason": "Browser notifications are off on this server: MORROW_VAPID_PUBLIC_KEY does not match "
                          "MORROW_VAPID_PRIVATE_KEY."}
    return {"enabled": True, "public_key": public, "reason": ""}


def subject() -> str:
    value = str(os.getenv("MORROW_VAPID_SUBJECT", "") or "").strip()
    if value.startswith(("https://", "mailto:")):
        return value
    from services.public_config import public_base_url

    return (public_base_url() or "https://morrow.soqlab.com").rstrip("/") + "/about-scanner"


def _hosts() -> tuple:
    extra = [h.strip().lower().lstrip(".") for h in str(os.getenv("MORROW_WEB_PUSH_HOSTS", "") or "").split(",")]
    return PUSH_HOST_SUFFIXES + tuple(h for h in extra if h)


def validate_endpoint(endpoint: Any, resolve: bool = True) -> str:
    """The endpoint, or PushError: https, port 443, a known push service, public addresses only."""
    from services import alert_routing

    text = str(endpoint or "").strip()
    try:
        alert_routing.validate_webhook_url(text, resolve=False)
    except alert_routing.AlertRoutingError as exc:
        raise PushError(400, exc.detail.replace("Webhook", "Push endpoint").replace("webhook", "push endpoint"),
                        "bad_endpoint") from None
    host = (urlsplit(text).hostname or "").lower().rstrip(".")
    if not any(host == s or host.endswith("." + s) for s in _hosts()):
        raise PushError(400, f"{host} is not a browser push service this server sends to.", "unknown_push_service")
    if resolve:
        try:
            alert_routing.public_addresses(host, 443)
        except alert_routing.AlertRoutingError as exc:
            raise PushError(400, exc.detail, "bad_endpoint") from None
    return text


def vapid_header(endpoint: str, key: Any = None, now: Optional[float] = None) -> str:
    """``vapid t=<ES256 JWT>, k=<public key>`` for one push service origin."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = key or _private_key()
    parts = urlsplit(endpoint)
    claims = {"aud": f"{parts.scheme}://{parts.hostname}", "exp": int((now or time.time()) + 12 * 3600), "sub": subject()}
    head = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode("ascii")
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"vapid t={head}.{body}.{b64u(signature)}, k={b64u(_public_bytes(key))}"


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(plaintext: bytes, p256dh: Any, auth: Any, salt: Optional[bytes] = None, server_key: Any = None) -> bytes:
    """The aes128gcm body for one push message (RFC 8291 section 3, RFC 8188 one record)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ua_public = unb64u(p256dh) if not isinstance(p256dh, bytes) else p256dh
    auth_secret = unb64u(auth) if not isinstance(auth, bytes) else auth
    if len(ua_public) != 65 or len(auth_secret) != 16:
        raise PushError(400, "The browser subscription keys are malformed.", "bad_keys")
    if len(plaintext) > RECORD_SIZE - 17 - 86:
        raise PushError(400, "The push message is too long.", "too_long")
    salt = salt or os.urandom(16)
    as_key = server_key or ec.generate_private_key(ec.SECP256R1())
    as_public = _public_bytes(as_key)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    shared = as_key.exchange(ec.ECDH(), peer)
    ikm = _hkdf(auth_secret, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    header = salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public
    return header + ciphertext


def send(subscription: Dict[str, Any], payload: Dict[str, Any], ttl: int = DEFAULT_TTL,
         timeout: float = 10.0) -> Dict[str, Any]:
    """Deliver one message. {ok, http_status, error, gone}; never raises."""
    from services import alert_routing

    st = status()
    if not st["enabled"]:
        return {"ok": False, "http_status": None, "error": st["reason"], "gone": False, "disabled": True}
    endpoint = str(subscription.get("endpoint") or "")
    try:
        validate_endpoint(endpoint, resolve=False)
        parts = urlsplit(endpoint)
        address = alert_routing.public_addresses(parts.hostname or "", 443)[0]
        body = encrypt(json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                       subscription.get("p256dh"), subscription.get("auth"))
        auth_header = vapid_header(endpoint)
    except (PushError, alert_routing.AlertRoutingError) as exc:
        return {"ok": False, "http_status": None, "error": exc.detail, "gone": False}
    except Exception as exc:
        return {"ok": False, "http_status": None, "error": f"Could not prepare the push: {exc.__class__.__name__}", "gone": False}
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    conn = None
    try:
        conn = alert_routing.open_connection(parts.hostname or "", 443, address, timeout)
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/octet-stream", "Content-Encoding": "aes128gcm", "TTL": str(int(ttl)),
            "Urgency": "normal", "Authorization": auth_header, "Content-Length": str(len(body))})
        resp = conn.getresponse()
        resp.read(1024)
        ok = 200 <= resp.status < 300
        return {"ok": ok, "http_status": resp.status, "gone": resp.status in (404, 410),
                "error": "" if ok else f"The push service answered HTTP {resp.status}."}
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"ok": False, "http_status": None, "error": f"Connection failed: {exc.__class__.__name__}", "gone": False}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
