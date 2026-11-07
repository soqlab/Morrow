"""Passive TLS discovery: read what proxies and sensors already log about each handshake.

A scanner sees an endpoint only when Morrow connects to it. A proxy sees every handshake it
terminates, including the key-exchange group the client and server actually agreed on. That
group decides whether the session is protected against harvest-now/decrypt-later. This module
turns one log line into one observation: host, port, TLS version, cipher suite and group.

Supported formats and the fields they are read from (checked against each product's docs):

  nginx    $ssl_protocol, $ssl_cipher, $ssl_curve (nginx 1.21.5+), $ssl_server_name / $host,
           $server_port. nginx's built-in formats log none of these, so a custom log_format is
           required: JSON (escape=json) or key=value. Unknown curves are logged in hex ("0x11ec").
  envoy    %DOWNSTREAM_TLS_VERSION%, %DOWNSTREAM_TLS_CIPHER%, %DOWNSTREAM_TLS_GROUP%,
           %REQUESTED_SERVER_NAME%, %DOWNSTREAM_LOCAL_PORT%, as json_format or key=value.
  haproxy  ssl_fc_protocol (%sslv), ssl_fc_cipher (%sslc), ssl_fc_curve (HAProxy built against
           OpenSSL 3.0+), ssl_fc_sni, the frontend port (%fp / dst_port), as key=value or JSON.
  alb      The AWS Application Load Balancer access log as AWS writes it (space separated,
           fields 1-36). ssl_cipher is field 15, ssl_protocol field 16, domain_name (SNI) field
           19. ALB does not log the key-exchange group at all, so for ALB the group is always
           "not logged", never inferred from anything else.
  zeek     ssl.log, JSON or TSV: version ("TLSv13"), cipher, curve, server_name, id.resp_h,
           id.resp_p. TSV needs the "#fields" header in the same batch; without it the column
           order would be a guess, so those lines are counted as unparseable instead.

Rules that hold for every format:

  * A line that cannot be parsed is counted with a reason and dropped. Nothing is guessed: a
    missing host, port or TLS version fails the line; a missing group is recorded as "not logged".
  * Only server-side facts are kept: host (SNI, Host or server address), port, version, cipher,
    group. Client addresses, request paths, query strings, user agents and the raw line are never
    returned by these parsers, so they cannot reach storage.

Classification reuses the scanner's own code: scanner.classify_key_exchange_group for the group
family and scanner._is_weak_cipher for the cipher, so a passively observed X25519MLKEM768 and a
scanned one are judged by exactly the same rule.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from scanner import TLS_NAMED_GROUPS, _is_weak_cipher, classify_key_exchange_group
from services import json_limits

FORMATS = ("nginx", "envoy", "haproxy", "alb", "zeek")
MAX_LINE_CHARS = 16_384

# ── Field aliases per format (JSON keys and key=value names, compared lowercased) ─────────────

_ALIASES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "nginx": {
        "host": ("ssl_server_name", "server_name", "host", "http_host"),
        "port": ("server_port", "port"),
        "version": ("ssl_protocol", "tls_version", "protocol_tls"),
        "cipher": ("ssl_cipher", "cipher"),
        "group": ("ssl_curve", "curve", "group", "tls_group"),
    },
    "envoy": {
        "host": ("requested_server_name", "sni", "server_name", "authority", ":authority", "host"),
        "port": ("downstream_local_port", "local_port", "port"),
        "version": ("downstream_tls_version", "tls_version"),
        "cipher": ("downstream_tls_cipher", "tls_cipher", "cipher"),
        "group": ("downstream_tls_group", "tls_group", "group", "curve"),
        "_address": ("downstream_local_address",),
    },
    "haproxy": {
        "host": ("ssl_fc_sni", "sni", "server_name", "host"),
        "port": ("fp", "frontend_port", "dst_port", "port"),
        "version": ("ssl_fc_protocol", "sslv", "ssl_version", "tls_version"),
        "cipher": ("ssl_fc_cipher", "sslc", "ssl_ciphers", "cipher"),
        "group": ("ssl_fc_curve", "curve", "group"),
    },
    "zeek": {
        "host": ("server_name",),
        "port": ("id.resp_p",),
        "version": ("version",),
        "cipher": ("cipher",),
        "group": ("curve",),
        "_address": ("id.resp_h",),
    },
}

_EMPTY = {"", "-", "null", "none", "(null)", "nil"}
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)*$")
# Both patterns run on every line of an attacker-supplied batch, so neither may backtrack. A key
# starts only where no key character precedes it (else a 16 KB run of letters with no "=" is
# retried from every offset: quadratic, about 20 s for one line), and the possessive quantifiers
# (Python 3.11+) stop an unterminated quoted value from being re-scanned.
_KV_RE = re.compile(r'(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]*+)=("(?:[^"\\]|\\.)*+"|\S*)')
_ALB_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*+"|\S+')
_ALB_TLS_TYPES = {"https", "h2", "grpcs", "wss"}
_ALB_TYPES = _ALB_TLS_TYPES | {"http", "ws"}

# ── Normalisation ─────────────────────────────────────────────────────────────────────────────

_GROUP_BY_LOWER: Dict[str, str] = {name.lower(): name for name in TLS_NAMED_GROUPS.values()}
_GROUP_BY_LOWER.update({
    "prime256v1": "secp256r1", "p-256": "secp256r1", "p256": "secp256r1",
    "p-384": "secp384r1", "p384": "secp384r1", "p-521": "secp521r1", "p521": "secp521r1",
    "x25519": "x25519", "x448": "x448",
})


def _blank(value: Any) -> bool:
    return value is None or str(value).strip().lower() in _EMPTY


def normalize_tls_version(value: Any) -> str:
    """"TLSv1.3" for every spelling the supported products use, or "" when unrecognisable."""
    text = str(value or "").strip()
    if _blank(text):
        return ""
    key = text.lower().replace(" ", "").replace("_", "")
    if key in {"sslv2", "sslv3"}:
        return "SSLv2" if key == "sslv2" else "SSLv3"
    match = re.fullmatch(r"(?:tls|tlsv)(1)\.?([0-3])", key)
    if match:
        return f"TLSv1.{match.group(2)}"
    if key in {"tlsv1", "tls1"}:
        return "TLSv1.0"
    return ""


def normalize_group(value: Any) -> Tuple[str, bool]:
    """(group name, observed). Hex ("0x11ec", nginx) and Zeek's "unknown-4588" are resolved
    through the IANA table the scanner uses; an unregistered code point stays "unknown-0x...."."""
    text = str(value or "").strip()
    if _blank(text):
        return "", False
    lower = text.lower()
    code: Optional[int] = None
    if re.fullmatch(r"0x[0-9a-f]{1,4}", lower):
        code = int(lower, 16)
    elif re.fullmatch(r"unknown-\d{1,5}", lower):
        code = int(lower.split("-", 1)[1])
    if code is not None:
        if code in TLS_NAMED_GROUPS:
            return TLS_NAMED_GROUPS[code], True
        return f"unknown-0x{code:04x}", True
    return _GROUP_BY_LOWER.get(lower, text[:64]), True


def _clean_host(value: Any) -> str:
    text = str(value or "").strip().strip('"').lower()
    if _blank(text):
        return ""
    if text.startswith("[") and "]" in text:            # [2001:db8::1]:443
        text = text[1:text.index("]")]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if text.count(":") == 1:                             # host:port in a Host header
        text = text.split(":", 1)[0]
    text = text.rstrip(".")
    return text if _HOSTNAME_RE.match(text) else ""


def _clean_port(value: Any) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return 0
    return port if 0 < port <= 65535 else 0


def _port_from_address(value: Any) -> int:
    text = str(value or "").strip()
    match = re.search(r":(\d{1,5})$", text)
    return _clean_port(match.group(1)) if match else 0


def _host_from_address(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("["):
        return _clean_host(text)
    if text.count(":") == 1:
        return _clean_host(text.split(":", 1)[0])
    return _clean_host(text)


# ── Classification (the scanner's rules) ──────────────────────────────────────────────────────

def classify_observation(tls_version: str, cipher: str, group: str, group_observed: bool) -> Dict[str, Any]:
    """Post-quantum verdict for one observed handshake.

    The group family comes from scanner.classify_key_exchange_group, the cipher check from
    scanner._is_weak_cipher, and the harvest-now/decrypt-later grading mirrors
    policy.derive_quantum_readiness: classical key exchange is "high", and "critical" when legacy
    TLS or a weak cipher is also in play.

    Only TLS 1.3 defines hybrid post-quantum groups, so a TLS 1.2-or-older handshake is classical
    whatever the log says about its group; that is stated as an inference in the reasons. A TLS 1.3
    handshake whose group was not logged (always the case for ALB) is "unknown", never "safe".
    """
    reasons: List[str] = []
    family = classify_key_exchange_group(group) if group_observed and not group.startswith("unknown-0x") else ""
    if group_observed and group.startswith("unknown-0x"):
        reasons.append("group_code_point_unregistered")
    version_num = {"SSLv2": 0.2, "SSLv3": 0.3, "TLSv1.0": 1.0, "TLSv1.1": 1.1, "TLSv1.2": 1.2, "TLSv1.3": 1.3}.get(tls_version, 0.0)
    legacy = 0 < version_num < 1.2
    weak = bool(cipher) and _is_weak_cipher(cipher)
    if legacy:
        reasons.append("legacy_tls")
    if weak:
        reasons.append("weak_cipher")

    if family in ("pq_hybrid", "pq_pure"):
        pq_status = "pq_safe_key_exchange"
        reasons.append(f"{family}_group_negotiated")
    elif family == "classical":
        pq_status = "quantum_vulnerable"
        reasons.append("classical_group_negotiated")
    elif version_num and version_num < 1.3:
        family = "classical"
        pq_status = "quantum_vulnerable"
        reasons.append("pre_tls13_key_exchange_is_classical")
    else:
        pq_status = "unknown"
        reasons.append("group_not_logged" if not group_observed else "group_unclassified")

    if pq_status == "pq_safe_key_exchange":
        hndl = "critical" if (legacy or weak) else "low"
    elif pq_status == "quantum_vulnerable":
        hndl = "critical" if (legacy or weak) else "high"
    else:
        hndl = "critical" if (legacy or weak) else "unknown"
    return {
        "key_exchange_family": family,
        "pq_status": pq_status,
        "hndl_risk": hndl,
        "reasons": reasons,
    }


# ── Per-format parsers ────────────────────────────────────────────────────────────────────────

class ParseError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _kv_pairs(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in _KV_RE.findall(line):
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1].replace('\\"', '"')
        out[key.lower()] = value
    return out


def _flatten(obj: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in obj.items():
        name = f"{prefix}{key}".lower()
        if isinstance(value, dict) and len(out) < 512:
            out.update(_flatten(value, name + "."))
        else:
            out[name] = value
    return out


def _pick(fields: Dict[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in fields and not _blank(fields[name]):
            return fields[name]
    return None


def _from_fields(fmt: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    aliases = _ALIASES[fmt]
    address = _pick(fields, aliases.get("_address", ()))
    host = _clean_host(_pick(fields, aliases["host"]))
    if not host and address is not None:
        host = _host_from_address(address)
    port = _clean_port(_pick(fields, aliases["port"]))
    if not port and address is not None:
        port = _port_from_address(address)
    raw_version = _pick(fields, aliases["version"])
    version = normalize_tls_version(raw_version)
    cipher = str(_pick(fields, aliases["cipher"]) or "").strip()[:128]
    group, group_observed = normalize_group(_pick(fields, aliases["group"]))
    if raw_version is None and not cipher:
        raise ParseError("no_tls_fields")
    if not version:
        raise ParseError("unrecognised_tls_version")
    if not host:
        raise ParseError("missing_host")
    if not port:
        raise ParseError("missing_port")
    return _observation(fmt, host, port, version, cipher, group, group_observed)


def _observation(fmt: str, host: str, port: int, version: str, cipher: str, group: str,
                 group_observed: bool, group_loggable: bool = True) -> Dict[str, Any]:
    return {
        "format": fmt,
        "host": host,
        "port": port,
        "tls_version": version,
        "cipher": cipher if not _blank(cipher) else "",
        "group": group,
        "group_observed": group_observed,
        "group_loggable": group_loggable,
        **classify_observation(version, cipher if not _blank(cipher) else "", group, group_observed),
    }


def _parse_structured(fmt: str, record: Any) -> Dict[str, Any]:
    if isinstance(record, dict):
        return _from_fields(fmt, _flatten(record))
    text = str(record)
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            obj = json_limits.loads(stripped)
        except ValueError:
            raise ParseError("invalid_json")
        if not isinstance(obj, dict):
            raise ParseError("invalid_json")
        return _from_fields(fmt, _flatten(obj))
    fields = _kv_pairs(text)
    if not fields:
        raise ParseError("no_tls_fields")
    return _from_fields(fmt, fields)


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return token[1:-1]
    return token


def parse_alb(line: Any) -> Optional[Dict[str, Any]]:
    """AWS ALB access log line. Returns None for a plaintext (http/ws) request: not TLS, not an error."""
    tokens = _ALB_TOKEN_RE.findall(str(line).strip())
    if len(tokens) < 19 or tokens[0] not in _ALB_TYPES:
        raise ParseError("not_alb_access_log")
    if tokens[0] not in _ALB_TLS_TYPES:
        return None
    request_line = _unquote(tokens[12])
    parts = request_line.split(" ")
    url_host, url_port = "", 0
    if len(parts) >= 2:
        try:
            split = urlsplit(parts[1])
            url_host = _clean_host(split.hostname or "")
            url_port = _clean_port(split.port or 0)
        except ValueError:
            pass
    cipher = tokens[14]
    version = normalize_tls_version(tokens[15])
    if not version:
        raise ParseError("unrecognised_tls_version")
    host = _clean_host(_unquote(tokens[18])) or url_host
    if not host:
        raise ParseError("missing_host")
    port = url_port                 # ALB writes protocol://host:port in every request line
    if not port:
        raise ParseError("missing_port")
    # ALB records no key-exchange group in any log it writes; say so rather than infer one.
    return _observation("alb", host, port, version, cipher, "", False, group_loggable=False)


_ZEEK_HEX_SEPARATOR_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")


def _zeek_separator(text: str) -> str:
    """The separator a "#separator" header names: Zeek writes it as hex escapes ("\\x09")."""
    raw = text.split(" ", 1)[1].strip() if " " in text else "\\x09"
    if _ZEEK_HEX_SEPARATOR_RE.fullmatch(raw):
        raw = bytes.fromhex(raw.replace("\\x", "")).decode("latin-1")
    if not raw:
        raise ParseError("zeek_invalid_separator")
    return raw


class ZeekTsvState:
    def __init__(self) -> None:
        self.fields: List[str] = []
        self.separator = "\t"
        self.unset = "-"
        self.empty = "(empty)"


def parse_zeek(line: Any, state: ZeekTsvState) -> Optional[Dict[str, Any]]:
    if isinstance(line, dict):
        return _from_fields("zeek", _flatten(line))
    text = str(line).rstrip("\r\n")
    if text.startswith("#"):
        if text.startswith("#separator"):
            state.separator = _zeek_separator(text)
        elif text.startswith("#unset_field"):
            state.unset = text.split(state.separator, 1)[1] if state.separator in text else state.unset
        elif text.startswith("#fields"):
            state.fields = [f.lower() for f in text.split(state.separator)[1:]]
        return None                                       # header / comment: neither data nor error
    if text.lstrip().startswith("{"):
        return _parse_structured("zeek", text)
    if not state.fields:
        raise ParseError("zeek_tsv_without_fields_header")
    values = text.split(state.separator)
    if len(values) != len(state.fields):
        raise ParseError("zeek_tsv_column_mismatch")
    record = {k: ("" if v in (state.unset, state.empty) else v) for k, v in zip(state.fields, values)}
    return _from_fields("zeek", record)


# ── Batch entry point ─────────────────────────────────────────────────────────────────────────

def parse_batch(fmt: str, records: Iterable[Any]) -> Dict[str, Any]:
    """Parse a batch. Returns observations plus counters; unparseable lines are counted by reason
    (with their position in the batch, never their content)."""
    fmt = str(fmt or "").strip().lower()
    if fmt not in FORMATS:
        raise ValueError(f"Unknown format {fmt!r}. Use one of: {', '.join(FORMATS)}.")
    observations: List[Dict[str, Any]] = []
    failures: Dict[str, int] = {}
    samples: List[Dict[str, Any]] = []
    skipped = 0
    received = 0
    state = ZeekTsvState()
    for index, record in enumerate(records):
        received += 1
        try:
            if isinstance(record, str) and len(record) > MAX_LINE_CHARS:
                raise ParseError("line_too_long")
            if isinstance(record, str) and not record.strip():
                skipped += 1
                continue
            if fmt == "alb":
                obs = parse_alb(record) if not isinstance(record, dict) else _parse_alb_dict(record)
            elif fmt == "zeek":
                obs = parse_zeek(record, state)
            else:
                obs = _parse_structured(fmt, record)
            if obs is None:
                skipped += 1
                continue
            observations.append(obs)
        except ParseError as exc:
            failures[exc.reason] = failures.get(exc.reason, 0) + 1
            if len(samples) < 20:
                samples.append({"index": index, "reason": exc.reason})
    return {
        "received": received,
        "parsed": len(observations),
        "skipped": skipped,
        "unparseable": sum(failures.values()),
        "unparseable_by_reason": failures,
        "unparseable_samples": samples,
        "observations": observations,
    }


def _parse_alb_dict(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """An ALB entry a shipper already split into named fields (e.g. Athena / Firehose JSON)."""
    fields = _flatten(record)
    rtype = str(fields.get("type") or "").lower()
    if rtype and rtype not in _ALB_TYPES:
        raise ParseError("not_alb_access_log")
    if rtype in ("http", "ws"):
        return None
    version = normalize_tls_version(fields.get("ssl_protocol"))
    if not version:
        raise ParseError("unrecognised_tls_version" if "ssl_protocol" in fields else "no_tls_fields")
    host = _clean_host(fields.get("domain_name"))
    port = 0
    for key in ("request_url", "request"):
        value = str(fields.get(key) or "")
        url = value.split(" ")[1] if value.count(" ") >= 1 else value
        try:
            split = urlsplit(url)
            host = host or _clean_host(split.hostname or "")
            port = port or _clean_port(split.port or 0)
        except ValueError:
            continue
    port = port or _clean_port(fields.get("request_port"))
    if not host:
        raise ParseError("missing_host")
    if not port:
        raise ParseError("missing_port")
    return _observation("alb", host, port, version, str(fields.get("ssl_cipher") or ""), "", False, group_loggable=False)
