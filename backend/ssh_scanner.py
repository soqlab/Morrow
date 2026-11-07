"""
SSH endpoint scanner for post-quantum readiness assessment.

Connects to an SSH server, reads the SSH_MSG_KEXINIT packet, and extracts:
- Supported key exchange algorithms (quantum-vulnerable: ecdh-*, dh-group*)
- Supported host key algorithms (quantum-vulnerable: ssh-rsa, ecdsa-*)
- Supported encryption algorithms
- Server banner/version

No authentication is performed. The scanner disconnects after reading KEXINIT.

quantum-safe algorithms to look for:
- mlkem768x25519-sha256 (OpenSSH 9.0+ hybrid)
- sntrup761x25519-sha512 (OpenSSH 8.5+)
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any, Dict, List, Optional


_TIMEOUT = 10
#: The whole read (banner + KEXINIT) must finish within this many seconds. The per-recv timeout
#: alone let a server that trickles one byte at a time hold a scan for hours.
_DEADLINE = 2 * _TIMEOUT
#: RFC 4253 section 4.2: the identification string, including CR LF, is at most 255 characters.
_MAX_BANNER_LINE = 255
#: Largest packet read. RFC 4253 section 6.1 requires 35000 bytes; KEXINIT is a few KB.
_MAX_PACKET = 65536


class SSHParseError(ValueError):
    """The server sent bytes that are not a well-formed SSH identification string or packet."""

# KEX algorithms that are quantum-vulnerable
_VULNERABLE_KEX = frozenset({
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "curve448-sha512",
})

# KEX algorithms that offer post-quantum hybrid protection
_MORROW_HYBRID_KEX = frozenset({
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "sntrup761x25519-sha512",
    "x25519-kyber512r3-sha256-d00@amazon.com",
    "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org",
})

# Host key algorithms — all current ones are quantum-vulnerable
_VULNERABLE_HOST_KEYS = frozenset({
    "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "ssh-ed25519", "ssh-ed448",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
})

_CRITICAL_KEX = frozenset({
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
})

_WEAK_CIPHERS = frozenset({
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "3des-cbc", "blowfish-cbc", "arcfour", "arcfour128", "arcfour256",
    "cast128-cbc",
})


def _recv(sock: socket.socket, n: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("SSH read deadline passed")
    sock.settimeout(min(_TIMEOUT, remaining))
    return sock.recv(n)


def _recv_exact(sock: socket.socket, n: int, deadline: float, what: str) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = _recv(sock, n - len(data), deadline)
        if not chunk:
            raise ConnectionError(f"Connection closed reading {what}")
        data += chunk
    return bytes(data)


def _read_banner(sock: socket.socket, deadline: float) -> str:
    """The server's identification string ("SSH-2.0-...")."""
    line = b""
    while not line.endswith(b"\n"):
        byte = _recv(sock, 1, deadline)
        if not byte:
            break
        line += byte
        if len(line) > _MAX_BANNER_LINE:
            raise SSHParseError("SSH identification string longer than 255 characters")
    return parse_banner(line)


def parse_banner(line: bytes) -> str:
    """The identification string without CR LF. Raises SSHParseError unless it starts with SSH-."""
    if not line.startswith(b"SSH-"):
        raise SSHParseError("not an SSH identification string")
    return line.decode("utf-8", "replace").strip()


def parse_packet_length(raw_len: bytes) -> int:
    """packet_length of an SSH binary packet (RFC 4253 section 6). Raises SSHParseError."""
    if len(raw_len) != 4:
        raise SSHParseError("truncated packet length")
    pkt_len = struct.unpack(">I", raw_len)[0]
    if pkt_len > _MAX_PACKET:
        raise SSHParseError(f"Packet too large: {pkt_len}")
    # padding_length byte + at least 4 bytes of padding.
    if pkt_len < 5:
        raise SSHParseError(f"Packet too short: {pkt_len}")
    return pkt_len


def parse_packet_body(raw: bytes) -> bytes:
    """The payload of an unencrypted packet body (padding_length, payload, padding)."""
    if not raw:
        raise SSHParseError("empty packet")
    padding_len = raw[0]
    if padding_len < 4 or padding_len > len(raw) - 1:
        raise SSHParseError(f"padding length {padding_len} does not fit a {len(raw)}-byte packet")
    return raw[1:len(raw) - padding_len]


def _read_packet(sock: socket.socket, deadline: Optional[float] = None) -> bytes:
    """Read a single SSH binary packet and return the payload."""
    if deadline is None:
        deadline = time.monotonic() + _DEADLINE
    pkt_len = parse_packet_length(_recv_exact(sock, 4, deadline, "packet length"))
    return parse_packet_body(_recv_exact(sock, pkt_len, deadline, "packet body"))


def _read_name_list(data: bytes, offset: int) -> tuple[List[str], int]:
    """Parse an SSH name-list (uint32 length + comma-separated names). Raises SSHParseError
    when the list is truncated, rather than returning the part that arrived."""
    if offset + 4 > len(data):
        raise SSHParseError("truncated name-list length")
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    if offset + length > len(data):
        raise SSHParseError("name-list overruns the packet")
    raw = data[offset: offset + length].decode("ascii", "ignore")
    names = [n.strip() for n in raw.split(",") if n.strip()] if raw else []
    return names, offset + length


def parse_kexinit(payload: bytes) -> Dict[str, List[str]]:
    """The algorithm lists of an SSH_MSG_KEXINIT payload (RFC 4253 section 7.1)."""
    if not payload or payload[0] != 20:
        raise SSHParseError(f"Unexpected SSH message type: {payload[0] if payload else 'none'}")
    if len(payload) < 17:
        raise SSHParseError("KEXINIT shorter than its cookie")
    offset = 17                                     # 1-byte type + 16-byte cookie
    lists = {}
    for key in ("kex", "host_key", "enc_c2s", "enc_s2c", "mac_c2s"):
        lists[key], offset = _read_name_list(payload, offset)
    return lists


def scan_ssh(host: str, port: int = 22) -> Dict[str, Any]:
    """
    Scan an SSH endpoint for quantum-vulnerability assessment.

    Returns a dict compatible with the Morrow result format,
    including a `findings` list using the same severity/rule_id schema.
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "scan_type": "ssh",
        "banner": "",
        "kex_algorithms": [],
        "host_key_algorithms": [],
        "encryption_algorithms": [],
        "mac_algorithms": [],
        "pq_hybrid_kex": [],
        "findings": [],
        "quantum_risk_score": 0,
        "quantum_risk_level": "unknown",
        "pq_ready": False,
        "error": None,
    }

    # On a hosted deployment an organization scans only its verified domains
    # (services/domain_verification). Refused before any connection is opened.
    from scanner import _scope_refusal

    refusal = _scope_refusal(host)
    if refusal:
        result["error"] = refusal
        result["error_code"] = "NOT_PERMITTED"
        return result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_TIMEOUT)
    try:
        sock.connect((host, port))
        deadline = time.monotonic() + _DEADLINE

        result["banner"] = _read_banner(sock, deadline)

        # Send our banner
        sock.sendall(b"SSH-2.0-Morrow_1.0\r\n")

        # Read and parse the KEXINIT packet (msg type 20)
        lists = parse_kexinit(_read_packet(sock, deadline))
        kex_algs = lists["kex"]

        result["kex_algorithms"]      = kex_algs
        result["host_key_algorithms"] = lists["host_key"]
        result["encryption_algorithms"] = list(dict.fromkeys(lists["enc_c2s"] + lists["enc_s2c"]))
        result["mac_algorithms"]      = lists["mac_c2s"]

        pq_kex = [k for k in kex_algs if k in _MORROW_HYBRID_KEX]
        result["pq_hybrid_kex"] = pq_kex
        result["pq_ready"] = len(pq_kex) > 0

    except (OSError, ConnectionError, ValueError, struct.error) as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # ── Generate findings ──────────────────────────────────────────────────
    findings: List[Dict[str, Any]] = []
    score = 0

    # Critical: very old KEX
    critical_kex = [k for k in result["kex_algorithms"] if k in _CRITICAL_KEX]
    if critical_kex:
        findings.append({
            "rule_id": "SSH_CRITICAL_KEX",
            "severity": "critical",
            "title": "Dangerously weak key exchange algorithms advertised",
            "fix": f"Disable {', '.join(critical_kex)} in sshd_config. These are broken against classical and quantum attackers.",
            "confidence": "high",
            "evidence": {"algorithms": critical_kex},
            "pq_note": "These algorithms predate modern security requirements. Remove immediately.",
        })
        score += 40

    # High: all KEX are quantum-vulnerable (no post-quantum hybrid)
    vulnerable_kex = [k for k in result["kex_algorithms"] if k in _VULNERABLE_KEX]
    if vulnerable_kex and not pq_kex:
        findings.append({
            "rule_id": "SSH_NO_MORROW_KEX",
            "severity": "high",
            "title": "No post-quantum key exchange available",
            "fix": "Upgrade to OpenSSH 9.0+ and add mlkem768x25519-sha256 or sntrup761x25519-sha512@openssh.com to KexAlgorithms.",
            "confidence": "high",
            "evidence": {"vulnerable_kex": vulnerable_kex, "pq_kex_available": pq_kex},
            "pq_note": "NIST recommends ML-KEM for key exchange. OpenSSH 9.0 ships mlkem768x25519-sha256.",
        })
        score += 30

    # High: all host keys are quantum-vulnerable
    vuln_host_keys = [k for k in result["host_key_algorithms"] if k in _VULNERABLE_HOST_KEYS]
    if vuln_host_keys:
        findings.append({
            "rule_id": "SSH_QUANTUM_VULNERABLE_HOST_KEY",
            "severity": "high",
            "title": "All host key algorithms are quantum-vulnerable",
            "fix": "Plan migration to ML-DSA-based SSH host keys when OpenSSH adds support (expected 2025-2026). Track IETF draft-ietf-sshm-pq.",
            "confidence": "high",
            "evidence": {"host_key_algorithms": vuln_host_keys},
            "pq_note": "RSA and EC host keys are vulnerable to Shor's algorithm. ML-DSA support is coming to OpenSSH.",
        })
        score += 20

    # Medium: weak encryption ciphers
    weak_enc = [c for c in result["encryption_algorithms"] if c in _WEAK_CIPHERS]
    if weak_enc:
        findings.append({
            "rule_id": "SSH_WEAK_CIPHER",
            "severity": "medium",
            "title": "Weak encryption ciphers advertised",
            "fix": f"Remove {', '.join(weak_enc)} from Ciphers in sshd_config. Use aes256-gcm@openssh.com or chacha20-poly1305@openssh.com.",
            "confidence": "high",
            "evidence": {"weak_ciphers": weak_enc},
            "pq_note": "CBC mode ciphers are vulnerable to Lucky13 attacks and represent poor cryptographic hygiene.",
        })
        score += 10

    # Info: post-quantum hybrid is available
    if pq_kex:
        findings.append({
            "rule_id": "SSH_MORROW_HYBRID_AVAILABLE",
            "severity": "info",
            "title": "Post-quantum hybrid KEX is available",
            "fix": "No action required. Ensure clients are configured to prefer post-quantum hybrid algorithms.",
            "confidence": "high",
            "evidence": {"pq_kex": pq_kex},
            "pq_note": "Good — this server supports post-quantum hybrid key exchange.",
        })

    result["findings"] = findings
    result["quantum_risk_score"] = min(score, 100)
    result["quantum_risk_level"] = (
        "critical" if score >= 60 else
        "high"     if score >= 40 else
        "medium"   if score >= 20 else
        "low"
    )
    return result
