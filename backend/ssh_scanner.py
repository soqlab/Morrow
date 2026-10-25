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
from typing import Any, Dict, List


_TIMEOUT = 10

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


def _read_packet(sock: socket.socket) -> bytes:
    """Read a single SSH binary packet and return the payload."""
    # Read 4-byte packet length
    raw_len = b""
    while len(raw_len) < 4:
        chunk = sock.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionError("Connection closed reading packet length")
        raw_len += chunk
    pkt_len = struct.unpack(">I", raw_len)[0]
    if pkt_len > 65536:
        raise ValueError(f"Packet too large: {pkt_len}")

    # Read the rest
    raw = b""
    while len(raw) < pkt_len:
        chunk = sock.recv(pkt_len - len(raw))
        if not chunk:
            raise ConnectionError("Connection closed reading packet body")
        raw += chunk

    padding_len = raw[0]
    payload = raw[1: pkt_len - padding_len]
    return payload


def _read_name_list(data: bytes, offset: int) -> tuple[List[str], int]:
    """Parse an SSH name-list (uint32 length + comma-separated names)."""
    if offset + 4 > len(data):
        return [], offset + 4
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    raw = data[offset: offset + length].decode("ascii", "ignore")
    names = [n.strip() for n in raw.split(",") if n.strip()] if raw else []
    return names, offset + length


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

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_TIMEOUT)
    try:
        sock.connect((host, port))

        # Read server banner
        banner_bytes = b""
        while not banner_bytes.endswith(b"\n"):
            byte = sock.recv(1)
            if not byte:
                break
            banner_bytes += byte
            if len(banner_bytes) > 512:
                break
        result["banner"] = banner_bytes.decode("utf-8", "replace").strip()

        # Send our banner
        sock.sendall(b"SSH-2.0-Morrow_1.0\r\n")

        # Read the KEXINIT packet (msg type 20)
        payload = _read_packet(sock)
        if not payload or payload[0] != 20:
            result["error"] = f"Unexpected SSH message type: {payload[0] if payload else 'none'}"
            return result

        # Parse KEXINIT: skip 1-byte type + 16-byte cookie
        offset = 17
        kex_algs,     offset = _read_name_list(payload, offset)
        host_key_algs, offset = _read_name_list(payload, offset)
        enc_c2s,       offset = _read_name_list(payload, offset)
        enc_s2c,       offset = _read_name_list(payload, offset)
        mac_c2s,       offset = _read_name_list(payload, offset)

        result["kex_algorithms"]      = kex_algs
        result["host_key_algorithms"] = host_key_algs
        result["encryption_algorithms"] = list(dict.fromkeys(enc_c2s + enc_s2c))
        result["mac_algorithms"]      = mac_c2s

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
