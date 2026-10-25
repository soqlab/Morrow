"""Known-answer tests for the SSH scanner.

ssh_scanner.scan_ssh had no coverage because it needs an SSH server. It does not
need a *real* one: the scanner reads the banner and the SSH_MSG_KEXINIT packet
and then disconnects, so a socket server that speaks those two things exercises
the binary framing, the name-list parser, and every classification rule.

These are known-answer tests -- the algorithm lists are fixed, so the expected
findings and the exact risk score are too. That matters more here than in most
places: this file is where the product decides whether a customer's SSH estate is
quantum-vulnerable, and a silent misclassification is the worst failure it has.
"""

import socket
import struct
import threading


from ssh_scanner import scan_ssh


def _name_list(names):
    raw = ",".join(names).encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def _kexinit_packet(kex, host_keys, ciphers, macs):
    """Build a wire-format SSH binary packet carrying SSH_MSG_KEXINIT (type 20)."""
    payload = (
        bytes([20])                      # SSH_MSG_KEXINIT
        + b"\x00" * 16                   # cookie
        + _name_list(kex)
        + _name_list(host_keys)
        + _name_list(ciphers)            # encryption client->server
        + _name_list(ciphers)            # encryption server->client
        + _name_list(macs)               # mac client->server
        + _name_list(macs)               # mac server->client
        + _name_list(["none"])           # compression c2s
        + _name_list(["none"])           # compression s2c
        + _name_list([])                 # languages c2s
        + _name_list([])                 # languages s2c
        + b"\x00"                        # first_kex_packet_follows
        + struct.pack(">I", 0)           # reserved
    )
    # packet_length counts the padding-length byte, the payload and the padding.
    padding = b"\x00" * 8
    body = bytes([len(padding)]) + payload + padding
    return struct.pack(">I", len(body)) + body


class _FakeSSHServer:
    """Speaks just enough of the SSH transport layer for the scanner to read."""

    def __init__(self, banner, kex, host_keys, ciphers, macs):
        self.banner = banner
        self.packet = _kexinit_packet(kex, host_keys, ciphers, macs)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(self.banner.encode() + b"\r\n")
                # The scanner sends its own banner before reading KEXINIT.
                conn.recv(512)
                conn.sendall(self.packet)
                # Give the client time to read before the socket tears down.
                conn.recv(1)
            except OSError:
                pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)
        return False


def _rules(result):
    return {f["rule_id"] for f in result["findings"]}


def test_legacy_server_is_scored_critical_with_every_rule_firing():
    with _FakeSSHServer(
        banner="SSH-2.0-OpenSSH_5.3",
        kex=["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "ecdh-sha2-nistp256"],
        host_keys=["ssh-rsa", "ecdsa-sha2-nistp256"],
        ciphers=["aes128-cbc", "3des-cbc", "aes256-ctr"],
        macs=["hmac-sha1"],
    ) as server:
        result = scan_ssh("127.0.0.1", server.port)

    assert result["error"] is None
    assert result["banner"] == "SSH-2.0-OpenSSH_5.3"
    assert result["pq_ready"] is False
    assert result["pq_hybrid_kex"] == []

    assert _rules(result) == {
        "SSH_CRITICAL_KEX",
        "SSH_NO_MORROW_KEX",
        "SSH_QUANTUM_VULNERABLE_HOST_KEY",
        "SSH_WEAK_CIPHER",
    }
    # 40 (critical kex) + 30 (no post-quantum kex) + 20 (host keys) + 10 (weak ciphers)
    assert result["quantum_risk_score"] == 100
    assert result["quantum_risk_level"] == "critical"

    critical = next(f for f in result["findings"] if f["rule_id"] == "SSH_CRITICAL_KEX")
    assert set(critical["evidence"]["algorithms"]) == {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
    }
    weak = next(f for f in result["findings"] if f["rule_id"] == "SSH_WEAK_CIPHER")
    assert set(weak["evidence"]["weak_ciphers"]) == {"aes128-cbc", "3des-cbc"}
    assert "aes256-ctr" not in weak["evidence"]["weak_ciphers"]


def test_pq_hybrid_server_suppresses_the_no_pq_finding():
    with _FakeSSHServer(
        banner="SSH-2.0-OpenSSH_9.6",
        kex=["mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"],
        host_keys=["ssh-ed25519", "rsa-sha2-512"],
        ciphers=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        macs=["hmac-sha2-256-etm@openssh.com"],
    ) as server:
        result = scan_ssh("127.0.0.1", server.port)

    assert result["error"] is None
    assert result["pq_ready"] is True
    assert result["pq_hybrid_kex"] == ["mlkem768x25519-sha256"]

    rules = _rules(result)
    assert "SSH_MORROW_HYBRID_AVAILABLE" in rules
    # Classical KEX is still advertised, but a post-quantum hybrid is offered alongside it,
    # so the "no post-quantum key exchange" finding must not fire.
    assert "SSH_NO_MORROW_KEX" not in rules
    assert "SSH_CRITICAL_KEX" not in rules
    assert "SSH_WEAK_CIPHER" not in rules

    # Host keys remain classical even on a post-quantum-hybrid server -- that is the whole
    # point of the separate rule, and it must survive the good-news case.
    assert "SSH_QUANTUM_VULNERABLE_HOST_KEY" in rules
    assert result["quantum_risk_score"] == 20
    assert result["quantum_risk_level"] == "medium"


def test_name_list_parsing_survives_a_server_offering_nothing():
    """An empty name-list is legal on the wire and must not raise or misreport."""
    with _FakeSSHServer(
        banner="SSH-2.0-Minimal",
        kex=[], host_keys=[], ciphers=[], macs=[],
    ) as server:
        result = scan_ssh("127.0.0.1", server.port)

    assert result["error"] is None
    assert result["kex_algorithms"] == []
    assert result["findings"] == []
    assert result["quantum_risk_level"] == "low"
    assert result["pq_ready"] is False


def test_unreachable_host_reports_an_error_rather_than_raising():
    # Port 1 on loopback: nothing listens, so connect() fails immediately.
    result = scan_ssh("127.0.0.1", 1)

    assert result["error"], "a refused connection must surface as an error string"
    assert result["scan_type"] == "ssh"
    assert result["findings"] == []
    assert result["quantum_risk_level"] in ("unknown", "low")


def test_non_ssh_service_is_rejected_without_inventing_findings():
    """Pointed at something that is not SSH, the scanner must report confusion
    rather than parsing garbage into a clean bill of health."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n")
                conn.recv(512)
                # A well-formed packet carrying the wrong message type.
                body = bytes([4]) + bytes([21]) + b"\x00" * 4
                conn.sendall(struct.pack(">I", len(body)) + body)
                conn.recv(1)
            except OSError:
                pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        result = scan_ssh("127.0.0.1", port)
    finally:
        listener.close()
        thread.join(timeout=5)

    assert result["error"], "a non-KEXINIT reply must be reported, not parsed"
    assert result["findings"] == []
    assert result["pq_ready"] is False
