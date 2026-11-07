"""Fuzz: SSH identification string, binary packet framing and KEXINIT parsing in ssh_scanner.

The end-to-end check drives scan_ssh against a fake server sending the fuzzed bytes: whatever
arrives, scan_ssh returns a result (with an error string) and never raises.
"""

from __future__ import annotations

import struct
import types

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

import ssh_scanner as ssh  # noqa: E402
from fuzz import checks  # noqa: E402
from fuzz.hypo import byte_inputs, fuzz_settings  # noqa: E402


@fuzz_settings(300)
@given(byte_inputs("ssh"), st.sampled_from([1, 3, 64, 4096]))
def test_scan_ssh_against_a_hostile_server(data, chunk):
    checks.check_ssh_server(data, chunk)


@fuzz_settings(300)
@given(byte_inputs("ssh_kexinit"))
def test_kexinit_parser(data):
    checks.check_ssh_kexinit(data)


@fuzz_settings(300)
@given(st.one_of(byte_inputs("ssh"), st.binary(max_size=64)))
def test_packet_framing(data):
    checks.check_ssh_packet(data[data.find(b"\n") + 1:] if b"\n" in data else data)


_NAME = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-@.", min_size=1, max_size=30)


@fuzz_settings(200)
@given(st.lists(st.lists(_NAME, max_size=8), min_size=10, max_size=10), st.binary(min_size=16, max_size=16))
def test_well_formed_kexinit_round_trips(lists, cookie):
    payload = bytes([20]) + cookie
    for names in lists:
        raw = ",".join(names).encode()
        payload += struct.pack(">I", len(raw)) + raw
    payload += b"\x00" + b"\x00" * 4
    out = ssh.parse_kexinit(payload)
    assert [out[k] for k in ("kex", "host_key", "enc_c2s", "enc_s2c", "mac_c2s")] == lists[:5]


def test_zero_length_packet_is_an_error_not_a_crash():
    """Regression: packet_length 0 made _read_packet index an empty body; the IndexError was not
    among the exceptions scan_ssh handles, so the scan raised instead of reporting an error."""
    result = _scan(b"SSH-2.0-x\r\n" + b"\x00\x00\x00\x00")
    assert result["error"] and "short" in result["error"]


def test_padding_longer_than_the_packet_is_refused():
    """Regression: padding_length larger than the packet sliced with a negative end and returned
    bytes from the middle of the packet as the payload."""
    body = bytes([200]) + bytes([20]) + b"\x00" * 30
    result = _scan(b"SSH-2.0-x\r\n" + struct.pack(">I", len(body)) + body)
    assert result["error"] and "padding" in result["error"]
    assert result["kex_algorithms"] == []


def test_truncated_name_list_is_refused():
    payload = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 1000) + b"curve25519-sha256"
    with pytest.raises(ssh.SSHParseError):
        ssh.parse_kexinit(payload)


def test_trickling_server_is_cut_off_by_the_overall_deadline(monkeypatch):
    """Regression: only the per-recv timeout bounded the read, so a server sending one byte
    every 9 s could hold a scan for days (64 KB packet)."""
    clock = [0.0]

    class Trickle(checks.FakePeer):
        def recv(self, n):
            clock[0] += 9.0
            return super().recv(min(n, 1))

    peer = Trickle(b"SSH-2.0-x\r\n" + struct.pack(">I", 60000) + b"\x05" * 60000)
    monkeypatch.setattr(ssh, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(ssh, "socket", checks._SocketShim(peer))
    result = ssh.scan_ssh("127.0.0.1", 22)
    assert result["error"]
    assert peer.recv_calls <= ssh._DEADLINE // 9 + 2


def _scan(data):
    peer = checks.FakePeer(data)
    original = ssh.socket
    ssh.socket = checks._SocketShim(peer)
    try:
        return ssh.scan_ssh("127.0.0.1", 22)
    finally:
        ssh.socket = original
