"""Bounded, DNS-pinned HTTPS checks. Never a general-purpose URL fetch endpoint."""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit

import dns.resolver
import urllib3


class CheckError(ValueError):
    pass


_SPECIAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20",
))
_PUBLIC_V6 = ipaddress.ip_network("2000::/3")


def public_address(value):
    addr = ipaddress.ip_address(value)
    if not addr.is_global or addr.is_multicast or getattr(addr, "ipv4_mapped", None):
        return False
    # Exclude transition/translation ranges rather than trusting an embedded IPv4 target.
    if addr.version == 6 and addr not in _PUBLIC_V6:
        return False
    return not any(addr in network for network in _SPECIAL_NETWORKS)


def hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise CheckError("Invalid hostname") from exc
    if len(value) > 253 or "." not in value or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise CheckError("Use a fully qualified public DNS hostname")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise CheckError("IP literals are not accepted")
    if value.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example")):
        raise CheckError("Private and reserved hostnames are not accepted")
    return value


def origin_url(value: str) -> str:
    try:
        url = urlsplit(value if "://" in value else "https://" + value)
        if url.scheme != "https" or url.username or url.password or url.port not in (None, 443):
            raise CheckError("Only HTTPS on port 443, without credentials, is supported")
        if url.path not in ("", "/") or url.query or url.fragment or "\\" in value:
            raise CheckError("Enter the site origin, without a path, query, or fragment")
        return "https://" + hostname(url.hostname or "")
    except (ValueError, UnicodeError) as exc:
        raise CheckError(str(exc)) from exc


def public_ips(host: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    result = []
    for kind in ("A", "AAAA"):
        try:
            result.extend(str(record) for record in resolver.resolve(host, kind))
        except dns.resolver.NoAnswer:
            continue
        except Exception as exc:
            raise CheckError("DNS lookup failed; no connection attempted") from exc
    if not result or len(result) > 32:
        raise CheckError("Hostname must resolve to public addresses")
    # Reject the entire answer, not just the first address (including mapped IPv6).
    for value in result:
        if not public_address(value):
            raise CheckError("Private, special-use, or mixed DNS answers are blocked")
    return sorted(set(result))


def txt_values(host: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        return [b"".join(record.strings).decode("ascii") for record in resolver.resolve(host, "TXT")]
    except Exception:
        return []


def request(host: str, path: str, *, method: str = "GET", headers=None, body=None, limit=65536) -> dict:
    host = hostname(host)
    if not path.startswith("/") or path.startswith("//") or any(c in path for c in ("\r", "\n", "\\")):
        raise CheckError("Invalid check path")
    addresses = public_ips(host)
    # Connect to the validated address; TLS SNI, certificate checks, and Host retain the DNS name.
    pool = urllib3.HTTPSConnectionPool(
        addresses[0], port=443, server_hostname=host, assert_hostname=host,
        cert_reqs="CERT_REQUIRED", timeout=urllib3.Timeout(connect=4, read=5), retries=False,
    )
    started = time.monotonic()
    response = None
    try:
        response = pool.urlopen(
            method, path, body=body, headers={"Host": host, "User-Agent": "Airlock-Gateway-Check/1", **(headers or {})},
            redirect=False, preload_content=False, retries=False,
        )
        chunks, size = [], 0
        while True:
            if time.monotonic() - started > 10:
                raise CheckError("Response exceeded the check deadline")
            chunk = response.read1(min(4096, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise CheckError("Response exceeds check size limit")
            chunks.append(chunk)
        payload = b"".join(chunks)
        return {"status": response.status, "body": payload,
                "latency_ms": round((time.monotonic() - started) * 1000, 1), "tls_certificate": "verified"}
    except CheckError:
        raise
    except (urllib3.exceptions.HTTPError, OSError, socket.error) as exc:
        # Transport exceptions can contain URLs and response data; never persist their raw messages.
        raise CheckError("HTTPS check failed (DNS, certificate, timeout, or connection)") from exc
    finally:
        if response is not None:
            response.close()
        pool.close()
