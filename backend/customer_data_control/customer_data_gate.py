"""Explicit-file metadata filter. Preview is offline; send requires approval of exact output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request
from urllib.parse import urlsplit

try:
    from ai_data_filter import canonical, minimize
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from services.ai_data_filter import canonical, minimize


def prepare(path, endpoint, version, allow_loopback_http=False):
    parsed = urlsplit(endpoint)
    local_http = allow_loopback_http and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (parsed.scheme != "https" and not local_http) or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use a credential-free HTTPS platform URL (loopback HTTP requires explicit development opt-in)")
    if parsed.path.rstrip("/") not in {"", "/v1"}:
        raise ValueError("Use the platform base URL, optionally ending in /v1")
    if version < 1:
        raise ValueError("Supply the approved policy version from Data Control")
    with open(path, "rb") as source:
        raw = source.read(1000001)
    if len(raw) > 1000000:
        raise ValueError("Input exceeds 1 MB; supply a bounded metadata export")
    metadata = minimize(json.loads(raw))
    if not isinstance(metadata, dict) or not metadata:
        raise ValueError("No supported cryptographic metadata found")
    result = {"destination": endpoint.rstrip("/") + "/ai-control/analyze-metadata",
              "payload": {"expected_version": version, "metadata": metadata}}
    if len(canonical(result).encode()) > 190000:
        raise ValueError("Filtered metadata exceeds upload limit; supply a smaller export")
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Redirect refused; review the actual destination")


def send(proposal, approved_sha256):
    digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
    if not approved_sha256 or not __import__("hmac").compare_digest(digest, approved_sha256):
        raise ValueError("Approval does not match this exact destination, policy version and minimized payload")
    token = os.getenv("MORROW_CUSTOMER_GATE_TOKEN", "")
    if not token:
        raise ValueError("Set MORROW_CUSTOMER_GATE_TOKEN to a scoped customer credential")
    req = urllib.request.Request(proposal["destination"], data=canonical(proposal["payload"]).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=180) as response:
        data = response.read(2000001)
        if len(data) > 2000000:
            raise ValueError("Response exceeds limit")
        return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preview", "send"])
    parser.add_argument("--input", required=True, help="One explicitly selected JSON export; no filesystem crawling")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--policy-version", type=int, required=True)
    parser.add_argument("--approved-sha256")
    parser.add_argument("--allow-loopback-http", action="store_true", help="Development only")
    args = parser.parse_args()
    try:
        proposal = prepare(args.input, args.endpoint, args.policy_version, args.allow_loopback_http)
        digest = hashlib.sha256(canonical(proposal).encode()).hexdigest()
        if args.command == "preview":
            print(json.dumps({**proposal, "approval_sha256": digest, "sent": False}, indent=2))
        else:
            print(json.dumps(send(proposal, args.approved_sha256), indent=2))
    except Exception as exc:
        # HTTP error bodies and input parse failures may contain customer data.
        print("Request not completed: " + (str(exc) if type(exc) is ValueError else type(exc).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
