"""morrow-sign: post-quantum signatures for your releases and your site, checked by anyone at Morrow.

    morrow-sign keygen --domain example.com          make a key pair on this machine
    morrow-sign register example.com-mk-xxxx.morrow-pub.json   register the PUBLIC key with Morrow
    morrow-sign sign dist/app-1.2.0.tar.gz --key K.morrow-key [--upload]
    morrow-sign sign-site ./public --key K.morrow-key [--upload]
    morrow-sign verify app-1.2.0.tar.gz              check a file (uses app-1.2.0.tar.gz.morrow-sig)
    morrow-sign badge --domain example.com           the HTML for the verify badge

The private key never leaves this machine: Morrow receives public keys, signatures and SHA-512
hashes, never a private key and never a signed file.

Environment: MORROW_SIGN_SERVER (default https://morrow.soqlab.com), MORROW_SIGN_TOKEN (an admin
API key or console token, for register), MORROW_SIGN_UPLOAD_KEY (an upload key, for --upload),
MORROW_SIGN_PASSPHRASE (the private key's passphrase, for unattended signing).
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from . import __version__
from .core import (SignError, SigningKey, assess, check_signature_shape, generate, hash_file, manifest_bytes,
                   normalize_domain, offline_key, parse_manifest, site_entries)

DEFAULT_SERVER = "https://morrow.soqlab.com"
TIMEOUT = 30


# ── io ───────────────────────────────────────────────────────────────────────

def _server(args: argparse.Namespace) -> str:
    return str(getattr(args, "server", None) or os.environ.get("MORROW_SIGN_SERVER") or DEFAULT_SERVER).rstrip("/")


def _request(method: str, url: str, body: Optional[Dict[str, Any]] = None, token: str = "") -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json", "User-Agent": f"morrow-sign/{__version__}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (the URL is the configured server)
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail")
        except Exception:
            detail = None
        raise SignError(f"Morrow answered {exc.code}: {detail or exc.reason}") from None
    except urllib.error.URLError as exc:
        raise SignError(f"Could not reach {url.split('/api/')[0].split('/pq-signing')[0]}: {exc.reason}") from None


def _read_json(path: str, what: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise SignError(f"There is no {what} at {path}.") from None
    except ValueError:
        raise SignError(f"{path} is not a {what} (not JSON).") from None


def _write_json(path: str, doc: Dict[str, Any], private: bool = False) -> None:
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if private:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)


def _passphrase(args: argparse.Namespace, confirm: bool) -> Optional[str]:
    env = os.environ.get("MORROW_SIGN_PASSPHRASE")
    if env:
        return env
    if getattr(args, "no_passphrase", False) or not sys.stdin.isatty():
        return None
    first = getpass.getpass("Passphrase for the private key (empty for none): ")
    if confirm and first and getpass.getpass("Again: ") != first:
        raise SignError("The passphrases differ.")
    return first or None


def _load_key(args: argparse.Namespace) -> SigningKey:
    doc = _read_json(args.key, "private key file")
    passphrase = None
    if doc.get("encrypted") is not None:
        passphrase = os.environ.get("MORROW_SIGN_PASSPHRASE") or (
            getpass.getpass("Passphrase for the private key: ") if sys.stdin.isatty() else None)
    return SigningKey(doc, passphrase)


def _upload(args: argparse.Namespace, signature: Dict[str, Any], entries: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    token = os.environ.get("MORROW_SIGN_UPLOAD_KEY") or ""
    if not token:
        raise SignError("--upload needs MORROW_SIGN_UPLOAD_KEY: create an upload key in Morrow under Signing.")
    body: Dict[str, Any] = {"signature": signature}
    if entries is not None:
        body["entries"] = entries
    return _request("POST", _server(args) + "/pq-signing/signatures", body, token)


def _out(args: argparse.Namespace, text: str) -> None:
    if not getattr(args, "json", False):
        print(text)


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_keygen(args: argparse.Namespace) -> int:
    domain = normalize_domain(args.domain)
    passphrase = _passphrase(args, confirm=True)
    private, public = generate(domain, passphrase)
    stem = args.out or os.path.join(args.dir or ".", f"{domain}-{public['key']}")
    key_path, pub_path = stem + ".morrow-key", stem + ".morrow-pub.json"
    if os.path.exists(key_path):
        raise SignError(f"{key_path} already exists; not overwriting a private key.")
    _write_json(key_path, private, private=True)
    _write_json(pub_path, public)
    if args.json:
        print(json.dumps({"key": public["key"], "domain": domain, "private_key_file": key_path,
                          "public_key_file": pub_path, "encrypted": bool(passphrase)}))
    else:
        print(f"Key {public['key']} for {domain} (ML-DSA-65 + Ed25519).")
        print(f"  private key: {key_path}  keep it secret{'' if passphrase else ', it has no passphrase'}; never upload or commit it")
        print(f"  public key:  {pub_path}  register it: morrow-sign register {pub_path}")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    public = _read_json(args.public_key, "public key file")
    if "secret" in public or "encrypted" in public:
        raise SignError("That is a PRIVATE key file. Register the .morrow-pub.json file; the private key never leaves "
                        "this machine.")
    token = os.environ.get("MORROW_SIGN_TOKEN") or ""
    if not token:
        raise SignError("register needs MORROW_SIGN_TOKEN: an admin API key for your organization. Or register the "
                        "key in the Morrow console, under Signing.")
    body: Dict[str, Any] = {"public_key": public, "label": args.label or ""}
    if args.rotates:
        body["rotates"] = args.rotates
    result = _request("POST", _server(args) + "/pq-signing/keys", body, token)
    key = result.get("key") or {}
    if args.json:
        print(json.dumps(result))
    else:
        print(f"Registered {key.get('key_id')} for {key.get('domain')}. Visitors see it at "
              f"{_server(args)}/verify/{key.get('domain')}")
        if result.get("retired"):
            print(f"Retired {result['retired'].get('key_id')}: it signs nothing new; what it signed before stays valid.")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    key = _load_key(args)
    results = []
    for path in args.files:
        digest, size = hash_file(path)
        sig = key.sign("file", os.path.basename(path), size, digest)
        sig_path = path + ".morrow-sig"
        _write_json(sig_path, sig)
        item: Dict[str, Any] = {"file": path, "signature_file": sig_path, "sha512": digest, "size": size}
        _out(args, f"Signed {path} -> {sig_path}")
        if args.upload:
            uploaded = _upload(args, sig)
            item["recorded"] = uploaded.get("signature", {}).get("id")
            item["verify_url"] = uploaded.get("verify_url")
            _out(args, f"  on the public record: {uploaded.get('verify_url')}")
        results.append(item)
    if args.json:
        print(json.dumps({"signed": results}))
    return 0


def cmd_sign_site(args: argparse.Namespace) -> int:
    key = _load_key(args)
    out = args.out or os.path.join(args.directory, "morrow-manifest.txt")
    entries = site_entries(args.directory, skip=[out, out + ".morrow-sig"])
    data = manifest_bytes(entries)
    with open(out, "wb") as handle:
        handle.write(data)
    sig = key.sign("manifest", args.name or f"{key.domain} site manifest", len(data), hashlib.sha512(data).hexdigest())
    _write_json(out + ".morrow-sig", sig)
    _out(args, f"Listed {len(entries)} files in {out} and signed it -> {out}.morrow-sig")
    result: Dict[str, Any] = {"manifest": out, "signature_file": out + ".morrow-sig", "files": len(entries)}
    if args.upload:
        uploaded = _upload(args, sig, entries)
        result["recorded"] = uploaded.get("signature", {}).get("id")
        _out(args, f"  on the public record: {_server(args)}/verify/{key.domain}")
    if args.json:
        print(json.dumps(result))
    return 0


def _public_record(args: argparse.Namespace, domain: str) -> Dict[str, Any]:
    return _request("GET", _server(args) + "/api/verify/" + urllib.parse.quote(domain) + "?limit=1")


def _find_record(args: argparse.Namespace, sig: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    found = _request("GET", f"{_server(args)}/api/verify/{urllib.parse.quote(sig['domain'])}/lookup?sha512={sig['sha512']}")
    for rec in found.get("signatures", []):
        if rec.get("ml_dsa_65") == sig["ml_dsa_65"] and rec.get("ed25519") == sig["ed25519"]:
            return rec
    return None


def _key_from(record: Dict[str, Any], sig: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return next((k for k in record.get("keys", []) if k.get("key_id") == sig["key"]), None)


def _verify_with_sig(args: argparse.Namespace, sig: Dict[str, Any], digest: str, size: int) -> Dict[str, Any]:
    check_signature_shape(sig)
    if args.public_key:
        key = offline_key(_read_json(args.public_key, "public key file"))
        if key["domain"] != sig["domain"]:
            raise SignError("The public key file is for another domain.")
        result = assess(sig, key if key["key_id"] == sig["key"] else None, None, digest, size)
        result["offline"] = True
        for c in result["checks"]:
            if c["check"] == "key":
                c["detail"] = "The signature names the key in the public key file." if c["ok"] else                     "The signature was made with another key than the one in the public key file."
        result["checks"] = [c for c in result["checks"] if c["check"] != "domain"]
        if result["valid"]:
            result["reason"] = "Valid post-quantum signature (checked offline)."
        return result
    record = _public_record(args, sig["domain"])
    return assess(sig, _key_from(record, sig), _find_record(args, sig), digest, size)


def cmd_verify(args: argparse.Namespace) -> int:
    digest, size = hash_file(args.file)
    sig_path = args.sig or (args.file + ".morrow-sig" if os.path.exists(args.file + ".morrow-sig") else None)
    if sig_path:
        result = _verify_with_sig(args, _read_json(sig_path, "signature file"), digest, size)
        result["via"] = "signature file"
    else:
        if not args.domain:
            raise SignError(f"No {args.file}.morrow-sig next to the file. Give --sig, or --domain to look the file up "
                            "on the domain's public record.")
        domain = normalize_domain(args.domain)
        base = f"{_server(args)}/api/verify/{urllib.parse.quote(domain)}"
        found = _request("GET", f"{base}/lookup?sha512={digest}")
        record = _public_record(args, domain)
        result = None
        for rec in found.get("signatures", []):
            sig = rec["document"]
            result = assess(sig, _key_from(record, sig), rec, digest, size)
            result["via"] = "public record"
            if result["valid"]:
                break
        if not (result and result["valid"]):
            for rec in found.get("in_manifests", []):
                full = _request("GET", f"{base}/signatures/{urllib.parse.quote(rec['id'])}")
                data = manifest_bytes(full.get("entries", []))
                listed = any(e["sha512"] == digest and e["size"] == size for e in parse_manifest(data))
                sig = full["document"]
                result = assess(sig, _key_from(record, sig), full, hashlib.sha512(data).hexdigest(), len(data))
                result["via"] = f"site manifest, as {rec.get('path')}"
                if not listed:
                    result["valid"] = False
                    result["reason"] = "The file is not in the signed manifest."
                if result["valid"]:
                    break
        if result is None:
            result = {"valid": False, "reason": f"{domain} has no signature on record for this file.", "checks": []}
    result["file"] = args.file
    result["sha512"] = digest
    if args.json:
        print(json.dumps(result))
    else:
        print(("VALID   " if result["valid"] else "INVALID ") + result["reason"])
        for c in result.get("checks", []):
            print(("  ok    " if c["ok"] else "  FAIL  ") + c["detail"])
        if result.get("offline"):
            print("  note  Checked offline against a public key file: revocation was not checked.")
    return 0 if result["valid"] else 1


def cmd_badge(args: argparse.Namespace) -> int:
    domain = normalize_domain(args.domain)
    base = _server(args)
    link = f"{base}/verify/{domain}"
    if args.file:
        digest, _ = hash_file(args.file)
        link += f"?sha512={digest}"
    print(f'<a href="{link}"><img src="{base}/verify/{domain}/badge.svg" '
          f'alt="Post-quantum signed. Verify on Morrow" height="20"></a>')
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="morrow-sign", description=__doc__.split("\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"morrow-sign {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, server: bool = True) -> None:
        p.add_argument("--json", action="store_true", help="print the result as JSON")
        if server:
            p.add_argument("--server", help=f"Morrow address (default $MORROW_SIGN_SERVER or {DEFAULT_SERVER})")

    p = sub.add_parser("keygen", help="make an ML-DSA-65 + Ed25519 key pair on this machine")
    p.add_argument("--domain", required=True, help="the verified domain the key will sign for")
    p.add_argument("--dir", help="where to write the two files (default: here)")
    p.add_argument("--out", help="file name stem instead of <domain>-<key id>")
    p.add_argument("--no-passphrase", action="store_true", help="do not ask for a passphrase")
    common(p, server=False)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("register", help="register a public key with Morrow (needs MORROW_SIGN_TOKEN)")
    p.add_argument("public_key", help="the .morrow-pub.json file keygen wrote")
    p.add_argument("--label", help="a name for the key, shown in the console")
    p.add_argument("--rotates", help="the key id this key replaces; that key is retired")
    common(p)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("sign", help="sign files; writes <file>.morrow-sig next to each")
    p.add_argument("files", nargs="+")
    p.add_argument("--key", required=True, help="the .morrow-key file")
    p.add_argument("--upload", action="store_true", help="put the signature (never the file) on the public record")
    common(p)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("sign-site", help="list a site's files with their SHA-512 and sign the list")
    p.add_argument("directory")
    p.add_argument("--key", required=True, help="the .morrow-key file")
    p.add_argument("--out", help="manifest path (default <directory>/morrow-manifest.txt)")
    p.add_argument("--name", help="what the manifest is called on the public record")
    p.add_argument("--upload", action="store_true", help="put the signature and the file list (paths, sizes, "
                                                          "hashes; never the files) on the public record")
    common(p)
    p.set_defaults(func=cmd_sign_site)

    p = sub.add_parser("verify", help="check a file against its signature and the domain's public record")
    p.add_argument("file")
    p.add_argument("--sig", help="the .morrow-sig file (default <file>.morrow-sig)")
    p.add_argument("--domain", help="look the file up on this domain's record when there is no .morrow-sig")
    p.add_argument("--public-key", help="check offline against a .morrow-pub.json (no revocation check)")
    common(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("badge", help="print the HTML for the verify badge")
    p.add_argument("--domain", required=True)
    p.add_argument("--file", help="link the badge to this file's signature")
    common(p)
    p.set_defaults(func=cmd_badge)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except SignError as exc:
        print(f"morrow-sign: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"morrow-sign: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
