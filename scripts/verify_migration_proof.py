#!/usr/bin/env python3
"""Offline verifier for Morrow migration proofs.

Checks, without a Morrow account and without contacting any Morrow server, that a migration proof
was signed by a key you trust, that none of its fields were changed, that its contents are
internally consistent (vulnerable before, clean after, in that order, for the same asset), and --
optionally -- that the audit-journal entries it cites are present, unaltered and correctly chained
in a journal export.

Dependencies: the Python standard library and the 'cryptography' package (pip install cryptography).
ML-DSA-65 signatures need cryptography >= 47 built with OpenSSL >= 3.5 (the PyPI wheels are).

Usage:
    python verify_migration_proof.py proof.json --keys morrow-proof-keys.json
    python verify_migration_proof.py proof.json --pin <sha256 fingerprint of the Ed25519 key>
    python verify_migration_proof.py proof.json --keys keys.json --journal journal-export.json

Get the keys file from https://<morrow-host>/.well-known/morrow-proof-keys.json, through a channel
you trust (or compare its fingerprints with ones the organization gave you). Without --keys or
--pin the verifier can only show the document is intact under the key embedded in it, which anyone
could have generated; it then exits with status 3.

Exit status: 0 verified, 1 a check failed, 2 unreadable input, 3 intact but signer not trusted.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DOCUMENT_FORMAT = "morrow.migration-proof/v1"
ENVELOPE_FORMAT = "morrow.signed-migration-proof/v1"
KEYS_FORMAT = "morrow.proof-keys/v1"
JOURNAL_FORMAT = "morrow.audit-journal/v1"
SIGNING_CONTEXT = b"morrow.migration-proof.v1\n"
PASSING_RISK_LEVELS = ("none", "ok", "pass", "info", "low")
JOURNAL_HASH_FIELDS = ("prev_hash", "actor_id", "actor_role", "action", "resource_type", "resource_id",
                       "decision", "reason", "details_json", "created_at")
ALG_ED25519 = "Ed25519"
ALG_MLDSA65 = "ML-DSA-65"


class Report:
    def __init__(self) -> None:
        self.checks: List[Dict[str, Any]] = []
        self.trusted = False

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)

    @property
    def exit_code(self) -> int:
        if not self.ok:
            return 1
        return 0 if self.trusted else 3

    def as_dict(self) -> Dict[str, Any]:
        return {"verified": self.ok and self.trusted, "intact": self.ok, "signer_trusted": self.trusted,
                "checks": self.checks}


def canonical_bytes(value: Any) -> bytes:
    def reject_floats(v: Any) -> None:
        if isinstance(v, float):
            raise ValueError("signed documents never contain floats")
        if isinstance(v, dict):
            for x in v.values():
                reject_floats(x)
        elif isinstance(v, list):
            for x in v:
                reject_floats(x)

    reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _verify_one(alg: str, public_key: bytes, signature: bytes, message: bytes) -> Optional[bool]:
    """True/False for a checked signature, None when this installation cannot check the algorithm."""
    from cryptography.exceptions import InvalidSignature

    try:
        if alg == ALG_ED25519:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        if alg == ALG_MLDSA65:
            try:
                from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
            except ImportError:
                return None
            MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
    except InvalidSignature:
        return False
    except Exception:
        return False
    return None


def _b64(value: Any) -> bytes:
    return base64.b64decode(str(value or ""), validate=True)


def check_signatures(envelope: Dict[str, Any], report: Report, trusted_keys: Optional[List[Dict[str, Any]]],
                     pins: List[str], allow_unverifiable_pq: bool) -> None:
    doc = envelope.get("document") or {}
    message = SIGNING_CONTEXT + canonical_bytes(doc)
    doc_keys = {k.get("kid"): k for k in doc.get("signing_keys") or [] if isinstance(k, dict)}
    sigs = [s for s in envelope.get("signatures") or [] if isinstance(s, dict)]
    report.add("signatures present", bool(sigs), f"{len(sigs)} signature(s)")
    report.add("Ed25519 signature present", any(s.get("alg") == ALG_ED25519 for s in sigs))
    signed_kids = {s.get("kid") for s in sigs}
    report.add("every key named in the document signed it", set(doc_keys) <= signed_kids and bool(doc_keys),
               "document keys: " + ", ".join(sorted(str(k) for k in doc_keys)))

    trusted_by_kid = {k.get("kid"): k for k in trusted_keys or [] if isinstance(k, dict)}
    issued = _parse_time(doc.get("issued_at"))
    trusted_hits = 0
    for sig in sigs:
        kid, alg = sig.get("kid"), sig.get("alg")
        key = doc_keys.get(kid)
        if not report.add(f"signature {kid}: key is listed in the document", key is not None):
            continue
        if not report.add(f"signature {kid}: algorithm matches its key", key.get("alg") == alg, str(alg)):
            continue
        try:
            pub = _b64(key.get("public_key"))
            raw_sig = _b64(sig.get("signature"))
        except Exception:
            report.add(f"signature {kid}: decodable", False)
            continue
        fingerprint = hashlib.sha256(pub).hexdigest()
        report.add(f"signature {kid}: fingerprint matches public key", fingerprint == key.get("fingerprint_sha256"))
        result = _verify_one(str(alg), pub, raw_sig, message)
        if result is None:
            report.add(f"signature {kid} ({alg})", allow_unverifiable_pq,
                       "this installation cannot verify " + str(alg) + "; upgrade 'cryptography'"
                       + (" (skipped by --allow-unverifiable-pq)" if allow_unverifiable_pq else ""))
            continue
        report.add(f"signature {kid} ({alg}) is valid", result)
        if not result:
            continue
        trusted = None
        if trusted_keys is not None:
            trusted = trusted_by_kid.get(kid)
            if trusted is not None:
                same = trusted.get("public_key") == key.get("public_key") and trusted.get("alg") == alg
                report.add(f"signature {kid}: key matches the trusted key file", same)
                if not same:
                    continue
                start = _parse_time(trusted.get("valid_from"))
                end = _parse_time(trusted.get("valid_until")) if trusted.get("valid_until") else None
                in_window = issued is not None and (start is None or issued >= start) and (end is None or issued <= end)
                report.add(f"signature {kid}: issued while the key was valid", in_window,
                           f"valid {trusted.get('valid_from')} .. {trusted.get('valid_until') or 'now'}")
                if in_window:
                    trusted_hits += 1
        if fingerprint in pins:
            trusted_hits += 1
    if trusted_keys is not None or pins:
        report.trusted = report.add("signed by a trusted key", trusted_hits > 0,
                                    "no signature was made by a key in --keys/--pin" if trusted_hits == 0 else "")
    else:
        report.trusted = False


def _passed(scan: Dict[str, Any]) -> bool:
    risk = str(scan.get("risk_level") or "").strip().lower()
    findings = scan.get("findings_count")
    return (isinstance(findings, int) and findings == 0) or risk in PASSING_RISK_LEVELS


def check_consistency(envelope: Dict[str, Any], report: Report) -> None:
    doc = envelope.get("document") or {}
    report.add("envelope format", envelope.get("format") == ENVELOPE_FORMAT, str(envelope.get("format")))
    report.add("document format", doc.get("format") == DOCUMENT_FORMAT, str(doc.get("format")))
    subject = doc.get("subject") or {}
    finding = doc.get("finding") or {}
    before = doc.get("before_scan") or {}
    after = doc.get("after_scan") or {}
    asset = subject.get("asset_key")
    report.add("asset named", bool(asset), str(asset))
    report.add("before and after scans are of the same asset",
               before.get("asset_key") == asset and after.get("asset_key") == asset)
    report.add("remediation is verified_closed", finding.get("status") == "verified_closed")
    report.add("after scan is the remediation's verification scan",
               bool(after.get("scan_id")) and after.get("scan_id") == finding.get("verification_scan_id"))
    report.add("before scan observed the endpoint", before.get("scan_status") == "ok")
    report.add("after scan observed the endpoint", after.get("scan_status") == "ok")
    report.add("before scan shows the vulnerability", before.get("passed") is False and not _passed(before),
               f"risk={before.get('risk_level')} findings={before.get('findings_count')}")
    report.add("after scan is clean", after.get("passed") is True and _passed(after),
               f"risk={after.get('risk_level')} findings={after.get('findings_count')}")
    t_before, t_after = _parse_time(before.get("scanned_at")), _parse_time(after.get("scanned_at"))
    report.add("before scan precedes after scan", bool(t_before and t_after and t_before < t_after),
               f"{before.get('scanned_at')} -> {after.get('scanned_at')}")
    report.add("before and after scans differ", before.get("scan_id") != after.get("scan_id"))

    events = {e.get("event"): e for e in doc.get("timeline") or [] if isinstance(e, dict)}
    closed = _parse_time((events.get("verified_closed") or {}).get("at"))
    issued = _parse_time(doc.get("issued_at"))
    report.add("timeline records the closure", closed is not None)
    report.add("closure is not before the verification scan", bool(closed and t_after and closed >= t_after))
    report.add("timeline scans match the evidence",
               (events.get("vulnerable_scan") or {}).get("scan_id") == before.get("scan_id")
               and (events.get("verification_scan") or {}).get("scan_id") == after.get("scan_id"))
    times = [_parse_time(e.get("at")) for e in events.values() if e.get("at")]
    report.add("issued after every event", bool(issued) and all(t is not None and t <= issued for t in times))
    assertions = doc.get("assertions") or {}
    report.add("assertions", assertions == {"vulnerable_before": True, "clean_after": True, "verified_closed": True})

    journal = doc.get("journal") or {}
    report.add("journal belongs to the subject organization", journal.get("organization_id") == subject.get("organization_id"))
    entries = [e for e in journal.get("entries") or [] if isinstance(e, dict)]
    ids = [e.get("id") for e in entries]
    if not report.add("journal entry ids are integers", all(isinstance(i, int) and not isinstance(i, bool) for i in ids)):
        return
    report.add("journal entries are in chain order", ids == sorted(ids) and len(ids) == len(set(ids)))
    by_id = {e.get("id"): e for e in entries}
    linked = all(by_id[i]["entry_hash"] == by_id[i + 1]["prev_hash"] for i in by_id if i + 1 in by_id)
    report.add("adjacent journal entries link", linked)
    report.add("journal hashes are well formed",
               all(len(str(e.get("entry_hash") or "")) == 64 for e in entries))
    for name, event in events.items():
        ref = event.get("journal_entry_id")
        if ref is not None:
            report.add(f"timeline '{name}' cites a listed journal entry", ref in by_id)
    head = journal.get("head") or {}
    report.add("journal head covers the cited entries",
               not entries or (isinstance(head.get("id"), int) and head["id"] >= max(ids)))


def journal_entry_hash(entry: Dict[str, Any]) -> str:
    values = [str(entry.get(name) or "") for name in JOURNAL_HASH_FIELDS]
    values[JOURNAL_HASH_FIELDS.index("details_json")] = str(entry.get("details_json") or "{}")
    return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


def check_journal(envelope: Dict[str, Any], export: Dict[str, Any], report: Report) -> None:
    doc = envelope.get("document") or {}
    journal = doc.get("journal") or {}
    report.add("journal export format", export.get("format") == JOURNAL_FORMAT, str(export.get("format")))
    report.add("journal export is the proof's organization",
               export.get("organization_id") == journal.get("organization_id"))
    entries = [e for e in export.get("entries") or [] if isinstance(e, dict)]
    bad_hash, bad_link = [], []
    prev = None
    for e in entries:
        if journal_entry_hash(e) != e.get("entry_hash"):
            bad_hash.append(e.get("id"))
        if prev is not None and str(e.get("prev_hash") or "") != str(prev.get("entry_hash") or ""):
            bad_link.append(e.get("id"))
        prev = e
    report.add("every exported journal entry hashes correctly", not bad_hash, f"bad: {bad_hash[:10]}" if bad_hash else f"{len(entries)} entries")
    report.add("exported journal is an unbroken chain", not bad_link, f"breaks at: {bad_link[:10]}" if bad_link else "")
    report.add("exported journal starts at the beginning of the chain",
               bool(entries) and not str(entries[0].get("prev_hash") or ""),
               "" if entries and not entries[0].get("prev_hash") else "export is truncated; earlier entries are not covered")
    exported = {e.get("id"): e for e in entries}
    for cited in journal.get("entries") or []:
        got = exported.get(cited.get("id"))
        report.add(f"journal entry {cited.get('id')} ({cited.get('action')}) is in the export unchanged",
                   got is not None and got.get("entry_hash") == cited.get("entry_hash")
                   and got.get("prev_hash") == cited.get("prev_hash")
                   and got.get("action") == cited.get("action")
                   and got.get("resource_id") == cited.get("resource_id"))
    head = journal.get("head") or {}
    got = exported.get(head.get("id"))
    report.add("journal head at issuance is in the export", got is not None and got.get("entry_hash") == head.get("entry_hash"))


def verify(proof: Dict[str, Any], keys: Optional[Dict[str, Any]] = None, pins: Optional[List[str]] = None,
           journal: Optional[Dict[str, Any]] = None, allow_unverifiable_pq: bool = False) -> Report:
    report = Report()
    envelope = proof.get("proof") if isinstance(proof.get("proof"), dict) else proof
    trusted_keys = None
    if keys is not None:
        report.add("keys file format", keys.get("format") == KEYS_FORMAT, str(keys.get("format")))
        trusted_keys = [k for k in keys.get("keys") or [] if isinstance(k, dict)]
    try:
        check_signatures(envelope, report, trusted_keys, [p.strip().lower() for p in pins or []], allow_unverifiable_pq)
    except ValueError as exc:
        report.add("document is canonicalizable", False, str(exc))
    check_consistency(envelope, report)
    if journal is not None:
        check_journal(envelope, journal, report)
    return report


def _load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a Morrow migration proof offline.")
    ap.add_argument("proof", help="proof JSON (the API response or the signed envelope)")
    ap.add_argument("--keys", help="trusted keys file (/.well-known/morrow-proof-keys.json)")
    ap.add_argument("--pin", action="append", default=[], help="trusted public-key SHA-256 fingerprint (repeatable)")
    ap.add_argument("--journal", help="audit journal export (/audit/journal/export) to check cited entries against")
    ap.add_argument("--allow-unverifiable-pq", action="store_true",
                    help="do not fail when this installation cannot check the ML-DSA signature")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    args = ap.parse_args(argv)
    try:
        proof = _load(args.proof)
        keys = _load(args.keys) if args.keys else None
        journal = _load(args.journal) if args.journal else None
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = verify(proof, keys=keys, pins=args.pin, journal=journal, allow_unverifiable_pq=args.allow_unverifiable_pq)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        for c in report.checks:
            line = ("PASS " if c["ok"] else "FAIL ") + c["check"]
            if c["detail"]:
                line += f"  [{c['detail']}]"
            print(line)
        doc = (proof.get("proof") or proof).get("document") or {}
        print()
        if report.exit_code == 0:
            print(f"VERIFIED: {doc.get('proof_id')} for {(doc.get('subject') or {}).get('asset_key')}")
        elif report.exit_code == 3:
            print("INTACT BUT NOT TRUSTED: supply --keys or --pin to establish who signed this proof.")
        else:
            print("NOT VERIFIED")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
