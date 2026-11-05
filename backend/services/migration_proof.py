"""Signed proof that a specific system was found vulnerable, fixed and re-verified clean.

A migration proof is issued only for a remediation in ``verified_closed`` state, and is built only
from Morrow's own records -- the remediation row, the per-asset ``scan_results`` rows, the stored
raw scan output and the hash-chained audit journal. Nothing in the request contributes content;
the only input is the remediation id, resolved inside the caller's organization.

The document is signed with the deployment's asymmetric key set (services/proof_signing.py), so an
auditor, insurer or customer can check it with ``scripts/verify_migration_proof.py`` and the public
keys from ``/.well-known/morrow-proof-keys.json`` -- no Morrow account, no call back to this server.

What the proof does and does not say
------------------------------------
* ``before_scan`` is the most recent successful scan of the asset, no later than the remediation
  was recorded (else the most recent one before the verification scan), that did not pass.
* ``after_scan`` is the scan named by the remediation's ``verification_scan_id``. It must have
  observed the endpoint (``scan_status == "ok"``) and passed by the same rule the verify loop uses
  to close the remediation. A verification scan that failed to connect is not evidence of a fix,
  so no proof is issued for it.
* ``journal.entries`` are the journal entries that record actions on this remediation and on the two
  scans. Each one's hash can be checked against a journal export (``/audit/journal/export``).
* Scanner version is reported when the stored raw scan result recorded it; older scans did not.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services import audit_chain, proof_signing

DOCUMENT_FORMAT = "morrow.migration-proof/v1"
ENVELOPE_FORMAT = "morrow.signed-migration-proof/v1"
#: Same rule db.auto_close_merged_remediations applies to close a merged remediation.
PASSING_RISK_LEVELS = ("none", "ok", "pass", "info", "low")
_READ_ACTION_SUFFIXES = (".get", ".list", ".read", ".pr_readiness", ".branch_cleanup_status",
                         ".migration_proof", ".export")


class ProofRefused(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _iso(value: Any) -> Optional[str]:
    """UTC ISO-8601 with a trailing Z, or None when the record holds no time."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _passed(row: Dict[str, Any]) -> bool:
    risk = str(row.get("risk_level") or "").strip().lower()
    try:
        findings = int(row.get("findings_count") or 0)
    except (TypeError, ValueError):
        findings = 0
    return findings == 0 or risk in PASSING_RISK_LEVELS


def _observed(row: Dict[str, Any]) -> bool:
    return str(row.get("scan_status") or "").strip().lower() == "ok"


def _text(value: Any) -> Optional[str]:
    s = str(value if value is not None else "").strip()
    return s or None


def _int(value: Any) -> Optional[int]:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n


def _raw_result(scan_id: str, asset_key: str) -> Optional[Dict[str, Any]]:
    from db import asset_key as make_asset_key, load_scan_row

    try:
        scan = load_scan_row(scan_id) or {}
    except Exception:
        return None
    for item in scan.get("results") or []:
        if not isinstance(item, dict):
            continue
        try:
            key = make_asset_key(str(item.get("host") or item.get("hostname") or ""), int(item.get("port") or 443))
        except (TypeError, ValueError):
            continue
        if key == asset_key:
            return item
    return None


def _evidence(row: Dict[str, Any], asset_key: str) -> Dict[str, Any]:
    raw = _raw_result(str(row.get("scan_id") or ""), asset_key)
    raw_digest = None
    scanner_version = None
    if raw is not None:
        raw_digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"),
                                               default=str).encode("utf-8")).hexdigest()
        scanner_version = _text(raw.get("scanner_version"))
    score = row.get("quantum_score")
    return {
        "scan_id": _text(row.get("scan_id")),
        "scanned_at": _iso(row.get("scanned_at")),
        "asset_key": asset_key,
        "scan_status": _text(row.get("scan_status")),
        "passed": _passed(row),
        "risk_level": _text(row.get("risk_level")),
        "findings_count": _int(row.get("findings_count")),
        "pq_relevance": _text(row.get("pq_relevance")),
        "quantum_score": None if score is None else str(score),
        "tls_version": _text(row.get("tls_version")),
        "key_exchange_group": _text(row.get("key_exchange")),
        "cipher": _text(row.get("cipher_name")),
        "certificate_key_type": _text(row.get("key_type")),
        "certificate_key_bits": _int(row.get("key_bits")),
        "certificate_key_curve": _text(row.get("key_curve")),
        "certificate_signature_algorithm": _text(row.get("sig_algorithm")),
        "scanner_version": scanner_version,
        "raw_result_sha256": raw_digest,
    }


def _pick_scans(rem: Dict[str, Any], history: List[Dict[str, Any]]):
    verification_scan_id = str(rem.get("verification_scan_id") or "").strip()
    if not verification_scan_id:
        raise ProofRefused(409, "the remediation has no verification scan on record")
    after = next((r for r in history if str(r.get("scan_id") or "") == verification_scan_id), None)
    if after is None:
        raise ProofRefused(409, "the verification scan's result for this asset is not on record")
    if not _observed(after):
        raise ProofRefused(409, "the verification scan did not observe the endpoint (scan_status is not ok); "
                                "a scan that could not connect is not evidence of a fix")
    if not _passed(after):
        raise ProofRefused(409, "the verification scan did not pass")
    after_at = _iso(after.get("scanned_at")) or ""
    created_at = _iso(rem.get("created_at")) or ""
    candidates = [r for r in history
                  if _observed(r) and not _passed(r) and (_iso(r.get("scanned_at")) or "") < after_at]
    candidates.sort(key=lambda r: _iso(r.get("scanned_at")) or "", reverse=True)
    before = next((r for r in candidates if (_iso(r.get("scanned_at")) or "") <= created_at), None)
    if before is None and candidates:
        before = candidates[0]
    if before is None:
        raise ProofRefused(409, "no recorded scan shows this asset in its vulnerable state before the fix")
    return before, after


def _journal(org_id: str, rem: Dict[str, Any], scan_ids: List[str]):
    entries = list(audit_chain.iter_entries(org_id))
    chain = audit_chain.verify_entries(entries)
    if not chain["ok"]:
        raise ProofRefused(409, "the audit journal fails verification; no proof is issued over a broken chain")
    rem_ids = {str(rem.get("id"))}
    if _text(rem.get("pr_url")):
        rem_ids.add(str(rem.get("pr_url")).strip())
    picked = []
    for e in entries:
        action = str(e.get("action") or "")
        if action.endswith(_READ_ACTION_SUFFIXES):
            continue
        rtype = str(e.get("resource_type") or "")
        rid = str(e.get("resource_id") or "")
        if (rtype == "remediation" and rid in rem_ids) or (rtype == "scan" and rid in scan_ids):
            picked.append({
                "id": int(e.get("id") or 0),
                "action": action,
                "resource_type": rtype,
                "resource_id": rid,
                "decision": _text(e.get("decision")),
                "actor_role": _text(e.get("actor_role")),
                "created_at": _iso(e.get("created_at")),
                "prev_hash": str(e.get("prev_hash") or ""),
                "entry_hash": str(e.get("entry_hash") or ""),
            })
    return picked, chain


def _first(entries: List[Dict[str, Any]], action: str, last: bool = False) -> Optional[Dict[str, Any]]:
    hits = [e for e in entries if e["action"] == action and e.get("decision") == "allow"]
    if not hits:
        return None
    return hits[-1] if last else hits[0]


def _timeline(rem, before, after, journal_entries):
    def ev(name, at, source, entry=None, **extra):
        item = {"event": name, "at": at, "source": source, "journal_entry_id": entry["id"] if entry else None}
        item.update(extra)
        return item

    approve = _first(journal_entries, "remediation.approve", last=True)
    pr = _first(journal_entries, "remediation.create_pr")
    merged_entry = _first(journal_entries, "remediation.mark_merged") or _first(journal_entries, "remediation.webhook_merged")
    closed_entry = _first(journal_entries, "remediation.verified_closed")
    events = [
        ev("finding_recorded", _iso(rem.get("created_at")), "remediation_record"),
        ev("vulnerable_scan", before["scanned_at"], "scan_results", scan_id=before["scan_id"]),
        ev("approved", approve["created_at"] if approve else None, "audit_journal", approve),
        ev("change_proposed", pr["created_at"] if pr else None, "audit_journal", pr, pr_url=_text(rem.get("pr_url"))),
        ev("merged", _iso(rem.get("merged_at")), "remediation_record", merged_entry),
        ev("verification_scan", after["scanned_at"], "scan_results", scan_id=after["scan_id"]),
        ev("verified_closed", _iso(rem.get("closed_at")), "remediation_record", closed_entry),
    ]
    return events


def build_proof(remediation_id: int, issuer: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from db import current_organization_id, get_asset_history, get_remediation

    org_id = current_organization_id()
    rem = get_remediation(int(remediation_id))
    if not rem:
        raise ProofRefused(404, "remediation not found")
    if str(rem.get("status") or "").strip().lower() != "verified_closed":
        raise ProofRefused(409, "a migration proof is issued only for a remediation in verified_closed state "
                                f"(this one is {str(rem.get('status') or 'unknown')})")
    asset_key = str(rem.get("asset_key") or "").strip()
    if not asset_key:
        raise ProofRefused(409, "the remediation names no asset")
    history = get_asset_history(asset_key, limit=200)
    before_row, after_row = _pick_scans(rem, history)
    before = _evidence(before_row, asset_key)
    after = _evidence(after_row, asset_key)
    journal_entries, chain = _journal(org_id, rem, [before["scan_id"], after["scan_id"]])

    try:
        keys = proof_signing.active_key_set(create=True)
    except proof_signing.SigningUnavailable as exc:
        raise ProofRefused(503, str(exc))
    if not keys:
        raise ProofRefused(503, "no proof signing key is available")

    host, _, port = asset_key.rpartition(":")
    proof_id = "mp-" + hashlib.sha256(f"{org_id}|{rem.get('id')}|{after['scan_id']}".encode("utf-8")).hexdigest()[:24]
    document = {
        "format": DOCUMENT_FORMAT,
        "proof_id": proof_id,
        "issued_at": _iso(datetime.now(timezone.utc)),
        "issuer": dict(issuer or {"product": "Morrow"}),
        "subject": {"organization_id": org_id, "asset_key": asset_key,
                    "host": host or asset_key, "port": _int(port)},
        "finding": {
            "remediation_id": int(rem.get("id") or 0),
            "vulnerability": _text(rem.get("vulnerability")),
            "file_path": _text(rem.get("file_path")),
            "repository": _text(rem.get("repository_name")),
            "pr_url": _text(rem.get("pr_url")),
            "status": "verified_closed",
            "verification_scan_id": after["scan_id"],
        },
        "before_scan": before,
        "after_scan": after,
        "timeline": _timeline(rem, before, after, journal_entries),
        "journal": {
            "organization_id": org_id,
            "hash_algorithm": "sha256",
            "hash_fields": list(audit_chain.HASH_FIELDS),
            "chain_verified_at_issuance": True,
            "entries_checked": chain["entries_checked"],
            "head": chain["head"],
            "entries": journal_entries,
        },
        "assertions": {"vulnerable_before": True, "clean_after": True, "verified_closed": True},
        "signing_keys": [proof_signing.public_descriptor(k) for k in keys],
    }
    message = proof_signing.canonical_bytes(document)
    try:
        signatures = proof_signing.sign(message, keys)
    except proof_signing.SigningUnavailable as exc:
        raise ProofRefused(503, str(exc))
    by_kid = {k["kid"]: k for k in keys}
    for sig in signatures:  # never hand out a proof this server cannot itself verify
        if not proof_signing.verify_signature(sig["alg"], by_kid[sig["kid"]]["public_key_b64"], sig["signature"], message):
            raise ProofRefused(500, "self-check of the proof signature failed")
    return {"format": ENVELOPE_FORMAT, "document": document, "signatures": signatures}
