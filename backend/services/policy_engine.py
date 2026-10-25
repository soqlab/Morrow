"""
Wave 15 — Policy-as-Code Engine
Define org post-quantum policies in YAML. Evaluate them against live scan/remediation data.
No external deps — uses stdlib yaml-alike (json for storage, simple evaluator).
"""
from __future__ import annotations
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

_DDL = [
    """CREATE TABLE IF NOT EXISTS morrow_policies (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        definition TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS policy_results (
        id TEXT PRIMARY KEY,
        policy_id TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        passed INTEGER NOT NULL DEFAULT 0,
        violations TEXT NOT NULL DEFAULT '[]',
        evaluated_at TEXT NOT NULL,
        asset_count INTEGER NOT NULL DEFAULT 0,
        violation_count INTEGER NOT NULL DEFAULT 0
    )""",
]

# ── Built-in policy templates ─────────────────────────────────────────────────

POLICY_TEMPLATES = [
    {
        "name": "No RSA < 4096 on production assets",
        "description": "All production assets must use RSA-4096 or stronger key algorithms.",
        "definition": {
            "rules": [
                {
                    "id": "rsa_key_size",
                    "description": "RSA keys must be 4096-bit or larger",
                    "field": "key_type",
                    "operator": "not_contains",
                    "value": "RSA2048",
                    "applies_to": {"environment": "production"},
                    "severity": "critical",
                }
            ]
        },
    },
    {
        "name": "TLS 1.3 required on all assets",
        "description": "All scanned assets must support TLS 1.3.",
        "definition": {
            "rules": [
                {
                    "id": "tls_version",
                    "description": "Assets must support TLS 1.3",
                    "field": "tls_version",
                    "operator": "equals",
                    "value": "TLSv1.3",
                    "severity": "high",
                }
            ]
        },
    },
    {
        "name": "No critical findings unresolved > 7 days",
        "description": "Critical severity findings must be remediated within 7 days.",
        "definition": {
            "rules": [
                {
                    "id": "critical_sla",
                    "description": "Critical findings SLA: 7 days",
                    "type": "sla",
                    "severity_filter": "critical",
                    "max_age_days": 7,
                    "severity": "critical",
                }
            ]
        },
    },
    {
        "name": "CRYSTALS-Kyber or Dilithium required post-2025",
        "description": "Assets must use NIST post-quantum approved algorithms: CRYSTALS-Kyber or CRYSTALS-Dilithium.",
        "definition": {
            "rules": [
                {
                    "id": "pq_algorithm",
                    "description": "Must use CRYSTALS-Kyber (ML-KEM) or CRYSTALS-Dilithium (ML-DSA)",
                    "field": "sig_algorithm",
                    "operator": "contains_any",
                    "value": ["CRYSTALS", "ML-KEM", "ML-DSA", "KYBER", "DILITHIUM"],
                    "severity": "high",
                    "grace_until": "2025-12-31",
                }
            ]
        },
    },
    {
        "name": "All assets must have an owner assigned",
        "description": "Every scanned asset must have an owner team assigned in the system.",
        "definition": {
            "rules": [
                {
                    "id": "owner_assigned",
                    "description": "Assets must have an owner",
                    "field": "owner",
                    "operator": "not_empty",
                    "severity": "medium",
                }
            ]
        },
    },
]


def init_tables(conn: sqlite3.Connection) -> None:
    for ddl in _DDL:
        conn.execute(ddl)
    conn.commit()


# ── Policy CRUD ───────────────────────────────────────────────────────────────

def create_policy(conn: sqlite3.Connection, org_id: str, name: str,
                  description: str, definition: Dict, enabled: bool = True) -> Dict:
    policy_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO morrow_policies (id, organization_id, name, description, definition, enabled, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (policy_id, org_id, name, description, json.dumps(definition), 1 if enabled else 0, now, now),
    )
    conn.commit()
    return get_policy(conn, policy_id)


def get_policy(conn: sqlite3.Connection, policy_id: str) -> Optional[Dict]:
    row = conn.execute(
        "SELECT id, organization_id, name, description, definition, enabled, created_at, updated_at FROM morrow_policies WHERE id=?",
        (policy_id,),
    ).fetchone()
    if not row:
        return None
    cols = ["id", "organization_id", "name", "description", "definition", "enabled", "created_at", "updated_at"]
    d = dict(zip(cols, row))
    d["definition"] = json.loads(d["definition"])
    d["enabled"] = bool(d["enabled"])
    return d


def list_policies(conn: sqlite3.Connection, org_id: str) -> List[Dict]:
    rows = conn.execute(
        """SELECT id, organization_id, name, description, definition, enabled, created_at, updated_at
           FROM morrow_policies WHERE organization_id=? ORDER BY created_at DESC""",
        (org_id,),
    ).fetchall()
    cols = ["id", "organization_id", "name", "description", "definition", "enabled", "created_at", "updated_at"]
    result = []
    for row in rows:
        d = dict(zip(cols, row))
        d["definition"] = json.loads(d["definition"])
        d["enabled"] = bool(d["enabled"])
        result.append(d)
    return result


def update_policy(conn: sqlite3.Connection, policy_id: str, org_id: str,
                  name: Optional[str] = None, description: Optional[str] = None,
                  definition: Optional[Dict] = None, enabled: Optional[bool] = None) -> Optional[Dict]:
    sets, vals = [], []
    now = datetime.now(timezone.utc).isoformat()
    if name is not None: sets.append("name=?"); vals.append(name)
    if description is not None: sets.append("description=?"); vals.append(description)
    if definition is not None: sets.append("definition=?"); vals.append(json.dumps(definition))
    if enabled is not None: sets.append("enabled=?"); vals.append(1 if enabled else 0)
    sets.append("updated_at=?"); vals.append(now)
    vals.extend([policy_id, org_id])
    conn.execute(f"UPDATE morrow_policies SET {','.join(sets)} WHERE id=? AND organization_id=?", vals)
    conn.commit()
    return get_policy(conn, policy_id)


def delete_policy(conn: sqlite3.Connection, policy_id: str, org_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM morrow_policies WHERE id=? AND organization_id=?", (policy_id, org_id)
    )
    conn.commit()
    return cur.rowcount > 0


# ── Policy evaluation ─────────────────────────────────────────────────────────

def _eval_rule(rule: Dict, assets: List[Dict], remediations: List[Dict]) -> List[Dict]:
    """Evaluate a single rule against assets/remediations. Returns violations."""
    violations = []
    rule_type = rule.get("type", "asset_field")
    now = datetime.now(timezone.utc)

    if rule_type == "sla":
        # SLA rule: count remediations with severity_filter older than max_age_days
        sev = rule.get("severity_filter", "critical")
        max_age = rule.get("max_age_days", 7)
        for rem in remediations:
            if (rem.get("severity") or "").lower() != sev.lower():
                continue
            created_str = rem.get("created_at") or rem.get("opened_at", "")
            if not created_str:
                continue
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                if created.tzinfo is None:
                    from datetime import timezone as _tz
                    created = created.replace(tzinfo=_tz.utc)
                age = (now.replace(tzinfo=timezone.utc) - created).days
                if age > max_age:
                    violations.append({
                        "asset": rem.get("asset_key", rem.get("id", "?")),
                        "field": "age_days",
                        "actual": age,
                        "expected": f"<= {max_age}",
                        "message": f"{sev.upper()} remediation open {age} days (SLA: {max_age})",
                    })
            except Exception:
                pass
        return violations

    # Asset field rules
    applies_to = rule.get("applies_to", {})
    field = rule.get("field", "")
    operator = rule.get("operator", "equals")
    expected = rule.get("value")
    grace_until = rule.get("grace_until")

    if grace_until:
        try:
            grace_dt = datetime.fromisoformat(grace_until)
            if grace_dt.tzinfo is None:
                grace_dt = grace_dt.replace(tzinfo=timezone.utc)
            if now.replace(tzinfo=timezone.utc) < grace_dt:
                return []  # still in grace period
        except Exception:
            pass

    for asset in assets:
        # Apply filter
        skip = False
        for filter_field, filter_val in applies_to.items():
            if str(asset.get(filter_field, "")).lower() != str(filter_val).lower():
                skip = True; break
        if skip:
            continue

        actual = asset.get(field, "")
        actual_str = str(actual or "")

        violated = False
        if operator == "equals":
            violated = actual_str.lower() != str(expected).lower()
        elif operator == "not_equals":
            violated = actual_str.lower() == str(expected).lower()
        elif operator == "contains":
            violated = str(expected).lower() not in actual_str.lower()
        elif operator == "not_contains":
            violated = str(expected).lower() in actual_str.lower()
        elif operator == "contains_any":
            violated = not any(v.lower() in actual_str.lower() for v in (expected or []))
        elif operator == "not_empty":
            violated = not actual_str.strip()
        elif operator == "is_empty":
            violated = bool(actual_str.strip())

        if violated:
            violations.append({
                "asset": asset.get("asset_key", asset.get("id", "?")),
                "field": field,
                "actual": actual_str[:100],
                "expected": str(expected)[:100],
                "message": f"{field} {operator} {expected}: got '{actual_str[:60]}'",
            })

    return violations


def evaluate_policy(conn: sqlite3.Connection, policy: Dict, org_id: str) -> Dict:
    """Evaluate a policy against current org data. Saves result to DB."""
    try:
        assets = [dict(r) for r in conn.execute(
            "SELECT * FROM scan_results WHERE organization_id=? LIMIT 2000", (org_id,)
        ).fetchall()]
    except Exception:
        assets = []

    try:
        remediations = [dict(r) for r in conn.execute(
            "SELECT * FROM remediations WHERE organization_id=? AND status != 'resolved' LIMIT 500",
            (org_id,),
        ).fetchall()]
    except Exception:
        remediations = []

    definition = policy.get("definition", {})
    rules = definition.get("rules", [])
    all_violations = []

    for rule in rules:
        v = _eval_rule(rule, assets, remediations)
        for violation in v:
            violation["rule_id"] = rule.get("id", "unknown")
            violation["rule_severity"] = rule.get("severity", "medium")
        all_violations.extend(v)

    passed = len(all_violations) == 0
    now = datetime.now(timezone.utc).isoformat()
    result_id = str(uuid.uuid4())

    try:
        conn.execute(
            """INSERT INTO policy_results
               (id, policy_id, organization_id, passed, violations, evaluated_at, asset_count, violation_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (result_id, policy["id"], org_id, 1 if passed else 0,
             json.dumps(all_violations[:200]), now, len(assets), len(all_violations)),
        )
        conn.commit()
    except Exception:
        pass

    return {
        "policy_id": policy["id"],
        "policy_name": policy["name"],
        "passed": passed,
        "violations": all_violations[:200],
        "violation_count": len(all_violations),
        "asset_count": len(assets),
        "evaluated_at": now,
    }


def get_policy_results(conn: sqlite3.Connection, org_id: str, limit: int = 50) -> List[Dict]:
    try:
        rows = conn.execute(
            """SELECT r.id, r.policy_id, p.name, r.passed, r.violation_count,
                      r.asset_count, r.evaluated_at
               FROM policy_results r
               JOIN morrow_policies p ON r.policy_id = p.id
               WHERE r.organization_id=? ORDER BY r.evaluated_at DESC LIMIT ?""",
            (org_id, limit),
        ).fetchall()
        cols = ["id", "policy_id", "policy_name", "passed", "violation_count",
                "asset_count", "evaluated_at"]
        result = []
        for row in rows:
            d = dict(zip(cols, row))
            d["passed"] = bool(d["passed"])
            result.append(d)
        return result
    except Exception:
        return []
