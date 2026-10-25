"""
Vendor post-quantum Assessment Workflow

Active vendor assessment lifecycle: create questionnaires, send them to
vendors, record their responses, auto-score post-quantum readiness, and track
score trends over time.

No emails are sent here — callers are responsible for delivery (e.g.
via smtp_notify.py). This module handles data persistence and scoring.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Questionnaire template ────────────────────────────────────────────────────

QUESTIONNAIRE_TEMPLATE: List[Dict[str, Any]] = [
    {
        "id": "q1",
        "category": "Inventory",
        "question": "Has your organization completed a cryptographic inventory?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, fully completed", "points": 10},
            {"label": "Partially completed", "points": 5},
            {"label": "No", "points": 0},
            {"label": "Unknown", "points": 0},
        ],
    },
    {
        "id": "q2",
        "category": "Planning",
        "question": "Do you have a documented post-quantum migration roadmap?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, with timeline and milestones", "points": 10},
            {"label": "Yes, but without a timeline", "points": 5},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q3",
        "category": "Awareness",
        "question": "Are you tracking NIST post-quantum standardization (FIPS 203/204/205)?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, actively tracking and implementing", "points": 10},
            {"label": "Aware but not actively tracking", "points": 5},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q4",
        "category": "Timeline",
        "question": "What is your target date for full post-quantum migration?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Before 2027", "points": 10},
            {"label": "2027–2029", "points": 7},
            {"label": "2030 or later", "points": 3},
            {"label": "No target date set", "points": 0},
        ],
    },
    {
        "id": "q5",
        "category": "Implementation",
        "question": "Do you currently use any NIST-approved post-quantum algorithms?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, in production systems", "points": 10},
            {"label": "In testing or pilot deployments", "points": 7},
            {"label": "Planning to implement", "points": 3},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q6",
        "category": "Threat Model",
        "question": "Do you have a harvest-now-decrypt-later (HNDL) threat assessment?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, formally documented", "points": 10},
            {"label": "Informal awareness only", "points": 5},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q7",
        "category": "Risk",
        "question": "Are long-lived secrets (>5 years) protected against quantum threat?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, all long-lived secrets are protected", "points": 10},
            {"label": "Most are protected", "points": 6},
            {"label": "Some are protected", "points": 3},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q8",
        "category": "TLS",
        "question": "Do your TLS configurations support TLS 1.3 everywhere?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, 100% of endpoints", "points": 10},
            {"label": "80–99% of endpoints", "points": 7},
            {"label": "50–79% of endpoints", "points": 3},
            {"label": "Below 50%", "points": 0},
        ],
    },
    {
        "id": "q9",
        "category": "Legacy",
        "question": "Have you deprecated MD5, SHA-1, DES, 3DES, and RC4?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, fully deprecated everywhere", "points": 10},
            {"label": "Mostly deprecated (>90%)", "points": 6},
            {"label": "Partially deprecated", "points": 3},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q10",
        "category": "Agility",
        "question": (
            "Do you have a crypto agility policy (ability to swap algorithms "
            "without re-architecture)?"
        ),
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, formally documented and tested", "points": 10},
            {"label": "Informal / ad-hoc approach", "points": 5},
            {"label": "No", "points": 0},
        ],
    },
    {
        "id": "q11",
        "category": "Cert Mgmt",
        "question": "Are certificate lifecycles monitored with automated renewal?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, fully automated", "points": 10},
            {"label": "Manual monitoring only", "points": 5},
            {"label": "Ad-hoc / reactive", "points": 2},
            {"label": "No monitoring", "points": 0},
        ],
    },
    {
        "id": "q12",
        "category": "Audits",
        "question": "Do you conduct annual third-party cryptographic audits?",
        "scoring_weight": 1.0,
        "options": [
            {"label": "Yes, annually", "points": 10},
            {"label": "Every 2–3 years", "points": 6},
            {"label": "Ad-hoc when needed", "points": 3},
            {"label": "Never", "points": 0},
        ],
    },
]

# Maximum possible raw score across all questions
_MAX_SCORE = sum(
    max(opt["points"] for opt in q["options"]) * q["scoring_weight"]
    for q in QUESTIONNAIRE_TEMPLATE
)


# ── DDL ───────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS vendor_assessments (
    id                  TEXT PRIMARY KEY,
    organization_id     TEXT NOT NULL,
    vendor_name         TEXT NOT NULL,
    vendor_email        TEXT,
    contact_name        TEXT,
    status              TEXT NOT NULL DEFAULT 'draft',
    questionnaire       TEXT NOT NULL DEFAULT '[]',
    responses           TEXT NOT NULL DEFAULT '{}',
    score               INTEGER NOT NULL DEFAULT 0,
    risk_level          TEXT NOT NULL DEFAULT 'unknown',
    sent_at             TEXT,
    responded_at        TEXT,
    scored_at           TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    notes               TEXT
);

CREATE TABLE IF NOT EXISTS vendor_assessment_history (
    id              TEXT PRIMARY KEY,
    assessment_id   TEXT NOT NULL REFERENCES vendor_assessments(id),
    organization_id TEXT NOT NULL,
    score           INTEGER NOT NULL,
    risk_level      TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vendor_assessments_org
    ON vendor_assessments(organization_id);
CREATE INDEX IF NOT EXISTS idx_vendor_assessments_status
    ON vendor_assessments(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_vendor_history_assessment
    ON vendor_assessment_history(assessment_id);
"""


def init_tables(conn: sqlite3.Connection) -> None:
    """Create vendor assessment tables if they do not exist."""
    with closing(conn.cursor()) as cur:
        cur.executescript(_DDL)
    conn.commit()


# ── Helper ────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(cur: sqlite3.Cursor, row: tuple) -> Dict[str, Any]:
    cols = [d[0] for d in cur.description]
    rec = dict(zip(cols, row))
    # Deserialise JSON columns
    for col in ("questionnaire", "responses"):
        if col in rec and rec[col]:
            try:
                rec[col] = json.loads(rec[col])
            except (json.JSONDecodeError, TypeError):
                rec[col] = {} if col == "responses" else []
    return rec


def _risk_from_score(score: int) -> str:
    """Map numeric score (0-100) to risk label."""
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


# ── Public API ────────────────────────────────────────────────────────────────

def get_questionnaire_template() -> List[Dict[str, Any]]:
    """Return the canonical questionnaire template."""
    return QUESTIONNAIRE_TEMPLATE


def create_assessment(
    conn: sqlite3.Connection,
    org_id: str,
    vendor_name: str,
    vendor_email: str,
    contact_name: str,
    notes: str = "",
) -> Dict[str, Any]:
    """
    Create a new vendor assessment in 'draft' status with the default
    questionnaire template embedded.
    """
    assessment_id = str(uuid.uuid4())
    now = _now()

    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            INSERT INTO vendor_assessments
                (id, organization_id, vendor_name, vendor_email, contact_name,
                 status, questionnaire, responses, score, risk_level,
                 created_at, updated_at, notes)
            VALUES (?, ?, ?, ?, ?, 'draft', ?, '{}', 0, 'unknown', ?, ?, ?)
            """,
            (
                assessment_id,
                org_id,
                vendor_name,
                vendor_email,
                contact_name,
                json.dumps(QUESTIONNAIRE_TEMPLATE),
                now,
                now,
                notes,
            ),
        )
    conn.commit()

    return get_assessment(conn, assessment_id, org_id)  # type: ignore[return-value]


def send_assessment(
    conn: sqlite3.Connection,
    assessment_id: str,
    org_id: str,
) -> Dict[str, Any]:
    """
    Mark an assessment as 'sent' and record the sent timestamp.

    The caller is responsible for actually delivering the questionnaire
    (e.g. via smtp_notify.send_email).

    Raises ValueError if the assessment is not found or is not in draft status.
    """
    now = _now()
    with closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT status FROM vendor_assessments WHERE id = ? AND organization_id = ?",
            (assessment_id, org_id),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"Assessment {assessment_id} not found")
        if row[0] not in ("draft", "sent"):
            raise ValueError(
                f"Cannot send assessment in status '{row[0]}'. "
                "Only draft or previously-sent assessments may be re-sent."
            )

        cur.execute(
            """
            UPDATE vendor_assessments
            SET status = 'sent', sent_at = ?, updated_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (now, now, assessment_id, org_id),
        )
    conn.commit()
    return get_assessment(conn, assessment_id, org_id)  # type: ignore[return-value]


def record_responses(
    conn: sqlite3.Connection,
    assessment_id: str,
    org_id: str,
    responses: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Save vendor responses and mark assessment as 'responded'.

    responses: dict mapping question id (e.g. "q1") to the selected
               option label or its point value.

    Raises ValueError if the assessment is not found.
    """
    if not isinstance(responses, dict):
        raise ValueError("responses must be a dict")

    now = _now()
    with closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT id FROM vendor_assessments WHERE id = ? AND organization_id = ?",
            (assessment_id, org_id),
        )
        if cur.fetchone() is None:
            raise ValueError(f"Assessment {assessment_id} not found")

        cur.execute(
            """
            UPDATE vendor_assessments
            SET responses = ?, status = 'responded', responded_at = ?, updated_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (json.dumps(responses), now, now, assessment_id, org_id),
        )
    conn.commit()
    return get_assessment(conn, assessment_id, org_id)  # type: ignore[return-value]


def score_assessment(
    conn: sqlite3.Connection,
    assessment_id: str,
    org_id: str,
) -> Dict[str, Any]:
    """
    Calculate a 0-100 score from the vendor's responses.

    Scoring logic:
      For each question, find the option whose label (or point value as str)
      matches the recorded response. Multiply its points by the question's
      scoring_weight. Sum across all questions. Normalise to 0-100.

    Saves a history snapshot and marks status as 'scored'.

    Raises ValueError if the assessment is not found or has no responses.
    """
    now = _now()
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT responses, questionnaire
            FROM vendor_assessments
            WHERE id = ? AND organization_id = ?
            """,
            (assessment_id, org_id),
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError(f"Assessment {assessment_id} not found")

        try:
            responses: Dict[str, Any] = json.loads(row[0] or "{}")
            questionnaire: List[Dict[str, Any]] = json.loads(row[1] or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Corrupt assessment data: {exc}") from exc

    if not responses:
        raise ValueError("No responses recorded — cannot score assessment")

    if not questionnaire:
        questionnaire = QUESTIONNAIRE_TEMPLATE

    # Calculate raw score
    raw_score = 0.0
    max_possible = 0.0

    for question in questionnaire:
        qid = question["id"]
        weight = float(question.get("scoring_weight", 1.0))
        options = question.get("options", [])
        q_max = max((opt["points"] for opt in options), default=0) * weight
        max_possible += q_max

        answer = responses.get(qid)
        if answer is None:
            continue

        # Match by label (string) or by points (int/str)
        matched_points = 0
        for opt in options:
            if answer == opt["label"] or str(answer) == str(opt["points"]):
                matched_points = opt["points"]
                break
        else:
            # If answer is a numeric string that directly represents points
            try:
                matched_points = int(answer)
                # Clamp to valid range
                valid = [opt["points"] for opt in options]
                if matched_points not in valid:
                    matched_points = 0
            except (ValueError, TypeError):
                matched_points = 0

        raw_score += matched_points * weight

    # Normalise to 0-100
    if max_possible > 0:
        normalised = int(round((raw_score / max_possible) * 100))
    else:
        normalised = 0

    normalised = max(0, min(100, normalised))
    risk_level = _risk_from_score(normalised)

    # Persist score
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            UPDATE vendor_assessments
            SET score = ?, risk_level = ?, status = 'scored', scored_at = ?, updated_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (normalised, risk_level, now, now, assessment_id, org_id),
        )

        # Snapshot in history
        cur.execute(
            """
            INSERT INTO vendor_assessment_history
                (id, assessment_id, organization_id, score, risk_level, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), assessment_id, org_id, normalised, risk_level, now),
        )

    conn.commit()
    return get_assessment(conn, assessment_id, org_id)  # type: ignore[return-value]


def list_assessments(
    conn: sqlite3.Connection,
    org_id: str,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return vendor assessments for an organisation, optionally filtered by status."""
    with closing(conn.cursor()) as cur:
        if status:
            cur.execute(
                """
                SELECT id, organization_id, vendor_name, vendor_email, contact_name,
                       status, score, risk_level, sent_at, responded_at, scored_at,
                       created_at, updated_at, notes
                FROM vendor_assessments
                WHERE organization_id = ? AND status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (org_id, status, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, organization_id, vendor_name, vendor_email, contact_name,
                       status, score, risk_level, sent_at, responded_at, scored_at,
                       created_at, updated_at, notes
                FROM vendor_assessments
                WHERE organization_id = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def get_assessment(
    conn: sqlite3.Connection,
    assessment_id: str,
    org_id: str,
) -> Optional[Dict[str, Any]]:
    """Return a single assessment including responses and questionnaire, or None."""
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT id, organization_id, vendor_name, vendor_email, contact_name,
                   status, questionnaire, responses, score, risk_level,
                   sent_at, responded_at, scored_at, created_at, updated_at, notes
            FROM vendor_assessments
            WHERE id = ? AND organization_id = ?
            """,
            (assessment_id, org_id),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return _row_to_dict(cur, row)


def update_assessment(
    conn: sqlite3.Connection,
    assessment_id: str,
    org_id: str,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """
    Update arbitrary fields on a vendor assessment.

    Permitted kwargs: vendor_name, vendor_email, contact_name, notes.
    Ignores unknown keys silently. Returns updated record or None if not found.
    """
    allowed = {"vendor_name", "vendor_email", "contact_name", "notes"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return get_assessment(conn, assessment_id, org_id)

    now = _now()
    updates["updated_at"] = now

    set_clause = ", ".join(f"{col} = ?" for col in updates)
    values = list(updates.values()) + [assessment_id, org_id]

    with closing(conn.cursor()) as cur:
        cur.execute(
            f"UPDATE vendor_assessments SET {set_clause} WHERE id = ? AND organization_id = ?",
            values,
        )
        if cur.rowcount == 0:
            return None

    conn.commit()
    return get_assessment(conn, assessment_id, org_id)


def archive_assessment(
    conn: sqlite3.Connection,
    assessment_id: str,
    org_id: str,
) -> bool:
    """
    Set an assessment status to 'archived'. Returns True on success.
    """
    now = _now()
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            UPDATE vendor_assessments
            SET status = 'archived', updated_at = ?
            WHERE id = ? AND organization_id = ?
            """,
            (now, assessment_id, org_id),
        )
        return cur.rowcount > 0


def get_vendor_history(
    conn: sqlite3.Connection,
    vendor_name: str,
    org_id: str,
) -> List[Dict[str, Any]]:
    """
    Return score history snapshots for a named vendor within an organisation.

    Useful for trend charts: each entry is one scored assessment snapshot.
    """
    with closing(conn.cursor()) as cur:
        cur.execute(
            """
            SELECT h.id, h.assessment_id, h.score, h.risk_level, h.recorded_at,
                   a.vendor_name, a.vendor_email
            FROM vendor_assessment_history h
            JOIN vendor_assessments a ON a.id = h.assessment_id
            WHERE a.organization_id = ? AND LOWER(a.vendor_name) = LOWER(?)
            ORDER BY h.recorded_at ASC
            """,
            (org_id, vendor_name),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
