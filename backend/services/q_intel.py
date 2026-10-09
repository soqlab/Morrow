"""
Q-Intel Engine — quantum hardware milestones and the Q-Day model

This module is the platform's single source of truth for "when could a
quantum computer break RSA/ECC?". The /qday/countdown endpoint, the HNDL
dashboard default year, the Q-Day forecast and the red-team simulation all
read their Q-Day years from ``q_day_reference()`` here.

It is a model, not a forecast. Every response that carries its output also
carries ``model_basis`` (see services/model_basis.py) listing the assumptions.

Model:
  available(year) = logistic_cap( baseline_lq * growth ** (year - baseline_year) )
  p_break(algo, year) = sigmoid( log2(available(year) / required(algo)) )

  baseline_lq      largest logical-qubit count among milestones (seeded or ingested)
  growth           10 ** (1/4) per year: the rate implied by IBM's published
                   fault-tolerance roadmap (~200 logical qubits in 2029, ~2,000 in 2033)
  required(RSA-n)  2n + 2 logical qubits (Häner, Roetteler, Svore 2017)
  required(ECC-n)  9n + 2*ceil(log2 n) + 10 logical qubits (Roetteler et al. 2017)

Seed milestones are shipped with the product (``is_seed`` = 1). Each figure
below was checked against the cited source in 2026-09; figures that could not
be verified are left as None rather than estimated.
"""

from __future__ import annotations

import math
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.model_basis import model_basis as _model_basis

MODEL_AS_OF = "2026-09"

# Bump when seed content changes. Seed rows carry deterministic ids with this
# prefix, so a database seeded by an older release is re-seeded in place.
_SEED_VERSION = "seed-v2"


# ── Seed milestones (verified public sources) ─────────────────────────────────
# qubit_count: physical qubits reported by the source.
# error_rate: two-qubit gate error reported by the source, or None if not stated.
# logical_qubits_eq: logical qubits the source reports demonstrating (0 if none).
_SEED_MILESTONES: List[Dict[str, Any]] = [
    {"date": "2019-10-23", "system": "Sycamore", "org": "Google", "qubit_count": 53,
     "error_rate": 0.0062, "logical_qubits_eq": 0.0, "significance": "high",
     "headline": "Google Sycamore (53 qubits) random-circuit-sampling experiment published in Nature",
     "source_url": "https://www.nature.com/articles/s41586-019-1666-5",
     "notes": "Error rate is the reported simultaneous two-qubit (CZ) error of 0.62%."},
    {"date": "2021-11-16", "system": "Eagle", "org": "IBM", "qubit_count": 127,
     "error_rate": None, "logical_qubits_eq": 0.0, "significance": "medium",
     "headline": "IBM unveils Eagle, a 127-qubit processor",
     "source_url": "https://newsroom.ibm.com/2021-11-16-IBM-Unveils-Breakthrough-127-Qubit-Quantum-Processor",
     "notes": ""},
    {"date": "2022-11-09", "system": "Osprey", "org": "IBM", "qubit_count": 433,
     "error_rate": None, "logical_qubits_eq": 0.0, "significance": "medium",
     "headline": "IBM unveils Osprey, a 433-qubit processor",
     "source_url": "https://newsroom.ibm.com/2022-11-09-IBM-Unveils-400-Qubit-Plus-Quantum-Processor-and-Next-Generation-IBM-Quantum-System-Two",
     "notes": ""},
    {"date": "2023-12-04", "system": "Condor", "org": "IBM", "qubit_count": 1121,
     "error_rate": None, "logical_qubits_eq": 0.0, "significance": "medium",
     "headline": "IBM introduces Condor, a 1,121-qubit processor",
     "source_url": "https://newsroom.ibm.com/2023-12-04-IBM-Debuts-Next-Generation-Quantum-Processor-IBM-Quantum-System-Two,-Extends-Roadmap-to-Advance-Era-of-Quantum-Utility",
     "notes": ""},
    {"date": "2023-12-04", "system": "Heron r1", "org": "IBM", "qubit_count": 133,
     "error_rate": None, "logical_qubits_eq": 0.0, "significance": "medium",
     "headline": "IBM introduces Heron (133 qubits), its highest-performing processor at the time",
     "source_url": "https://newsroom.ibm.com/2023-12-04-IBM-Debuts-Next-Generation-Quantum-Processor-IBM-Quantum-System-Two,-Extends-Roadmap-to-Advance-Era-of-Quantum-Utility",
     "notes": ""},
    {"date": "2023-12-06", "system": "Logical processor (neutral atoms)", "org": "Harvard / QuEra / MIT",
     "qubit_count": 280, "error_rate": None, "logical_qubits_eq": 48.0, "significance": "high",
     "headline": "Programmable processor runs circuits on up to 48 logical qubits encoded in 280 physical atoms",
     "source_url": "https://www.nature.com/articles/s41586-023-06927-3",
     "notes": "Bluvstein et al., Nature 2024. Logical qubits use [[8,3,2]] error-detecting code blocks."},
    {"date": "2024-09-10", "system": "H2 + qubit virtualization", "org": "Microsoft / Quantinuum",
     "qubit_count": 56, "error_rate": 0.002, "logical_qubits_eq": 12.0, "significance": "high",
     "headline": "Microsoft and Quantinuum create 12 logical qubits on Quantinuum's 56-qubit H2",
     "source_url": "https://azure.microsoft.com/en-us/blog/quantum/2024/09/10/microsoft-and-quantinuum-create-12-logical-qubits-and-demonstrate-a-hybrid-end-to-end-chemistry-simulation/",
     "notes": "Error rate is the reported 99.8% two-qubit fidelity of H2."},
    {"date": "2024-11-13", "system": "Heron r2", "org": "IBM", "qubit_count": 156,
     "error_rate": None, "logical_qubits_eq": 0.0, "significance": "medium",
     "headline": "IBM Heron r2 (156 qubits) runs circuits of up to 5,000 two-qubit gates",
     "source_url": "https://www.ibm.com/quantum/blog/qdc-2024",
     "notes": ""},
    {"date": "2024-11-19", "system": "Neutral-atom system + qubit virtualization", "org": "Microsoft / Atom Computing",
     "qubit_count": 112, "error_rate": None, "logical_qubits_eq": 28.0, "significance": "high",
     "headline": "Microsoft and Atom Computing entangle 24 logical qubits and compute with 28 logical qubits from 112 atoms",
     "source_url": "https://azure.microsoft.com/en-us/blog/quantum/2024/11/19/microsoft-and-atom-computing-offer-a-commercial-quantum-machine-with-the-largest-number-of-entangled-logical-qubits-on-record/",
     "notes": ""},
    {"date": "2024-12-09", "system": "Willow", "org": "Google", "qubit_count": 105,
     "error_rate": 0.0033, "logical_qubits_eq": 1.0, "significance": "critical",
     "headline": "Google Willow (105 qubits) runs a distance-7 surface-code logical memory below the error-correction threshold",
     "source_url": "https://arxiv.org/abs/2408.13687",
     "notes": "Error rate is the mean simultaneous CZ error (0.33%) from Google's Willow spec sheet."},
    {"date": "2025-02-19", "system": "Majorana 1", "org": "Microsoft", "qubit_count": 8,
     "error_rate": None, "logical_qubits_eq": 0.0, "significance": "medium",
     "headline": "Microsoft announces Majorana 1 with eight topological qubits; the physics community disputes the claim",
     "source_url": "https://azure.microsoft.com/en-us/blog/quantum/2025/02/19/microsoft-unveils-majorana-1-the-worlds-first-quantum-processor-powered-by-topological-qubits/",
     "notes": "Nature's editorial note on the accompanying paper says it does not by itself show Majorana zero modes: https://www.nature.com/articles/d41586-025-00683-2"},
]


# ── Logical qubits required per algorithm ─────────────────────────────────────
def _rsa_logical(n: int) -> float:
    return float(2 * n + 2)  # Häner, Roetteler, Svore 2017 (arXiv:1611.07995)


def _ecc_logical(n: int) -> float:
    return float(9 * n + 2 * math.ceil(math.log2(n)) + 10)  # Roetteler et al. 2017 (arXiv:1706.06752)


# pqc_* are sentinels: Shor's algorithm does not apply, so the model never
# assigns them a meaningful break probability.
_ALGO_LOGICAL_QUBITS_REQUIRED: Dict[str, float] = {
    "rsa2048":           _rsa_logical(2048),
    "rsa3072":           _rsa_logical(3072),
    "rsa4096":           _rsa_logical(4096),
    "ecc256":            _ecc_logical(256),
    "ecc384":            _ecc_logical(384),
    "x25519":            _ecc_logical(255),
    "dh_classical":      _rsa_logical(2048),
    "pqc_hybrid":        1e12,
    "pqc_pure":          1e12,
    "unknown_classical": _rsa_logical(2048),
}

_LQ_GROWTH_PER_YEAR = 10 ** 0.25  # ≈1.78×/yr: IBM roadmap, ~200 LQ (2029) → ~2,000 LQ (2033)
_LQ_CAP = 100_000.0               # logistic cap on projected logical qubits
_SIGMOID_SCALE_LOG2 = 1.0         # probability transition width, in doublings

_SOURCES = [
    "Häner, Roetteler, Svore 2017 — Factoring using 2n+2 qubits with Toffoli based modular multiplication: https://arxiv.org/abs/1611.07995",
    "Roetteler, Naehrig, Svore, Lauter 2017 — Quantum resource estimates for computing elliptic curve discrete logarithms: https://arxiv.org/abs/1706.06752",
    "IBM 2025 — IBM lays out clear path to fault-tolerant quantum computing (Starling ~200 logical qubits 2029; Blue Jay ~2,000 logical qubits 2033+): https://www.ibm.com/quantum/blog/large-scale-ftqc",
    "Gidney 2025 — How to factor 2048 bit RSA integers with less than a million noisy qubits: https://arxiv.org/abs/2505.15917",
]


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db():
    from db import get_connection
    return get_connection()


def _insert_seed_rows(conn) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for idx, m in enumerate(_SEED_MILESTONES):
        conn.execute(
            """INSERT OR IGNORE INTO q_intel_milestones
               (id, date, system, org, qubit_count, error_rate,
                logical_qubits_eq, significance, headline, source_url,
                notes, ingested_at, is_seed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (f"{_SEED_VERSION}-{idx:02d}", m["date"], m["system"], m["org"],
             m["qubit_count"],
             # 0 means "not reported"; the ingest API requires a positive rate,
             # so 0 is never a real measurement.
             m["error_rate"] if m["error_rate"] is not None else 0.0,
             m["logical_qubits_eq"], m["significance"], m["headline"],
             m["source_url"], m.get("notes") or "", now),
        )


def _ensure_tables() -> None:
    # Schema + seed reconciliation used to run (DDL, two COUNTs, two commits) on every model read.
    from db import mark_schema_ensured, schema_ensured
    if schema_ensured("q_intel_milestones"):
        return
    _ensure_tables_uncached()
    mark_schema_ensured("q_intel_milestones")


def _ensure_tables_uncached() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS q_intel_milestones (
                id              TEXT PRIMARY KEY,
                date            TEXT NOT NULL,
                system          TEXT NOT NULL,
                org             TEXT NOT NULL,
                qubit_count     INTEGER NOT NULL DEFAULT 0,
                error_rate      REAL NOT NULL DEFAULT 0.001,
                logical_qubits_eq REAL NOT NULL DEFAULT 0.0,
                significance    TEXT NOT NULL DEFAULT 'medium',
                headline        TEXT NOT NULL DEFAULT '',
                source_url      TEXT NOT NULL DEFAULT '',
                notes           TEXT NOT NULL DEFAULT '',
                ingested_at     TEXT NOT NULL,
                is_seed         INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qintel_date ON q_intel_milestones(date DESC)"
        )
        conn.commit()
        # Replace seed rows from older releases (they carried unverified figures).
        stale = conn.execute(
            "SELECT COUNT(*) FROM q_intel_milestones WHERE is_seed = 1 AND id NOT LIKE ?",
            (f"{_SEED_VERSION}-%",),
        ).fetchone()[0]
        current = conn.execute(
            "SELECT COUNT(*) FROM q_intel_milestones WHERE id LIKE ?",
            (f"{_SEED_VERSION}-%",),
        ).fetchone()[0]
        if stale:
            conn.execute("DELETE FROM q_intel_milestones WHERE is_seed = 1 AND id NOT LIKE ?",
                         (f"{_SEED_VERSION}-%",))
        if stale or current < len(_SEED_MILESTONES):
            _insert_seed_rows(conn)
        conn.commit()


def _seed_as_rows() -> List[Dict[str, Any]]:
    return [{**m, "is_seed": 1} for m in _SEED_MILESTONES]


def _load_milestones() -> List[Dict[str, Any]]:
    """All milestones, oldest first. Falls back to the shipped seeds if the DB is unavailable."""
    try:
        _ensure_tables()
        with closing(_db()) as conn:
            conn.row_factory = sqlite3.Row
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM q_intel_milestones ORDER BY date ASC"
            ).fetchall()]
        return rows or _seed_as_rows()
    except Exception:
        return _seed_as_rows()


# ── Core model ────────────────────────────────────────────────────────────────

def _sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0


def _baseline(milestones: List[Dict]) -> Dict[str, Any]:
    candidates = [m for m in milestones if (m.get("logical_qubits_eq") or 0) > 0]
    if not candidates:
        return {"logical_qubits": 0.0, "year": datetime.now(timezone.utc).year, "milestone": {}}
    best = max(candidates, key=lambda m: (m.get("logical_qubits_eq") or 0.0, str(m.get("date") or "")))
    try:
        year = int(str(best.get("date") or "")[:4])
    except ValueError:
        year = datetime.now(timezone.utc).year
    return {"logical_qubits": float(best.get("logical_qubits_eq") or 0.0), "year": year, "milestone": best}


def _effective_logical_qubits(year: float, milestones: List[Dict]) -> float:
    """Projected logical-qubit capacity in ``year`` (fractional years allowed)."""
    base = _baseline(milestones)
    best_lq = base["logical_qubits"]
    if best_lq <= 0:
        return 0.0
    years_ahead = float(year) - base["year"]
    if years_ahead <= 0:
        return best_lq
    projected = best_lq * (_LQ_GROWTH_PER_YEAR ** years_ahead)
    return _LQ_CAP * projected / (_LQ_CAP + projected)


def _p_break_algo(algo: str, effective_lq: float) -> float:
    required = _ALGO_LOGICAL_QUBITS_REQUIRED.get(algo, _ALGO_LOGICAL_QUBITS_REQUIRED["unknown_classical"])
    if effective_lq <= 0:
        return 0.0
    x = math.log2(effective_lq / required) / _SIGMOID_SCALE_LOG2
    return round(_sigmoid(x), 4)


def _first_year_at(algo: str, threshold: float, milestones: List[Dict],
                   start: int, end: int = 2080) -> Optional[int]:
    for yr in range(start, end + 1):
        if _p_break_algo(algo, _effective_logical_qubits(yr, milestones)) >= threshold:
            return yr
    return None


def q_day_crossing_year(algo: str = "rsa2048", threshold: float = 0.5,
                        milestones: Optional[List[Dict]] = None) -> Optional[float]:
    """Fractional year at which p_break(algo) first reaches ``threshold``."""
    ms = milestones if milestones is not None else _load_milestones()
    lo, hi = 2000.0, 2100.0
    if _p_break_algo(algo, _effective_logical_qubits(hi, ms)) < threshold:
        return None
    for _ in range(60):
        mid = (lo + hi) / 2.0
        if _p_break_algo(algo, _effective_logical_qubits(mid, ms)) < threshold:
            lo = mid
        else:
            hi = mid
    return round(hi, 2)


def model_basis_for(milestones: Optional[List[Dict]] = None) -> Dict[str, Any]:
    ms = milestones if milestones is not None else _load_milestones()
    base = _baseline(ms)
    bm = base["milestone"] or {}
    baseline_line = (
        f"Baseline: {base['logical_qubits']:g} logical qubits in {base['year']} "
        f"({bm.get('org', '')} — {bm.get('system', '')}), the largest count among the milestones on record; "
        "error-detected logical qubits are counted, which makes the projection earlier rather than later."
        if bm else "Baseline: no milestone with logical qubits on record, so the model projects no capacity."
    )
    return _model_basis(
        kind="model",
        summary=(
            "Q-Day years and probabilities are an illustrative projection from recorded hardware milestones "
            "and the stated growth assumption; they are not a prediction, an expert consensus, or a guarantee."
        ),
        assumptions=[
            baseline_line,
            "Logical-qubit capacity grows about 1.78x per year, the rate implied by IBM's published roadmap "
            "(~200 logical qubits in 2029 to ~2,000 in 2033); actual progress may be faster or slower.",
            "Breaking RSA-n needs 2n+2 logical qubits (4,098 for RSA-2048); ECC over an n-bit field needs "
            "9n+2*ceil(log2 n)+10 (2,330 for P-256). Classical DH and unknown algorithms are treated like RSA-2048.",
            "Break probability is a logistic curve in log2(available / required): 50% when capacity equals the requirement.",
            "Projected capacity is capped logistically at 100,000 logical qubits.",
            "Gate counts, runtime, error rates and newer algorithms that trade qubits for time (e.g. Gidney 2025) are not modelled.",
            "Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) are not attacked by Shor's algorithm and are held near zero.",
        ],
        sources=_SOURCES + [m.get("source_url") for m in ms if m.get("is_seed") and m.get("source_url")],
        as_of=MODEL_AS_OF,
    )


def q_day_reference(algo: str = "rsa2048", milestones: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """
    Reference Q-Day scenario years for ``algo``, shared by every consumer:
      accelerated_year   first year p_break >= 10%
      expected_year      first year p_break >= 50%
      conservative_year  first year p_break >= 90% (outer planning bound)
    """
    ms = milestones if milestones is not None else _load_milestones()
    start = min(2000, datetime.now(timezone.utc).year)
    return {
        "algorithm": algo,
        "accelerated_year": _first_year_at(algo, 0.10, ms, start),
        "expected_year": _first_year_at(algo, 0.50, ms, start),
        "conservative_year": _first_year_at(algo, 0.90, ms, start),
        "expected_crossing_year": q_day_crossing_year(algo, 0.5, ms),
        "thresholds": {"accelerated": 0.10, "expected": 0.50, "conservative": 0.90},
    }


def probability_curve(algo: str = "rsa2048", years: Optional[List[int]] = None,
                      milestones: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
    ms = milestones if milestones is not None else _load_milestones()
    now_year = datetime.now(timezone.utc).year
    years = years or list(range(now_year, now_year + 16))
    return [{"year": yr, "probability": _p_break_algo(algo, _effective_logical_qubits(yr, ms))}
            for yr in years]


def compute_q_day_model(years: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Compute current Q-Day probability curves for all algorithm classes.
    Returns curves updated based on latest ingested milestones.
    """
    milestones = _load_milestones()
    now_year = datetime.now(timezone.utc).year
    years = years or list(range(now_year, now_year + 16))

    curves: Dict[str, Dict[int, float]] = {}
    for algo in _ALGO_LOGICAL_QUBITS_REQUIRED:
        curves[algo] = {}
        for year in years:
            elq = _effective_logical_qubits(year, milestones)
            curves[algo][year] = _p_break_algo(algo, elq)

    # "Q-Day 50%" per algo, searched beyond the requested window so a short
    # window does not report None for a year that the model does reach.
    q_day_50_pct: Dict[str, Optional[int]] = {
        algo: _first_year_at(algo, 0.50, milestones, min(years) if years else now_year)
        for algo in curves
    }

    current_elq = _effective_logical_qubits(now_year, milestones)
    best_milestone = _baseline(milestones)["milestone"] or {}

    return {
        "curves": {algo: [{"year": yr, "probability": prob} for yr, prob in sorted(c.items())]
                   for algo, c in curves.items()},
        "q_day_50pct_estimates": q_day_50_pct,
        "current_effective_logical_qubits": round(current_elq, 1),
        "best_milestone": {
            "system": best_milestone.get("system", ""),
            "org": best_milestone.get("org", ""),
            "date": best_milestone.get("date", ""),
            "logical_qubits_eq": best_milestone.get("logical_qubits_eq", 0),
        },
        "milestone_count": len(milestones),
        "seed_milestone_count": sum(1 for m in milestones if m.get("is_seed")),
        "model_updated_at": datetime.now(timezone.utc).isoformat(),
        "rsa2048_q_day_50pct": q_day_50_pct.get("rsa2048"),
        "ecc256_q_day_50pct": q_day_50_pct.get("ecc256"),
        "reference_years": q_day_reference("rsa2048", milestones),
        "logical_qubits_required": dict(_ALGO_LOGICAL_QUBITS_REQUIRED),
        "model_basis": model_basis_for(milestones),
    }


def _feed_row(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    is_seed = bool(out.get("is_seed"))
    out["is_seed"] = is_seed
    out["kind"] = "seed" if is_seed else "ingested"
    if not out.get("error_rate"):
        out["error_rate"] = None  # not reported by the source
    return out


def feed_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="seed",
        summary=(
            "Rows marked is_seed are public milestones shipped with the product and checked against the linked "
            "source; other rows were ingested by your organization. This is not a live news feed."
        ),
        assumptions=[
            "logical_qubits_eq is the logical-qubit count the source reports demonstrating, including error-detected qubits.",
            "error_rate is the two-qubit gate error the source states; null means the source did not state one.",
        ],
        sources=[m["source_url"] for m in _SEED_MILESTONES],
        as_of=MODEL_AS_OF,
    )


def get_intelligence_feed(limit: int = 30) -> List[Dict[str, Any]]:
    """Return recent intelligence events sorted by date descending."""
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT * FROM q_intel_milestones
               ORDER BY date DESC, ingested_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_feed_row(dict(r)) for r in rows]


def ingest_milestone(
    date: str,
    system: str,
    org: str,
    qubit_count: int,
    error_rate: float,
    logical_qubits_eq: float,
    significance: str,
    headline: str,
    source_url: str = "",
    notes: str = "",
) -> Dict[str, Any]:
    """
    Ingest a new quantum computing milestone. Automatically recomputes Q-Day model.
    """
    _ensure_tables()
    mid = secrets.token_hex(8)
    now = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        conn.execute(
            """INSERT INTO q_intel_milestones
               (id, date, system, org, qubit_count, error_rate, logical_qubits_eq,
                significance, headline, source_url, notes, ingested_at, is_seed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (mid, date, system, org, qubit_count, error_rate, logical_qubits_eq,
             significance, headline, source_url or "", notes or "", now),
        )
        conn.commit()
    return {"id": mid, "date": date, "system": system, "org": org,
            "qubit_count": qubit_count, "ingested_at": now}


def get_q_day_probability(algo: str, year: int) -> float:
    """Quick lookup: what's the probability algo is broken by year?"""
    milestones = _load_milestones()
    elq = _effective_logical_qubits(year, milestones)
    return _p_break_algo(algo, elq)


def list_seed_milestones() -> List[Dict[str, Any]]:
    """Shipped seed milestones (no DB access)."""
    return [dict(m) for m in _SEED_MILESTONES]
