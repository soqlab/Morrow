"""Board slide in one click (services/board_slide.py, routers/board_slide.py).

The content builder is tested case by case (no data, partial, full, each trend source, each deadline
state). Both formats are read back: the PPTX with the standard library's zip and XML readers (and
python-pptx when it is installed), the PDF by inflating its content streams. The API tests run the
real stack with the kill switch's fixture: members of every role download, other organizations
see nothing of it, and each download is one audit entry without the slide's content.
"""

import base64
import io
import re
import zipfile
import zlib
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import pytest

from test_invite_landing import api_fixture  # noqa: F401  (registers the "api" fixture)
from test_crypto_switch import audit_actions, bearer, stack  # noqa: F401  (stack is a fixture)

from services import board_slide as bs
from services import decrypt_window

NOW = datetime(2026, 11, 16, 9, 0, tzinfo=timezone.utc)
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"


def fact(key, kex="X25519", status="ok", at="2026-11-01T00:00:00Z"):
    return {"asset_key": key, "key_exchange": kex, "scan_status": status, "scanned_at": at}


FACTS = [fact("pay.acme.example:443"), fact("api.acme.example:443", "X25519MLKEM768"),
         fact("old.acme.example:443", "", "error", "2026-10-02T00:00:00Z")]
HISTORY = [fact("pay.acme.example:443", at="2026-09-03T00:00:00Z"), fact("api.acme.example:443", at="2026-09-03T00:00:00Z")] + FACTS
FIXES = [{"asset_key": "pay.acme.example:443", "host": "pay.acme.example",
          "top_findings": [{"remediation": "Enable TLS 1.3 on the termination layer."},
                           {"remediation": "Remove weak suites (RC4/3DES)."}]}]


def drill(at, likely, low, high):
    return {"created_at": at, "time_to_safe_days": likely, "days": {"low": low, "likely": likely, "high": high}, "broken": "X25519"}


# ── Reading the files back ──────────────────────────────────────────────────────────────────────


def pptx_parts(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        assert z.testzip() is None
        return {n: z.read(n) for n in z.namelist()}


def pptx_text(blob):
    slide = ET.fromstring(pptx_parts(blob)["ppt/slides/slide1.xml"])
    return " ".join(t.text or "" for t in slide.iter(f"{{{A}}}t"))


def pdf_text(blob):
    """The text a PDF shows: every content stream inflated, every string shown with Tj joined."""
    out = []
    for m in re.finditer(rb"\bstream\r?\n(.*?)endstream", blob, re.S):
        raw = m.group(1).strip()
        if raw.endswith(b"~>"):                                                     # reportlab: ASCII85, then Flate
            raw = base64.a85decode(raw, adobe=True)
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            pass
        for s in re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", raw):
            out.append(re.sub(rb"\\(.)", rb"\1", s).decode("cp1252"))
    return " ".join(out)


def check_pptx(blob):
    parts = pptx_parts(blob)
    slides = [n for n in parts if re.match(r"ppt/slides/slide\d+\.xml$", n)]
    assert slides == ["ppt/slides/slide1.xml"]
    assert not [n for n in parts if n.startswith("ppt/media/")]                     # no images, so no images of text
    for name, data in parts.items():
        if name.endswith((".xml", ".rels")):
            ET.fromstring(data)                                                     # every part is well-formed XML
    pres = ET.fromstring(parts["ppt/presentation.xml"])
    size = pres.find(f"{{{P}}}sldSz")
    assert (int(size.get("cx")), int(size.get("cy"))) == (12192000, 6858000)        # 16:9
    slide = ET.fromstring(parts["ppt/slides/slide1.xml"])
    assert not list(slide.iter(f"{{{P}}}pic"))
    try:
        from pptx import Presentation
    except ImportError:
        return parts
    prs = Presentation(io.BytesIO(blob))
    assert len(prs.slides) == 1 and prs.slide_width * 9 == prs.slide_height * 16
    names = [s.name for s in prs.slides[0].shapes]
    assert {"Deadline", "Risk sentence", "Next actions", "Sources"} <= set(names)
    assert all(s.has_text_frame for s in prs.slides[0].shapes if s.name in ("Deadline", "Risk sentence"))
    return parts


def check_pdf(blob):
    assert blob.startswith(b"%PDF-") and blob.rstrip().endswith(b"%%EOF")
    assert len(re.findall(rb"/Type\s*/Page\b(?!s)", blob)) == 1
    assert re.search(rb"/MediaBox\s*\[\s*0\s+0\s+960\s+540\s*\]", blob)           # one 16:9 page
    try:
        from pypdf import PdfReader
    except ImportError:
        return
    assert len(PdfReader(io.BytesIO(blob)).pages) == 1


# ── The content ─────────────────────────────────────────────────────────────────────────────────


def test_no_data_says_not_measured_and_invents_nothing():
    c = bs.build("Acme", [], [], [], [], [], now=NOW)
    assert c["risk"]["sentence"].startswith("Not measured yet") and c["risk"]["measured"] is False
    assert c["endpoints"] == {"total": 0, "safe": 0, "at_risk": 0, "unknown": 0, "statement": "No endpoint scanned yet"}
    assert c["trend"]["kind"] is None and c["trend"]["points"] == [] and "not measured yet" in c["trend"]["text"]
    assert c["actions"] == ["Scan the hosts you run. Morrow then shows which ones are at risk and the exact change for each."]
    assert "Scans: none yet" in c["sources"] and not any(s.startswith("Trend:") for s in c["sources"])
    # The data still has a lifetime (assumed, and labelled so), so the deadline is still an estimate with its source.
    assert c["headline"]["is_estimate"] is True and c["deadline"]["basis"]["assumed"] is True
    assert any("Quantum year: estimate 2035 to 2040" in s and "Global Risk Institute" in s for s in c["sources"])
    for render, check in ((bs.render_pptx, check_pptx), (bs.render_pdf, check_pdf)):
        check(render(c))
    assert "Not measured yet" in pptx_text(bs.render_pptx(c))


def test_partial_one_scan_no_history_no_fix_queue():
    c = bs.build("", FACTS[:1], [], [], [], FACTS[:1], now=NOW)
    assert c["risk"]["state"] == "at_risk" and "pay.acme.example today could be read from about 2035" in c["risk"]["sentence"]
    assert "Fix 1 setting" in c["risk"]["sentence"]                                # the key exchange itself
    assert c["endpoints"]["statement"] == "Quantum-safe key exchange on 0 of 1 scanned endpoint"
    assert c["trend"]["kind"] is None                                              # one month is not a trend
    assert c["actions"][0].startswith("Turn on a quantum-safe key exchange (hybrid ML-KEM) on pay.acme.example.")
    assert any("Confirm which kind of data" in a for a in c["actions"])            # the deadline assumed the data
    assert c["organization"] == "" and c["sources"][-1] == "Generated 2026-11-16 by Morrow"
    assert bs.filename(c, "pdf") == "board-slide-2026-11-16.pdf"


def test_full_measured_share_trend_actions_and_sources():
    c = bs.build("Acme Ltd", FACTS, [], FIXES, [], HISTORY, now=NOW)
    assert c["endpoints"]["safe"] == 1 and c["endpoints"]["at_risk"] == 1 and c["endpoints"]["unknown"] == 1
    assert c["endpoints"]["statement"] == "Quantum-safe key exchange on 1 of 2 scanned endpoints; 1 could not be read"
    assert "Fix 2 settings" in c["risk"]["sentence"]
    t = c["trend"]
    assert t["kind"] == "pq_share" and t["is_estimate"] is False and t["label"].startswith("Measured")
    assert [(p["label"], p["value"], p["safe"], p["of"]) for p in t["points"]] == [
        ("Sep 2026", 0, 0, 2), ("Oct 2026", 0, 0, 2), ("Nov 2026", 50, 1, 2)]
    assert t["text"] == ("Quantum-safe share of scanned endpoints, by month: Sep 2026: 0% (0 of 2); "
                         "Oct 2026: 0% (0 of 2); Nov 2026: 50% (1 of 2).")
    assert 1 <= len(c["actions"]) <= 3
    assert c["actions"] == [
        "Turn on a quantum-safe key exchange (hybrid ML-KEM) on pay.acme.example. Make it safe in Morrow gives the exact change for each server.",
        "Enable TLS 1.3 on the termination layer (pay.acme.example).",
        "Re-scan 1 endpoint Morrow could not read, so the picture is complete."]
    src = " | ".join(c["sources"])
    assert "Scans: 3 endpoints, newest scan 2026-11-01 (Morrow, measured)" in src
    assert "Shelf-Life v0.1" in src and "dated 20" in src
    assert "Trend: Morrow scans, Sep 2026 to 2026-11-16, measured" in src
    assert "Next actions: Morrow fix queue, newest scan 2026-11-01" in src
    assert c["sources"][-1] == "Generated 2026-11-16 by Morrow for Acme Ltd"
    assert bs.filename(c, "pptx") == "board-slide-acme-ltd-2026-11-16.pptx"


def test_deadline_is_mosca_on_the_harvest_clock_with_its_range():
    low, likely = decrypt_window.CRQC_ESTIMATE["low"], decrypt_window.CRQC_ESTIMATE["likely"]
    # Personal data (assumed) must stay private for decades: the deadline has passed.
    c = bs.build("", FACTS[:1], [], [], [], [], now=NOW)
    d = c["deadline"]
    assert d["status"] == "overdue" and c["headline"]["value"] == "Overdue" and d["secret_until"] == 2026 + d["years"]
    assert c["headline"]["range"] == f"overdue since {d['since']}; a quantum computer could read it from {low} to {likely}"
    assert d["since"] == likely - d["years"] and c["headline"]["time_to_safe"] is None
    # Passwords and keys (20 years, chosen): by year, the three states.
    for year, status, value in ((2010, "ahead", str(low - 20)), (2016, "due", "Now"), (2026, "overdue", "Overdue")):
        c = bs.build("", FACTS[:1], [], [], [], [], data="auth", now=datetime(year, 6, 1, tzinfo=timezone.utc))
        assert (c["deadline"]["status"], c["headline"]["value"]) == (status, value)
        assert c["deadline"]["years"] == 20 and c["deadline"]["basis"]["assumed"] is False
    assert bs.build("", FACTS[:1], [], [], [], [], data="auth", now=datetime(2010, 6, 1, tzinfo=timezone.utc))["headline"]["range"] == \
        f"{low - 20} to {likely - 20}"


def test_a_longer_lifetime_in_the_inventory_sets_the_deadline():
    assets = [{"asset_key": "pay.acme.example:443", "confidentiality_lifetime": "100 years", "updated_at": "2026-10-01T00:00:00Z"},
              {"asset_key": "x:443", "confidentiality_lifetime": "long-term"}]           # no number: not used
    c = bs.build("", FACTS[:1], assets, [], [], [], data="auth", now=NOW)
    assert c["deadline"]["years"] == 100 and c["deadline"]["basis"]["kind"] == "inventory"
    assert any('pay.acme.example:443, "100 years" (100 years), updated 2026-10-01' in s for s in c["sources"])
    assert bs.lifetime_years("10y+") == 10 and bs.lifetime_years("30 days") == 1 and bs.lifetime_years("long") is None


def test_every_endpoint_safe_is_met():
    facts = [fact("a.example:443", "X25519MLKEM768"), fact("b.example:443", "SecP256r1MLKEM768")]
    c = bs.build("", facts, [], [], [], [], now=NOW)
    assert c["risk"]["state"] == "safe" and "already quantum-safe" in c["risk"]["sentence"]
    assert c["headline"]["value"] == "Met" and c["headline"]["is_estimate"] is False
    assert c["actions"] == ["Run a fire drill to see how fast you could switch if an algorithm broke."]


def test_fire_drills_are_the_trend_without_two_months_of_scans_and_are_labelled_estimates():
    drills = [drill("2026-08-01T00:00:00Z", 24, 10, 60), drill("2026-11-01T00:00:00Z", 9, 4, 31)]
    c = bs.build("", FACTS[:1], [], [], drills, FACTS[:1], now=NOW)
    t = c["trend"]
    assert t["kind"] == "fire_drill" and t["is_estimate"] is True and "Estimate" in t["label"]
    assert [p["value"] for p in t["points"]] == [24, 9]
    assert "2026-11-01: about 9 days (estimate 4 to 31)" in t["text"]
    assert any(s == "Trend: Morrow fire drills, 2026-08-01 to 2026-11-01, estimates" for s in c["sources"])
    assert c["headline"]["time_to_safe"] == "Time to make it safe: about 9 days (fire drill estimate, 2026-11-01)"
    check_pptx(bs.render_pptx(c))
    check_pdf(bs.render_pdf(c))
    assert "Time to make it safe: about 9 days" in pptx_parts(bs.render_pptx(c))["ppt/slides/slide1.xml"].decode("utf-8")


def test_both_formats_carry_the_content_and_the_chart_has_a_text_alternative():
    c = bs.build("Acme <Ltd> & \"Co\"", FACTS, [], FIXES, [], HISTORY, now=NOW)
    pptx = bs.render_pptx(c)
    parts = check_pptx(pptx)
    text = pptx_text(pptx)
    for needle in ("Must be quantum-safe by", "Overdue", c["risk"]["sentence"], "Enable TLS 1.3 on the termination layer",
                   "Sources:", "Quantum Threat Timeline Report 2025", "Nov 2026", "50%", "Acme <Ltd> & \"Co\""):
        assert needle in text, needle
    slide = ET.fromstring(parts["ppt/slides/slide1.xml"])
    groups = [g for g in slide.iter(f"{{{P}}}grpSp")]
    assert len(groups) == 1
    alt = groups[0].find(f"{{{P}}}nvGrpSpPr/{{{P}}}cNvPr").get("descr")
    assert alt == c["trend"]["text"]
    core = ET.fromstring(parts["docProps/core.xml"])
    assert "Acme <Ltd>" in "".join(core.itertext())

    pdf = bs.render_pdf(c)
    check_pdf(pdf)
    words = re.sub(r"\s+", " ", pdf_text(pdf))
    for needle in ("Must be quantum-safe by", "Overdue", "pay.acme.example", "Enable TLS 1.3 on the termination layer",
                   "Sources:", "Quantum Threat Timeline Report 2025", "50%", "Nov 2026", "Nov 2026: 50% (1 of 2)."):
        assert needle in words, needle
    with pytest.raises(ValueError):
        bs.render(c, "docx")


# ── Over the API ────────────────────────────────────────────────────────────────────────────────


def test_every_member_downloads_both_formats(stack):  # noqa: F811  (pytest fixture injection)
    c = stack["client"]
    for who in ("viewer", "operator", "admin"):
        res = c.get("/board-slide/export.pptx", headers=stack[who])
        assert res.status_code == 200, res.text
        assert res.headers["content-type"] == bs.FORMATS["pptx"]
        assert res.headers["content-disposition"].startswith('attachment; filename="board-slide-acme-')
        assert res.headers["cache-control"] == "no-store"
        check_pptx(res.content)
        assert "old.acme.example" in pptx_text(res.content)                       # the one classical endpoint
        pdf = c.get("/v1/board-slide/export.pdf?data=health&jur=GB", headers=stack[who])
        assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
        check_pdf(pdf.content)
        assert "old.acme.example" in pdf_text(pdf.content)
    body = c.get("/board-slide?data=health&jur=GB", headers=stack["viewer"]).json()
    assert body["endpoints"]["total"] == 5 and body["endpoints"]["at_risk"] == 1
    assert body["organization"] == "Acme" and "health records" in body["risk"]["sentence"].lower()
    assert c.get("/board-slide/export.pptx").status_code == 401
    assert c.get("/board-slide/export.pdf", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_each_export_is_one_audit_entry_without_the_slides_content(stack):  # noqa: F811  (pytest fixture injection)
    import db

    c = stack["client"]
    before = audit_actions().count("board_slide.export")
    assert c.get("/board-slide/export.pptx", headers=stack["viewer"]).status_code == 200
    assert c.get("/board-slide/export.pdf", headers=stack["viewer"]).status_code == 200
    assert audit_actions().count("board_slide.export") == before + 2
    token = db.set_current_organization_id("org-acme")
    try:
        rows = [r for r in db.list_audit_logs(limit=500) if r["action"] == "board_slide.export"]
    finally:
        db.reset_current_organization_id(token)
    assert sorted(r["resource_id"] for r in rows[:2]) == ["pdf", "pptx"]
    assert all(r["decision"] == "allow" for r in rows)
    flat = repr(rows)
    assert "acme.example" not in flat and "quantum computer" not in flat and "Shelf-Life" not in flat


def test_another_organization_sees_only_its_own_slide(stack):  # noqa: F811  (pytest fixture injection)
    from test_invite_landing import make_org

    c = stack["client"]
    make_org(c, "org-beta", "Beta")
    beta = bearer(stack["app"], c, "viewer", "org-beta")
    body = c.get("/board-slide", headers=beta).json()
    assert body["organization"] == "Beta" and body["endpoints"]["total"] == 0
    assert body["risk"]["sentence"].startswith("Not measured yet")
    for fmt in ("pptx", "pdf"):
        res = c.get(f"/board-slide/export.{fmt}", headers=beta)
        assert res.status_code == 200 and "board-slide-beta-" in res.headers["content-disposition"]
        text = pptx_text(res.content) if fmt == "pptx" else pdf_text(res.content)
        assert "acme" not in text.lower() and "Not measured yet" in text
    assert audit_actions("org-beta").count("board_slide.export") == 2
    assert "Acme" in c.get("/board-slide", headers=stack["viewer"]).json()["organization"]


def test_a_support_view_cannot_download_it():
    from services import support_sessions

    for path in ("/board-slide/export.pptx", "/v1/board-slide/export.pdf"):
        assert support_sessions.denied_reason(support_sessions.normalize_path(path)) if hasattr(support_sessions, "normalize_path") \
            else support_sessions.denied_reason(path)


def test_the_console_offers_the_slide_and_both_copies_match():
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "static", "index.html"), "rb") as fh:
        console = fh.read()
    with open(os.path.join(here, "..", "frontend", "index.html"), "rb") as fh:
        assert fh.read() == console
    text = console.decode("utf-8")
    assert "/board-slide/export.${fmt}" in text and 'data-act="boardSlide" data-fmt="pptx"' in text
    assert 'sec("Why it matters"' in text and "boardSlideBtns());" in text           # Overview, next to Why it matters
    assert "<span style=\"flex:1\"></span>${boardSlideBtns()}" in text                # Board & ROI
