"""Make it safe: Morrow Shield. For a host that is not quantum-safe and has no one-click fix, the plan
offers the docker run command for shield/ filled in for that host, what must be true and the honest
limits; "I've put it in front" is the same outside re-check and proof as Done.

No network: the grade and DNS are the fakes of test_make_safe_done.py.
"""
import json
import os
import re

import pytest

from services import make_safe as ms
from services import public_grade as _grade
from test_make_safe_done import HOST, cf, cf_dns, client, graded, isolated_store  # noqa: F401  (fixtures)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


@pytest.fixture(autouse=True)
def _store(isolated_store):  # noqa: F811
    yield


def elsewhere(host):
    """DNS that is not on Cloudflare: no one-click fix."""
    return {"cname": [], "addresses": ["192.0.2.10"], "ns": ["ns1.example.net", "ns2.example.net"], "ns_zone": "example.com"}


def test_a_host_on_its_own_server_with_dns_elsewhere_is_offered_shield():
    plan = ms.plan(HOST, graded(), lookup=elsewhere)
    assert plan["one_click"] is None
    sh = plan["shield"]
    assert sh["name"] == "Morrow Shield" and sh["one_click"] is False
    assert sh["command"].startswith("docker run -d --name morrow-shield ")
    assert f"-e SHIELD_DOMAINS={HOST} " in sh["command"]
    assert "-e SHIELD_UPSTREAM=http://host.docker.internal:8080" in sh["command"]
    assert "-p 443:8443 -p 80:8080" in sh["command"] and "--read-only" in sh["command"]
    assert sh["command"].rstrip().endswith(sh["image"]) and sh["image"].startswith("ghcr.io/soqlab/morrow-shield:")
    assert sh["verify_command"] == f"docker exec morrow-shield shield check {HOST}"
    assert any("Docker" in r for r in sh["requires"])
    assert any(f"DNS for {HOST}" in r for r in sh["requires"])
    assert any("80 and 443" in r for r in sh["requires"])
    assert sh["readme_url"].startswith("https://github.com/soqlab/Morrow/")


def test_an_unidentified_stack_is_offered_shield_too():
    plan = ms.plan(HOST, graded(server_software="", certificate={"issuer": ""}), lookup=elsewhere)
    assert plan["detected"]["stack"] == "unknown" and plan["shield"]


def test_no_shield_when_safe_or_when_one_click_applies_or_behind_an_edge(cf):  # noqa: F811
    assert ms.plan(HOST, graded(True), lookup=elsewhere)["shield"] is None
    grey = ms.plan(HOST, graded(), lookup=cf_dns)
    assert grey["one_click"] and grey["shield"] is None
    behind_cloudfront = lambda h: {**elsewhere(h), "cname": ["d111111abcdef8.cloudfront.net"]}  # noqa: E731
    assert ms.plan(HOST, graded(), lookup=behind_cloudfront)["shield"] is None


def test_shield_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("MORROW_MAKE_SAFE_SHIELD_ENABLED", "0")
    assert ms.plan(HOST, graded(), lookup=elsewhere)["shield"] is None


@pytest.mark.parametrize("host", ["a;rm -rf /.example", "$(id).example.com", "example.com`x`", "a b.example", "-x.example.com",
                                  "x" * 64 + ".example.com", "localhost", "*.example.com"])
def test_nothing_but_a_plain_hostname_reaches_the_command(host):
    assert ms.shield_offer(host, {"stack": "unknown"}, False) is None


def test_the_shield_data_names_its_sources_and_never_claims_one_click():
    data = ms.recipes()["shield"]
    assert data["sources"]
    for src in data["sources"]:
        assert src["url"].startswith("https://") and re.match(r"^\d{4}-\d{2}-\d{2}$", src["checked"]) and src["quote"]
    urls = " ".join(s["url"] for s in data["sources"])
    assert "go.dev/doc/go1.24" in urls and "letsencrypt.org" in urls and "acme/autocert" in urls
    text = json.dumps(data).lower()
    assert "not one click" in text
    # Every other mention of one click is a denial, never a promise.
    for m in re.finditer(r"one[ -]click", text):
        assert text[max(0, m.start() - 12):m.start()].rstrip().endswith(("not", "never")), text[m.start() - 40:m.end()]
    for word in ("trial", "upgrade", "pro plan", "premium"):
        assert word not in text


def test_the_command_matches_the_shield_image_and_readme():
    """The command Morrow shows is the one shield/README.md documents, for the image the workflow builds."""
    sh = ms.shield_offer("example.com", {"stack": "unknown"}, False)
    with open(os.path.join(ROOT, "shield", "README.md"), encoding="utf-8") as fh:
        readme = fh.read()
    assert sh["command"] in readme
    with open(os.path.join(ROOT, "shield", "Dockerfile"), encoding="utf-8") as fh:
        dockerfile = fh.read()
    assert "SHIELD_LISTEN=:8443" in dockerfile and "SHIELD_HTTP_LISTEN=:8080" in dockerfile and "USER 65532" in dockerfile
    with open(os.path.join(ROOT, ".github", "workflows", "shield.yml"), encoding="utf-8") as fh:
        workflow = fh.read()
    assert sh["image"].rsplit(":", 1)[0] in workflow and 'tags: ["shield-v*"]' in workflow


def test_the_image_keeps_the_recipes_file_with_the_shield_entry():
    """The Shield offer lives in data/make_safe_recipes.json, which .dockerignore lets back into the image."""
    with open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8") as fh:
        lines = [line.strip() for line in fh]
    assert "!backend/data/make_safe_recipes.json" in lines[lines.index("**/data/"):]
    assert "shield" in ms.recipes()


def test_put_it_in_front_then_the_same_recheck_ends_in_the_signed_proof(client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(ms, "_dns_lookup", elsewhere)
    _grade.store(graded())
    plan = client.get(f"/api/public/make-safe/{HOST}").json()
    assert plan["one_click"] is None and plan["shield"]["command"]

    def fake_check(domain, ip="", fresh=False, **_):  # the outside now reaches Shield
        result = graded(True, server_software="")
        _grade.store(result)
        return result

    monkeypatch.setattr(_grade, "check", fake_check)
    rc = client.post(f"/api/public/make-safe/{HOST}/recheck", json={"start": True}).json()
    assert rc["watch"]["status"] == "live" and rc["result"]["key_exchange"] == "X25519MLKEM768"
    env = client.get(rc["proof_url"] + ".json").json()
    assert ms.verify_envelope(env)["valid"] is True and env["document"]["status"] == "quantum_safe"
    assert client.get(f"/api/public/make-safe/{HOST}").json()["shield"] is None


def test_the_done_ui_offers_shield_as_one_command_and_runs_the_same_check():
    with open(os.path.join(HERE, "static", "make-safe-done.js"), encoding="utf-8") as fh:
        js = fh.read()
    assert "if (!oc && p.shield && !this.change) { this.shieldOffer(); return; }" in js
    assert "I\\u2019ve put it in front" in js and "One command and a DNS change, not one click." in js
    assert 'data-act="shield-copy"' in js and '"Copied"' in js
    assert "Honest limits" in js and "What must be true" in js
    # "I've put it in front" is the by-hand sequence: the same recheck, "Quantum-safe." and proof.
    assert "this.shield = true; this.opts.byHand = true;\r\n    this.run(null);" in js or \
        "this.shield = true; this.opts.byHand = true;\n    this.run(null);" in js
    with open(os.path.join(HERE, "static", "make-safe.js"), encoding="utf-8") as fh:
        ms_js = fh.read()
    assert "(p.one_click || p.shield) && window.MorrowDone" in ms_js
