"""The two schedule APIs must each validate against their own request schema.

/scan-schedules (Wave 14) takes name + targets + interval_hours. /schedules takes a saved
collection_id + interval_minutes. Both request models were originally named ScheduleCreateRequest /
ScheduleUpdateRequest, and a later class statement rebinds the name for every function defined after
it — so POST/PUT /scan-schedules validated incoming bodies against the *collection* schema while
their handlers read req.name / req.targets / req.interval_hours.

That left the endpoint unusable in both directions: sending what the handler wanted returned 422
(collection_id missing), and sending what the model wanted returned 500 (AttributeError on
req.name). No GET-only route sweep could see it, which is why it survived.
"""
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path):
    old_db = os.environ.get("MORROW_SCANNER_DB")
    os.environ["MORROW_SCANNER_DB"] = str(tmp_path / "schedules.db")

    import importlib
    import app as fastapi_app

    fastapi_app = importlib.reload(fastapi_app)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    fastapi_app.init_db()

    with TestClient(fastapi_app.app) as c:
        yield c

    if old_db is None:
        os.environ.pop("MORROW_SCANNER_DB", None)
    else:
        os.environ["MORROW_SCANNER_DB"] = old_db
    importlib.reload(fastapi_app)


HEADERS = {"x-user-id": "admin", "x-user-role": "admin"}


def test_scan_schedule_accepts_name_targets_interval_hours(client):
    res = client.post(
        "/scan-schedules",
        headers=HEADERS,
        json={"name": "nightly", "targets": ["example.com"], "interval_hours": 24, "enabled": True},
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("name") == "nightly"
    assert body.get("targets") == ["example.com"]
    assert body.get("interval_hours") == 24


def test_scan_schedule_rejects_the_collection_schema(client):
    """Posting the other API's body must be a clean 422, never a 500 from the handler."""
    res = client.post(
        "/scan-schedules",
        headers=HEADERS,
        json={"collection_id": 1, "interval_minutes": 60, "enabled": True},
    )

    assert res.status_code == 422, res.text


def test_created_scan_schedule_is_listed(client):
    client.post(
        "/scan-schedules",
        headers=HEADERS,
        json={"name": "weekly", "targets": ["a.example.com"], "interval_hours": 168},
    )

    res = client.get("/scan-schedules", headers=HEADERS)

    assert res.status_code == 200, res.text
    names = [s.get("name") for s in res.json().get("schedules") or []]
    assert "weekly" in names


def test_scan_schedule_update_accepts_its_own_schema(client):
    created = client.post(
        "/scan-schedules",
        headers=HEADERS,
        json={"name": "to-update", "targets": ["b.example.com"], "interval_hours": 12},
    ).json()

    res = client.put(
        f"/scan-schedules/{created['id']}",
        headers=HEADERS,
        json={"interval_hours": 48, "enabled": False},
    )

    assert res.status_code == 200, res.text


def test_collection_schedule_model_is_separate(client):
    """/schedules keeps its own schema: a missing collection is a 400, not a validation error."""
    res = client.post(
        "/schedules",
        headers=HEADERS,
        json={"collection_id": 999999, "interval_minutes": 60, "enabled": True},
    )

    # The body validated (so the model is the collection one); the collection simply does not exist.
    assert res.status_code == 400, res.text


def test_no_write_handler_reads_a_field_its_model_does_not_declare(client):
    """Sweep every POST/PUT/PATCH route for the /scan-schedules failure mode.

    FastAPI validates the body against the annotated model, so a handler that reads a field the
    model does not declare raises AttributeError and returns 500 — for every request, regardless of
    input. A duplicate model name is one way to get there; this checks the outcome directly, across
    all write routes, rather than only the cause.
    """
    import inspect
    import re
    import sys

    from fastapi.routing import APIRoute

    app_module = sys.modules["app"]
    problems = []
    for route in app_module.app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not (route.methods or set()) & {"POST", "PUT", "PATCH"}:
            continue
        try:
            source = inspect.getsource(route.endpoint)
            params = inspect.signature(route.endpoint).parameters
        except (OSError, TypeError, ValueError):
            continue
        for name, param in params.items():
            annotation = param.annotation
            if isinstance(annotation, str):  # unresolved string annotation
                annotation = getattr(app_module, annotation.split("[")[0].strip(), None)
            fields = getattr(annotation, "model_fields", None)
            if not isinstance(fields, dict):
                continue
            read = set(re.findall(rf"\b{re.escape(name)}\.([a-zA-Z_][a-zA-Z0-9_]*)", source))
            read -= {
                "model_dump", "model_dump_json", "dict", "json", "model_copy", "model_validate",
                "model_fields", "model_config", "copy", "model_extra", "model_fields_set",
            }
            undeclared = sorted(read - set(fields))
            if undeclared:
                problems.append(
                    f"{'/'.join(sorted(route.methods))} {route.path}: handler reads "
                    f"{undeclared} which {annotation.__name__} does not declare "
                    f"(declares {sorted(fields)})"
                )

    assert not problems, "write handlers reading undeclared model fields:\n" + "\n".join(problems)


def test_request_model_names_are_not_reused(client):
    """A rebound request-model name silently changes the contract of earlier endpoints."""
    import ast
    import pathlib

    source = pathlib.Path(__file__).resolve().parent.joinpath("app.py").read_text(encoding="utf-8-sig")
    tree = ast.parse(source)
    seen = {}
    duplicates = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name.endswith(("Request", "Response")):
            if node.name in seen:
                duplicates.append(f"{node.name} defined at lines {seen[node.name]} and {node.lineno}")
            seen[node.name] = node.lineno

    assert not duplicates, (
        "duplicate request/response model names change the contract of endpoints defined between "
        "them:\n" + "\n".join(duplicates)
    )
