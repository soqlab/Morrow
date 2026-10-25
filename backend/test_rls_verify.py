from services.rls_verify import evaluate_rls_state


def test_evaluate_rls_state_passes_when_tables_and_role_are_safe():
    tables = [
        {"relname": "assets", "relrowsecurity": True, "relforcerowsecurity": True},
        {"relname": "scans", "relrowsecurity": True, "relforcerowsecurity": True},
    ]
    role = {"role_name": "morrow_app", "rolsuper": False, "rolbypassrls": False}

    result = evaluate_rls_state(tables, role, expected_tables=["assets", "scans"])

    assert result["status"] == "pass"
    assert result["role_ok"] is True
    assert result["failures"] == []


def test_evaluate_rls_state_fails_missing_force_rls_and_bypass_role():
    tables = [
        {"relname": "assets", "relrowsecurity": True, "relforcerowsecurity": False},
    ]
    role = {"role_name": "postgres", "rolsuper": True, "rolbypassrls": True}

    result = evaluate_rls_state(tables, role, expected_tables=["assets", "scans"])

    assert result["status"] == "fail"
    assert result["missing_tables"] == ["scans"]
    assert result["missing_rls"] == ["assets"]
    assert result["role_ok"] is False
