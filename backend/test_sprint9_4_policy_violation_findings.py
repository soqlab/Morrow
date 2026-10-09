import unittest

from policy import DEFAULT_POLICY, evaluate_policy_violations, policy_violations_to_findings, evaluate_tls_findings


class TestSprint94PolicyViolationFindings(unittest.TestCase):
    def test_key_too_small_becomes_finding(self):
        pol = dict(DEFAULT_POLICY)
        pol["allowed_keys"] = ["RSA>=3072"]

        facts = {
            "policy": pol,
            "key_type": "RSA",
            "key_detail": "RSA-2048",
            "tls_supported_versions": ["TLSv1.2"],
        }
        facts["policy_violations"] = evaluate_policy_violations(facts, pol)

        findings = policy_violations_to_findings(facts)
        ids = [f.get("rule_id") for f in findings]
        self.assertIn("POLICY_KEY_TOO_SMALL", ids)

        f = next(x for x in findings if x.get("rule_id") == "POLICY_KEY_TOO_SMALL")
        self.assertEqual((f.get("severity") or "").lower(), "high")
        self.assertIn("Key too small", f.get("title") or "")

    def test_tls_below_min_becomes_finding(self):
        pol = dict(DEFAULT_POLICY)
        pol["min_tls"] = "1.2"

        facts = {
            "policy": pol,
            "tls_supported_versions": ["TLSv1", "TLSv1.1", "TLSv1.2"],
        }
        facts["policy_violations"] = evaluate_policy_violations(facts, pol)

        findings = policy_violations_to_findings(facts)
        self.assertTrue(any(f.get("rule_id") == "POLICY_TLS_BELOW_MIN" for f in findings))

    def test_evaluate_tls_findings_includes_policy_findings(self):
        pol = dict(DEFAULT_POLICY)
        pol["allowed_keys"] = ["RSA>=3072"]

        facts = {
            "policy": pol,
            "key_type": "RSA",
            "key_detail": "RSA-2048",
            "tls_supported_versions": ["TLSv1.2"],
        }
        facts["policy_violations"] = evaluate_policy_violations(facts, pol)

        findings = evaluate_tls_findings(facts)
        self.assertTrue(any(f.get("rule_id") == "POLICY_KEY_TOO_SMALL" for f in findings))


if __name__ == "__main__":
    unittest.main()
