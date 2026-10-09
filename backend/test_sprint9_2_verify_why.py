import unittest

import scanner
import policy


class FakeVerifyErr(Exception):
    def __init__(self, msg, verify_code=None, verify_message=None):
        super().__init__(msg)
        self.verify_code = verify_code
        self.verify_message = verify_message or msg


class TestSprint92VerifyWhy(unittest.TestCase):
    def test_classify_expired(self):
        e = FakeVerifyErr("certificate has expired")
        out = scanner._classify_verify_error(e)  # type: ignore
        self.assertEqual(out["verify_reason"], "expired")

    def test_classify_missing_intermediate(self):
        e = FakeVerifyErr("unable to verify the first certificate")
        out = scanner._classify_verify_error(e)  # type: ignore
        self.assertEqual(out["verify_reason"], "missing_intermediate")

    def test_classify_untrusted_root(self):
        e = FakeVerifyErr("unable to get local issuer certificate")
        out = scanner._classify_verify_error(e)  # type: ignore
        self.assertEqual(out["verify_reason"], "untrusted_root")

    def test_refine_untrusted_to_missing_if_chain_short_and_aia(self):
        facts = {
            "verify_reason": "untrusted_root",
            "subject": "CN=example.com",
            "issuer": "CN=Example Intermediate",
            "chain_length": 1,
            "ca_issuers_urls": ["http://ca.example/issuer.crt"],
        }
        scanner._refine_verify_reason(facts)  # type: ignore
        self.assertEqual(facts["verify_reason"], "missing_intermediate")

    def test_policy_finding_missing_intermediate_high_confidence(self):
        facts = {"verify_reason": "missing_intermediate", "verify_error": "unable to verify the first certificate"}
        findings = policy.evaluate_tls_findings(facts)
        ids = [f["rule_id"] for f in findings]
        self.assertIn("VERIFY_MISSING_INTERMEDIATE", ids)
        f = [x for x in findings if x["rule_id"] == "VERIFY_MISSING_INTERMEDIATE"][0]
        self.assertEqual(f["confidence"], "high")
        self.assertEqual(f["severity"], "high")


if __name__ == "__main__":
    unittest.main()
