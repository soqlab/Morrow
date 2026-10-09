import unittest


class TestSprint96OCSPStapling(unittest.TestCase):
    def test_parse_openssl_no_response_sent(self):
        from scanner import _parse_openssl_ocsp_output

        sample = """
OCSP response: no response sent
---
"""
        out = _parse_openssl_ocsp_output(sample)
        self.assertTrue(out.get("ocsp_stapling_supported"))
        self.assertFalse(out.get("ocsp_stapled"))

    def test_parse_openssl_good(self):
        from scanner import _parse_openssl_ocsp_output

        sample = """
OCSP Response Status: successful (0x0)
Cert Status: good
This Update: Jan 01 00:00:00 2026 GMT
Next Update: Feb 01 00:00:00 2026 GMT
"""
        out = _parse_openssl_ocsp_output(sample)
        self.assertTrue(out.get("ocsp_stapling_supported"))
        self.assertTrue(out.get("ocsp_stapled"))
        self.assertEqual(out.get("ocsp_stapled_status"), "good")

    def test_parse_openssl_revoked(self):
        from scanner import _parse_openssl_ocsp_output

        sample = """
OCSP Response Status: successful
Cert Status: revoked
"""
        out = _parse_openssl_ocsp_output(sample)
        self.assertTrue(out.get("ocsp_stapled"))
        self.assertEqual(out.get("ocsp_stapled_status"), "revoked")

    def test_policy_finding_stapling_not_enabled(self):
        from policy import evaluate_tls_findings

        facts = {
            "ocsp_stapling_supported": True,
            "ocsp_stapled": False,
            "ocsp_urls": ["http://ocsp.example.com"],
        }
        findings = evaluate_tls_findings(facts)
        ids = [f.get("rule_id") for f in findings]
        self.assertIn("OCSP_STAPLING_MISSING", ids)
        f = next(x for x in findings if x.get("rule_id") == "OCSP_STAPLING_MISSING")
        self.assertEqual(f.get("title"), "OCSP Stapling Not Enabled")
        self.assertEqual((f.get("severity") or "").lower(), "low")


if __name__ == "__main__":
    unittest.main()
