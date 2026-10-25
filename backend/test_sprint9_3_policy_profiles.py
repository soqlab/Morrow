import unittest


import policy


class TestSprint93PolicyProfiles(unittest.TestCase):
    def setUp(self):
        # Clear cache between tests
        policy._POLICY_CACHE = None

    def test_load_default_policy(self):
        pol = policy.load_active_policy()
        self.assertIsInstance(pol, dict)
        self.assertEqual(pol.get("min_tls"), "1.2")
        self.assertIn("RC4", pol.get("banned_ciphers"))
        self.assertIn("RSA>=3072", pol.get("allowed_keys"))
        self.assertEqual(bool(pol.get("require_stapling")), False)

    def test_policy_violations_detected(self):
        pol = {
            "name": "default",
            "min_tls": "1.2",
            "banned_ciphers": ["RC4", "3DES"],
            "allowed_keys": ["ECC", "RSA>=3072"],
            "require_stapling": False,
        }
        facts = {
            "tls_supported_versions": ["TLSv1.0", "TLSv1.2"],
            "tls12_accepted_ciphers": ["RC4-SHA", "ECDHE-RSA-AES128-GCM-SHA256"],
            "tls12_weak_accepted_ciphers": [],
            "key_type": "RSA",
            "key_detail": "2048",
            "ocsp_stapled": False,
            "ocsp_stapling_supported": True,
        }
        v = policy.evaluate_policy_violations(facts, pol)
        ids = sorted([x.get("id") for x in v])
        self.assertIn("POLICY_TLS_BELOW_MIN", ids)
        self.assertIn("POLICY_BANNED_CIPHER", ids)
        self.assertIn("POLICY_KEY_TOO_SMALL", ids)

    def test_policy_key_not_allowed(self):
        pol = {
            "name": "pq",
            "min_tls": "1.2",
            "banned_ciphers": [],
            "allowed_keys": ["ECC"],
            "require_stapling": False,
        }
        facts = {
            "tls_supported_versions": ["TLSv1.2"],
            "tls12_accepted_ciphers": [],
            "tls12_weak_accepted_ciphers": [],
            "key_type": "RSA",
            "key_detail": "4096",
        }
        v = policy.evaluate_policy_violations(facts, pol)
        ids = [x.get("id") for x in v]
        self.assertIn("POLICY_KEY_NOT_ALLOWED", ids)


if __name__ == "__main__":
    unittest.main()
