import unittest
from unittest.mock import patch, Mock

import requests

import scanner


class TestSprint97OCSPReachability(unittest.TestCase):
    def test_timeout_is_soft_fail(self):
        with patch("scanner.requests.post", side_effect=requests.exceptions.Timeout()):
            r = scanner._probe_ocsp_post_endpoint("http://ocsp.example.test", timeout=0.01)
            self.assertFalse(r["reachable"])
            self.assertEqual(r["error"], "timeout")
            self.assertEqual(r["method"], "POST")
            self.assertIsNotNone(r["elapsed_ms"])

    def test_http_response_is_reachable_even_if_404(self):
        fake = Mock()
        fake.status_code = 404
        fake.content = b"nope"
        with patch("scanner.requests.post", return_value=fake):
            r = scanner._probe_ocsp_post_endpoint("http://ocsp.example.test", timeout=0.5)
            self.assertTrue(r["reachable"])
            self.assertEqual(r["status_code"], 404)
            self.assertEqual(r["method"], "POST")
            self.assertIsNotNone(r["elapsed_ms"])


if __name__ == "__main__":
    unittest.main()
