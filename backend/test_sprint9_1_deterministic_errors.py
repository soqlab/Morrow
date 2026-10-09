
import unittest
import socket
import ssl

import scanner as scanner


class TestSprint91DeterministicErrorCodes(unittest.TestCase):
    def test_tls_version_too_low_from_sslerror(self):
        e = ssl.SSLError("tlsv1 alert protocol version")
        self.assertEqual(scanner._error_code_from_exception(e), scanner.ERR_TLS_VERSION_TOO_LOW)

    def test_cert_expired_from_verify_reason(self):
        code = scanner._error_code_from_verify_reason("expired", "certificate has expired")
        self.assertEqual(code, scanner.ERR_CERT_EXPIRED)

    def test_hostname_mismatch_from_verify_reason(self):
        code = scanner._error_code_from_verify_reason("hostname_mismatch", "hostname 'a' doesn't match")
        self.assertEqual(code, scanner.ERR_HOSTNAME_MISMATCH)

    def test_self_signed_from_message(self):
        code = scanner._error_code_from_verify_reason("untrusted_issuer", "self signed certificate")
        self.assertEqual(code, scanner.ERR_SELF_SIGNED)

    def test_dns_from_exception(self):
        e = socket.gaierror(-2, "Name or service not known")
        self.assertEqual(scanner._error_code_from_exception(e), scanner.ERR_DNS)

    def test_timeout_from_exception(self):
        e = socket.timeout("timed out")
        self.assertEqual(scanner._error_code_from_exception(e), scanner.ERR_TIMEOUT)

    def test_connection_refused_from_exception(self):
        e = ConnectionRefusedError("refused")
        self.assertEqual(scanner._error_code_from_exception(e), scanner.ERR_CONNECTION_ERROR)


if __name__ == "__main__":
    unittest.main()
