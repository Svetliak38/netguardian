"""Trust modes for certificate inspection: strict, medium, soft."""

from __future__ import annotations

import unittest
from unittest import mock

from netguardian.sslcheck import _sans_match, inspect

GOOD_CERT = {
    "issuer": ((("organizationName", "Test CA"),),),
    "subject": ((("commonName", "www.example.com"),),),
    "subjectAltName": (("DNS", "www.example.com"), ("DNS", "*.example.org")),
    "notAfter": "Dec 31 23:59:59 2030 GMT",
}

EXPIRED_CERT = dict(GOOD_CERT, notAfter="Jan 01 00:00:00 2000 GMT")


class _FakeTLS:
    def __init__(self, cert):
        self._cert = cert

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def version(self):
        return "TLSv1.3"

    def getpeercert(self):
        return self._cert


class _FakeContext:
    def __init__(self, cert):
        self._cert = cert

    def wrap_socket(self, raw, server_hostname=None):
        return _FakeTLS(self._cert)


class _FakeRaw:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _inspect(mode, cert=GOOD_CERT):
    with mock.patch("netguardian.sslcheck.socket.create_connection", return_value=_FakeRaw()):
        with mock.patch(
            "netguardian.sslcheck.ssl.create_default_context", return_value=_FakeContext(cert)
        ):
            with mock.patch(
                "netguardian.sslcheck.ssl._create_unverified_context", return_value=_FakeContext(cert)
            ):
                return inspect("www.example.com", mode=mode)


class SansMatchTests(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(_sans_match(["www.example.com"], "www.example.com"))

    def test_wildcard_subdomain(self) -> None:
        self.assertTrue(_sans_match(["*.example.com"], "a.example.com"))

    def test_wildcard_does_not_match_apex(self) -> None:
        self.assertFalse(_sans_match(["*.example.com"], "example.com"))

    def test_case_insensitive(self) -> None:
        self.assertTrue(_sans_match(["WWW.Example.COM"], "www.example.com"))

    def test_empty(self) -> None:
        self.assertFalse(_sans_match([], "www.example.com"))


class ModeTests(unittest.TestCase):
    def test_strict_success_is_acceptable(self) -> None:
        info = _inspect("strict")
        self.assertTrue(info.verified)
        self.assertTrue(info.acceptable)
        self.assertEqual(info.mode, "strict")

    def test_medium_accepts_matching_san_without_chain(self) -> None:
        info = _inspect("medium")
        self.assertFalse(info.verified)
        self.assertTrue(info.acceptable)
        self.assertEqual(info.mode, "medium")

    def test_medium_rejects_foreign_domain(self) -> None:
        with mock.patch("netguardian.sslcheck.socket.create_connection", return_value=_FakeRaw()):
            with mock.patch(
                "netguardian.sslcheck.ssl._create_unverified_context",
                return_value=_FakeContext(GOOD_CERT),
            ):
                info = inspect("other.invalid", mode="medium")
        self.assertFalse(info.acceptable)

    def test_medium_rejects_expired(self) -> None:
        info = _inspect("medium", cert=EXPIRED_CERT)
        self.assertFalse(info.acceptable)

    def test_soft_ignores_certificate(self) -> None:
        info = _inspect("soft", cert=EXPIRED_CERT)
        self.assertTrue(info.acceptable)
        self.assertFalse(info.verified)

    def test_unknown_mode_falls_back_to_strict(self) -> None:
        info = _inspect("yolo")
        self.assertEqual(info.mode, "strict")
        self.assertTrue(info.acceptable)

    def test_handshake_failure_is_not_acceptable(self) -> None:
        with mock.patch(
            "netguardian.sslcheck.socket.create_connection", side_effect=OSError("refused")
        ):
            info = inspect("www.example.com", mode="soft")
        self.assertFalse(info.acceptable)
        self.assertIn("refused", info.error)


if __name__ == "__main__":
    unittest.main()
