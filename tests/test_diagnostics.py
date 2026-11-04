"""Repeated TLS probing per address: an open TCP port must not be trusted."""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from unittest import mock

from netguardian.diagnostics import DiagnosticReport, IpProbe, probe_ips


@dataclass
class FakeCert:
    verified: bool
    error: str = ""


class IpProbeTests(unittest.TestCase):
    def test_rate_is_zero_without_attempts(self) -> None:
        probe = IpProbe("1.2.3.4", True, 0, 0)
        self.assertEqual(probe.rate, 0.0)
        self.assertEqual(probe.verdict, "dead")

    def test_thresholds(self) -> None:
        self.assertEqual(IpProbe("a", True, 3, 0).verdict, "ok")
        self.assertEqual(IpProbe("a", True, 1, 2).verdict, "flaky")
        self.assertEqual(IpProbe("a", True, 0, 3).verdict, "dead")

    def test_report_has_no_probes_by_default(self) -> None:
        self.assertEqual(DiagnosticReport(domain="example.com").ip_probes, [])


class ProbeIpsTests(unittest.TestCase):
    def test_counts_successful_handshakes(self) -> None:
        with mock.patch("netguardian.diagnostics.tcp_probe", return_value=True):
            probes = probe_ips(
                "example.com",
                ["1.2.3.4"],
                attempts=3,
                tls_inspector=lambda *a, **k: FakeCert(True),
            )
        self.assertEqual(len(probes), 1)
        self.assertEqual((probes[0].tls_ok, probes[0].tls_fail), (3, 0))
        self.assertEqual(probes[0].verdict, "ok")

    def test_counts_failed_handshakes(self) -> None:
        with mock.patch("netguardian.diagnostics.tcp_probe", return_value=True):
            probes = probe_ips(
                "example.com",
                ["1.2.3.4"],
                attempts=3,
                tls_inspector=lambda *a, **k: FakeCert(False, "timeout"),
            )
        self.assertEqual(probes[0].tls_fail, 3)
        self.assertEqual(probes[0].last_error, "timeout")
        self.assertEqual(probes[0].verdict, "dead")

    def test_partial_success_is_flaky(self) -> None:
        answers = [FakeCert(True), FakeCert(False, "reset"), FakeCert(True)]
        with mock.patch("netguardian.diagnostics.tcp_probe", return_value=True):
            probes = probe_ips(
                "example.com",
                ["1.2.3.4"],
                attempts=3,
                tls_inspector=lambda *a, **k: answers.pop(0),
            )
        self.assertEqual(probes[0].verdict, "flaky")

    def test_tcp_probe_receives_ports_argument(self) -> None:
        with mock.patch("netguardian.diagnostics.tcp_probe", return_value=True) as tcp:
            probe_ips(
                "example.com",
                ["1.2.3.4"],
                attempts=1,
                timeout=7.0,
                tls_inspector=lambda *a, **k: FakeCert(True),
            )
        tcp.assert_called_once_with("1.2.3.4", (443,), 7.0)

    def test_exception_is_recorded_not_raised(self) -> None:
        def boom(*args, **kwargs):
            raise OSError("handshake failed")

        with mock.patch("netguardian.diagnostics.tcp_probe", return_value=True):
            probes = probe_ips("example.com", ["1.2.3.4"], attempts=2, tls_inspector=boom)
        self.assertEqual(probes[0].tls_fail, 2)
        self.assertEqual(probes[0].last_error, "handshake failed")

    def test_empty_ip_list(self) -> None:
        self.assertEqual(probe_ips("example.com", []), [])


class _Settings:
    local_dns = ""
    dns_timeout_sec = 1
    tcp_timeout_sec = 1


class _Config:
    def __init__(self) -> None:
        self.settings = _Settings()
        self.profiles = {}


class _Hosts:
    def exists(self) -> bool:
        return False


class VerdictTests(unittest.TestCase):
    def _run(self, *, tcp_ok=True, probes=None, http=200, verified=True):
        from netguardian import diagnostics as diag

        probe = IpProbe("1.2.3.4", True, 3, 0) if probes is None else probes
        with mock.patch.object(diag, "system_lookup", return_value=["1.2.3.4"]):
            with mock.patch.object(diag, "tcp_probe", return_value=tcp_ok):
                with mock.patch.object(diag, "probe_ips", return_value=probes or [probe] if tcp_ok else []):
                    return diag.run(
                        "example.com",
                        _Config(),
                        _Hosts(),
                        tls_inspector=lambda *a, **k: FakeCert(verified),
                        proxy_reader=lambda: "",
                        http_probe=lambda domain: http,
                        admin=False,
                    )

    def test_waf_is_not_a_broken_route(self) -> None:
        from netguardian import diagnostics as diag

        report = self._run(http=403)
        self.assertEqual(report.verdict, diag.VERDICT_WAF)
        self.assertEqual(report.action, diag.ACTION_PROXY)

    def test_all_probes_dead_pins(self) -> None:
        from netguardian import diagnostics as diag

        report = self._run(probes=[IpProbe("1.2.3.4", True, 0, 3, "timeout")])
        self.assertEqual(report.verdict, diag.VERDICT_TLS)
        self.assertEqual(report.action, diag.ACTION_PIN)

    def test_flaky_plus_ok_means_flaky(self) -> None:
        from netguardian import diagnostics as diag

        report = self._run(
            probes=[IpProbe("1.2.3.4", True, 3, 0), IpProbe("5.6.7.8", True, 1, 2, "reset")]
        )
        self.assertEqual(report.verdict, diag.VERDICT_FLAKY)
        self.assertEqual(report.action, diag.ACTION_PIN)

    def test_no_probes_is_not_reported_as_tls(self) -> None:
        from netguardian import diagnostics as diag

        report = self._run(tcp_ok=False)
        self.assertEqual(report.ip_probes, [])
        self.assertEqual(report.verdict, diag.VERDICT_TCP)

    def test_healthy_route(self) -> None:
        from netguardian import diagnostics as diag

        report = self._run()
        self.assertEqual(report.verdict, diag.VERDICT_OK)
        self.assertEqual(report.action, diag.ACTION_OK)


class HttpStatusTests(unittest.TestCase):
    def test_http_error_returns_code(self) -> None:
        from netguardian import diagnostics as diag

        with mock.patch("urllib.request.urlopen", side_effect=__import__("urllib.error", fromlist=["HTTPError"]).HTTPError("u", 403, "no", {}, None)):
            self.assertEqual(diag.http_status("example.com"), 403)

    def test_failure_returns_zero(self) -> None:
        from netguardian import diagnostics as diag

        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
            self.assertEqual(diag.http_status("example.com"), 0)


if __name__ == "__main__":
    unittest.main()
