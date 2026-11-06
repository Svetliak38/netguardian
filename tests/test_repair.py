"""Tests for the safe hosts repair planner/apply path (no network, no admin)."""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from netguardian.config import Config, Profile, Settings
from netguardian.errors import AdminRequiredError, HostsSyntaxError
from netguardian.hosts import HostsFile
from netguardian.repair import repair_hosts
from tests.support import TempDir

SAMPLE = "127.0.0.1 localhost\r\n"


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping

    def resolve(self, domain, **kwargs):
        ip = self.mapping.get(domain)
        return SimpleNamespace(ip=ip) if ip else None


class RepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.root = Path(self._tmp.name)
        self.hosts_path = self.root / "hosts"
        self.hosts_path.write_text(SAMPLE, encoding="utf-8", newline="")
        self.hosts = HostsFile(
            self.hosts_path,
            backup_dir=self.root / "backups",
            keep_backups=5,
            admin_check=lambda: True,
        )
        self.hosts.apply("demo", {"example.com": "1.1.1.1"})
        self.profile = Profile(
            name="demo",
            description="demo",
            domains=["example.com"],
            process_hints=[],
            strategy="static_only",
            static_candidates=["2.2.2.2"],
            expected_issuers=["Test CA"],
            ports=[443],
        )
        self.config = Config(
            path=self.root / "routes.json",
            settings=Settings(tcp_timeout_sec=0.1, pin_mode="strict"),
            profiles={"demo": self.profile},
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @staticmethod
    def tls(domain, *, ip, port=443, timeout=5.0, mode="strict"):
        good = ip == "2.2.2.2"
        return SimpleNamespace(
            acceptable=good,
            verified=good,
            issuer="Test CA" if good else "",
            error="" if good else "TLS failed",
        )

    @staticmethod
    def probe(ip, ports, timeout):
        return ip == "2.2.2.2"

    def repair(self, *, resolver=None, dry_run=False, admin=True):
        self.hosts._admin_check = lambda: admin
        return repair_hosts(
            self.hosts,
            self.config,
            resolver or FakeResolver({"example.com": "2.2.2.2"}),
            dry_run=dry_run,
            timeout=0.1,
            probe=self.probe,
            tls_inspect=self.tls,
        )

    def block_ip(self):
        return self.hosts.blocks()[0].entries[0][0]

    def test_replaces_dead_marked_ip(self) -> None:
        report = self.repair()
        self.assertTrue(report.written)
        self.assertEqual(report.replaced, 1)
        self.assertEqual(self.block_ip(), "2.2.2.2")
        self.assertIsNotNone(report.backup)

    def test_dry_run_does_not_write(self) -> None:
        report = self.repair(dry_run=True)
        self.assertFalse(report.written)
        self.assertEqual(self.block_ip(), "1.1.1.1")

    def test_no_candidate_is_left_untouched(self) -> None:
        report = self.repair(resolver=FakeResolver({}))
        self.assertEqual(report.dead, 1)
        self.assertEqual(self.block_ip(), "1.1.1.1")

    def test_unmanaged_lines_are_preserved(self) -> None:
        self.hosts_path.write_text(SAMPLE + "9.9.9.9 custom.example\r\n", encoding="utf-8", newline="")
        self.repair()
        self.assertIn("9.9.9.9 custom.example", self.hosts_path.read_text(encoding="utf-8"))

    def test_malformed_block_raises_without_changes(self) -> None:
        self.hosts_path.write_text(
            SAMPLE + "# === NETGUARDIAN FIX (demo) [x] BEGIN ===\r\n1.1.1.1 example.com\r\n",
            encoding="utf-8",
            newline="",
        )
        with self.assertRaises(HostsSyntaxError):
            self.repair()

    def test_admin_required_before_write(self) -> None:
        with self.assertRaises(AdminRequiredError):
            self.repair(admin=False)

    def test_one_line_with_two_domains_is_replaced_once(self) -> None:
        self.hosts_path.write_text(
            SAMPLE
            + "# === NETGUARDIAN FIX (demo) [x] BEGIN ===\r\n"
            + "1.1.1.1 example.com example.org\r\n"
            + "# === NETGUARDIAN FIX (demo) [x] END ===\r\n",
            encoding="utf-8",
            newline="",
        )
        self.profile.domains = ["example.com", "example.org"]
        report = self.repair(resolver=FakeResolver({"example.com": "2.2.2.2", "example.org": "2.2.2.2"}))
        self.assertEqual(report.replaced, 2)
        self.assertFalse([a for a in report.actions if a.status == "error"])
        self.assertIn("2.2.2.2 example.com example.org", self.hosts_path.read_text(encoding="utf-8"))


    def test_fast_candidate_with_bad_tls_falls_back_to_slower(self) -> None:
        class RankedResolver:
            def resolve(self, domain, **kwargs):
                return SimpleNamespace(
                    ip="2.2.2.2",
                    candidate_rtts={"2.2.2.2": 10.0, "3.3.3.3": 50.0},
                )

        def probe(ip, ports, timeout):
            return ip in {"2.2.2.2", "3.3.3.3"}

        def tls(domain, *, ip, port=443, timeout=5.0, mode="strict"):
            good = ip == "3.3.3.3"
            return SimpleNamespace(
                acceptable=good,
                verified=good,
                issuer="Test CA" if good else "",
                error="" if good else "TLS failed",
            )

        self.hosts._admin_check = lambda: True
        report = repair_hosts(
            self.hosts,
            self.config,
            RankedResolver(),
            dry_run=False,
            timeout=0.1,
            probe=probe,
            tls_inspect=tls,
        )
        self.assertEqual(report.replaced, 1)
        self.assertEqual(self.block_ip(), "3.3.3.3")


if __name__ == "__main__":
    unittest.main()
