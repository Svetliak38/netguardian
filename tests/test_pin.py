"""Ad-hoc pins: verified before writing, reversible, ordered."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from netguardian.hosts import HostsFile, pin_profile
from netguardian.sslcheck import CertInfo


def _hosts(tmp: str) -> HostsFile:
    path = Path(tmp) / "hosts"
    path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    return HostsFile(path, backup_dir=Path(tmp) / "backup", admin_check=lambda: True)


def _inspector(acceptable: bool, error: str = ""):
    def fake(domain: str, *, ip: str, mode: str = "strict") -> CertInfo:
        return CertInfo(domain=domain, ip=ip, acceptable=acceptable, error=error, mode=mode)

    return fake


class PinTests(unittest.TestCase):
    def test_profile_name_is_normalised(self) -> None:
        self.assertEqual(pin_profile(" Example.COM. "), "pin:example.com")

    def test_pin_writes_a_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            ok, message = hosts.pin("example.com", "1.2.3.4", inspector=_inspector(True))
            self.assertTrue(ok, message)
            self.assertEqual(hosts.pinned_for("example.com"), ["1.2.3.4"])
            self.assertIn("pin:example.com", hosts.read().text)

    def test_refusal_leaves_the_file_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            before = hosts.read().text
            ok, message = hosts.pin(
                "example.com", "1.2.3.4", inspector=_inspector(False, "bad certificate")
            )
            self.assertFalse(ok)
            self.assertIn("bad certificate", message)
            self.assertEqual(hosts.read().text, before)

    def test_second_pin_does_not_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            inspector = _inspector(True)
            hosts.pin("example.com", "1.2.3.4", inspector=inspector)
            ok, message = hosts.pin("example.com", "1.2.3.4", inspector=inspector)
            self.assertTrue(ok, message)
            self.assertEqual(hosts.pinned_for("example.com"), ["1.2.3.4"])

    def test_repin_replaces_the_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            inspector = _inspector(True)
            hosts.pin("example.com", "1.2.3.4", inspector=inspector)
            hosts.pin("example.com", "5.6.7.8", inspector=inspector)
            self.assertEqual(hosts.pinned_for("example.com"), ["5.6.7.8"])

    def test_unpin_removes_the_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            hosts.pin("example.com", "1.2.3.4", inspector=_inspector(True))
            ok, _ = hosts.unpin("example.com")
            self.assertTrue(ok)
            self.assertEqual(hosts.pinned_for("example.com"), [])
            self.assertNotIn("pin:example.com", hosts.read().text)

    def test_unpin_missing_pin_reports_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            ok, message = hosts.unpin("example.com")
            self.assertFalse(ok)
            self.assertTrue(message)

    def test_empty_domain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = _hosts(tmp)
            ok, message = hosts.pin("   ", "1.2.3.4", inspector=_inspector(True))
            self.assertFalse(ok)
            self.assertTrue(message)


    def test_pin_without_admin_reports_instead_of_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts"
            path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            hosts = HostsFile(path, backup_dir=Path(tmp) / "backup", admin_check=lambda: False)
            ok, message = hosts.pin("example.com", "1.2.3.4", inspector=_inspector(True))
            self.assertFalse(ok)
            self.assertTrue(message)

    def test_unpin_without_admin_reports_instead_of_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts"
            path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            allowed = HostsFile(path, backup_dir=Path(tmp) / "backup", admin_check=lambda: True)
            allowed.pin("example.com", "1.2.3.4", inspector=_inspector(True))
            denied = HostsFile(path, backup_dir=Path(tmp) / "backup", admin_check=lambda: False)
            ok, message = denied.unpin("example.com")
            self.assertFalse(ok)
            self.assertTrue(message)
            self.assertEqual(allowed.pinned_for("example.com"), ["1.2.3.4"])


class PinModeTests(unittest.TestCase):
    def test_default_is_strict(self) -> None:
        from netguardian.config import Settings

        self.assertEqual(Settings().pin_mode, "strict")

    def test_mode_is_normalised(self) -> None:
        from netguardian.config import _as_pin_mode

        self.assertEqual(_as_pin_mode(" STRICT "), "strict")
        self.assertEqual(_as_pin_mode("Medium"), "medium")
        self.assertEqual(_as_pin_mode("soft"), "soft")

    def test_typo_is_rejected(self) -> None:
        from netguardian.config import _as_pin_mode

        with self.assertRaises(ValueError):
            _as_pin_mode("yolo")


if __name__ == "__main__":
    unittest.main()
