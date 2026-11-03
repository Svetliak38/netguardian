"""Unit tests for the hosts-file layer (no elevation, no network)."""

from __future__ import annotations

import unittest
from pathlib import Path

from netguardian.errors import AdminRequiredError, HostsSyntaxError
from netguardian.hosts import HostsFile, parse_blocks
from tests.support import TempDir

SAMPLE = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# localhost name resolution is handled within DNS itself.\r\n"
    "127.0.0.1       localhost\r\n"
    "::1             localhost\r\n"
)


class HostsTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.root = Path(self._tmp.name)
        self.hosts_path = self.root / "hosts"
        self.hosts_path.write_text(SAMPLE, encoding="utf-8", newline="")
        self.backup_dir = self.root / "backups"
        self.hosts = HostsFile(
            self.hosts_path,
            backup_dir=self.backup_dir,
            keep_backups=5,
            admin_check=lambda: True,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def read(self, encoding: str = "utf-8") -> str:
        return self.hosts_path.read_bytes().decode(encoding)


class ApplyTests(HostsTestBase):
    def test_apply_creates_single_marked_block(self) -> None:
        result = self.hosts.apply(
            "demo", {"example.com": "1.2.3.4", "example.org": "5.6.7.8"}
        )
        self.assertTrue(result.written)
        self.assertTrue(result.changed)
        self.assertEqual(result.count, 2)
        text = self.read()
        self.assertIn("1.2.3.4", text)
        self.assertIn("example.com", text)
        blocks = self.hosts.blocks()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].profile, "demo")
        self.assertEqual(
            {domain: ip for ip, domain in blocks[0].entries},
            {"example.com": "1.2.3.4", "example.org": "5.6.7.8"},
        )

    def test_second_apply_is_a_noop(self) -> None:
        mapping = {"example.com": "1.2.3.4"}
        self.hosts.apply("demo", mapping)
        before = self.read()
        result = self.hosts.apply("demo", mapping)
        self.assertFalse(result.changed)
        self.assertFalse(result.written)
        self.assertEqual(self.read(), before)

    def test_apply_replaces_old_block_without_duplicates(self) -> None:
        self.hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.hosts.apply("demo", {"example.com": "9.9.9.9"})
        blocks = [block for block in self.hosts.blocks() if block.profile == "demo"]
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].entries, [("9.9.9.9", "example.com")])

    def test_other_profiles_are_preserved(self) -> None:
        self.hosts.apply("one", {"one.example": "1.1.1.1"})
        self.hosts.apply("two", {"two.example": "2.2.2.2"})
        profiles = {block.profile for block in self.hosts.blocks()}
        self.assertEqual(profiles, {"one", "two"})

    def test_backup_created_before_write(self) -> None:
        result = self.hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.assertIsNotNone(result.backup)
        assert result.backup is not None
        self.assertTrue(result.backup.is_file())
        self.assertEqual(result.backup.read_bytes().decode("utf-8"), SAMPLE)

    def test_dry_run_writes_nothing(self) -> None:
        before = self.read()
        result = self.hosts.apply("demo", {"example.com": "1.2.3.4"}, dry_run=True)
        self.assertTrue(result.changed)
        self.assertFalse(result.written)
        self.assertEqual(self.read(), before)

    def test_conflict_is_reported_and_blocks_write(self) -> None:
        with open(self.hosts_path, "a", encoding="utf-8", newline="") as handle:
            handle.write("9.9.9.9 example.com\r\n")
        before = self.read()
        result = self.hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.assertFalse(result.written)
        self.assertTrue(result.conflicts)
        self.assertEqual(self.read(), before)

    def test_force_overrides_conflict(self) -> None:
        with open(self.hosts_path, "a", encoding="utf-8", newline="") as handle:
            handle.write("9.9.9.9 example.com\r\n")
        result = self.hosts.apply("demo", {"example.com": "1.2.3.4"}, force=True)
        self.assertTrue(result.written)
        self.assertTrue(result.conflicts)

    def test_conflict_with_another_profile_block(self) -> None:
        self.hosts.apply("other", {"example.com": "9.9.9.9"})
        before = self.read()
        result = self.hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.assertFalse(result.written)
        self.assertTrue(any("other" in line for line in result.conflicts))
        self.assertEqual(self.read(), before)

    def test_non_admin_is_rejected(self) -> None:
        hosts = HostsFile(self.hosts_path, backup_dir=self.backup_dir, admin_check=lambda: False)
        before = self.read()
        with self.assertRaises(AdminRequiredError):
            hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.assertEqual(self.read(), before)

    def test_malformed_marker_stops_before_writing(self) -> None:
        with open(self.hosts_path, "a", encoding="utf-8", newline="") as handle:
            handle.write("# === NETGUARDIAN FIX (broken) BEGIN ===\r\n")
        before = self.read()
        with self.assertRaises(HostsSyntaxError):
            self.hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.assertEqual(self.read(), before)

    def test_legacy_timestamp_markers_are_understood(self) -> None:
        with open(self.hosts_path, "a", encoding="utf-8", newline="") as handle:
            handle.write("# === NETGUARDIAN FIX (old) [20260101_120000] BEGIN ===\r\n")
            handle.write("8.8.8.8 old.example\r\n")
            handle.write("# === NETGUARDIAN FIX (old) [20260101_120000] END ===\r\n")
        blocks = parse_blocks(self.hosts.read().lines)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].timestamp, "20260101_120000")
        self.assertEqual(blocks[0].entries, [("8.8.8.8", "old.example")])


class EncodingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.root = Path(self._tmp.name)
        self.hosts_path = self.root / "hosts"
        self.backup_dir = self.root / "backups"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_cp1251_comments_survive(self) -> None:
        original = "# Комментарий на русском\r\n127.0.0.1 localhost\r\n"
        self.hosts_path.write_bytes(original.encode("cp1251"))
        hosts = HostsFile(self.hosts_path, backup_dir=self.backup_dir, admin_check=lambda: True)
        hosts.apply("demo", {"example.com": "1.2.3.4"})
        text = self.hosts_path.read_bytes().decode("cp1251")
        self.assertIn("Комментарий на русском", text)
        self.assertIn("1.2.3.4", text)

    def test_crlf_is_preserved(self) -> None:
        self.hosts_path.write_bytes(SAMPLE.encode("utf-8"))
        hosts = HostsFile(self.hosts_path, backup_dir=self.backup_dir, admin_check=lambda: True)
        hosts.apply("demo", {"example.com": "1.2.3.4"})
        raw = self.hosts_path.read_bytes()
        self.assertIn(b"\r\n", raw)
        self.assertEqual(raw.count(b"\n"), raw.count(b"\r\n"))

    def test_missing_final_newline_is_handled(self) -> None:
        self.hosts_path.write_text("127.0.0.1 localhost", encoding="utf-8")
        hosts = HostsFile(self.hosts_path, backup_dir=self.backup_dir, admin_check=lambda: True)
        hosts.apply("demo", {"example.com": "1.2.3.4"})
        self.assertEqual(len([b for b in hosts.blocks() if b.profile == "demo"]), 1)


class RemoveAndRestoreTests(HostsTestBase):
    def test_remove_one_profile(self) -> None:
        self.hosts.apply("one", {"one.example": "1.1.1.1"})
        self.hosts.apply("two", {"two.example": "2.2.2.2"})
        removed = self.hosts.remove("one")
        self.assertEqual(removed, 1)
        self.assertEqual([block.profile for block in self.hosts.blocks()], ["two"])

    def test_remove_all(self) -> None:
        self.hosts.apply("one", {"one.example": "1.1.1.1"})
        self.hosts.apply("two", {"two.example": "2.2.2.2"})
        self.assertEqual(self.hosts.remove(None), 2)
        self.assertEqual(self.hosts.blocks(), [])

    def test_remove_dry_run_writes_nothing(self) -> None:
        self.hosts.apply("one", {"one.example": "1.1.1.1"})
        before = self.read()
        self.assertEqual(self.hosts.remove(None, dry_run=True), 1)
        self.assertEqual(self.read(), before)

    def test_restore_returns_previous_content(self) -> None:
        self.hosts.apply("one", {"one.example": "1.1.1.1"})
        after_first = self.read()
        backup = self.hosts.create_backup("snapshot")
        assert backup is not None
        self.hosts.apply("two", {"two.example": "2.2.2.2"})
        self.hosts.restore(backup)
        self.assertEqual(self.read(), after_first)

    def test_restore_rejects_plain_file(self) -> None:
        bogus = self.root / "not-a-backup.txt"
        bogus.write_text("hello", encoding="utf-8")
        with self.assertRaises(Exception):
            self.hosts.restore(bogus)


if __name__ == "__main__":
    unittest.main()
