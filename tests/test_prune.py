"""Tests for ``netguardian prune`` and for profiles marked ``fixable: false``."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from netguardian import cli
from netguardian.cli import Context, cmd_apply, cmd_prune, main
from netguardian.config import load_config
from netguardian.hosts import HostsFile
from netguardian.paths import AppPaths
from tests.support import TempDir

DEAD_IP = "10.0.0.1"
ALIVE_IP = "10.0.0.2"
BROKEN_IP = "10.0.0.3"

PROFILES = {
    "demo": {
        "description": "prunable profile",
        "domains": ["example.com", "api.example.com", "cdn.example.com"],
        "strategy": "static_only",
        "static_candidates": [ALIVE_IP],
        "expected_issuers": ["Test CA"],
        "ports": [443],
    },
    "diag": {
        "description": "diagnostics only",
        "domains": ["patch.example.com"],
        "strategy": "dns_discovery_only",
        "static_candidates": [],
        "expected_issuers": ["Test CA"],
        "ports": [443],
        "fixable": False,
    },
}


def block(profile: str, pairs) -> str:
    lines = [f"# === NETGUARDIAN FIX ({profile}) [20260101_000000] BEGIN ==="]
    lines += [f"{ip:<15} {domain}" for ip, domain in pairs]
    lines.append(f"# === NETGUARDIAN FIX ({profile}) [20260101_000000] END ===")
    return "\r\n".join(lines)


class PruneTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.root = Path(self._tmp.name)
        self.hosts_path = self.root / "hosts"
        self.hosts_path.write_text("127.0.0.1 localhost\r\n", encoding="utf-8", newline="")
        self.data_dir = self.root / "data"
        self.config_path = self.root / "routes.json"
        self.config_path.write_text(
            json.dumps(
                {
                    "settings": {"local_dns": "", "tcp_timeout_sec": 1},
                    "profiles": PROFILES,
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_hosts(self, text: str) -> None:
        self.hosts_path.write_text(text, encoding="utf-8", newline="")

    def make_context(self) -> Context:
        paths = AppPaths.resolve(
            config=str(self.config_path),
            data_dir=str(self.data_dir),
            hosts=str(self.hosts_path),
        )
        paths.ensure_directories()
        config, _ = load_config(self.config_path)
        ctx = Context(paths=paths, config=config, interactive=False, json=False)
        ctx.hosts = HostsFile(
            self.hosts_path, backup_dir=self.data_dir / "backups", admin_check=lambda: True
        )
        return ctx

    def args(self, **kwargs):
        defaults = dict(profile=None, all=False, dry_run=False, yes=True, tcp_only=False, timeout=1.0)
        defaults.update(kwargs)
        return SimpleNamespace(**defaults)

    def hosts_text(self) -> str:
        return self.hosts_path.read_text(encoding="utf-8")


class PruneCommandTests(PruneTestBase):
    def test_dry_run_reports_dead_entry_and_keeps_the_file(self) -> None:
        self.write_hosts(
            "127.0.0.1 localhost\r\n"
            + block("demo", [(DEAD_IP, "example.com"), (ALIVE_IP, "api.example.com")])
            + "\r\n"
        )
        before = self.hosts_text()
        ctx = self.make_context()

        with patch.object(cli, "tcp_probe", side_effect=lambda ip, ports, timeout: ip != DEAD_IP):
            with redirect_stdout(io.StringIO()) as out:
                code = cmd_prune(ctx, self.args(dry_run=True, all=True))

        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("example.com", out.getvalue())
        self.assertEqual(before, self.hosts_text())

    def test_dead_entry_is_removed_and_alive_entry_is_kept(self) -> None:
        self.write_hosts(
            "127.0.0.1 localhost\r\n"
            + block("demo", [(DEAD_IP, "example.com"), (ALIVE_IP, "api.example.com")])
            + "\r\n"
        )
        ctx = self.make_context()

        with patch.object(cli, "tcp_probe", side_effect=lambda ip, ports, timeout: ip != DEAD_IP):
            with patch.object(cli, "inspect", return_value=SimpleNamespace(verified=True, issuer="Test CA", error="", days_left=90)):
                with patch.object(cli, "is_admin", return_value=True):
                    with redirect_stdout(io.StringIO()):
                        code = cmd_prune(ctx, self.args(profile="demo"))

        self.assertEqual(code, cli.EXIT_OK)
        text = self.hosts_text()
        self.assertIn("api.example.com", text)
        self.assertIn(ALIVE_IP, text)
        self.assertEqual(ctx.hosts.entries_for("demo"), {"api.example.com": ALIVE_IP})

    def test_block_is_dropped_when_every_entry_is_dead(self) -> None:
        self.write_hosts(
            "127.0.0.1 localhost\r\n" + block("demo", [(DEAD_IP, "example.com")]) + "\r\n"
        )
        ctx = self.make_context()

        with patch.object(cli, "tcp_probe", return_value=False):
            with patch.object(cli, "is_admin", return_value=True):
                with redirect_stdout(io.StringIO()):
                    code = cmd_prune(ctx, self.args(profile="demo"))

        self.assertEqual(code, cli.EXIT_OK)
        text = self.hosts_text()
        self.assertNotIn("NETGUARDIAN FIX (demo)", text)
        self.assertIn("127.0.0.1 localhost", text)

    def test_tcp_only_keeps_entries_that_fail_tls(self) -> None:
        self.write_hosts(
            "127.0.0.1 localhost\r\n" + block("demo", [(BROKEN_IP, "example.com")]) + "\r\n"
        )
        ctx = self.make_context()
        broken = SimpleNamespace(verified=False, issuer="", error="connection reset", days_left=None)

        with patch.object(cli, "tcp_probe", return_value=True):
            with patch.object(cli, "inspect", return_value=broken):
                with patch.object(cli, "is_admin", return_value=True):
                    with redirect_stdout(io.StringIO()):
                        code = cmd_prune(ctx, self.args(profile="demo", tcp_only=True))

        self.assertEqual(code, cli.EXIT_OK)
        text = self.hosts_text()
        self.assertIn("example.com", text)
        self.assertIn(BROKEN_IP, text)

    def test_broken_entry_is_removed_without_tcp_only(self) -> None:
        self.write_hosts(
            "127.0.0.1 localhost\r\n" + block("demo", [(BROKEN_IP, "example.com")]) + "\r\n"
        )
        ctx = self.make_context()
        broken = SimpleNamespace(verified=False, issuer="", error="connection reset", days_left=None)

        with patch.object(cli, "tcp_probe", return_value=True):
            with patch.object(cli, "inspect", return_value=broken):
                with patch.object(cli, "is_admin", return_value=True):
                    with redirect_stdout(io.StringIO()):
                        code = cmd_prune(ctx, self.args(profile="demo"))

        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("example.com", self.hosts_text())

    def test_foreign_lines_are_reported_but_never_removed(self) -> None:
        self.write_hosts(
            "127.0.0.1 localhost\r\n"
            f"{DEAD_IP:<15} manual.example.com\r\n"
            + block("demo", [(ALIVE_IP, "api.example.com")])
            + "\r\n"
        )
        before = self.hosts_text()
        ctx = self.make_context()

        with patch.object(cli, "tcp_probe", side_effect=lambda ip, ports, timeout: ip != DEAD_IP):
            with redirect_stdout(io.StringIO()) as out:
                code = cmd_prune(ctx, self.args(all=True, dry_run=True, foreign=True))

        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("manual.example.com", out.getvalue())
        self.assertEqual(before, self.hosts_text())

    def test_prune_without_target_raises(self) -> None:
        ctx = self.make_context()
        with self.assertRaises(Exception):
            cmd_prune(ctx, self.args())


class NotFixableProfileTests(PruneTestBase):
    def test_apply_refuses_a_diagnostics_only_profile(self) -> None:
        before = self.hosts_text()
        ctx = self.make_context()
        args = SimpleNamespace(profile="diag", dry_run=False, force=False, no_verify=False)

        with redirect_stdout(io.StringIO()) as out:
            code = cmd_apply(ctx, args)

        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(before, self.hosts_text())
        self.assertIn("diag", out.getvalue())

    def test_json_output_reports_fixable_false(self) -> None:
        ctx = self.make_context()
        ctx.json = True
        args = SimpleNamespace(profile="diag", dry_run=False, force=False, no_verify=False)

        with redirect_stdout(io.StringIO()) as out:
            code = cmd_apply(ctx, args)

        self.assertEqual(code, cli.EXIT_OK)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["fixable"])
        self.assertFalse(payload["applied"])


class PruneParserTests(PruneTestBase):
    def test_prune_help_is_available(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
