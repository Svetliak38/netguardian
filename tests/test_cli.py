"""CLI-level tests: argument handling, JSON output and the apply pipeline."""

from __future__ import annotations

import argparse
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from netguardian import cli
from netguardian.cli import Context, cmd_apply, main
from netguardian.config import load_config
from netguardian.hosts import HostsFile
from netguardian.paths import AppPaths
from netguardian.sslcheck import CertInfo
from tests.support import TempDir

PROFILE = {
    "description": "test profile",
    "domains": ["example.com"],
    "strategy": "static_only",
    "static_candidates": ["1.2.3.4"],
    "expected_issuers": ["Test CA"],
}


class CliTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.root = Path(self._tmp.name)
        self.hosts_path = self.root / "hosts"
        self.hosts_path.write_text("127.0.0.1 localhost\r\n", encoding="utf-8", newline="")
        self.data_dir = self.root / "data"
        self.config_path = self.root / "routes.json"
        self.config_path.write_text(
            json.dumps({"settings": {"local_dns": "", "tcp_timeout_sec": 1}, "profiles": {"demo": PROFILE}}),
            encoding="utf-8",
        )
        self.backup_dir = self.data_dir / "backups"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def base_args(self):
        return [
            "--config",
            str(self.config_path),
            "--data-dir",
            str(self.data_dir),
            "--hosts",
            str(self.hosts_path),
            "--lang",
            "en",
        ]

    def run_cli(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(self.base_args() + list(args))
        return code, output.getvalue()

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
            self.hosts_path, backup_dir=self.backup_dir, admin_check=lambda: True
        )
        return ctx


class ParserTests(CliTestBase):
    def test_version_exits_zero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_global_options_work_after_the_command(self) -> None:
        code, output = self.run_cli("config", "--check", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["profiles"], 1)

    def test_json_error_is_machine_readable(self) -> None:
        self.config_path.write_text("{broken", encoding="utf-8")
        code, output = self.run_cli("config", "--check", "--json")
        self.assertEqual(code, 2)
        payload = json.loads(output)
        self.assertFalse(payload["ok"])
        self.assertIn("JSON", payload["error"])


class StatusTests(CliTestBase):
    def test_status_reports_active_blocks(self) -> None:
        self.hosts_path.write_text(
            "127.0.0.1 localhost\r\n"
            "# === NETGUARDIAN FIX (demo) [20260101_000000] BEGIN ===\r\n"
            "1.2.3.4         example.com\r\n"
            "# === NETGUARDIAN FIX (demo) [20260101_000000] END ===\r\n",
            encoding="utf-8",
            newline="",
        )
        code, output = self.run_cli("status", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(len(payload["blocks"]), 1)
        self.assertEqual(payload["blocks"][0]["profile"], "demo")
        self.assertEqual(payload["blocks"][0]["entries"][0]["ip"], "1.2.3.4")

    def test_status_reports_malformed_block(self) -> None:
        self.hosts_path.write_text(
            "# === NETGUARDIAN FIX (demo) BEGIN ===\r\n", encoding="utf-8", newline=""
        )
        code, _output = self.run_cli("status", "--json")
        self.assertEqual(code, 4)


class CleanupTests(CliTestBase):
    def test_cleanup_dry_run_keeps_file(self) -> None:
        ctx = self.make_context()
        ctx.hosts.apply("demo", {"example.com": "1.2.3.4"})
        before = self.hosts_path.read_bytes()
        code, output = self.run_cli("cleanup", "--all", "--dry-run", "--json")
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["removed"], 1)
        self.assertEqual(self.hosts_path.read_bytes(), before)

    def test_cleanup_without_target_is_an_error(self) -> None:
        code, _output = self.run_cli("cleanup", "--json")
        self.assertEqual(code, 2)


class ApplyTests(CliTestBase):
    class FakeResolver:
        def __init__(self, ip="1.2.3.4"):
            self.ip = ip

        def resolve(self, domain, **kwargs):
            from netguardian.resolver import Resolution

            return Resolution(domain=domain, ip=self.ip, source="static")

    def _apply(self, verified=True, issuer="Test CA"):
        ctx = self.make_context()
        ctx.resolver = lambda: self.FakeResolver()
        info = CertInfo(
            domain="example.com",
            ip="1.2.3.4",
            verified=verified,
            issuer=issuer,
            days_left=90,
            error="" if verified else "certificate verify failed",
        )
        args = argparse.Namespace(profile="demo", dry_run=False, force=False, no_verify=False)
        output = io.StringIO()
        with patch.object(cli, "is_admin", return_value=True), patch.object(
            cli, "inspect", return_value=info
        ), redirect_stdout(output):
            code = cmd_apply(ctx, args)
        return code, ctx, output.getvalue()

    def test_apply_writes_verified_route(self) -> None:
        code, ctx, _output = self._apply()
        self.assertEqual(code, 0)
        blocks = ctx.hosts.blocks()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].entries, [("1.2.3.4", "example.com")])

    def test_failed_verification_rolls_back(self) -> None:
        code, ctx, _output = self._apply(verified=False)
        self.assertEqual(code, 1)
        self.assertEqual(ctx.hosts.blocks(), [])
        self.assertEqual(self.hosts_path.read_bytes(), b"127.0.0.1 localhost\r\n")

    def test_issuer_mismatch_rolls_back(self) -> None:
        code, ctx, _output = self._apply(issuer="Evil CA")
        self.assertEqual(code, 1)
        self.assertEqual(ctx.hosts.blocks(), [])

    def test_non_admin_apply_returns_exit_code_three(self) -> None:
        with patch.object(cli, "is_admin", return_value=False):
            code, _output = self.run_cli("apply", "demo")
        self.assertEqual(code, 3)

    def test_relaunch_argv_keeps_path_overrides(self) -> None:
        ctx = self.make_context()
        argv = cli._relaunch_argv(ctx, ["apply", "demo"])
        self.assertEqual(argv[argv.index("--config") + 1], str(self.config_path))
        self.assertEqual(argv[argv.index("--data-dir") + 1], str(self.data_dir))
        self.assertEqual(argv[argv.index("--hosts") + 1], str(self.hosts_path))
        self.assertEqual(argv[-2:], ["apply", "demo"])


class DiagnosticsTests(CliTestBase):
    def test_invalid_domain_is_a_config_error(self) -> None:
        code, _output = self.run_cli("diag", "not a domain", "--json")
        self.assertEqual(code, 2)


class LanguageTests(CliTestBase):
    def test_language_is_persisted(self) -> None:
        code, _output = self.run_cli("lang", "ru")
        self.assertEqual(code, 0)
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["settings"]["language"], "ru")


if __name__ == "__main__":
    unittest.main()
