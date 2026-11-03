"""Configuration parsing, validation and persistence tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from netguardian.config import (
    ConfigError,
    DEFAULT_CONFIG,
    load_config,
    normalize_domain,
    parse_config,
    save_config,
    update_setting,
)
from tests.support import TempDir


def minimal(**overrides):
    data = {
        "settings": {"local_dns": ""},
        "profiles": {
            "demo": {
                "domains": ["example.com"],
                "strategy": "dns_discovery_only",
            }
        },
    }
    data.update(overrides)
    return data


class DomainNormalizationTests(unittest.TestCase):
    def test_url_is_reduced_to_host(self) -> None:
        self.assertEqual(normalize_domain("https://GitHub.com/owner/repo?x=1"), "github.com")

    def test_port_and_credentials_are_stripped(self) -> None:
        self.assertEqual(normalize_domain("http://user:pass@example.com:8443/x"), "example.com")

    def test_trailing_dot_is_removed(self) -> None:
        self.assertEqual(normalize_domain("example.com."), "example.com")

    def test_idn_is_punycoded(self) -> None:
        self.assertEqual(normalize_domain("münich.de"), "xn--mnich-kva.de")

    def test_garbage_is_rejected(self) -> None:
        for value in ("", "not a domain", "http://", "localhost", "-bad.example", "a..b"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_domain(value)


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.root = Path(self._tmp.name)
        self.path = self.root / "routes.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, data) -> Path:
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return self.path

    def test_missing_file_is_created_with_defaults(self) -> None:
        config, created = load_config(self.path)
        self.assertTrue(created)
        self.assertTrue(self.path.is_file())
        self.assertEqual(len(config.profiles), len(DEFAULT_CONFIG["profiles"]))
        self.assertEqual(config.settings.language, "auto")

    def test_defaults_fill_missing_settings(self) -> None:
        config, created = load_config(self.write(minimal()))
        self.assertFalse(created)
        self.assertEqual(config.settings.tcp_timeout_sec, 3)
        self.assertTrue(config.settings.verify_after_apply)
        self.assertEqual(config.settings.cache_ttl_hours, 6)

    def test_system_dns_alias_is_normalised(self) -> None:
        config = parse_config(minimal(settings={"local_dns": "system"}), self.path)
        self.assertEqual(config.settings.local_dns, "")

    def test_invalid_json_reports_syntax_error(self) -> None:
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ConfigError) as ctx:
            load_config(self.path)
        self.assertIn("JSON", str(ctx.exception))

    def test_unknown_strategy_is_rejected(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["strategy"] = "magic"
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_static_first_needs_candidates(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["strategy"] = "static_first"
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_static_candidates_must_be_ipv4(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["strategy"] = "static_first"
        data["profiles"]["demo"]["static_candidates"] = ["::1"]
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_profile_needs_a_domain(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["domains"] = []
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_invalid_profile_name_is_rejected(self) -> None:
        data = {"settings": {}, "profiles": {"bad name!": {"domains": ["example.com"]}}}
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_unknown_settings_produce_warnings(self) -> None:
        config = parse_config(minimal(settings={"local_dns": "", "future_option": 1}), self.path)
        self.assertTrue(any("future_option" in warning for warning in config.warnings))

    def test_language_is_validated(self) -> None:
        with self.assertRaises(ConfigError):
            parse_config(minimal(settings={"language": "klingon"}), self.path)

    def test_ports_are_validated(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["ports"] = [70000]
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_duplicate_domains_are_collapsed(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["domains"] = ["Example.com", "example.com", "https://example.com/x"]
        config = parse_config(data, self.path)
        self.assertEqual(config.profiles["demo"].domains, ["example.com"])

    def test_domain_candidates_are_parsed(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["strategy"] = "static_first"
        data["profiles"]["demo"]["domain_candidates"] = {"example.com": ["1.2.3.4", "5.6.7.8"]}
        config = parse_config(data, self.path)
        self.assertEqual(
            config.profiles["demo"].domain_candidates,
            {"example.com": ["1.2.3.4", "5.6.7.8"]},
        )

    def test_domain_candidates_key_must_be_listed_in_domains(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["domain_candidates"] = {"other.example": ["1.2.3.4"]}
        with self.assertRaises(ConfigError):
            parse_config(data, self.path)

    def test_roundtrip_preserves_unknown_profile_fields(self) -> None:
        data = minimal()
        data["profiles"]["demo"]["custom_note"] = "keep me"
        config = parse_config(data, self.path)
        save_config(config)
        reloaded, _ = load_config(self.path, create=False)
        self.assertEqual(reloaded.profiles["demo"].raw.get("custom_note"), "keep me")

    def test_update_setting_persists(self) -> None:
        config = parse_config(minimal(), self.path)
        update_setting(config, "tcp_timeout_sec", 7)
        reloaded, _ = load_config(self.path, create=False)
        self.assertEqual(reloaded.settings.tcp_timeout_sec, 7)

    def test_to_dict_is_loadable(self) -> None:
        config = parse_config(minimal(), self.path)
        again = parse_config(config.to_dict(), self.path)
        self.assertEqual(again.profile_names(), config.profile_names())


if __name__ == "__main__":
    unittest.main()
