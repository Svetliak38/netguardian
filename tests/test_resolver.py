"""Resolver, cache and DNS wire-format tests (network-free)."""

from __future__ import annotations

import json
import socket
import struct
import time
import unittest
from pathlib import Path

from netguardian.config import Settings
from netguardian.resolver import (
    Cache,
    DnsError,
    Resolver,
    _parse_response,
    _build_query,
)
from tests.support import TempDir


def dns_response(qid: int, ips, name: str = "example.com", cname: str = "") -> bytes:
    labels = name.split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    answer_count = len(ips) + (1 if cname else 0)
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, answer_count, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    answers = b""
    if cname:
        rdata = b"".join(bytes([len(part)]) + part.encode("ascii") for part in cname.split(".")) + b"\x00"
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
    for ip in ips:
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + question + answers


class DnsWireTests(unittest.TestCase):
    def test_query_is_well_formed(self) -> None:
        packet = _build_query("example.com")
        self.assertEqual(packet[0:2], packet[0:2])
        self.assertEqual(struct.unpack("!H", packet[4:6])[0], 1)  # qdcount
        self.assertIn(b"\x07example\x03com\x00", packet)

    def test_response_returns_all_a_records(self) -> None:
        qid = struct.unpack("!H", _build_query("example.com")[:2])[0]
        data = dns_response(qid, ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(_parse_response(data, "example.com"), ["1.2.3.4", "5.6.7.8"])

    def test_duplicate_records_are_collapsed(self) -> None:
        qid = 7
        data = dns_response(qid, ["1.2.3.4", "1.2.3.4"])
        self.assertEqual(_parse_response(data, "example.com"), ["1.2.3.4"])

    def test_cname_answer_is_tolerated(self) -> None:
        qid = 7
        data = dns_response(qid, ["9.9.9.9"], cname="edge.example.net")
        self.assertEqual(_parse_response(data, "example.com"), ["9.9.9.9"])

    def test_error_rcode_raises(self) -> None:
        header = struct.pack("!HHHHHH", 1, 0x8183, 0, 0, 0, 0)
        with self.assertRaises(DnsError):
            _parse_response(header, "example.com")


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.path = Path(self._tmp.name) / "cache.json"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_legacy_layout_is_migrated(self) -> None:
        self.path.write_text(
            json.dumps({"github.com": {"ip": "140.82.121.3", "timestamp": time.time()}}),
            encoding="utf-8",
        )
        cache = Cache(self.path, ttl_hours=6)
        entry = cache.get("github.com")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.ip, "140.82.121.3")

    def test_expired_entries_are_ignored(self) -> None:
        self.path.write_text(
            json.dumps({"old.example": {"ip": "1.1.1.1", "timestamp": time.time() - 7200}}),
            encoding="utf-8",
        )
        cache = Cache(self.path, ttl_hours=1)
        self.assertIsNone(cache.get("old.example"))
        self.assertEqual(cache.prune(), 1)
        self.assertEqual(len(cache), 0)

    def test_zero_ttl_disables_the_cache(self) -> None:
        cache = Cache(self.path, ttl_hours=0)
        cache.put("example.com", "1.1.1.1")
        self.assertIsNone(cache.get("example.com"))
        self.assertEqual(len(cache), 0)

    def test_flush_writes_versioned_layout(self) -> None:
        cache = Cache(self.path, ttl_hours=6)
        cache.put("example.com", "1.1.1.1", source="static")
        cache.flush()
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(raw["version"], 2)
        self.assertEqual(raw["entries"]["example.com"]["ip"], "1.1.1.1")
        reloaded = Cache(self.path, ttl_hours=6)
        entry = reloaded.get("example.com")
        assert entry is not None
        self.assertEqual(entry.source, "static")

    def test_corrupt_cache_is_ignored(self) -> None:
        self.path.write_text("{broken", encoding="utf-8")
        cache = Cache(self.path, ttl_hours=6)
        self.assertEqual(len(cache), 0)


class FakeDns:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def query(self, domain, server):
        self.calls.append((domain, server))
        return list(self.answers)


class ResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TempDir()
        self.cache = Cache(Path(self._tmp.name) / "cache.json", ttl_hours=6)
        self.settings = Settings(local_dns="192.0.2.1", tcp_timeout_sec=1)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_static_first_uses_reachable_candidate(self) -> None:
        probes = []

        def probe(ip, ports, timeout):
            probes.append(ip)
            return ip == "5.6.7.8"

        resolver = Resolver(self.settings, self.cache, probe=probe)
        result = resolver.resolve(
            "example.com",
            strategy="static_first",
            static_candidates=["1.2.3.4", "5.6.7.8"],
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.ip, "5.6.7.8")
        self.assertEqual(result.source, "static")
        self.assertEqual(probes, ["1.2.3.4", "5.6.7.8"])

    def test_static_first_falls_back_to_dns(self) -> None:
        dns = FakeDns(["9.9.9.9"])
        resolver = Resolver(
            self.settings,
            self.cache,
            dns_client=dns,
            probe=lambda ip, ports, timeout: ip == "9.9.9.9",
        )
        result = resolver.resolve(
            "example.com", strategy="static_first", static_candidates=["1.2.3.4"]
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.ip, "9.9.9.9")
        self.assertTrue(dns.calls)

    def test_per_domain_candidates_take_priority(self) -> None:
        probes = []

        def probe(ip, ports, timeout):
            probes.append(ip)
            return ip == "9.9.9.9"

        resolver = Resolver(self.settings, self.cache, probe=probe)
        result = resolver.resolve(
            "example.com",
            strategy="static_first",
            static_candidates=["1.1.1.1"],
            domain_candidates={"example.com": ["9.9.9.9"]},
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.ip, "9.9.9.9")
        self.assertEqual(probes, ["9.9.9.9"])

    def test_cache_hit_skips_dns(self) -> None:
        self.cache.put("example.com", "3.3.3.3")
        dns = FakeDns(["9.9.9.9"])
        resolver = Resolver(
            self.settings, self.cache, dns_client=dns, probe=lambda *args: True
        )
        result = resolver.resolve("example.com", strategy="dns_discovery_only")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.source, "cache")
        self.assertEqual(dns.calls, [])

    def test_dead_cache_entry_is_dropped(self) -> None:
        self.cache.put("example.com", "3.3.3.3")
        dns = FakeDns(["4.4.4.4"])
        resolver = Resolver(
            self.settings,
            self.cache,
            dns_client=dns,
            probe=lambda ip, ports, timeout: ip == "4.4.4.4",
        )
        result = resolver.resolve("example.com", strategy="dns_discovery_only")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.ip, "4.4.4.4")
        self.assertNotEqual(self.cache.get("example.com").ip, "3.3.3.3")

    def test_static_only_never_queries_dns(self) -> None:
        dns = FakeDns(["9.9.9.9"])
        resolver = Resolver(
            self.settings, self.cache, dns_client=dns, probe=lambda *args: False
        )
        result = resolver.resolve(
            "example.com", strategy="static_only", static_candidates=["1.2.3.4"]
        )
        self.assertIsNone(result)
        self.assertEqual(dns.calls, [])

    def test_no_reachable_address_returns_none(self) -> None:
        dns = FakeDns(["9.9.9.9"])
        resolver = Resolver(
            self.settings, self.cache, dns_client=dns, probe=lambda *args: False
        )
        self.assertIsNone(resolver.resolve("example.com", strategy="static_only", static_candidates=["1.2.3.4"]))

    def test_result_is_cached(self) -> None:
        dns = FakeDns(["4.4.4.4"])
        resolver = Resolver(
            self.settings, self.cache, dns_client=dns, probe=lambda ip, *args: ip == "4.4.4.4"
        )
        resolver.resolve("example.com", strategy="dns_discovery_only")
        entry = self.cache.get("example.com")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.ip, "4.4.4.4")


if __name__ == "__main__":
    unittest.main()
