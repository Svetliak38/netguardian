"""Parsing tests for netstat/tasklist output and stuck-connection filtering."""

from __future__ import annotations

import unittest

from netguardian.scanner import (
    Connection,
    find_stuck,
    match_profile,
    parse_netstat,
    parse_tasklist,
    split_address,
)

NETSTAT = """\ufeff

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.5:52344      93.184.216.34:443      SYN_SENT        1234
  TCP    192.168.1.5:52345      93.184.216.35:443      ESTABLISHED     1234
  TCP    [fe80::1%12]:54632     [2001:db8::1]:443      CLOSE_WAIT      4321
  TCP    127.0.0.1:5000         127.0.0.1:6000         CLOSE_WAIT      99
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1772
  TCP    10.0.0.2:1234          203.0.113.9:80         FIN_WAIT_2      555
  UDP    0.0.0.0:500            *:*                    1234
"""

TASKLIST = """"Image Name","PID","Session Name","Session#","Mem Usage"
"System Idle Process","0","Services","0","8 K"
"game.exe","1234","Console","1","120,000 K"
"My,App.exe","4321","Console","1","54,000 K"
"not a pid","abc","Console","1","1 K"
"""


class SplitAddressTests(unittest.TestCase):
    def test_ipv4(self) -> None:
        self.assertEqual(split_address("1.2.3.4:443"), ("1.2.3.4", 443))

    def test_ipv6_with_zone(self) -> None:
        self.assertEqual(split_address("[fe80::1%12]:443"), ("fe80::1%12", 443))

    def test_wildcard(self) -> None:
        self.assertEqual(split_address("*:*"), ("*", 0))


class NetstatTests(unittest.TestCase):
    def test_tcp_rows_are_parsed(self) -> None:
        connections = parse_netstat(NETSTAT)
        self.assertEqual(len(connections), 6)
        first = connections[0]
        self.assertEqual(first.local_ip, "192.168.1.5")
        self.assertEqual(first.local_port, 52344)
        self.assertEqual(first.remote_ip, "93.184.216.34")
        self.assertEqual(first.remote_port, 443)
        self.assertEqual(first.state, "SYN_SENT")
        self.assertEqual(first.pid, 1234)

    def test_ipv6_row_is_parsed(self) -> None:
        connections = parse_netstat(NETSTAT)
        ipv6 = [item for item in connections if item.remote_ip == "2001:db8::1"]
        self.assertEqual(len(ipv6), 1)
        self.assertEqual(ipv6[0].local_ip, "fe80::1%12")
        self.assertEqual(ipv6[0].pid, 4321)

    def test_udp_and_headers_are_ignored(self) -> None:
        connections = parse_netstat(NETSTAT)
        self.assertTrue(all(item.proto.startswith("TCP") for item in connections))

    def test_garbage_lines_do_not_crash(self) -> None:
        self.assertEqual(parse_netstat("hello world\nTCP\n"), [])


class TasklistTests(unittest.TestCase):
    def test_quoted_values_and_commas(self) -> None:
        mapping = parse_tasklist(TASKLIST)
        self.assertEqual(mapping[1234], "game.exe")
        self.assertEqual(mapping[4321], "My,App.exe")
        self.assertNotIn("abc", mapping)


def _conn(
    local_port: int,
    remote_ip: str,
    state: str,
    pid: int,
    name: str,
    remote_port: int = 443,
    local_ip: str = "10.0.0.1",
) -> Connection:
    return Connection("TCP", local_ip, local_port, remote_ip, remote_port, state, pid, name)


class FindStuckTests(unittest.TestCase):
    def test_persistent_connection_is_reported(self) -> None:
        first = [_conn(1000, "93.184.216.34", "SYN_SENT", 10, "game.exe")]
        second = [_conn(1000, "93.184.216.34", "SYN_SENT", 10, "game.exe")]
        stuck = find_stuck(first, ["game"], ("SYN_SENT",), interval_sec=4.0, second=second)
        self.assertEqual(len(stuck), 1)
        self.assertEqual(stuck[0].reason, "persistent")
        self.assertEqual(stuck[0].seen_sec, 4.0)

    def test_state_change_is_not_dropped(self) -> None:
        first = [_conn(1001, "93.184.216.35", "ESTABLISHED", 10, "game.exe")]
        second = [_conn(1001, "93.184.216.35", "CLOSE_WAIT", 10, "game.exe")]
        stuck = find_stuck(first, [], ("CLOSE_WAIT",), second=second)
        self.assertEqual([item.reason for item in stuck], ["state"])

    def test_pileup_keeps_real_sockets(self) -> None:
        second = [_conn(2000 + i, "2.22.145.91", "ESTABLISHED", 10, "chrome.exe") for i in range(6)]
        stuck = find_stuck([], [], second=second, pileup_threshold=6)
        self.assertEqual(len(stuck), 6)
        self.assertTrue(all(item.reason == "pileup" for item in stuck))
        # Пустых адресов быть не должно: каждая запись — реальный сокет.
        self.assertEqual(stuck[0].local, "10.0.0.1:2000")
        self.assertEqual(stuck[5].local, "10.0.0.1:2005")

    def test_persistent_wins_over_pileup(self) -> None:
        rows = [_conn(3000 + i, "2.22.145.91", "ESTABLISHED", 10, "chrome.exe") for i in range(6)]
        # ESTABLISHED is only a stuck state if the user listed it explicitly.
        stuck = find_stuck(
            rows, [], ("ESTABLISHED",), second=rows, pileup_threshold=6
        )
        self.assertEqual(len(stuck), 6)
        self.assertTrue(all(item.reason == "persistent" for item in stuck))

    def test_loopback_and_hints(self) -> None:
        rows = [
            _conn(1003, "127.0.0.1", "CLOSE_WAIT", 12, "loop.exe", remote_port=1004, local_ip="127.0.0.1"),
            _conn(1004, "93.184.216.36", "CLOSE_WAIT", 11, "other.exe"),
        ]
        stuck = find_stuck(rows, ["other"], ("CLOSE_WAIT",), second=rows)
        self.assertEqual([item.pid for item in stuck], [11])

    def test_state_matching_is_case_insensitive(self) -> None:
        rows = [_conn(1000, "93.184.216.34", "SYN_SENT", 10, "game.exe")]
        self.assertEqual(len(find_stuck(rows, [], ("syn_sent",), second=rows)), 1)

    def test_time_wait_is_not_stuck(self) -> None:
        rows = [_conn(4000, "95.100.107.143", "TIME_WAIT", 4321, "chrome.exe") for _ in range(3)]
        self.assertEqual(find_stuck(rows, [], second=rows), [])

    def test_pid_zero_rows_are_ignored(self) -> None:
        rows = [_conn(4001, "95.100.107.143", "SYN_SENT", 0, "System Idle Process")]
        self.assertEqual(find_stuck(rows, [], second=rows), [])

    def test_empty_inputs(self) -> None:
        self.assertEqual(find_stuck([], [], second=[]), [])


class MatchProfileTests(unittest.TestCase):
    def test_match_profile(self) -> None:
        profiles = {"game": ["game.exe"], "browser": ["msedge"]}
        self.assertEqual(match_profile("Game.exe", profiles), "game")
        self.assertIsNone(match_profile("unknown.exe", profiles))


if __name__ == "__main__":
    unittest.main()
