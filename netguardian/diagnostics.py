"""End-to-end connection diagnostics and human-readable report."""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import i18n, ui
from .config import Config, normalize_domain
from .hosts import HostsFile
from .log import get_logger
from .resolver import DnsClient, DnsError, Resolver, system_lookup, tcp_probe
from .sslcheck import CertInfo, inspect

VERDICT_OK = "ok"
VERDICT_DNS = "dns"
VERDICT_TCP = "tcp"
VERDICT_TLS = "tls"
VERDICT_HOSTS = "hosts"
VERDICT_FLAKY = "flaky"
VERDICT_WAF = "waf"

ACTION_OK = "ok"
ACTION_APPLY = "apply"
ACTION_CLEANUP = "cleanup"
ACTION_PROXY = "proxy"
ACTION_NETWORK = "network"
ACTION_PIN = "pin"
ACTION_UNPIN = "unpin"
ACTION_RETRY = "retry"

# Akamai and friends answer 403 to bot-looking agents; a plain "Mozilla/5.0"
# used to be treated as a successful reachability check.
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
)


@dataclass
class IpProbe:
    """One address tried several times: an open TCP port proves nothing."""

    ip: str
    tcp_ok: bool
    tls_ok: int
    tls_fail: int
    last_error: str = ""

    @property
    def rate(self) -> float:
        total = self.tls_ok + self.tls_fail
        return self.tls_ok / total if total else 0.0

    @property
    def verdict(self) -> str:
        if self.rate >= 0.8:
            return "ok"
        if self.rate > 0:
            return "flaky"
        return "dead"


def probe_ips(
    domain: str,
    ips: Sequence[str],
    attempts: int = 3,
    timeout: float = 6.0,
    tls_inspector=inspect,
) -> List[IpProbe]:
    """Try the TLS handshake *attempts* times per address.

    A host can accept TCP and still never answer the handshake; that is the
    case this function exists for, so TCP is only recorded, never trusted.
    """
    probes: List[IpProbe] = []
    for ip in ips:
        try:
            tcp_ok = tcp_probe(ip, (443,), timeout)
        except Exception as exc:  # pragma: no cover - defensive
            probes.append(IpProbe(ip, False, 0, attempts, str(exc)))
            continue
        tls_ok = 0
        tls_fail = 0
        last_error = ""
        for _ in range(attempts):
            try:
                cert = tls_inspector(domain, ip=ip, timeout=timeout)
                if cert.verified:
                    tls_ok += 1
                else:
                    tls_fail += 1
                    last_error = cert.error or "certificate not verified"
            except Exception as exc:
                tls_fail += 1
                last_error = str(exc)
        probes.append(IpProbe(ip, tcp_ok, tls_ok, tls_fail, last_error))
    return probes


@dataclass
class DiagnosticReport:
    domain: str
    hosts_pairs: List[Tuple[str, str]] = field(default_factory=list)
    hosts_stale: bool = False
    system_ips: List[str] = field(default_factory=list)
    local_dns: str = ""
    local_ips: List[str] = field(default_factory=list)
    tcp_results: List[Tuple[str, int, bool]] = field(default_factory=list)
    cert: Optional[CertInfo] = None
    proxy: str = ""
    admin: bool = False
    profile: Optional[str] = None
    verdict: str = VERDICT_OK
    action: str = ACTION_OK
    dns_error: str = ""
    ip_probes: List[IpProbe] = field(default_factory=list)
    http_status: int = 0

    @property
    def working_ips(self) -> List[str]:
        return [ip for ip, _port, ok in self.tcp_results if ok]

    @property
    def candidates(self) -> List[str]:
        return [ip for ip, _port, _ok in self.tcp_results]


def system_proxy() -> str:
    """Return the configured system proxy, if any (best effort)."""
    for variable in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        value = os.environ.get(variable)
        if value:
            return value
    if os.name != "nt":
        return ""
    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return ""
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            return str(server or "")
    except OSError:
        return ""


def find_profile_for_domain(config: Config, domain: str) -> Optional[str]:
    for name, profile in config.profiles.items():
        if domain in profile.domains:
            return name
    return None


def _hosts_pairs(hosts: HostsFile, domain: str) -> List[Tuple[str, str]]:
    if not hosts.exists():
        return []
    try:
        lines = hosts.read().lines
    except Exception as exc:  # pragma: no cover - defensive
        get_logger().warning("cannot read hosts for diagnostics: %s", exc)
        return []
    pairs: List[Tuple[str, str]] = []
    for line in lines:
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if len(parts) < 2:
            continue
        for name in parts[1:]:
            if name.strip().lower().rstrip(".") == domain:
                pairs.append((parts[0], domain))
    return pairs


def http_status(domain: str, timeout: float = 8.0) -> int:
    """HTTP status of the site root, asked politely.

    Returns 0 when the request itself failed, so a caller can tell
    "no answer" from "answered 403".
    """
    request = urllib.request.Request(
        f"https://{domain}/",
        headers={"User-Agent": BROWSER_UA},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:
        return 0


def run(
    raw_domain: str,
    config: Config,
    hosts: HostsFile,
    *,
    resolver: Optional[Resolver] = None,
    tls_inspector=inspect,
    proxy_reader=system_proxy,
    admin: Optional[bool] = None,
    http_probe=http_status,
) -> DiagnosticReport:
    domain = normalize_domain(raw_domain)
    report = DiagnosticReport(domain=domain)
    report.hosts_pairs = _hosts_pairs(hosts, domain)
    report.local_dns = config.settings.local_dns
    report.proxy = proxy_reader()
    if admin is None:
        from .security import is_admin

        admin = is_admin()
    report.admin = bool(admin)
    report.profile = find_profile_for_domain(config, domain)

    try:
        report.system_ips = system_lookup(domain, timeout=config.settings.dns_timeout_sec)
    except DnsError as exc:
        report.dns_error = str(exc)

    if config.settings.local_dns:
        client = DnsClient(config.settings.dns_timeout_sec)
        try:
            report.local_ips = client.query(domain, config.settings.local_dns)
        except DnsError as exc:
            get_logger().info("local DNS query failed: %s", exc)

    candidates: List[str] = []
    for address in [ip for ip, _ in report.hosts_pairs] + report.local_ips + report.system_ips:
        if address not in candidates:
            candidates.append(address)

    port = config.settings.tcp_timeout_sec
    for address in candidates[:8]:
        report.tcp_results.append(
            (address, 443, tcp_probe(address, (443,), port))
        )

    working = report.working_ips
    tls_timeout = max(5.0, config.settings.tcp_timeout_sec)
    if working:
        report.cert = tls_inspector(
            domain,
            ip=working[0],
            timeout=tls_timeout,
        )
        # Only TCP-open addresses are worth the repeated handshake.
        report.ip_probes = probe_ips(
            domain,
            working,
            timeout=tls_timeout,
            tls_inspector=tls_inspector,
        )

    hosts_ips = [ip for ip, _ in report.hosts_pairs]
    if hosts_ips and working and not any(ip in working for ip in hosts_ips):
        # A hosts entry points at a dead address while another route works.
        report.hosts_stale = True

    report.http_status = http_probe(domain)

    if report.http_status in (403, 451):
        # A live WAF answer is not a broken route: pinning cannot fix it.
        report.verdict = VERDICT_WAF
        report.action = ACTION_PROXY
    elif report.ip_probes and all(probe.verdict == "dead" for probe in report.ip_probes):
        report.verdict = VERDICT_TLS
        report.action = (
            ACTION_PIN if any(probe.tcp_ok for probe in report.ip_probes) else ACTION_NETWORK
        )
    elif any(probe.verdict == "flaky" for probe in report.ip_probes) and any(
        probe.verdict == "ok" for probe in report.ip_probes
    ):
        report.verdict = VERDICT_FLAKY
        report.action = ACTION_PIN
    elif report.hosts_stale:
        report.verdict = VERDICT_HOSTS
        report.action = ACTION_CLEANUP
    elif not candidates:
        report.verdict = VERDICT_DNS
        report.action = ACTION_APPLY if report.profile else ACTION_NETWORK
    elif not working:
        report.verdict = VERDICT_TCP
        report.action = ACTION_APPLY if report.profile else ACTION_NETWORK
    elif report.cert is not None and not report.cert.verified:
        report.verdict = VERDICT_TLS
        report.action = ACTION_PROXY
    else:
        report.verdict = VERDICT_OK
        report.action = ACTION_OK
    return report


def render(report: DiagnosticReport) -> None:
    """Print a report using the active language."""
    ui.header(i18n.t("diag.running", domain=report.domain))
    if report.hosts_pairs:
        for ip, _domain in report.hosts_pairs:
            ui.detail(i18n.t("diag.hosts", value=f"{ip} {report.domain}"))
    else:
        ui.detail(i18n.t("diag.no_hosts"))
    if report.system_ips:
        ui.detail(i18n.t("diag.dns_system", ips=", ".join(report.system_ips)))
    elif report.dns_error:
        ui.warn(i18n.t("diag.dns_fail", error=report.dns_error))
    if report.local_dns:
        if report.local_ips:
            ui.detail(i18n.t("diag.dns_local", server=report.local_dns, ips=", ".join(report.local_ips)))
        else:
            ui.detail(i18n.t("diag.dns_local", server=report.local_dns, ips=i18n.t("common.none")))
    for ip, port, ok in report.tcp_results:
        state = i18n.t("diag.tcp_ok") if ok else i18n.t("diag.tcp_fail")
        (ui.ok if ok else ui.warn)(i18n.t("diag.tcp", ip=ip, port=port, state=state))
    for probe in report.ip_probes:
        line = i18n.t(
            "diag.probe_line",
            ip=probe.ip,
            ok=probe.tls_ok,
            fail=probe.tls_fail,
            state=i18n.t(f"diag.probe_{probe.verdict}"),
        )
        (ui.ok if probe.verdict == "ok" else ui.warn)(line)
    if report.cert is not None:
        cert = report.cert
        state = i18n.t("diag.tls_ok") if cert.verified else i18n.t("diag.tls_fail")
        (ui.ok if cert.verified else ui.err)(i18n.t("diag.tls", state=state))
        if cert.issuer or cert.subject:
            ui.detail(
                i18n.t(
                    "diag.cert",
                    subject=cert.subject or i18n.t("common.unknown"),
                    issuer=cert.issuer or i18n.t("common.unknown"),
                    days=cert.days_left if cert.days_left is not None else "?",
                )
            )
        if cert.error and not cert.verified:
            ui.detail(cert.error)
    if report.proxy:
        ui.warn(i18n.t("diag.proxy", value=report.proxy))
    else:
        ui.detail(i18n.t("diag.proxy_off"))
    ui.header(i18n.t("diag.verdict", verdict=i18n.t(f"diag.verdict_{report.verdict}")))
    ui.info(i18n.t("diag.hint", action=i18n.t(f"diag.action_{report.action}")))
    _render_actions(report)


_ACTION_KEYS = {
    ACTION_OK: "diag.act_ok",
    ACTION_APPLY: "diag.act_apply",
    ACTION_CLEANUP: "diag.act_cleanup",
    ACTION_PROXY: "diag.act_proxy",
    ACTION_NETWORK: "diag.act_network",
    ACTION_PIN: "diag.act_pin",
    ACTION_UNPIN: "diag.act_unpin",
    ACTION_RETRY: "diag.act_retry",
}


def _render_actions(report: DiagnosticReport) -> None:
    """Numbered, actionable list instead of a single vague hint."""
    key = _ACTION_KEYS.get(report.action, "diag.act_network")
    ui.header(i18n.t("diag.actions"))
    ui.info(f"1. {i18n.t(key)}")
    hint_key = f"{key}_hint"
    hint = i18n.t(hint_key)
    if hint != hint_key:
        ui.detail(hint)
    if report.verdict == VERDICT_FLAKY and report.ip_probes:
        best = max(report.ip_probes, key=lambda probe: probe.rate)
        ui.detail(i18n.t("diag.best_ip", ip=best.ip, rate=f"{best.rate:.0%}"))


__all__ = [
    "ACTION_APPLY",
    "ACTION_CLEANUP",
    "ACTION_NETWORK",
    "ACTION_OK",
    "ACTION_PIN",
    "ACTION_PROXY",
    "ACTION_RETRY",
    "ACTION_UNPIN",
    "DiagnosticReport",
    "IpProbe",
    "VERDICT_DNS",
    "VERDICT_FLAKY",
    "VERDICT_HOSTS",
    "VERDICT_OK",
    "VERDICT_TCP",
    "VERDICT_TLS",
    "VERDICT_WAF",
    "find_profile_for_domain",
    "http_status",
    "probe_ips",
    "render",
    "run",
    "system_proxy",
]
