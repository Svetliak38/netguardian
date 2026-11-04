"""TLS certificate inspection for pinned and unpinned routes."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Sequence, Tuple

PIN_MODES = ("strict", "medium", "soft")


@dataclass
class CertInfo:
    domain: str
    ip: Optional[str] = None
    verified: bool = False
    issuer: str = ""
    subject: str = ""
    not_after: Optional[datetime] = None
    days_left: Optional[int] = None
    sans: List[str] = field(default_factory=list)
    protocol: str = ""
    error: str = ""
    mode: str = "strict"
    acceptable: bool = False

    @property
    def expired(self) -> bool:
        return self.days_left is not None and self.days_left < 0


def _name_to_dict(value) -> dict:
    result: dict = {}
    for item in value or ():
        for key, text in item:
            result[key] = text
    return result


def issuer_matches(issuer: str, expected: Sequence[str]) -> bool:
    if not expected:
        return True
    haystack = (issuer or "").lower()
    return any(token.lower() in haystack for token in expected if token)


def _sans_match(sans: Sequence[str], domain: str) -> bool:
    """True when *domain* is listed in the certificate SANs (wildcards too)."""
    name = (domain or "").strip().lower().rstrip(".")
    for san in sans or ():
        entry = (san or "").strip().lower().rstrip(".")
        if entry == name:
            return True
        if entry.startswith("*.") and name.endswith(entry[1:]):
            return True
    return False


def inspect(
    domain: str,
    *,
    ip: Optional[str] = None,
    port: int = 443,
    timeout: float = 5.0,
    allow_unverified_retry: bool = True,
    mode: str = "strict",
) -> CertInfo:
    """Open a TLS connection to *domain* (optionally via a pinned *ip*).

    When *ip* is given the TCP connection goes to that address while SNI and
    host name verification still use *domain*, which is exactly what a hosts
    override does.

    ``mode`` chooses how much trust is demanded: ``strict`` keeps the standard
    chain and host name check, ``medium`` accepts an unknown issuer when the
    SAN and the expiry still match, ``soft`` only wants a handshake. An
    unknown value falls back to ``strict`` so a typo cannot open a hole.
    """
    if mode not in PIN_MODES:
        mode = "strict"
    info = CertInfo(domain=domain, ip=ip, mode=mode)
    target = ip or domain
    context = ssl.create_default_context() if mode == "strict" else ssl._create_unverified_context()
    try:
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                info.protocol = tls.version() or ""
                info.verified = mode == "strict"
                _fill(info, tls.getpeercert())
                if mode == "strict":
                    info.acceptable = True
                elif mode == "medium":
                    info.acceptable = (
                        _sans_match(info.sans, domain)
                        and info.days_left is not None
                        and info.days_left >= 0
                    )
                else:
                    info.acceptable = True
        return info
    except ssl.SSLCertVerificationError as exc:
        info.error = exc.verify_message or str(exc)
        _fill_unverified(info, target, domain, port, timeout, allow_unverified_retry)
        return info
    except (ssl.SSLError, OSError) as exc:
        info.error = str(exc)
        return info


def _fill(info: CertInfo, cert: dict) -> None:
    if not cert:
        return
    issuer = _name_to_dict(cert.get("issuer"))
    subject = _name_to_dict(cert.get("subject"))
    info.issuer = issuer.get("organizationName") or issuer.get("commonName") or ""
    info.subject = subject.get("commonName") or ""
    info.sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    not_after = cert.get("notAfter")
    if not_after:
        try:
            stamp = ssl.cert_time_to_seconds(not_after)
            info.not_after = datetime.fromtimestamp(stamp)
            info.days_left = int((info.not_after - datetime.now()).total_seconds() // 86400)
        except (ValueError, OverflowError):
            pass


def _fill_unverified(
    info: CertInfo,
    target: str,
    domain: str,
    port: int,
    timeout: float,
    enabled: bool,
) -> None:
    """Retrieve certificate metadata even when validation failed.

    This is diagnostics only: ``info.verified`` stays False.
    """
    if not enabled:
        return
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                info.protocol = tls.version() or ""
                _fill(info, tls.getpeercert())
    except (ssl.SSLError, OSError):
        pass


def describe(info: CertInfo) -> str:
    """One-line human description used by validate/diagnose."""
    if info.error and not info.verified:
        return f"{info.domain}: {info.error}"
    parts = [f"issuer={info.issuer or 'unknown'}"]
    if info.days_left is not None:
        parts.append(f"expires_in={info.days_left}d")
    return f"{info.domain}: " + ", ".join(parts)


__all__ = ["CertInfo", "PIN_MODES", "describe", "inspect", "issuer_matches"]
