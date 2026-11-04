"""Configuration model, validation and persistence.

The on-disk format is the same ``routes.json`` used by NetGuardian 2.x, so
existing profiles keep working.  New optional settings receive defaults on
load and are written back only when the user edits the configuration.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import i18n
from .errors import ConfigError
from .fsutil import atomic_write_text
from .log import get_logger
from .sslcheck import PIN_MODES


def _as_pin_mode(value: Any) -> str:
    """Reject a typo instead of silently falling back to strict."""
    mode = str(value).strip().lower()
    if mode not in PIN_MODES:
        raise ValueError(f"pin_mode must be one of {', '.join(PIN_MODES)}, got {value!r}")
    return mode

STRATEGIES = ("static_first", "dns_discovery_only", "static_only", "system_dns")
DEFAULT_PORTS = (443,)
STUCK_STATES_DEFAULT = ("SYN_SENT", "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "language": "auto",
    "local_dns": "",
    "dns_timeout_sec": 3,
    "tcp_timeout_sec": 3,
    "cache_ttl_hours": 6,
    "backup_keep": 10,
    "verify_after_apply": True,
    "pin_mode": "strict",
    "stuck_states": list(STUCK_STATES_DEFAULT),
}

DEFAULT_PROFILES: Dict[str, Dict[str, Any]] = {
    "microsoft_fix": {
        "description": "Microsoft Edge / Windows Update nodes",
        "process_hints": ["svchost", "MoUsoCoreWorker"],
        "domains": ["msdl.microsoft.com", "download.microsoft.com"],
        "strategy": "static_first",
        "static_candidates": ["150.171.27.10", "150.171.28.10"],
        "expected_issuers": ["Microsoft Corporation", "DigiCert"],
        "ports": [443],
    },
    "github_access": {
        "description": "GitHub web, API, raw content and archives",
        "process_hints": ["git", "Code", "chrome", "firefox", "msedge"],
        "domains": [
            "github.com",
            "api.github.com",
            "raw.githubusercontent.com",
            "gist.githubusercontent.com",
            "codeload.github.com",
        ],
        "strategy": "static_first",
        "static_candidates": [],
        "domain_candidates": {
            "github.com": ["140.82.121.3", "140.82.112.3", "140.82.113.3", "140.82.114.3"],
            "api.github.com": ["140.82.121.6", "140.82.112.6", "140.82.113.6"],
            "raw.githubusercontent.com": [
                "185.199.108.133",
                "185.199.109.133",
                "185.199.110.133",
                "185.199.111.133",
            ],
            "gist.githubusercontent.com": [
                "185.199.108.133",
                "185.199.109.133",
                "185.199.110.133",
                "185.199.111.133",
            ],
            "codeload.github.com": ["140.82.121.9", "140.82.112.9"],
        },
        "expected_issuers": ["Sectigo", "DigiCert", "Let's Encrypt", "GitHub"],
        "ports": [443],
    },
    "gitlab_access": {
        "description": "GitLab web and container registry",
        "process_hints": ["git", "chrome", "firefox", "msedge"],
        "domains": ["gitlab.com", "registry.gitlab.com"],
        "strategy": "static_first",
        "static_candidates": [],
        "domain_candidates": {
            "gitlab.com": ["172.65.251.78"],
            "registry.gitlab.com": ["35.227.35.254"],
        },
        "expected_issuers": ["Sectigo", "DigiCert", "Let's Encrypt"],
        "ports": [443],
    },
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "settings": dict(DEFAULT_SETTINGS),
    "profiles": {name: dict(profile) for name, profile in DEFAULT_PROFILES.items()},
}

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


# --------------------------------------------------------------------------
# value normalisation
# --------------------------------------------------------------------------
def normalize_domain(value: Any) -> str:
    """Turn a URL or host name into a lowercase ASCII host name."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty domain")
    text = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", text)
    text = re.split(r"[/?#]", text, maxsplit=1)[0]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        raise ValueError("IPv6 literals cannot be pinned through the hosts file")
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.rstrip(".").lower()
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid international domain: {exc}") from exc
    if not _DOMAIN_RE.match(text):
        raise ValueError("not a valid host name")
    return text


def _normalize_ip(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc
    if address.version != 4:
        raise ValueError("only IPv4 addresses are supported for hosts pinning")
    return str(address)


def _as_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return number


def _as_float(value: Any, name: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return number


def _as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("1", "true", "yes", "on"):
        return True
    if isinstance(value, str) and value.strip().lower() in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false")


def _as_string_list(value: Any, name: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    result = []
    for item in value:
        text = str(item).strip()
        if text:
            result.append(text)
    return result


# --------------------------------------------------------------------------
# model
# --------------------------------------------------------------------------
@dataclass
class Settings:
    language: str = "auto"
    local_dns: str = ""
    dns_timeout_sec: float = 3.0
    tcp_timeout_sec: float = 3.0
    cache_ttl_hours: float = 6.0
    backup_keep: int = 10
    verify_after_apply: bool = True
    pin_mode: str = "strict"
    stuck_states: List[str] = field(default_factory=lambda: list(STUCK_STATES_DEFAULT))


@dataclass
class Profile:
    name: str
    description: str
    domains: List[str]
    process_hints: List[str]
    strategy: str
    static_candidates: List[str]
    expected_issuers: List[str]
    ports: List[int]
    # False means: this profile is diagnostics-only. Pinning its domains in
    # hosts cannot help, so ``apply`` refuses instead of writing a fix that
    # will be rolled back on every run.
    fixable: bool = True
    domain_candidates: Dict[str, List[str]] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    path: Path
    settings: Settings
    profiles: Dict[str, Profile]
    raw_settings: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    # -- convenience -------------------------------------------------------
    def profile(self, name: str) -> Profile:
        try:
            return self.profiles[name]
        except KeyError as exc:
            raise ConfigError(i18n.t("validate.no_profile", profile=name)) from exc

    def profile_names(self) -> List[str]:
        return list(self.profiles.keys())

    @property
    def domain_count(self) -> int:
        return sum(len(profile.domains) for profile in self.profiles.values())

    def to_dict(self) -> Dict[str, Any]:
        settings = dict(self.raw_settings)
        settings.update(
            {
                "language": self.settings.language,
                "local_dns": self.settings.local_dns,
                "dns_timeout_sec": self.settings.dns_timeout_sec,
                "tcp_timeout_sec": self.settings.tcp_timeout_sec,
                "cache_ttl_hours": self.settings.cache_ttl_hours,
                "backup_keep": self.settings.backup_keep,
                "verify_after_apply": self.settings.verify_after_apply,
                "pin_mode": self.settings.pin_mode,
                "stuck_states": list(self.settings.stuck_states),
            }
        )
        profiles: Dict[str, Any] = {}
        for name, profile in self.profiles.items():
            data = dict(profile.raw)
            data.update(
                {
                    "description": profile.description,
                    "domains": list(profile.domains),
                    "process_hints": list(profile.process_hints),
                    "strategy": profile.strategy,
                    "static_candidates": list(profile.static_candidates),
                    "expected_issuers": list(profile.expected_issuers),
                    "ports": list(profile.ports),
                    "fixable": profile.fixable,
                }
            )
            if profile.domain_candidates:
                data["domain_candidates"] = {
                    domain: list(addresses) for domain, addresses in profile.domain_candidates.items()
                }
            else:
                data.pop("domain_candidates", None)
            profiles[name] = data
        return {"settings": settings, "profiles": profiles}


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def _parse_settings(raw: Any, path: Path, warnings: List[str]) -> Tuple[Settings, Dict[str, Any]]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(i18n.t("config.invalid", path=path, reason="'settings' must be an object"))
    merged = dict(DEFAULT_SETTINGS)
    merged.update(raw)
    known = set(DEFAULT_SETTINGS)
    for key in raw:
        if key not in known:
            warnings.append(f"unknown setting ignored: {key}")

    language = str(merged.get("language", "auto")).strip().lower() or "auto"
    if language not in ("auto", *i18n.SUPPORTED_LANGUAGES):
        raise ConfigError(
            i18n.t("config.invalid", path=path, reason=f"language must be auto, en or ru (got {language!r})")
        )

    local_dns = str(merged.get("local_dns", "") or "").strip()
    if local_dns.lower() in ("", "auto", "system", "default"):
        local_dns = ""
    else:
        try:
            local_dns = _normalize_ip(local_dns)
        except ValueError as exc:
            raise ConfigError(i18n.t("config.invalid", path=path, reason=f"local_dns: {exc}")) from exc

    try:
        settings = Settings(
            language=language,
            local_dns=local_dns,
            dns_timeout_sec=_as_float(merged["dns_timeout_sec"], "dns_timeout_sec", 1, 30),
            tcp_timeout_sec=_as_float(merged["tcp_timeout_sec"], "tcp_timeout_sec", 1, 30),
            cache_ttl_hours=_as_float(merged["cache_ttl_hours"], "cache_ttl_hours", 0, 720),
            backup_keep=_as_int(merged["backup_keep"], "backup_keep", 1, 100),
            verify_after_apply=_as_bool(merged["verify_after_apply"], "verify_after_apply"),
            pin_mode=_as_pin_mode(merged["pin_mode"]),
            stuck_states=[str(s).strip().upper() for s in _as_string_list(merged["stuck_states"], "stuck_states")]
            or list(STUCK_STATES_DEFAULT),
        )
    except ValueError as exc:
        raise ConfigError(i18n.t("config.invalid", path=path, reason=str(exc))) from exc
    return settings, raw


def _parse_profile(name: str, raw: Any, path: Path) -> Profile:
    if not _PROFILE_NAME_RE.match(name):
        raise ConfigError(i18n.t("config.invalid", path=path, reason=f"invalid profile name {name!r}"))
    if not isinstance(raw, dict):
        raise ConfigError(i18n.t("config.invalid", path=path, reason=f"profile {name!r} must be an object"))

    try:
        domains = []
        for item in _as_string_list(raw.get("domains"), f"{name}.domains"):
            domain = normalize_domain(item)
            if domain not in domains:
                domains.append(domain)
        if not domains:
            raise ValueError("at least one domain is required")

        strategy = str(raw.get("strategy", "dns_discovery_only")).strip().lower()
        if strategy not in STRATEGIES:
            raise ValueError(f"strategy must be one of: {', '.join(STRATEGIES)}")

        static_candidates = []
        for item in _as_string_list(raw.get("static_candidates"), f"{name}.static_candidates"):
            ip = _normalize_ip(item)
            if ip not in static_candidates:
                static_candidates.append(ip)

        domain_candidates: Dict[str, List[str]] = {}
        raw_domain_candidates = raw.get("domain_candidates") or {}
        if not isinstance(raw_domain_candidates, dict):
            raise ValueError("domain_candidates must be an object")
        for domain_key, addresses in raw_domain_candidates.items():
            domain = normalize_domain(domain_key)
            if domain not in domains:
                raise ValueError(f"domain_candidates key {domain!r} is not listed in domains")
            normalized: List[str] = []
            for item in _as_string_list(addresses, f"{name}.domain_candidates.{domain}"):
                ip = _normalize_ip(item)
                if ip not in normalized:
                    normalized.append(ip)
            if not normalized:
                raise ValueError(f"domain_candidates.{domain} must not be empty")
            domain_candidates[domain] = normalized

        if strategy in ("static_first", "static_only") and not static_candidates and not domain_candidates:
            raise ValueError(
                f"strategy {strategy} requires static_candidates or domain_candidates"
            )

        ports = []
        for item in raw.get("ports") or list(DEFAULT_PORTS):
            ports.append(_as_int(item, f"{name}.ports", 1, 65535))
        if not ports:
            ports = list(DEFAULT_PORTS)

        fixable_raw = raw.get("fixable", True)
        if not isinstance(fixable_raw, bool):
            raise ValueError("fixable must be true or false")

        profile = Profile(
            name=name,
            description=str(raw.get("description", "") or ""),
            domains=domains,
            process_hints=_as_string_list(raw.get("process_hints"), f"{name}.process_hints"),
            strategy=strategy,
            static_candidates=static_candidates,
            expected_issuers=_as_string_list(raw.get("expected_issuers"), f"{name}.expected_issuers"),
            ports=ports,
            fixable=fixable_raw,
            domain_candidates=domain_candidates,
            raw=dict(raw),
        )
    except ValueError as exc:
        raise ConfigError(i18n.t("config.invalid", path=path, reason=f"profile {name!r}: {exc}")) from exc
    return profile


def parse_config(raw: Any, path: Path) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError(i18n.t("config.invalid", path=path, reason="top level must be an object"))
    warnings: List[str] = []
    settings, raw_settings = _parse_settings(raw.get("settings"), path, warnings)
    raw_profiles = raw.get("profiles", {})
    if raw_profiles is None:
        raw_profiles = {}
    if not isinstance(raw_profiles, dict):
        raise ConfigError(i18n.t("config.invalid", path=path, reason="'profiles' must be an object"))
    profiles = {name: _parse_profile(name, value, path) for name, value in raw_profiles.items()}
    return Config(path=path, settings=settings, profiles=profiles, raw_settings=raw_settings, warnings=warnings)


def load_config(path: Path, *, create: bool = True) -> Tuple[Config, bool]:
    """Load and validate *path*; optionally create it with defaults.

    Returns ``(config, created)``.
    """
    path = Path(path)
    created = False
    if not path.is_file():
        if not create:
            raise ConfigError(i18n.t("config.missing", path=path), hint=i18n.t("config.hint"))
        write_default_config(path)
        created = True
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            i18n.t("config.invalid", path=path, reason=f"JSON syntax error at line {exc.lineno}: {exc.msg}"),
            hint=i18n.t("config.hint"),
        ) from exc
    except OSError as exc:
        raise ConfigError(i18n.t("config.invalid", path=path, reason=str(exc)), hint=i18n.t("config.hint")) from exc
    config = parse_config(raw, path)
    for warning in config.warnings:
        get_logger().warning(warning)
    return config, created


def write_default_config(path: Path) -> None:
    save_config_dict(DEFAULT_CONFIG, path)


def save_config_dict(data: Dict[str, Any], path: Path) -> None:
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    try:
        atomic_write_text(Path(path), text)
    except OSError as exc:
        raise ConfigError(i18n.t("config.invalid", path=path, reason=f"cannot write: {exc}")) from exc


def save_config(config: Config, path: Optional[Path] = None) -> None:
    save_config_dict(config.to_dict(), Path(path or config.path))


def update_setting(config: Config, key: str, value: Any) -> None:
    """Validate and persist one setting without touching the rest."""
    data = config.to_dict()
    data["settings"][key] = value
    parsed = parse_config(data, config.path)
    config.settings = parsed.settings
    config.raw_settings = parsed.raw_settings
    save_config(config)


__all__ = [
    "Config",
    "ConfigError",
    "DEFAULT_CONFIG",
    "DEFAULT_PROFILES",
    "DEFAULT_SETTINGS",
    "DEFAULT_PORTS",
    "Profile",
    "STRATEGIES",
    "STUCK_STATES_DEFAULT",
    "Settings",
    "load_config",
    "normalize_domain",
    "parse_config",
    "save_config",
    "save_config_dict",
    "update_setting",
    "write_default_config",
]
