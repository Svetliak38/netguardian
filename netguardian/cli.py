"""Command-line interface and interactive control center."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__, i18n, ui
from .config import (
    Config,
    ConfigError,
    Profile,
    load_config,
    normalize_domain,
    save_config,
)
from .diagnostics import DiagnosticReport, render as render_diagnostic, run as run_diagnostic
from .errors import AdminRequiredError, HostsError, NetGuardianError
from .hosts import HostsFile
from .log import setup as setup_logging
from .log import get_logger
from .paths import AppPaths
from .repair import repair_hosts
from .resolver import Cache, Resolver, tcp_probe
from .scanner import find_stuck, list_connections, match_profile
from .security import is_admin, relaunch_elevated
from .sslcheck import inspect, issuer_matches
from .tcpview import TcpViewError, ensure as ensure_tcpview, launch as launch_tcpview

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_ADMIN = 3
EXIT_HOSTS = 4


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------
@dataclass
class Context:
    paths: AppPaths
    config: Config
    interactive: bool
    json: bool
    cache: Cache = field(init=False)
    hosts: HostsFile = field(init=False)

    def __post_init__(self) -> None:
        self.cache = Cache(self.paths.cache_file, self.config.settings.cache_ttl_hours)
        self.cache.prune()
        self.hosts = HostsFile(
            self.paths.hosts_file,
            backup_dir=self.paths.backup_dir,
            keep_backups=self.config.settings.backup_keep,
        )

    @property
    def human(self) -> bool:
        return not self.json

    def resolver(self) -> Resolver:
        return Resolver(self.config.settings, self.cache)


def _dump(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _admin_text() -> str:
    return i18n.t("common.admin") if is_admin() else i18n.t("common.not_admin")


def _ensure_admin(ctx: Context, relaunch_args: Sequence[str]) -> bool:
    """Return True when the current process may continue."""
    if is_admin():
        return True
    if ctx.json:
        raise AdminRequiredError(i18n.t("admin.required"), hint=i18n.t("admin.hint"))
    if ctx.interactive and ui.confirm(i18n.t("admin.elevate_question"), default=False):
        if relaunch_elevated(_relaunch_argv(ctx, relaunch_args)):
            ui.info(i18n.t("admin.elevated_continue"))
            return False
        ui.err(i18n.t("admin.elevate_failed", error="UAC request rejected"))
    raise AdminRequiredError(i18n.t("admin.required"), hint=i18n.t("admin.hint"))


def _relaunch_argv(ctx: Context, command_args: Sequence[str]) -> List[str]:
    """Preserve path and language overrides when restarting through UAC."""
    return [
        "--config",
        str(ctx.paths.config_file),
        "--data-dir",
        str(ctx.paths.data_dir),
        "--hosts",
        str(ctx.paths.hosts_file),
        "--lang",
        i18n.get_language(),
        *command_args,
    ]


def _parse_settings_text(config: Config) -> str:
    settings = config.settings
    return (
        f"language={settings.language}, local_dns={settings.local_dns or 'system'}, "
        f"tcp_timeout={settings.tcp_timeout_sec}s, dns_timeout={settings.dns_timeout_sec}s, "
        f"cache_ttl={settings.cache_ttl_hours}h, backups={settings.backup_keep}, "
        f"verify={settings.verify_after_apply}"
    )


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_scan(ctx: Context, args: argparse.Namespace) -> int:
    try:
        connections = list_connections()
    except RuntimeError as exc:
        raise NetGuardianError(i18n.t("scan.failed", error=exc)) from exc
    hints: List[str] = []
    for profile in ctx.config.profiles.values():
        hints.extend(profile.process_hints)
    stuck = find_stuck(connections, hints, ctx.config.settings.stuck_states)

    if ctx.json:
        _dump(
            [
                {
                    "pid": item.pid,
                    "process": item.process,
                    "state": item.state,
                    "local": item.local,
                    "remote": item.remote,
                }
                for item in stuck
            ]
        )
        return EXIT_OK

    if not stuck:
        ui.ok(i18n.t("scan.none"))
        return EXIT_OK

    ui.header(i18n.t("scan.found", count=len(stuck)))
    ui.table(
        ["PID", "PROCESS", "STATE", "REMOTE"],
        [[item.pid, item.process or "?", item.state, item.remote] for item in stuck],
    )
    first = stuck[0]
    hints_map = {name: profile.process_hints for name, profile in ctx.config.profiles.items()}
    profile_name = match_profile(first.process, hints_map)
    if profile_name:
        ui.info(i18n.t("scan.match", profile=profile_name))
        if ctx.interactive and ui.confirm(i18n.t("scan.confirm", profile=profile_name), default=False):
            return cmd_apply(
                ctx,
                argparse.Namespace(
                    profile=profile_name,
                    dry_run=False,
                    force=False,
                    no_verify=False,
                    yes=True,
                ),
            )
    else:
        ui.warn(i18n.t("scan.no_match"))
    return EXIT_OK


def _resolve_profile(ctx: Context, profile: Profile, *, show: bool) -> Tuple[Dict[str, str], List[str]]:
    if show:
        ui.info(i18n.t("apply.start", profile=profile.name))
    resolver = ctx.resolver()
    mapping: Dict[str, str] = {}
    missing: List[str] = []
    try:
        for domain in profile.domains:
            resolution = resolver.resolve(
                domain,
                strategy=profile.strategy,
                static_candidates=profile.static_candidates,
                domain_candidates=profile.domain_candidates,
                ports=tuple(profile.ports),
            )
            if resolution is None:
                missing.append(domain)
                if show:
                    ui.warn(i18n.t("apply.domain_missing", domain=domain))
                continue
            mapping[domain] = resolution.ip
            if show:
                ui.detail(i18n.t("apply.domain_ok", domain=domain, ip=resolution.ip, source=resolution.source))
    finally:
        ctx.cache.flush()
    return mapping, missing


def _verify_mapping(ctx: Context, profile: Profile, mapping: Dict[str, str]) -> List[Tuple[str, str]]:
    failures: List[Tuple[str, str]] = []
    timeout = max(5.0, ctx.config.settings.tcp_timeout_sec)
    for domain, ip in mapping.items():
        info = inspect(domain, ip=ip, timeout=timeout)
        if not info.verified:
            failures.append((domain, info.error or i18n.t("validate.untrusted", domain=domain, reason="TLS")))
            continue
        if not issuer_matches(info.issuer, profile.expected_issuers):
            failures.append(
                (
                    domain,
                    i18n.t(
                        "validate.issuer_mismatch",
                        issuer=info.issuer,
                        expected=", ".join(profile.expected_issuers),
                    ),
                )
            )
    return failures


def cmd_apply(ctx: Context, args: argparse.Namespace) -> int:
    profiles = ctx.config.profiles
    if not profiles:
        raise ConfigError(i18n.t("apply.no_profiles"))

    name = getattr(args, "profile", None)
    if not name:
        if not ctx.interactive:
            raise ConfigError(i18n.t("apply.bad_selection"))
        ui.header(i18n.t("apply.select"))
        names = list(profiles)
        for index, key in enumerate(names, start=1):
            description = profiles[key].description
            ui.plain(f"  [{index}] {key}" + (f" - {description}" if description else ""))
        choice = ui.choose(i18n.t("apply.prompt"), len(names))
        if choice is None:
            ui.warn(i18n.t("common.cancelled"))
            return EXIT_OK
        name = names[choice - 1]
    if name not in profiles:
        raise ConfigError(i18n.t("validate.no_profile", profile=name))
    profile = profiles[name]

    if not profile.fixable:
        reason = i18n.t("apply.not_fixable_reason")
        hint = i18n.t(
            "apply.not_fixable_hint", domain=profile.domains[0] if profile.domains else name
        )
        if ctx.json:
            _dump(
                {
                    "profile": name,
                    "ok": True,
                    "applied": False,
                    "fixable": False,
                    "reason": reason,
                    "hint": hint,
                }
            )
            return EXIT_OK
        ui.warn(i18n.t("apply.not_fixable", profile=name))
        ui.detail(reason)
        ui.info(hint)
        return EXIT_OK

    if not getattr(args, "dry_run", False):
        if not _ensure_admin(
            ctx,
            ["apply", name] + ([] if not getattr(args, "no_verify", False) else ["--no-verify"]),
        ):
            return EXIT_OK

    show = ctx.human
    mapping, missing = _resolve_profile(ctx, profile, show=show)
    if not mapping:
        if ctx.json:
            _dump({"profile": name, "ok": False, "error": i18n.t("apply.nothing")})
            return EXIT_ERROR
        ui.err(i18n.t("apply.nothing"))
        return EXIT_ERROR

    result = ctx.hosts.apply(
        name,
        mapping,
        dry_run=getattr(args, "dry_run", False),
        force=getattr(args, "force", False),
    )
    if result.conflicts and not getattr(args, "force", False):
        if ctx.json:
            _dump({"profile": name, "ok": False, "conflicts": result.conflicts})
        else:
            ui.err(i18n.t("apply.conflict_count", count=len(result.conflicts)))
            for line in result.conflicts:
                ui.detail(i18n.t("apply.blocked_conflict", line=line))
            ui.info(i18n.t("apply.conflict_hint"))
        return EXIT_ERROR

    verified = True
    failures: List[Tuple[str, str]] = []
    if result.written and ctx.config.settings.verify_after_apply and not getattr(args, "no_verify", False):
        if ctx.human:
            ui.info(i18n.t("apply.verify_start"))
        failures = _verify_mapping(ctx, profile, mapping)
        if failures:
            verified = False
            if ctx.human:
                for domain, reason in failures:
                    ui.err(i18n.t("apply.verify_failed", domain=domain, reason=reason))
            try:
                if result.backup is not None:
                    ctx.hosts.restore(result.backup)
                else:
                    ctx.hosts.remove(name)
                if ctx.human:
                    ui.warn(i18n.t("apply.rolled_back"))
            except (HostsError, AdminRequiredError) as exc:
                if ctx.human:
                    ui.err(i18n.t("apply.rollback_failed", error=exc))
        elif ctx.human:
            for domain, ip in mapping.items():
                ui.ok(i18n.t("apply.verify_ok", domain=domain, ip=ip))

    if ctx.json:
        _dump(
            {
                "profile": name,
                "ok": verified,
                "written": result.written,
                "changed": result.changed,
                "mapping": mapping,
                "skipped": missing,
                "conflicts": result.conflicts,
                "verified": verified,
                "failures": [{"domain": domain, "reason": reason} for domain, reason in failures],
                "backup": str(result.backup) if result.backup else None,
            }
        )
        return EXIT_OK if verified else EXIT_ERROR

    if result.written:
        ui.ok(i18n.t("apply.written", profile=name, count=result.count))
    elif result.changed:
        ui.info(i18n.t("common.dry_run"))
    else:
        ui.info(i18n.t("apply.unchanged"))
    if missing:
        ui.warn(i18n.t("apply.domain_missing", domain=", ".join(missing)))
    return EXIT_OK if verified else EXIT_ERROR


def cmd_cleanup(ctx: Context, args: argparse.Namespace) -> int:
    profile = getattr(args, "profile", None)
    remove_all = bool(getattr(args, "all", False))
    if not remove_all and not profile:
        if not ctx.interactive:
            raise ConfigError(i18n.t("cleanup.need_target"))
        blocks = ctx.hosts.blocks()
        if not blocks:
            ui.info(i18n.t("cleanup.none"))
            return EXIT_OK
        ui.header(i18n.t("cleanup.select"))
        for index, block in enumerate(blocks, start=1):
            ui.plain(f"  [{index}] {block.profile} ({len(block.entries)} entries)")
        ui.plain(f"  [A] {i18n.t('cleanup.all')}")
        ui.plain(f"  [0] {i18n.t('cleanup.back')}")
        choice = ui.ask(i18n.t("menu.prompt"))
        if choice is None or choice.strip() == "0":
            return EXIT_OK
        if choice.strip().lower() == "a":
            remove_all = True
        else:
            try:
                block = blocks[int(choice) - 1]
            except (ValueError, IndexError):
                ui.warn(i18n.t("common.invalid_choice"))
                return EXIT_OK
            profile = block.profile

    if not getattr(args, "yes", False) and ctx.interactive:
        prompt = i18n.t("cleanup.confirm_all") if remove_all else i18n.t("cleanup.confirm_one", profile=profile)
        if not ui.confirm(prompt, default=False):
            return EXIT_OK

    if not getattr(args, "dry_run", False):
        if not _ensure_admin(ctx, ["cleanup"] + ([] if not remove_all else ["--all"])):
            return EXIT_OK

    removed = ctx.hosts.remove(None if remove_all else profile, dry_run=getattr(args, "dry_run", False))
    if ctx.json:
        _dump({"ok": True, "removed": removed})
        return EXIT_OK
    if removed == 0:
        ui.info(i18n.t("cleanup.none"))
    else:
        ui.ok(i18n.t("cleanup.done", count=removed))
    if getattr(args, "dry_run", False):
        ui.info(i18n.t("common.dry_run"))
    return EXIT_OK


def _foreign_entries(ctx: Context) -> List[Tuple[int, str, str]]:
    """Return ``(line_number, ip, domain)`` for hosts lines outside our blocks.

    These lines were written by hand or by another tool. NetGuardian must not
    delete them - ``0.0.0.0 domain`` is a deliberate block, not a broken fix -
    so this is a report-only path.
    """
    document = ctx.hosts.read()
    inside = set()
    for block in ctx.hosts.blocks():
        inside.update(range(block.start, block.end + 1))
    found: List[Tuple[int, str, str]] = []
    for index, line in enumerate(document.lines):
        if index in inside:
            continue
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if len(parts) != 2:
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0]))
        except ValueError:
            continue
        found.append((index + 1, ip, parts[1].strip().lower()))
    return found


def cmd_prune(ctx: Context, args: argparse.Namespace) -> int:
    """Remove pinned entries whose address no longer works.

    Two kinds of damage are told apart:

    * ``dead``   - the pinned address does not accept TCP on the profile ports;
    * ``broken`` - TCP opens, but the certificate is not valid for the domain,
      or the handshake is reset.

    The distinction matters: a dead address is fixed by pinning another one,
    a broken one is not - it means filtering, not a stale address. Both are
    pruned by default, because a pinned entry that cannot carry TLS is as
    useless as a dead one; ``--tcp-only`` keeps the broken ones in place.
    """
    profile_name = getattr(args, "profile", None)
    prune_all = bool(getattr(args, "all", False))
    dry_run = bool(getattr(args, "dry_run", False))
    tcp_only = bool(getattr(args, "tcp_only", False))
    timeout = float(getattr(args, "timeout", 0) or max(3.0, ctx.config.settings.tcp_timeout_sec))

    blocks = ctx.hosts.blocks()
    if profile_name:
        blocks = [block for block in blocks if block.profile == profile_name]
    elif not prune_all:
        raise ConfigError(i18n.t("prune.need_target"))
    if not blocks:
        if ctx.json:
            _dump({"ok": True, "removed": 0, "blocks": []})
        else:
            ui.info(i18n.t("prune.no_blocks"))
        return EXIT_OK

    if ctx.human:
        ui.info(i18n.t("prune.header"))

    dead_total = 0
    broken_total = 0
    kept_total = 0
    planned: List[Tuple[str, Dict[str, str]]] = []

    for block in blocks:
        profile = ctx.config.profiles.get(block.profile)
        ports = tuple(profile.ports) if profile else (443,)
        alive: Dict[str, str] = {}
        dead = 0
        broken = 0
        for ip, domain in block.entries:
            if not tcp_probe(ip, ports, timeout):
                dead += 1
                if ctx.human:
                    ui.err(i18n.t("prune.dead", domain=domain, ip=ip))
                continue
            if not tcp_only:
                info = inspect(domain, ip=ip, timeout=timeout)
                issuer_ok = issuer_matches(info.issuer, profile.expected_issuers) if profile else True
                if not (info.verified and issuer_ok):
                    broken += 1
                    if ctx.human:
                        ui.err(
                            i18n.t(
                                "prune.broken",
                                domain=domain,
                                ip=ip,
                                reason=info.error or "certificate mismatch",
                            )
                        )
                    continue
            alive[domain] = ip
            kept_total += 1
        dead_total += dead
        broken_total += broken
        if dead or broken:
            planned.append((block.profile, alive))

    foreign_bad: List[Tuple[int, str, str]] = []
    if getattr(args, "foreign", False):
        for line_no, ip, domain in _foreign_entries(ctx):
            # 0.0.0.0 / 127.x are deliberate blocks or loopbacks, not fixes.
            if ip.startswith("0.0.0.0") or ip.startswith("127."):
                continue
            if not tcp_probe(ip, (443,), timeout):
                foreign_bad.append((line_no, ip, domain))
                if ctx.human:
                    ui.warn(i18n.t("prune.foreign", line=line_no, domain=domain, ip=ip))
                continue
            if tcp_only:
                continue
            info = inspect(domain, ip=ip, timeout=timeout)
            if not info.verified:
                foreign_bad.append((line_no, ip, domain))
                if ctx.human:
                    ui.warn(
                        i18n.t(
                            "prune.foreign_broken",
                            line=line_no,
                            domain=domain,
                            ip=ip,
                            reason=info.error or "certificate mismatch",
                        )
                    )

    if not planned:
        if ctx.json:
            _dump(
                {
                    "ok": True,
                    "removed": 0,
                    "dead": 0,
                    "broken": 0,
                    "kept": kept_total,
                    "foreign": [f"{ip} {domain}" for _, ip, domain in foreign_bad],
                }
            )
        else:
            ui.info(i18n.t("prune.none"))
        return EXIT_OK

    removed = dead_total + broken_total
    if ctx.human:
        ui.warn(i18n.t("prune.summary", dead=dead_total, broken=broken_total, keep=kept_total))

    if dry_run:
        if ctx.json:
            _dump(
                {
                    "ok": True,
                    "dry_run": True,
                    "would_remove": removed,
                    "dead": dead_total,
                    "broken": broken_total,
                    "kept": kept_total,
                }
            )
        else:
            ui.info(i18n.t("prune.dry_run"))
        return EXIT_OK

    if not getattr(args, "yes", False) and ctx.interactive:
        if not ui.confirm(i18n.t("prune.confirm", count=removed), default=False):
            return EXIT_OK
    if not _ensure_admin(ctx, ["prune"] + (["--all"] if prune_all else [])):
        return EXIT_OK

    applied: List[str] = []
    try:
        for name, alive in planned:
            if alive:
                ctx.hosts.apply(name, alive, force=True)
            else:
                ctx.hosts.remove(name)
            applied.append(name)
        # Re-read the file and prove that the removed domains are really gone.
        for name, alive in planned:
            remaining = ctx.hosts.entries_for(name)
            if remaining != alive:
                raise HostsError(
                    i18n.t("prune.verify_failed", error=f"{name}: {sorted(remaining)} != {sorted(alive)}")
                )
    except HostsError as exc:
        if ctx.json:
            _dump({"ok": False, "error": str(exc)})
            return EXIT_ERROR
        ui.err(str(exc))
        return EXIT_ERROR

    if ctx.json:
        _dump(
            {
                "ok": True,
                "removed": removed,
                "dead": dead_total,
                "broken": broken_total,
                "kept": kept_total,
                "profiles": applied,
                "foreign": [f"{ip} {domain}" for _, ip, domain in foreign_bad],
            }
        )
        return EXIT_OK
    ui.ok(i18n.t("prune.done", count=removed))
    ui.info(i18n.t("prune.verified"))
    return EXIT_OK


def cmd_repair(ctx: Context, args: argparse.Namespace) -> int:
    """One-button repair: replace dead marked IPs with working ones."""
    dry_run = bool(getattr(args, "dry_run", False))
    yes = bool(getattr(args, "yes", False))
    timeout = float(getattr(args, "timeout", 0) or max(3.0, ctx.config.settings.tcp_timeout_sec))

    report = repair_hosts(
        ctx.hosts,
        ctx.config,
        ctx.resolver(),
        dry_run=True,
        timeout=timeout,
    )

    if ctx.human:
        ui.header(i18n.t("repair.header"))
        for action in report.actions:
            if action.status == "kept":
                ui.detail(i18n.t("repair.kept", domain=action.domain, ip=action.old_ip))
            elif action.status == "replaced":
                ui.ok(i18n.t("repair.replaced", domain=action.domain, old=action.old_ip, new=action.new_ip))
            elif action.status == "dead":
                ui.warn(i18n.t("repair.dead", domain=action.domain, ip=action.old_ip, reason=action.reason))
            else:
                ui.err(i18n.t("repair.error", domain=action.domain, ip=action.old_ip, reason=action.reason))
        ui.info(i18n.t("repair.unmanaged", count=report.unmanaged))
        ui.info(
            i18n.t(
                "repair.summary",
                replaced=report.replaced,
                dead=report.dead,
                kept=report.kept,
                unmanaged=report.unmanaged,
            )
        )

    if not report.changed:
        if ctx.json:
            _dump(
                {
                    "ok": True,
                    "changed": False,
                    "replaced": 0,
                    "dead": report.dead,
                    "kept": report.kept,
                    "unmanaged": report.unmanaged,
                    "actions": [action.__dict__ for action in report.actions],
                }
            )
        elif ctx.human:
            ui.info(i18n.t("repair.no_change"))
        return EXIT_OK

    if dry_run:
        if ctx.json:
            _dump(
                {
                    "ok": True,
                    "dry_run": True,
                    "changed": False,
                    "would_replace": report.replaced,
                    "dead": report.dead,
                    "kept": report.kept,
                    "unmanaged": report.unmanaged,
                    "actions": [action.__dict__ for action in report.actions],
                }
            )
        elif ctx.human:
            ui.info(i18n.t("repair.dry_run"))
        return EXIT_OK

    if not yes and ctx.interactive:
        if not ui.confirm(i18n.t("repair.confirm", count=report.replaced), default=False):
            return EXIT_OK

    if not _ensure_admin(ctx, ["repair", "--yes"]):
        return EXIT_OK

    report = repair_hosts(
        ctx.hosts,
        ctx.config,
        ctx.resolver(),
        dry_run=False,
        timeout=timeout,
    )

    if ctx.json:
        _dump(
            {
                "ok": report.ok,
                "changed": report.changed,
                "written": report.written,
                "replaced": report.replaced,
                "dead": report.dead,
                "kept": report.kept,
                "unmanaged": report.unmanaged,
                "backup": str(report.backup) if report.backup else None,
                "actions": [action.__dict__ for action in report.actions],
            }
        )
        return EXIT_OK if report.ok else EXIT_ERROR

    if report.written:
        ui.ok(i18n.t("repair.done", count=report.replaced))
        if report.backup:
            ui.detail(str(report.backup))
    return EXIT_OK if report.ok else EXIT_ERROR


def cmd_validate(ctx: Context, args: argparse.Namespace) -> int:
    name = getattr(args, "profile", None)
    profiles = [ctx.config.profile(name)] if name else list(ctx.config.profiles.values())
    if ctx.human:
        ui.info(i18n.t("validate.running"))
    resolver = ctx.resolver()
    records: List[Dict[str, Any]] = []
    ok_count = 0
    total = 0
    try:
        for profile in profiles:
            pinned = ctx.hosts.entries_for(profile.name)
            for domain in profile.domains:
                total += 1
                ip = pinned.get(domain)
                if not ip:
                    resolution = resolver.resolve(
                        domain,
                        strategy=profile.strategy,
                        static_candidates=profile.static_candidates,
                        domain_candidates=profile.domain_candidates,
                        ports=tuple(profile.ports),
                    )
                    ip = resolution.ip if resolution else None
                if not ip:
                    records.append({"profile": profile.name, "domain": domain, "ok": False, "reason": "no address"})
                    if ctx.human:
                        ui.err(i18n.t("validate.unreachable", domain=domain, ip=i18n.t("common.none")))
                    continue
                info = inspect(domain, ip=ip, timeout=max(5.0, ctx.config.settings.tcp_timeout_sec))
                issuer_ok = issuer_matches(info.issuer, profile.expected_issuers)
                good = info.verified and issuer_ok
                if good:
                    ok_count += 1
                records.append(
                    {
                        "profile": profile.name,
                        "domain": domain,
                        "ip": ip,
                        "ok": good,
                        "verified": info.verified,
                        "issuer": info.issuer,
                        "days_left": info.days_left,
                        "reason": "" if good else (info.error or "issuer mismatch"),
                    }
                )
                if ctx.human:
                    if good:
                        ui.ok(i18n.t("validate.ok", domain=domain, issuer=info.issuer or "?"))
                        if info.days_left is not None and info.days_left < 30:
                            ui.detail(i18n.t("validate.expires", days=info.days_left))
                    else:
                        reason = info.error or i18n.t(
                            "validate.issuer_mismatch",
                            issuer=info.issuer,
                            expected=", ".join(profile.expected_issuers),
                        )
                        ui.err(i18n.t("validate.untrusted", domain=domain, reason=reason))
    finally:
        ctx.cache.flush()
    if ctx.json:
        _dump({"ok": ok_count == total, "validated": ok_count, "total": total, "records": records})
        return EXIT_OK if ok_count == total else EXIT_ERROR
    ui.info(i18n.t("validate.summary", ok=ok_count, total=total))
    return EXIT_OK if ok_count == total else EXIT_ERROR


def cmd_diag(ctx: Context, args: argparse.Namespace) -> int:
    domain = getattr(args, "domain", None)
    if not domain:
        if not ctx.interactive:
            raise ConfigError(i18n.t("diag.prompt"))
        domain = ui.ask(i18n.t("diag.prompt"))
        if not domain:
            return EXIT_OK
    try:
        report = run_diagnostic(domain, ctx.config, ctx.hosts)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if ctx.json:
        _dump(
            {
                "domain": report.domain,
                "verdict": report.verdict,
                "action": report.action,
                "hosts": [{"ip": ip, "domain": name} for ip, name in report.hosts_pairs],
                "system_ips": report.system_ips,
                "local_dns": report.local_dns,
                "local_ips": report.local_ips,
                "tcp": [{"ip": ip, "port": port, "open": ok} for ip, port, ok in report.tcp_results],
                "certificate": {
                    "verified": report.cert.verified,
                    "issuer": report.cert.issuer,
                    "subject": report.cert.subject,
                    "days_left": report.cert.days_left,
                    "error": report.cert.error,
                }
                if report.cert
                else None,
                "proxy": report.proxy,
                "profile": report.profile,
                "http_status": report.http_status,
                "ip_probes": [
                    {
                        "ip": probe.ip,
                        "tcp_open": probe.tcp_ok,
                        "tls_ok": probe.tls_ok,
                        "tls_fail": probe.tls_fail,
                        "verdict": probe.verdict,
                        "error": probe.last_error,
                    }
                    for probe in report.ip_probes
                ],
            }
        )
        return EXIT_OK if report.verdict == "ok" else EXIT_ERROR
    render_diagnostic(report)
    if ctx.interactive and report.ip_probes:
        _offer_pin(ctx, report)
    return EXIT_OK if report.verdict == "ok" else EXIT_ERROR


def _offer_pin(ctx: Context, report: DiagnosticReport) -> None:
    """Offer to pin the address that actually answers, never a dead one."""
    best = max(report.ip_probes, key=lambda probe: probe.rate)
    if best.rate <= 0:
        return
    mode = ctx.config.settings.pin_mode
    if mode != "strict":
        ui.warn(i18n.t(f"pin.warn_{mode}"))
    if not ui.confirm(
        i18n.t("diag.pin_offer", ip=best.ip, domain=report.domain, mode=mode), default=False
    ):
        return
    ok, message = ctx.hosts.pin(report.domain, best.ip, mode=mode)
    (ui.ok if ok else ui.err)(message)


def cmd_probe(ctx: Context, args: argparse.Namespace) -> int:
    """Full probe: every address, repeated handshakes, and hung sockets."""
    domain = getattr(args, "domain", None)
    if not domain:
        raise ConfigError(i18n.t("diag.prompt"))
    try:
        report = run_diagnostic(domain, ctx.config, ctx.hosts)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    render_diagnostic(report)

    addresses = {probe.ip for probe in report.ip_probes}
    if addresses:
        try:
            stuck = find_stuck()
        except RuntimeError as exc:
            ui.warn(i18n.t("scan.failed", error=exc))
            return EXIT_ERROR
        related = [item for item in stuck if item.connection.remote_ip in addresses]
        if related:
            ui.header(i18n.t("probe.stuck"))
            ui.table(
                ["PID", "PROCESS", "STATE", "REMOTE", "REASON"],
                [
                    [item.pid, item.process or "?", item.state, item.remote, item.reason]
                    for item in related
                ],
            )
    # The exit code stays tied to the route verdict, not to hung sockets.
    return EXIT_OK if report.verdict == "ok" else EXIT_ERROR


def cmd_status(ctx: Context, args: argparse.Namespace) -> int:
    hosts_exists = ctx.hosts.exists()
    blocks = ctx.hosts.blocks() if hosts_exists else []
    cache_items = ctx.cache.items()
    backups = ctx.hosts.backups()

    if ctx.json:
        _dump(
            {
                "version": __version__,
                "admin": is_admin(),
                "config": str(ctx.paths.config_file),
                "hosts": str(ctx.paths.hosts_file),
                "hosts_exists": hosts_exists,
                "blocks": [
                    {
                        "profile": block.profile,
                        "timestamp": block.timestamp,
                        "entries": [{"ip": ip, "domain": domain} for ip, domain in block.entries],
                    }
                    for block in blocks
                ],
                "cache": [
                    {"domain": domain, "ip": entry.ip, "source": entry.source, "age": entry.age_text()}
                    for domain, entry in cache_items
                ],
                "backups": [str(path) for path in backups],
                "profiles": len(ctx.config.profiles),
            }
        )
        return EXIT_OK

    ui.header(i18n.t("status.title"))
    ui.plain(i18n.t("status.config", path=ctx.paths.config_file))
    if hosts_exists:
        ui.plain(i18n.t("status.hosts", path=ctx.paths.hosts_file))
    else:
        ui.warn(i18n.t("status.hosts_missing", path=ctx.paths.hosts_file))
    ui.plain(i18n.t("status.profiles", count=len(ctx.config.profiles)))
    ui.plain(i18n.t("status.blocks", count=len(blocks)))
    if not blocks:
        ui.detail(i18n.t("status.no_blocks"))
    for block in blocks:
        ui.plain(
            i18n.t(
                "status.block",
                profile=block.profile,
                count=len(block.entries),
                ts=block.timestamp or i18n.t("common.unknown"),
            )
        )
        for ip, domain in block.entries:
            ui.plain(i18n.t("status.entry", ip=ip, domain=domain))
    ui.plain(i18n.t("status.cache", count=len(cache_items)))
    if not cache_items:
        ui.detail(i18n.t("status.cache_empty"))
    for domain, entry in cache_items[:10]:
        ui.plain(i18n.t("status.cache_entry", domain=domain, ip=entry.ip, age=entry.age_text()))
    ui.plain(i18n.t("status.backups", count=len(backups)))
    return EXIT_OK


def cmd_backups(ctx: Context, args: argparse.Namespace) -> int:
    backups = ctx.hosts.backups()
    if not backups:
        if ctx.json:
            _dump({"ok": True, "backups": [], "restored": None})
        else:
            ui.info(i18n.t("backups.none"))
        return EXIT_OK

    restore_name = getattr(args, "restore", None)
    if restore_name is None:
        if ctx.json:
            _dump({"ok": True, "backups": [str(path) for path in backups]})
            return EXIT_OK
        ui.header(i18n.t("backups.title"))
        for index, path in enumerate(backups, start=1):
            ui.plain(f"  [{index}] {path.name}")
        if not ctx.interactive:
            return EXIT_OK
        choice = ui.ask(i18n.t("menu.prompt"))
        if not choice:
            return EXIT_OK
        restore_name = choice

    target: Optional[Path] = None
    if restore_name.isdigit():
        index = int(restore_name) - 1
        if 0 <= index < len(backups):
            target = backups[index]
    else:
        for path in backups:
            if path.name == restore_name or str(path) == restore_name:
                target = path
                break
    if target is None:
        raise HostsError(i18n.t("backups.invalid", path=restore_name))

    if not getattr(args, "yes", False) and ctx.interactive:
        if not ui.confirm(i18n.t("backups.confirm", name=target.name), default=False):
            return EXIT_OK
    if not _ensure_admin(ctx, ["backups", "--restore", target.name, "--yes"]):
        return EXIT_OK
    ctx.hosts.restore(target)
    if ctx.json:
        _dump({"ok": True, "restored": str(target)})
    else:
        ui.ok(i18n.t("backups.restored", name=target.name))
    return EXIT_OK


def cmd_tcpview(ctx: Context, args: argparse.Namespace) -> int:
    try:
        path, valid, detail = ensure_tcpview(
            ctx.paths.data_dir,
            allow_unsigned=bool(getattr(args, "allow_unsigned", False)),
        )
    except TcpViewError as exc:
        raise NetGuardianError(str(exc)) from exc
    if ctx.human:
        ui.ok(i18n.t("tcpview.found", path=path))
        if valid:
            ui.detail(i18n.t("tcpview.signature_ok", signer=detail))
        else:
            ui.warn(i18n.t("tcpview.signature_bad", reason=detail))
    try:
        launch_tcpview(path)
    except TcpViewError as exc:
        raise NetGuardianError(str(exc)) from exc
    if ctx.json:
        _dump({"ok": True, "path": str(path), "signature": valid, "signer": detail})
    else:
        ui.ok(i18n.t("tcpview.launched"))
    return EXIT_OK


def cmd_config(ctx: Context, args: argparse.Namespace) -> int:
    if getattr(args, "path", False):
        print(ctx.paths.config_file)
        return EXIT_OK
    if getattr(args, "show", False):
        _dump(ctx.config.to_dict())
        return EXIT_OK
    if getattr(args, "check", False):
        if ctx.json:
            _dump(
                {
                    "ok": True,
                    "path": str(ctx.config.path),
                    "profiles": len(ctx.config.profiles),
                    "domains": ctx.config.domain_count,
                }
            )
        else:
            ui.ok(i18n.t("config.valid", profiles=len(ctx.config.profiles), domains=ctx.config.domain_count))
        return EXIT_OK
    ui.header(i18n.t("config.current", path=ctx.paths.config_file))
    ui.plain(i18n.t("config.profiles", names=", ".join(ctx.config.profile_names()) or i18n.t("common.none")))
    ui.plain(i18n.t("config.settings", settings=_parse_settings_text(ctx.config)))
    ui.plain(i18n.t("config.language", language=i18n.language_name()))
    return EXIT_OK


def cmd_lang(ctx: Context, args: argparse.Namespace) -> int:
    code = getattr(args, "code", None)
    if not code:
        if ctx.json:
            _dump({"ok": True, "language": i18n.get_language(), "configured": ctx.config.settings.language})
        else:
            ui.info(i18n.t("lang.current", language=i18n.language_name()))
        return EXIT_OK
    if code.lower() == "auto":
        ctx.config.settings.language = "auto"
        i18n.set_language(i18n.detect_system_language())
    else:
        if code.lower() not in i18n.SUPPORTED_LANGUAGES:
            raise ConfigError(i18n.t("lang.invalid", code=code))
        i18n.set_language(code)
        ctx.config.settings.language = code
    save_config(ctx.config)
    if ctx.json:
        _dump({"ok": True, "language": i18n.get_language(), "configured": ctx.config.settings.language})
    else:
        ui.ok(i18n.t("lang.changed", language=i18n.language_name()))
    return EXIT_OK


# --------------------------------------------------------------------------
# interactive menu
# --------------------------------------------------------------------------
def cmd_menu(ctx: Context) -> int:
    while True:
        ui.clear_screen()
        ui.banner(
            __version__,
            i18n.t("app.tagline"),
            i18n.t("menu.header_mode", admin=_admin_text(), data=ctx.paths.data_dir),
        )
        ui.plain(i18n.t("menu.title"))
        ui.rule()
        for key in (
            "menu.scan",
            "menu.apply",
            "menu.validate",
            "menu.cleanup",
            "menu.repair",
            "menu.tcpview",
            "menu.diag",
            "menu.status",
            "menu.backups",
            "menu.settings",
            "menu.lang",
            "menu.exit",
        ):
            ui.plain(i18n.t(key))
        ui.rule()
        choice = ui.ask(i18n.t("menu.prompt"))
        if choice is None or choice.strip().upper() in ("0", "Q"):
            return EXIT_OK
        command = choice.strip().upper()
        handler = None
        fake: Optional[argparse.Namespace] = None
        if command == "1":
            handler, fake = cmd_scan, argparse.Namespace()
        elif command == "2":
            handler, fake = cmd_apply, argparse.Namespace(profile=None, dry_run=False, force=False, no_verify=False)
        elif command == "3":
            handler, fake = cmd_validate, argparse.Namespace(profile=None)
        elif command == "4":
            handler, fake = cmd_cleanup, argparse.Namespace(profile=None, all=False, yes=False, dry_run=False)
        elif command == "R":
            handler, fake = cmd_repair, argparse.Namespace(yes=False, dry_run=False, timeout=0.0)
        elif command == "5":
            handler, fake = cmd_tcpview, argparse.Namespace(allow_unsigned=False)
        elif command == "6":
            handler, fake = cmd_diag, argparse.Namespace(domain=None)
        elif command == "7":
            handler, fake = cmd_status, argparse.Namespace()
        elif command == "8":
            handler, fake = cmd_backups, argparse.Namespace(restore=None, yes=False)
        elif command == "9":
            handler, fake = cmd_settings, argparse.Namespace()
        elif command == "L":
            handler, fake = cmd_menu_language, argparse.Namespace()
        else:
            ui.warn(i18n.t("common.invalid_choice"))
            ui.pause()
            continue
        try:
            handler(ctx, fake)
        except NetGuardianError as exc:
            ui.err(exc.message)
            if exc.hint:
                ui.detail(exc.hint)
        except KeyboardInterrupt:
            ui.plain()
            ui.info(i18n.t("common.interrupted"))
        except Exception as exc:  # keep the menu alive on unexpected errors
            get_logger().exception("menu action failed")
            ui.err(i18n.t("common.unexpected", error=exc))
        ui.pause()


def cmd_menu_language(ctx: Context, args: argparse.Namespace) -> int:
    new_language = "ru" if i18n.get_language() == "en" else "en"
    i18n.set_language(new_language)
    ctx.config.settings.language = new_language
    save_config(ctx.config)
    ui.ok(i18n.t("lang.changed", language=i18n.language_name()))
    return EXIT_OK


def cmd_settings(ctx: Context, args: argparse.Namespace) -> int:
    ui.header(i18n.t("config.current", path=ctx.paths.config_file))
    ui.plain(i18n.t("config.settings", settings=_parse_settings_text(ctx.config)))
    ui.plain(i18n.t("status.hosts", path=ctx.paths.hosts_file))
    ui.plain(i18n.t("status.backups", count=len(ctx.hosts.backups())))
    if ctx.interactive and os.name == "nt":
        if ui.confirm(i18n.t("settings.open_folder"), default=False):
            try:
                os.startfile(str(ctx.paths.config_file.parent))  # type: ignore[attr-defined]
            except OSError as exc:
                ui.err(str(exc))
    return EXIT_OK


# --------------------------------------------------------------------------
# argument parsing / dispatch
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="PATH", default=argparse.SUPPRESS, help="path to routes.json")
    common.add_argument("--data-dir", metavar="PATH", default=argparse.SUPPRESS, help="directory for cache, logs and backups")
    common.add_argument("--hosts", metavar="PATH", default=argparse.SUPPRESS, help="override the hosts file path")
    common.add_argument("--lang", choices=("en", "ru", "auto"), default=argparse.SUPPRESS, help="interface language")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable ANSI colours")
    common.add_argument("--verbose", action="store_true", default=argparse.SUPPRESS, help="mirror the log to the console")

    parser = argparse.ArgumentParser(
        prog="netguardian",
        parents=[common],
        description="NetGuardian - pin host names to reachable addresses through the Windows hosts file.",
        epilog=(
            "Examples:\n"
            "  netguardian                    open the control center\n"
            "  netguardian scan               look for stuck connections\n"
            "  netguardian apply github_access\n"
            "  netguardian validate --json\n"
            "  netguardian cleanup --all --yes\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"NetGuardian {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser("scan", parents=[common], help="scan for stuck connections")
    scan.set_defaults(func=cmd_scan)

    apply_cmd = subparsers.add_parser("apply", parents=[common], help="apply a profile")
    apply_cmd.add_argument("profile", nargs="?", help="profile name")
    apply_cmd.add_argument("--dry-run", action="store_true", help="resolve and validate without writing")
    apply_cmd.add_argument("--force", action="store_true", help="override conflicting hosts entries")
    apply_cmd.add_argument("--no-verify", action="store_true", help="skip TLS verification after writing")
    apply_cmd.set_defaults(func=cmd_apply)

    cleanup = subparsers.add_parser("cleanup", parents=[common], help="remove NetGuardian fixes")
    cleanup.add_argument("profile", nargs="?", help="remove only this profile")
    cleanup.add_argument("--all", action="store_true", help="remove every NetGuardian block")
    cleanup.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    cleanup.add_argument("--dry-run", action="store_true", help="show what would be removed")
    cleanup.set_defaults(func=cmd_cleanup)

    repair = subparsers.add_parser(
        "repair", parents=[common], help="check and replace dead pinned addresses"
    )
    repair.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    repair.add_argument("--dry-run", action="store_true", help="show the plan without writing")
    repair.add_argument("--timeout", type=float, default=0.0, metavar="SEC", help="per-check timeout in seconds")
    repair.set_defaults(func=cmd_repair)

    prune = subparsers.add_parser(
        "prune", parents=[common], help="remove pinned entries whose address is dead or broken"
    )
    prune.add_argument("profile", nargs="?", help="prune only this profile")
    prune.add_argument("--all", action="store_true", help="prune every NetGuardian block")
    prune.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    prune.add_argument("--dry-run", action="store_true", help="show what would be removed")
    prune.add_argument(
        "--tcp-only", dest="tcp_only", action="store_true",
        help="remove only entries with no TCP answer, keep TLS failures",
    )
    prune.add_argument(
        "--foreign", action="store_true",
        help="also report unusable hosts lines that NetGuardian did not create (never removed)",
    )
    prune.add_argument(
        "--timeout", type=float, default=0.0, metavar="SEC", help="per-check timeout in seconds"
    )
    prune.set_defaults(func=cmd_prune)

    validate = subparsers.add_parser("validate", parents=[common], help="verify pinned routes over TLS")
    validate.add_argument("profile", nargs="?", help="validate only this profile")
    validate.set_defaults(func=cmd_validate)

    diag = subparsers.add_parser("diag", parents=[common], help="diagnose a connection problem")
    diag.add_argument("domain", nargs="?", help="domain or URL to test")
    diag.set_defaults(func=cmd_diag)

    probe = subparsers.add_parser(
        "probe", parents=[common], help="full probe: every address, repeated handshakes"
    )
    probe.add_argument("domain", nargs="?", help="domain or URL to test")
    probe.set_defaults(func=cmd_probe)

    status = subparsers.add_parser("status", parents=[common], help="show active fixes and cache")
    status.set_defaults(func=cmd_status)

    backups = subparsers.add_parser("backups", parents=[common], help="list or restore hosts backups")
    backups.add_argument("--restore", metavar="NAME", help="backup file name or index")
    backups.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    backups.set_defaults(func=cmd_backups)

    tcpview = subparsers.add_parser("tcpview", parents=[common], help="download and launch TCPView")
    tcpview.add_argument("--allow-unsigned", action="store_true", help="run even without a valid signature")
    tcpview.set_defaults(func=cmd_tcpview)

    config_cmd = subparsers.add_parser("config", parents=[common], help="inspect the configuration")
    config_cmd.add_argument("--check", action="store_true", help="validate the configuration")
    config_cmd.add_argument("--show", action="store_true", help="print the effective configuration")
    config_cmd.add_argument("--path", action="store_true", help="print the configuration path")
    config_cmd.set_defaults(func=cmd_config)

    lang = subparsers.add_parser("lang", parents=[common], help="show or change the interface language")
    lang.add_argument("code", nargs="?", choices=("en", "ru", "auto"), help="language code")
    lang.set_defaults(func=cmd_lang)

    menu = subparsers.add_parser("menu", parents=[common], help="open the interactive control center")
    menu.set_defaults(func=cmd_menu)
    return parser


def _resolve_language(args: argparse.Namespace, config: Config) -> str:
    requested = getattr(args, "lang", None)
    if requested and requested != "auto":
        return requested
    configured = config.settings.language
    if configured and configured != "auto":
        return configured
    return i18n.detect_system_language()


def run(args: argparse.Namespace) -> int:
    paths = AppPaths.resolve(
        config=getattr(args, "config", None),
        data_dir=getattr(args, "data_dir", None),
        hosts=getattr(args, "hosts", None),
    )
    try:
        paths.ensure_directories()
    except OSError:
        pass
    setup_logging(paths.log_dir, verbose=getattr(args, "verbose", False))
    get_logger().info(
        "NetGuardian %s started: config=%s hosts=%s", __version__, paths.config_file, paths.hosts_file
    )

    created = False
    try:
        config, created = load_config(paths.config_file)
    except ConfigError as exc:
        if getattr(args, "json", False):
            _dump({"ok": False, "error": exc.message, "hint": exc.hint})
            return EXIT_CONFIG
        raise

    i18n.set_language(_resolve_language(args, config))
    ui.set_color(not getattr(args, "no_color", False) and sys.stdout.isatty())
    ui.set_interactive(args.command in (None, "menu"))

    if created and args.command in (None, "menu"):
        ui.info(i18n.t("config.created", path=paths.config_file))

    interactive = args.command in (None, "menu")
    ctx = Context(paths=paths, config=config, interactive=interactive, json=getattr(args, "json", False))
    if args.command in (None, "menu"):
        return cmd_menu(ctx)
    return args.func(ctx, args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ui.setup_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except NetGuardianError as exc:
        if getattr(args, "json", False):
            _dump({"ok": False, "error": exc.message, "hint": exc.hint})
        else:
            ui.err(exc.message)
            if exc.hint:
                ui.detail(exc.hint)
        return exc.exit_code
    except KeyboardInterrupt:
        print()
        ui.info(i18n.t("common.interrupted"))
        return 130
    except Exception as exc:  # pragma: no cover - last-resort guard
        get_logger().exception("unhandled error")
        if getattr(args, "json", False):
            _dump({"ok": False, "error": str(exc)})
        else:
            ui.err(i18n.t("common.unexpected", error=exc))
        return EXIT_ERROR


__all__ = ["Context", "build_parser", "main", "run"]
