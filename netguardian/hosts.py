"""Safe, reversible management of the Windows ``hosts`` file.

Design rules:

* a NetGuardian change is one clearly delimited block per profile;
* the original file is backed up before every write;
* the new content is written atomically, so a crash can never leave a
  half-written ``hosts`` file behind;
* the file is re-read and verified after writing;
* a malformed or foreign marker stops the operation instead of guessing.

The module never assumes the file lives in ``C:\\Windows`` - the path is
injected, which also makes the whole layer testable without elevation.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import i18n
from .errors import AdminRequiredError, HostsError, HostsPermissionError, HostsSyntaxError
from .fsutil import atomic_write_bytes, rotate_files
from .log import get_logger
from .security import is_admin

MARKER_RE = re.compile(
    r"^\s*#\s*=+\s*NETGUARDIAN\s+FIX\s*\((?P<profile>[^)]*)\)\s*"
    r"(?:\[(?P<ts>[^\]]*)\])?\s*(?P<kind>BEGIN|END)\s*=+\s*$",
    re.IGNORECASE,
)
BACKUP_GLOB = "hosts-*.bak"
MAX_HOSTS_BYTES = 8 * 1024 * 1024


@dataclass
class HostsDocument:
    text: str
    encoding: str
    newline: str
    lines: List[str]
    trailing_newline: bool


@dataclass
class Block:
    profile: str
    timestamp: str
    start: int
    end: int
    entries: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def domains(self) -> List[str]:
        return [domain for _, domain in self.entries]


@dataclass
class ApplyResult:
    profile: str
    changed: bool
    written: bool
    count: int
    conflicts: List[str] = field(default_factory=list)
    backup: Optional[Path] = None
    block_text: str = ""


def _detect_encoding(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    for candidate in ("utf-8", "cp1251"):
        try:
            raw.decode(candidate)
            return candidate
        except UnicodeDecodeError:
            continue
    return "latin-1"


def _split_lines(text: str) -> Tuple[List[str], bool]:
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    trailing = normalised.endswith("\n")
    lines = normalised.split("\n")
    if trailing and lines and lines[-1] == "":
        lines.pop()
    return lines, trailing


def load_document(path: Path) -> HostsDocument:
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise HostsError(i18n.t("error.hosts_read", path=path, error="file not found")) from exc
    except PermissionError as exc:
        raise HostsPermissionError(i18n.t("error.hosts_read", path=path, error="access denied")) from exc
    except OSError as exc:
        raise HostsError(i18n.t("error.hosts_read", path=path, error=exc)) from exc
    if len(raw) > MAX_HOSTS_BYTES:
        raise HostsError(i18n.t("error.hosts_read", path=path, error="file is too large"))
    encoding = _detect_encoding(raw)
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise HostsError(i18n.t("error.hosts_read", path=path, error=str(exc))) from exc
    lines, trailing = _split_lines(text)
    newline = "\r\n" if "\r\n" in text else "\n"
    return HostsDocument(text=text, encoding=encoding, newline=newline, lines=lines, trailing_newline=trailing)


def parse_blocks(lines: Sequence[str]) -> List[Block]:
    blocks: List[Block] = []
    opened: Optional[Tuple[str, str, int]] = None
    for index, line in enumerate(lines):
        match = MARKER_RE.match(line)
        if match:
            kind = match.group("kind").upper()
            profile = match.group("profile").strip()
            timestamp = (match.group("ts") or "").strip()
            if kind == "BEGIN":
                if opened is not None:
                    raise HostsSyntaxError(
                        i18n.t("error.hosts_malformed", line=opened[2] + 1)
                    )
                opened = (profile, timestamp, index)
            else:
                if opened is None:
                    raise HostsSyntaxError(i18n.t("error.hosts_malformed", line=index + 1))
                if opened[0] != profile:
                    raise HostsSyntaxError(i18n.t("error.hosts_malformed", line=index + 1))
                entries = _parse_entries(lines[opened[2] + 1 : index])
                blocks.append(
                    Block(profile=opened[0], timestamp=opened[1], start=opened[2], end=index, entries=entries)
                )
                opened = None
            continue
        upper = line.upper()
        if "#" in line and "NETGUARDIAN" in upper and "FIX" in upper and ("BEGIN" in upper or "END" in upper):
            raise HostsSyntaxError(i18n.t("error.hosts_malformed", line=index + 1))
    if opened is not None:
        raise HostsSyntaxError(i18n.t("error.hosts_malformed", line=opened[2] + 1))
    return blocks


def _parse_entries(lines: Iterable[str]) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    for line in lines:
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if len(parts) < 2:
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0]))
        except ValueError:
            continue
        for domain in parts[1:]:
            entries.append((ip, domain.strip().lower()))
    return entries


def render_block(profile: str, mapping: Dict[str, str], timestamp: Optional[str] = None) -> List[str]:
    stamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    lines = [f"# === NETGUARDIAN FIX ({profile}) [{stamp}] BEGIN ==="]
    for domain, ip in mapping.items():
        lines.append(f"{ip:<15} {domain}")
    lines.append(f"# === NETGUARDIAN FIX ({profile}) [{stamp}] END ===")
    return lines


class HostsFile:
    """High-level operations on one hosts file."""

    def __init__(
        self,
        path: Path,
        *,
        backup_dir: Optional[Path] = None,
        keep_backups: int = 10,
        admin_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.path = Path(path)
        self.backup_dir = Path(backup_dir) if backup_dir else self.path.parent
        self.keep_backups = max(1, int(keep_backups))
        self._admin_check = admin_check or is_admin

    # -- reading -----------------------------------------------------------
    def exists(self) -> bool:
        return self.path.is_file()

    def read(self) -> HostsDocument:
        return load_document(self.path)

    def blocks(self) -> List[Block]:
        return parse_blocks(self.read().lines)

    def entries_for(self, profile: str) -> Dict[str, str]:
        for block in self.blocks():
            if block.profile == profile:
                return {domain: ip for ip, domain in block.entries}
        return {}

    # -- conflicts ---------------------------------------------------------
    @staticmethod
    def find_conflicts(lines: Sequence[str], blocks: Sequence[Block], mapping: Dict[str, str]) -> List[str]:
        blocked = {block.start: block.end for block in blocks}
        skip_until = -1
        conflicts: List[str] = []
        wanted = {domain: ip for domain, ip in mapping.items()}
        for index, line in enumerate(lines):
            if index <= skip_until:
                continue
            if index in blocked:
                skip_until = blocked[index]
                continue
            content = line.split("#", 1)[0].strip()
            if not content:
                continue
            parts = content.split()
            if len(parts) < 2:
                continue
            try:
                ip = str(ipaddress.IPv4Address(parts[0]))
            except ValueError:
                continue
            for domain in parts[1:]:
                domain = domain.strip().lower().rstrip(".")
                if domain in wanted and wanted[domain] != ip:
                    conflicts.append(content)
                    break
        return conflicts

    # -- backups -----------------------------------------------------------
    def create_backup(self, tag: str = "auto") -> Optional[Path]:
        if not self.path.is_file():
            return None
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise HostsError(i18n.t("error.backup", error=exc)) from exc
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        safe_tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", tag)[:24] or "auto"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        target = self.backup_dir / f"hosts-{stamp}-{safe_tag}.bak"
        try:
            atomic_write_bytes(target, raw)
        except OSError as exc:
            raise HostsError(i18n.t("error.backup", error=exc)) from exc
        rotate_files(self.backup_dir, BACKUP_GLOB, self.keep_backups)
        get_logger().info("hosts backup: %s", target)
        return target

    def backups(self) -> List[Path]:
        if not self.backup_dir.is_dir():
            return []
        return sorted(
            (p for p in self.backup_dir.glob(BACKUP_GLOB) if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

    def restore(self, backup: Path, *, dry_run: bool = False) -> Path:
        backup = Path(backup)
        if not backup.is_file():
            raise HostsError(i18n.t("backups.invalid", path=backup))
        try:
            backup.resolve().relative_to(self.backup_dir.resolve())
        except (OSError, ValueError) as exc:
            raise HostsError(i18n.t("backups.invalid", path=backup)) from exc
        try:
            raw = backup.read_bytes()
        except OSError as exc:
            raise HostsError(i18n.t("error.restore", path=self.path, error=exc)) from exc
        if len(raw) > MAX_HOSTS_BYTES:
            raise HostsError(i18n.t("backups.invalid", path=backup))
        # The content must be decodable and free of marker damage.
        encoding = _detect_encoding(raw)
        try:
            lines, _ = _split_lines(raw.decode(encoding))
        except UnicodeDecodeError as exc:
            raise HostsError(i18n.t("backups.invalid", path=backup)) from exc
        parse_blocks(lines)
        if dry_run:
            return backup
        self._require_admin()
        safety = self.create_backup("pre-restore")
        try:
            atomic_write_bytes(self.path, raw)
        except PermissionError as exc:
            raise HostsPermissionError(i18n.t("error.hosts_denied", path=self.path)) from exc
        except OSError as exc:
            raise HostsError(i18n.t("error.restore", path=self.path, error=exc)) from exc
        try:
            if self.path.read_bytes() != raw:
                raise HostsError(i18n.t("error.restore", path=self.path, error="verification failed"))
        except OSError as exc:
            raise HostsError(i18n.t("error.restore", path=self.path, error=exc)) from exc
        get_logger().info("hosts restored from %s (safety copy: %s)", backup, safety)
        return backup

    # -- writing -----------------------------------------------------------
    def _require_admin(self) -> None:
        if not self._admin_check():
            raise AdminRequiredError(i18n.t("admin.required"), hint=i18n.t("admin.hint"))

    def apply(
        self,
        profile: str,
        mapping: Dict[str, str],
        *,
        dry_run: bool = False,
        force: bool = False,
    ) -> ApplyResult:
        if not mapping:
            raise HostsError(i18n.t("apply.nothing"))
        document = self.read()
        blocks = parse_blocks(document.lines)
        conflicts = self.find_conflicts(document.lines, blocks, mapping)
        for block in blocks:
            if block.profile == profile:
                continue
            for ip, domain in block.entries:
                if domain in mapping and mapping[domain] != ip:
                    conflicts.append(f"{ip} {domain} (NetGuardian profile '{block.profile}')")
        if conflicts and not force:
            return ApplyResult(
                profile=profile, changed=False, written=False, count=0, conflicts=conflicts
            )

        existing = [block for block in blocks if block.profile == profile]
        if len(existing) == 1 and {domain: ip for ip, domain in existing[0].entries} == mapping:
            return ApplyResult(profile=profile, changed=False, written=False, count=len(mapping))

        kept = self._without_profile(document.lines, blocks, profile)
        block_lines = render_block(profile, mapping)
        # Separate the block from the previous content with exactly one blank line.
        if kept and kept[-1].strip():
            kept = kept + [""]
        new_lines = kept + block_lines
        new_text = document.newline.join(new_lines) + document.newline

        changed = new_text != document.text
        result = ApplyResult(
            profile=profile,
            changed=changed,
            written=False,
            count=len(mapping),
            conflicts=conflicts,
            block_text="\n".join(block_lines),
        )
        if not changed or dry_run:
            return result

        self._require_admin()
        result.backup = self.create_backup(profile)
        original_bytes = document.text.encode(document.encoding)
        try:
            atomic_write_bytes(self.path, new_text.encode(document.encoding))
        except PermissionError as exc:
            raise HostsPermissionError(i18n.t("error.hosts_denied", path=self.path)) from exc
        except OSError as exc:
            raise HostsError(i18n.t("error.hosts_write", path=self.path, error=exc)) from exc
        try:
            self._verify_written(profile, mapping)
        except HostsError:
            # Never leave a half-validated hosts file behind.
            try:
                atomic_write_bytes(self.path, original_bytes)
            except OSError:
                get_logger().exception("could not roll back hosts after failed verification")
            raise
        result.written = True
        get_logger().info("applied profile %s (%d entries)", profile, len(mapping))
        return result

    def remove(self, profile: Optional[str] = None, *, dry_run: bool = False) -> int:
        document = self.read()
        blocks = parse_blocks(document.lines)
        targets = [block for block in blocks if profile is None or block.profile == profile]
        if not targets:
            return 0
        new_lines, removed = self._remove_ranges(document.lines, targets)
        new_text = document.newline.join(new_lines)
        if document.trailing_newline and new_lines:
            new_text += document.newline
        if dry_run:
            return removed
        self._require_admin()
        self.create_backup("cleanup")
        try:
            atomic_write_bytes(self.path, new_text.encode(document.encoding))
        except PermissionError as exc:
            raise HostsPermissionError(i18n.t("error.hosts_denied", path=self.path)) from exc
        except OSError as exc:
            raise HostsError(i18n.t("error.hosts_write", path=self.path, error=exc)) from exc
        try:
            if any(block.profile == profile for block in self.blocks()):
                raise HostsError(i18n.t("error.hosts_write", path=self.path, error="verification failed"))
        except HostsError:
            try:
                atomic_write_bytes(self.path, document.text.encode(document.encoding))
            except OSError:
                get_logger().exception("could not roll back hosts after failed cleanup")
            raise
        get_logger().info("removed %d block(s) (profile=%s)", removed, profile or "all")
        return removed

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _without_profile(lines: Sequence[str], blocks: Sequence[Block], profile: str) -> List[str]:
        targets = [block for block in blocks if block.profile == profile]
        if not targets:
            return list(lines)
        kept, _ = HostsFile._remove_ranges(lines, targets)
        return kept

    @staticmethod
    def _remove_ranges(lines: Sequence[str], targets: Sequence[Block]) -> Tuple[List[str], int]:
        drop = set()
        for block in targets:
            for index in range(block.start, block.end + 1):
                drop.add(index)
        kept: List[str] = []
        for index, line in enumerate(lines):
            if index not in drop:
                kept.append(line)
        # A block is always appended with a leading blank line; drop trailing
        # blank lines so repeated apply/remove cycles do not grow the file.
        while len(kept) > 1 and not kept[-1].strip():
            kept.pop()
        return kept, len(targets)

    def _verify_written(self, profile: str, mapping: Dict[str, str]) -> None:
        document = self.read()
        blocks = [block for block in parse_blocks(document.lines) if block.profile == profile]
        if len(blocks) != 1:
            raise HostsError(i18n.t("error.hosts_write", path=self.path, error="verification failed"))
        actual = {domain: ip for ip, domain in blocks[0].entries}
        if actual != mapping:
            raise HostsError(i18n.t("error.hosts_write", path=self.path, error="verification failed"))


__all__ = [
    "ApplyResult",
    "BACKUP_GLOB",
    "Block",
    "HostsDocument",
    "HostsFile",
    "MARKER_RE",
    "load_document",
    "parse_blocks",
    "render_block",
]
