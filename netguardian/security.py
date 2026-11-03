"""Windows privilege and code-signing helpers."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path
from shutil import which
from typing import Dict, List, Optional, Sequence, Tuple


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    """True when the current process runs with an elevated token."""
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated(args: Optional[Sequence[str]] = None) -> bool:
    """Start a new elevated instance through the UAC prompt.

    Returns True when the shell accepted the request.  The original process
    should exit afterwards; the new window continues the work.
    """
    if not is_windows():
        return False
    extra = list(args if args is not None else sys.argv[1:])
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = subprocess.list2cmdline(extra)
            cwd = str(Path(exe).parent)
        else:
            exe = sys.executable
            params = subprocess.list2cmdline(["-m", "netguardian", *extra])
            cwd = str(Path(__file__).resolve().parent.parent)
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, cwd, 1)
        return int(result) > 32
    except Exception:
        return False


def _powershell_candidates() -> List[str]:
    """PowerShell hosts to try, in order (5.1 first, then PowerShell 7)."""
    candidates: List[str] = []
    for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = which(name)
        if found and found not in candidates:
            candidates.append(found)
    return candidates


def _ps_literal(value: str) -> str:
    return value.replace("'", "''")


def _decode_console(raw: bytes) -> str:
    """Decode captured PowerShell output (UTF-8, OEM or ANSI)."""
    for encoding in ("utf-8-sig", "cp866", "cp1251"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\ufffd" not in text:
            return text
    return raw.decode("utf-8", "replace")


def authenticode_status(path: Path, timeout: float = 25.0) -> Tuple[bool, str]:
    """Check the Authenticode signature of *path*.

    Returns ``(is_valid, detail)`` where *detail* is the signer subject or the
    reason the check failed.  Only a valid signature counts as success; the
    caller decides whether the signer must be Microsoft.
    """
    shells = _powershell_candidates()
    if not shells:
        return False, "PowerShell is not available"

    script = (
        "$ErrorActionPreference = 'Stop'; "
        "try { $s = Get-AuthenticodeSignature -LiteralPath '"
        + _ps_literal(str(path))
        + "'; if ($s.Status -eq 'Valid') { 'NGVALID'; $s.SignerCertificate.Subject } "
        "else { 'NGINVALID'; [string]$s.Status; [string]$s.StatusMessage } } "
        "catch { 'NGERROR'; $_.Exception.Message }"
    )
    last_error = "signature check failed"
    for shell in shells:
        try:
            completed = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            last_error = f"signature check failed: {exc}"
            continue
        stdout = _decode_console(completed.stdout or b"")
        stderr = _decode_console(completed.stderr or b"")
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        if not lines:
            last_error = (stderr or "no output").strip()[:300]
            continue
        head = lines[0]
        detail = " ".join(lines[1:]).strip()
        if head == "NGVALID":
            return True, detail or "valid signature"
        if head == "NGINVALID":
            return False, detail or "invalid signature"
        # A shell that cannot load Microsoft.PowerShell.Security lands here;
        # try the next host before giving up.
        last_error = detail or head
    return False, last_error[:300]


#: Organization values that may legitimately sign a Microsoft binary.  Matched
#: exactly (case-insensitive) against the parsed ``O`` attribute -- never as a
#: substring, so a third-party certificate titled "Totally Legit Microsoft
#: Reseller Ltd" cannot pass.
_MICROSOFT_ORGS = frozenset({"microsoft corporation", "microsoft"})

#: Common-name fallback for subjects that carry no organization attribute.
_MICROSOFT_NAMES = frozenset({"microsoft corporation", "microsoft"})


def _split_subject(subject: str) -> List[Tuple[str, str]]:
    """Split an X.500 subject into ``(attribute, value)`` pairs.

    Handles quoted values and backslash escapes, and keeps multi-valued RDNs
    (``CN=a+O=b``) as separate pairs.  Anything unparseable is dropped rather
    than guessed at.
    """
    pieces: List[str] = []
    current: List[str] = []
    in_quotes = False
    escaped = False
    for char in subject:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            continue
        if char in ",+" and not in_quotes:
            pieces.append("".join(current))
            current = []
            continue
        current.append(char)
    pieces.append("".join(current))

    pairs: List[Tuple[str, str]] = []
    for piece in pieces:
        key, sep, value = piece.partition("=")
        if not sep:
            continue
        key = key.strip().upper()
        value = value.strip()
        if key and value:
            pairs.append((key, value))
    return pairs


def signer_is_microsoft(detail: str) -> bool:
    """True when *detail* names Microsoft as the certificate **organization**.

    The subject is parsed instead of substring-matched.  A certificate whose
    organization merely *contains* the word (for example
    ``O=Evil Microsoft Ltd``) is rejected even though a naive
    ``"microsoft" in detail`` check would accept it.
    """
    subject = (detail or "").strip()
    if not subject:
        return False

    pairs = _split_subject(subject)
    if not pairs:
        # No X.500 attribute survived parsing.  A bare word is not a subject,
        # and guessing would reopen the substring hole in another shape.
        return False

    attributes: Dict[str, List[str]] = {}
    for key, value in pairs:
        attributes.setdefault(key, []).append(value)

    organizations = attributes.get("O")
    if organizations:
        return any(org.lower() in _MICROSOFT_ORGS for org in organizations)
    return any(name.lower() in _MICROSOFT_NAMES for name in attributes.get("CN", []))


__all__ = [
    "authenticode_status",
    "is_admin",
    "is_windows",
    "relaunch_elevated",
    "signer_is_microsoft",
]
