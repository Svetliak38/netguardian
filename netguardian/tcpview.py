"""Download, verify and launch Sysinternals TCPView.

NetGuardian 2.x downloaded ``Tcpview.zip`` (wrong case) and executed whatever
came out of the archive.  This module fixes the URL, prefers the signed live
binary, verifies the Authenticode signature and only then runs the file.
"""

from __future__ import annotations

import ctypes
import io
import os
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Optional, Tuple

from . import i18n
from .log import get_logger
from .security import authenticode_status, signer_is_microsoft

LIVE_URL = "https://live.sysinternals.com/Tcpview.exe"
ZIP_URL = "https://download.sysinternals.com/files/TCPView.zip"
DOC_URL = "https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview"
TCPVIEW_NAME = "Tcpview.exe"
TCPVIEW64_NAME = "Tcpview64.exe"
MAX_DOWNLOAD = 64 * 1024 * 1024


class TcpViewError(Exception):
    """Raised when TCPView cannot be obtained or started."""


def _fetch(url: str, timeout: float = 30.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "NetGuardian/3"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise TcpViewError("download is too large")
    return data


def _extract_executable(archive: bytes) -> Tuple[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            members = [
                member
                for member in bundle.infolist()
                if member.filename.lower().endswith(".exe")
                and os.path.basename(member.filename).lower().startswith("tcpview")
                and member.file_size <= MAX_DOWNLOAD
            ]
            if not members:
                raise TcpViewError("no Tcpview executable inside the archive")
            preferred = next(
                (m for m in members if os.path.basename(m.filename).lower() == TCPVIEW64_NAME.lower()),
                members[0],
            )
            return os.path.basename(preferred.filename), bundle.read(preferred)
    except zipfile.BadZipFile as exc:
        raise TcpViewError(f"corrupted archive: {exc}") from exc


def _verify_microsoft(path: Path) -> Tuple[bool, str]:
    valid, detail = authenticode_status(path)
    if not valid:
        return False, detail
    if not signer_is_microsoft(detail):
        return False, f"unexpected signer: {detail}"
    return True, detail


def ensure(
    dest_dir: Path,
    *,
    allow_unsigned: bool = False,
    timeout: float = 30.0,
    fetch: Optional[Callable[[str, float], bytes]] = None,
    verifier: Optional[Callable[[Path], Tuple[bool, str]]] = None,
) -> Tuple[Path, bool, str]:
    """Return ``(path, signature_ok, detail)`` for a usable TCPView copy."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / TCPVIEW_NAME
    fetch = fetch or _fetch
    verifier = verifier or _verify_microsoft

    if target.is_file():
        valid, detail = verifier(target)
        if valid or allow_unsigned:
            return target, valid, detail
        raise TcpViewError(i18n.t("tcpview.signature_bad", reason=detail))

    last_error = ""
    for url in (LIVE_URL, ZIP_URL):
        try:
            get_logger().info("downloading TCPView from %s", url)
            payload = fetch(url, timeout)
            name = TCPVIEW_NAME
            if url.lower().endswith(".zip"):
                name, payload = _extract_executable(payload)
            if not payload:
                raise TcpViewError("empty download")
            handle, temp_name = tempfile.mkstemp(prefix=".tcpview-", suffix=".exe", dir=str(dest_dir))
            os.close(handle)
            temp = Path(temp_name)
            try:
                temp.write_bytes(payload)
                valid, detail = verifier(temp)
                if not valid and not allow_unsigned:
                    raise TcpViewError(i18n.t("tcpview.signature_bad", reason=detail))
                os.replace(temp, target)
                get_logger().info("TCPView saved as %s (%s)", target, name)
                return target, valid, detail
            finally:
                if temp.exists():
                    try:
                        temp.unlink()
                    except OSError:
                        pass
        except (OSError, TcpViewError, urllib.error.URLError) as exc:
            last_error = str(exc)
            get_logger().warning("TCPView source failed (%s): %s", url, exc)
            continue
    raise TcpViewError(i18n.t("tcpview.unavailable", error=last_error or "all sources failed"))


def launch(path: Path) -> None:
    """Start TCPView, requesting elevation if Windows demands it."""
    path = Path(path)
    try:
        subprocess.Popen([str(path)], cwd=str(path.parent))
        return
    except OSError as exc:
        if getattr(exc, "winerror", None) != 740:
            raise TcpViewError(i18n.t("tcpview.failed", error=exc)) from exc
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(path), None, str(path.parent), 1
        )
        if int(result) <= 32:
            raise TcpViewError(i18n.t("tcpview.failed", error=f"ShellExecuteW={result}"))
    except OSError as exc:
        raise TcpViewError(i18n.t("tcpview.failed", error=exc)) from exc


__all__ = [
    "DOC_URL",
    "LIVE_URL",
    "MAX_DOWNLOAD",
    "TCPVIEW64_NAME",
    "TCPVIEW_NAME",
    "TcpViewError",
    "ZIP_URL",
    "ensure",
    "launch",
]
