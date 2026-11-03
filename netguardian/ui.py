"""Console user-interface helpers: colour, prompts, tables, banner."""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Iterable, List, Optional, Sequence

from .i18n import t

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_GREY = "\033[90m"


class _State:
    color = True
    interactive = True


def setup_console() -> None:
    """Switch the console to UTF-8 and enable ANSI escape processing."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    try:
        kernel32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def set_color(enabled: bool) -> None:
    _State.color = bool(enabled)


def color_enabled() -> bool:
    return _State.color


def _paint(text: str, *codes: str) -> str:
    if not _State.color or not codes:
        return text
    return "".join(codes) + text + _RESET


def ok(message: str) -> None:
    print(f"{_paint('[+]', _GREEN)} {message}")


def warn(message: str) -> None:
    print(f"{_paint('[!]', _YELLOW)} {message}")


def err(message: str) -> None:
    print(f"{_paint('[x]', _RED)} {message}")


def info(message: str) -> None:
    print(f"{_paint('[i]', _CYAN)} {message}")


def detail(message: str) -> None:
    print(f"    {_paint(message, _GREY)}")


def plain(message: str = "") -> None:
    print(message)


def header(title: str) -> None:
    print()
    print(_paint(title, _BOLD))


def rule(width: int = 62) -> None:
    print(_paint("-" * width, _GREY))


def clear_screen() -> None:
    if not _State.interactive:
        return
    if os.name == "nt":
        os.system("cls")
    else:
        print("\033[2J\033[H", end="")


LOGO = r"""
  _   _      _    ____                     _ _
 | \ | | ___| |_ / ___|_   _  __ _ _ __ __| (_) __ _ _ __
 |  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` | |/ _` | '_ \
 | |\  |  __/ |_| |_| | |_| | (_| | | | (_| | | (_| | | | |
 |_| \_|\___|\__|\____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|
""".strip("\n")


def banner(version: str, tagline: str, mode: str = "") -> None:
    print(_paint(LOGO, _CYAN))
    print(f"  {_paint('v' + version, _DIM)}  {tagline}")
    if mode:
        print(f"  {_paint(mode, _GREY)}")
    rule()


def table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    rows = [list(map(str, row)) for row in rows]
    if not headers and not rows:
        return
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            if index >= len(widths):
                widths.append(len(cell))
            else:
                widths[index] = max(widths[index], len(cell))
    if headers:
        print("  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)).rstrip())
        print(_paint("  ".join("-" * w for w in widths), _GREY))
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())


def ask(prompt: str, default: str = "") -> Optional[str]:
    """Read a line; returns None on EOF so callers can abort cleanly."""
    try:
        value = input(prompt)
    except EOFError:
        return None
    except KeyboardInterrupt:
        print()
        return None
    value = value.strip()
    return value if value else default


def confirm(prompt: str, default: bool = False) -> bool:
    while True:
        answer = ask(prompt)
        if answer is None:
            return default
        lowered = answer.lower()
        if lowered in ("y", "yes", "д", "да", "1", "+"):
            return True
        if lowered in ("n", "no", "н", "нет", "0", "-"):
            return False
        warn(t("common.yesno_hint"))


def choose(prompt: str, count: int) -> Optional[int]:
    """Ask for a 1-based index in ``1..count``."""
    answer = ask(prompt)
    if answer is None:
        return None
    try:
        index = int(answer)
    except ValueError:
        return None
    if 1 <= index <= count:
        return index
    return None


def pause() -> None:
    if not _State.interactive:
        return
    ask(t("common.press_enter"))


def set_interactive(enabled: bool) -> None:
    _State.interactive = bool(enabled)


def is_interactive() -> bool:
    return _State.interactive


__all__ = [
    "LOGO",
    "ask",
    "banner",
    "choose",
    "clear_screen",
    "color_enabled",
    "confirm",
    "detail",
    "err",
    "header",
    "info",
    "is_interactive",
    "ok",
    "pause",
    "plain",
    "rule",
    "set_color",
    "set_interactive",
    "setup_console",
    "table",
    "warn",
]
