"""Rotating file logging plus an optional verbose console mirror."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .paths import LOG_NAME

LOGGER_NAME = "netguardian"
_FORMAT = "[%(asctime)s] %(levelname)-7s %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup(
    log_dir: Path,
    *,
    verbose: bool = False,
    quiet: bool = False,
    console: bool = False,
) -> logging.Logger:
    """(Re)configure the package logger. Returns the logger itself."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    formatter = logging.Formatter(_FORMAT, _DATEFMT)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / LOG_NAME,
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # A read-only location must never prevent the program from running.
        pass

    if console and not quiet:
        stream = logging.StreamHandler(sys.stdout)
        stream.setLevel(logging.DEBUG if verbose else logging.INFO)
        stream.setFormatter(formatter)
        logger.addHandler(stream)

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def log_path(log_dir: Path) -> Path:
    return log_dir / LOG_NAME


__all__ = ["LOGGER_NAME", "get_logger", "log_path", "setup"]
