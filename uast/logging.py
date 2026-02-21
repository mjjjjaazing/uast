"""
Structured logging for UAST.

Sets up a rotating file handler at ~/.uast/logs/uast.log with:
  - 5MB per file, 7 backup files
  - Structured format: timestamp · level · module · message
  - Console handler controlled by --log-level / --quiet flags
  - File permissions set to 0o600 (user-only read/write)

Usage:
    from uast.logging import setup_logging
    setup_logging(level="DEBUG")  # Call once at CLI entry point
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


LOG_DIR = Path.home() / ".uast" / "logs"
LOG_FILE = LOG_DIR / "uast.log"
LOG_FORMAT = "%(asctime)s · %(levelname)-8s · %(name)-20s · %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_BYTES = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 7


def _sanitize_message(msg: str) -> str:
    """Strip control characters that could enable log injection."""
    return msg.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")


class SafeFormatter(logging.Formatter):
    """Formatter that sanitizes log messages to prevent log injection."""

    def format(self, record: logging.LogRecord) -> str:
        record.msg = _sanitize_message(str(record.msg))
        return super().format(record)


def setup_logging(
    level: str = "WARNING",
    quiet: bool = False,
    log_dir: Optional[Path] = None,
) -> None:
    """
    Configure UAST logging.

    Args:
        level: Log level for console output (DEBUG, INFO, WARNING, ERROR).
        quiet: If True, suppress all console output (file logging still active).
        log_dir: Override log directory (for testing). Defaults to ~/.uast/logs/.
    """
    effective_dir = log_dir or LOG_DIR
    effective_file = effective_dir / "uast.log"

    # Ensure log directory exists
    effective_dir.mkdir(parents=True, exist_ok=True)

    # Root logger for uast namespace
    root_logger = logging.getLogger("uast")
    root_logger.setLevel(logging.DEBUG)  # capture everything; handlers filter

    # Remove existing handlers to avoid duplicate output on re-init
    root_logger.handlers.clear()

    formatter = SafeFormatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    # File handler — always DEBUG (captures everything)
    file_handler = RotatingFileHandler(
        str(effective_file),
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Set file permissions to 0o600 (user-only)
    try:
        os.chmod(str(effective_file), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Best effort — may fail on some systems

    # Console handler — controlled by level/quiet
    if not quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level.upper(), logging.WARNING))
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
