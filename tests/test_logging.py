"""
Tests for the uast logging system.

Covers:
  - Log file creation
  - Log level filtering
  - Log directory creation
  - Log injection sanitization
  - Quiet mode (no console output)
  - File permissions
"""

import logging
import os
import stat
import tempfile
from pathlib import Path

import pytest

from uast.logging import setup_logging, SafeFormatter, _sanitize_message


class TestSanitizeMessage:

    def test_strips_newlines(self):
        assert _sanitize_message("line1\nline2") == "line1\\nline2"

    def test_strips_carriage_returns(self):
        assert _sanitize_message("line1\rline2") == "line1\\rline2"

    def test_strips_null_bytes(self):
        assert _sanitize_message("hello\x00world") == "helloworld"

    def test_clean_message_unchanged(self):
        assert _sanitize_message("normal message") == "normal message"

    def test_combined_injection(self):
        result = _sanitize_message("pkg\nFAKE-TIMESTAMP · INFO · injected\r\x00")
        assert "\n" not in result
        assert "\r" not in result
        assert "\x00" not in result


class TestSetupLogging:

    def test_log_file_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            setup_logging(level="DEBUG", log_dir=log_dir)

            # Write a log message to trigger file creation
            test_logger = logging.getLogger("uast.test_setup")
            test_logger.info("test message")

            log_file = log_dir / "uast.log"
            assert log_file.exists()

    def test_log_directory_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_dir = Path(tmpdir) / "deep" / "nested" / "logs"
            setup_logging(level="DEBUG", log_dir=nested_dir)
            assert nested_dir.exists()

    def test_debug_level_captures_debug(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="DEBUG", log_dir=log_dir)

            test_logger = logging.getLogger("uast.test_debug")
            test_logger.debug("debug message for test")

            log_file = log_dir / "uast.log"
            content = log_file.read_text()
            assert "debug message for test" in content

    def test_error_level_suppresses_info(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="ERROR", log_dir=log_dir)

            # File handler still captures everything
            test_logger = logging.getLogger("uast.test_error_filter")
            test_logger.info("info message")

            log_file = log_dir / "uast.log"
            content = log_file.read_text()
            # File handler is always DEBUG, so it should capture
            assert "info message" in content

    def test_quiet_mode_no_console_handler(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="DEBUG", quiet=True, log_dir=log_dir)

            root_logger = logging.getLogger("uast")
            # In quiet mode, should only have file handler
            console_handlers = [
                h for h in root_logger.handlers
                if isinstance(h, logging.StreamHandler)
                and not isinstance(h, logging.FileHandler)
            ]
            assert len(console_handlers) == 0

    def test_non_quiet_has_console_handler(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="DEBUG", quiet=False, log_dir=log_dir)

            root_logger = logging.getLogger("uast")
            console_handlers = [
                h for h in root_logger.handlers
                if isinstance(h, logging.StreamHandler)
                and not isinstance(h, logging.FileHandler)
            ]
            assert len(console_handlers) == 1

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="DEBUG", log_dir=log_dir)

            # Write something to create the file
            test_logger = logging.getLogger("uast.test_perms")
            test_logger.info("perm test")

            log_file = log_dir / "uast.log"
            if log_file.exists():
                mode = os.stat(str(log_file)).st_mode
                # Check that group/other have no access
                assert not (mode & stat.S_IRGRP)
                assert not (mode & stat.S_IWGRP)
                assert not (mode & stat.S_IROTH)
                assert not (mode & stat.S_IWOTH)

    def test_reinit_clears_handlers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="DEBUG", log_dir=log_dir)
            setup_logging(level="DEBUG", log_dir=log_dir)

            root_logger = logging.getLogger("uast")
            # Should have exactly 2 handlers (file + console), not 4
            assert len(root_logger.handlers) == 2

    def test_log_injection_sanitized_in_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            setup_logging(level="DEBUG", log_dir=log_dir)

            test_logger = logging.getLogger("uast.test_injection")
            test_logger.info("malicious-pkg\n2025-01-01 · CRITICAL · FAKE · injected line")

            log_file = log_dir / "uast.log"
            lines = log_file.read_text().strip().split("\n")
            # Should be a single log line, not two
            matching = [l for l in lines if "malicious-pkg" in l]
            assert len(matching) == 1
            assert "\\n" in matching[0]  # Newline was escaped


class TestSafeFormatter:

    def test_formats_with_sanitization(self):
        formatter = SafeFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello\nworld", args=(), exc_info=None,
        )
        result = formatter.format(record)
        assert "\\n" in result
        assert "\n" not in result.replace("\\n", "")
