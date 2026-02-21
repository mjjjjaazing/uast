"""
Package utilities — shared download and extraction logic.

Refactored from payload.py to support reuse by version_diff.py
and provenance.py without duplicating download/extract code.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from typing import Optional

logger = logging.getLogger("uast.package_utils")

# Valid package name pattern (prevents command injection)
_VALID_PACKAGE_NAME = re.compile(r"^[a-zA-Z0-9][\w.\-]{0,213}$")


def validate_package_name(name: str) -> bool:
    """Check if a package name is safe for use in subprocess commands."""
    return bool(_VALID_PACKAGE_NAME.match(name))


def download_package(
    name: str,
    version: Optional[str],
    dest_dir: str,
    sdist_only: bool = False,
    timeout: int = 60,
) -> Optional[str]:
    """
    Download a package using pip download.

    Args:
        name: Package name.
        version: Specific version, or None for latest.
        dest_dir: Directory to download into.
        sdist_only: If True, only download sdist (no wheels).
        timeout: Subprocess timeout in seconds.

    Returns:
        Path to the downloaded archive, or None on failure.
    """
    if not validate_package_name(name):
        logger.warning("Invalid package name for download: %r", name)
        return None

    pkg_spec = f"{name}=={version}" if version else name

    cmd = [
        sys.executable, "-m", "pip", "download",
        "--no-deps",
        "-d", dest_dir,
    ]

    if sdist_only:
        cmd.extend(["--no-binary", ":all:"])

    cmd.append(pkg_spec)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return _find_archive(dest_dir)

        # Fallback: allow binary if sdist failed
        if sdist_only:
            cmd_wheel = [
                sys.executable, "-m", "pip", "download",
                "--no-deps", "-d", dest_dir, pkg_spec,
            ]
            result = subprocess.run(
                cmd_wheel, capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0:
                return _find_archive(dest_dir)

    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("Package download failed for %s: %s", name, e)

    return None


def extract_archive(path: str, dest: str) -> bool:
    """
    Extract a .tar.gz, .tar.bz2, .zip, or .whl archive to dest.

    Filters out path traversal and absolute paths for security.

    Returns True on success, False on failure.
    """
    try:
        if path.endswith((".tar.gz", ".tar.bz2")):
            with tarfile.open(path) as tf:
                members = []
                for m in tf.getmembers():
                    if m.name.startswith("/") or ".." in m.name:
                        continue
                    members.append(m)
                tf.extractall(dest, members=members)
            return True
        elif path.endswith((".zip", ".whl")):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.filename.startswith("/") or ".." in info.filename:
                        continue
                    zf.extract(info, dest)
            return True
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
        logger.warning("Archive extraction failed for %s: %s", path, e)
    return False


def _find_archive(directory: str) -> Optional[str]:
    """Find the first archive file in a directory."""
    for f in os.listdir(directory):
        if f.endswith((".tar.gz", ".zip", ".whl", ".tar.bz2")):
            return os.path.join(directory, f)
    return None
