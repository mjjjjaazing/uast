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
        if path.endswith((".tar.gz", ".tar.bz2", ".tgz")):
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


def download_npm_package(
    name: str,
    version: Optional[str],
    dest_dir: str,
    timeout: int = 60,
) -> Optional[str]:
    """
    Download an npm package tarball via the npm registry API.

    Args:
        name: Package name.
        version: Specific version, or None for latest.
        dest_dir: Directory to download into.
        timeout: Request timeout in seconds.

    Returns:
        Path to the downloaded tarball, or None on failure.
    """
    from uast.http_client import http_client

    # Validate package name
    if not name or not re.match(r"^[@a-zA-Z0-9][\w.@/\-]{0,213}$", name):
        logger.warning("Invalid npm package name for download: %r", name)
        return None

    try:
        # Fetch package metadata
        if version:
            url = f"https://registry.npmjs.org/{name}/{version}"
        else:
            url = f"https://registry.npmjs.org/{name}/latest"

        resp = http_client.get(url, timeout=timeout)
        if resp.status_code != 200:
            logger.warning("npm registry returned %d for %s", resp.status_code, name)
            return None

        data = resp.json()
        tarball_url = data.get("dist", {}).get("tarball")
        if not tarball_url:
            logger.warning("No tarball URL in npm metadata for %s", name)
            return None

        # Download tarball
        import requests
        tarball_resp = requests.get(tarball_url, timeout=timeout, stream=True)
        if tarball_resp.status_code != 200:
            logger.warning("Tarball download failed for %s: %d", name, tarball_resp.status_code)
            return None

        # Write to dest_dir
        tarball_name = tarball_url.split("/")[-1]
        if not tarball_name.endswith(".tgz"):
            tarball_name = f"{name.replace('/', '-')}-{version or 'latest'}.tgz"
        dest_path = os.path.join(dest_dir, tarball_name)

        with open(dest_path, "wb") as f:
            for chunk in tarball_resp.iter_content(chunk_size=8192):
                f.write(chunk)

        return dest_path

    except Exception as e:
        logger.warning("npm package download failed for %s: %s", name, e)
        return None


def _find_archive(directory: str) -> Optional[str]:
    """Find the first archive file in a directory."""
    for f in os.listdir(directory):
        if f.endswith((".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2")):
            return os.path.join(directory, f)
    return None
