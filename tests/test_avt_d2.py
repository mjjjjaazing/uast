"""
Tests for AVT D2: Permission & Scope detectors.

Covers:
  - PRIV-001: Privilege escalation (setuid, sudo, chmod 0o777, chown)
  - SCOPE-001: Scope creep (sensitive module imports)
"""

import ast

from uast.payload import SuspiciousPatternVisitor


# ---------------------------------------------------------------------------
# PRIV-001: Privilege escalation
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:

    def _visit(self, code: str, is_setup: bool = False) -> list:
        tree = ast.parse(code)
        visitor = SuspiciousPatternVisitor("test.py", is_setup_file=is_setup)
        visitor.visit(tree)
        return visitor.findings

    def test_detects_os_setuid(self):
        code = """
import os
os.setuid(0)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PRIV-001" for f in findings)

    def test_detects_os_setgid(self):
        code = """
import os
os.setgid(0)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PRIV-001" for f in findings)

    def test_detects_os_seteuid(self):
        code = """
import os
os.seteuid(0)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PRIV-001" for f in findings)

    def test_detects_os_chown(self):
        code = """
import os
os.chown("/tmp/file", 0, 0)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PRIV-001" for f in findings)

    def test_detects_chmod_world_writable(self):
        code = """
import os
os.chmod("/tmp/file", 0o777)
"""
        findings = self._visit(code)
        priv = [f for f in findings if f.signal_id == "PRIV-001"]
        assert len(priv) > 0
        assert "0o777" in priv[0].title

    def test_detects_chmod_other_write(self):
        """Any mode with o+w (0o002 bit set) should be flagged."""
        code = """
import os
os.chmod("/tmp/file", 0o766)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PRIV-001" for f in findings)

    def test_chmod_restrictive_not_flagged(self):
        """Normal restrictive chmod (e.g. 0o600) should not trigger."""
        code = """
import os
os.chmod("/tmp/file", 0o600)
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PRIV-001" for f in findings)

    def test_chmod_644_not_flagged(self):
        code = """
import os
os.chmod("/tmp/file", 0o644)
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PRIV-001" for f in findings)

    def test_detects_sudo_in_subprocess_list(self):
        code = """
import subprocess
subprocess.run(["sudo", "apt-get", "install", "evil"])
"""
        findings = self._visit(code)
        priv = [f for f in findings if f.signal_id == "PRIV-001"]
        assert any("sudo" in f.title.lower() or "sudo" in f.detail.lower() for f in priv)

    def test_detects_sudo_in_subprocess_string(self):
        code = """
import subprocess
subprocess.call("sudo rm -rf /")
"""
        findings = self._visit(code)
        priv = [f for f in findings if f.signal_id == "PRIV-001"]
        assert any("sudo" in f.title.lower() or "sudo" in f.detail.lower() for f in priv)

    def test_detects_sudo_in_os_system(self):
        code = """
import os
os.system("sudo chmod 777 /etc/passwd")
"""
        findings = self._visit(code)
        priv = [f for f in findings if f.signal_id == "PRIV-001"]
        assert any("sudo" in f.title.lower() or "sudo" in f.detail.lower() for f in priv)

    def test_normal_subprocess_no_priv(self):
        """subprocess.run without sudo should not trigger PRIV-001."""
        code = """
import subprocess
subprocess.run(["ls", "-la"])
"""
        findings = self._visit(code)
        # PAYLOAD-002 fires (subprocess detection) but not PRIV-001
        assert not any(f.signal_id == "PRIV-001" for f in findings)

    def test_normal_os_getcwd_no_priv(self):
        code = """
import os
os.getcwd()
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PRIV-001" for f in findings)


# ---------------------------------------------------------------------------
# SCOPE-001: Scope creep — sensitive module imports
# ---------------------------------------------------------------------------

class TestScopeCreep:

    def _visit(self, code: str) -> list:
        tree = ast.parse(code)
        visitor = SuspiciousPatternVisitor("test.py")
        visitor.visit(tree)
        return visitor.findings

    def test_detects_socket_import(self):
        code = "import socket"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_detects_smtplib_import(self):
        code = "import smtplib"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_detects_ctypes_import(self):
        code = "import ctypes"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_detects_from_socket_import(self):
        code = "from socket import AF_INET, SOCK_STREAM"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_detects_from_ctypes_submodule(self):
        code = "from ctypes.util import find_library"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_detects_ftplib(self):
        code = "import ftplib"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_detects_mmap(self):
        code = "import mmap"
        findings = self._visit(code)
        assert any(f.signal_id == "SCOPE-001" for f in findings)

    def test_normal_import_os_not_scope(self):
        """os is too common to be flagged as scope creep."""
        code = "import os"
        findings = self._visit(code)
        assert not any(f.signal_id == "SCOPE-001" for f in findings)

    def test_normal_import_json_not_scope(self):
        code = "import json"
        findings = self._visit(code)
        assert not any(f.signal_id == "SCOPE-001" for f in findings)

    def test_normal_import_sys_not_scope(self):
        code = "import sys"
        findings = self._visit(code)
        assert not any(f.signal_id == "SCOPE-001" for f in findings)

    def test_normal_import_pathlib_not_scope(self):
        code = "from pathlib import Path"
        findings = self._visit(code)
        assert not any(f.signal_id == "SCOPE-001" for f in findings)
