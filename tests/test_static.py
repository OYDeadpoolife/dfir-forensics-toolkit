"""Repository hygiene: required files, safe code, no secrets, reproducible demo evidence, lint."""

import hashlib
import json
import re
import shutil
import subprocess
import sys

import pytest

from conftest import DEMO_EVIDENCE, ROOT

REQUIRED_FILES = [
    "README.md", "LICENSE", ".gitignore", ".editorconfig", "Makefile", "requirements-dev.txt", "TEST_RESULTS.md",
    "bin/dfir-triage", "lib/dfir_common.sh", "lib/dfir_validate.sh", "lib/dfir_hash.sh", "lib/dfir_modules.sh",
    "lib/dfir_report.sh", "templates/analyst-report-template.md",
    "demo-case/README.md", "demo-case/tools/build_synthetic_evidence.py", "demo-case/evidence/ws01_triage_synthetic.bin",
    "demo-case/evidence/ws01_triage_synthetic.bin.sha256", "demo-case/evidence/evidence_layout.json",
    "docs/forensics-workflow.md", "docs/usage.md", "docs/tool-integration.md", "docs/design-notes.md",
    "docs/troubleshooting.md", "screenshots/README.md", ".github/workflows/ci.yml",
]
SHELL_FILES = ["bin/dfir-triage", "lib/dfir_common.sh", "lib/dfir_validate.sh", "lib/dfir_hash.sh", "lib/dfir_modules.sh", "lib/dfir_report.sh"]
# Written in pieces so this file does not match itself; the last marker is the account name used while developing.
LOCAL_PATH_MARKERS = ("/Use" + "rs/", "orhay" + "yosef")  # fictional C:\\Users\\jdoe paths in the demo are fine


@pytest.mark.parametrize("relative", REQUIRED_FILES)
def test_required_file_exists(relative):
    path = ROOT / relative
    assert path.is_file(), f"missing {relative}"
    if path.suffix in {".md", ".yml"}:
        assert path.stat().st_size > 150, f"{relative} looks empty"


def test_code_never_installs_software_or_escalates_privileges():
    forbidden = re.compile(r"^\s*(sudo|su|apt|apt-get|yum|dnf|brew|pip3?|npm|curl|wget|chown)\b", re.MULTILINE)
    for relative in SHELL_FILES:
        code = (ROOT / relative).read_text(encoding="utf-8")
        for number, line in enumerate(code.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            match = forbidden.search(line)
            assert match is None, f"{relative}:{number}: unexpected command '{line.strip()}'"
        assert not re.search(r"\beval\b", code), f"{relative}: eval is not allowed"
        assert not re.search(r"\bEUID\b|\bid -u\b|whoami", code), f"{relative}: must not depend on the user being root"


def test_destructive_commands_are_limited_to_known_safe_uses():
    """Only a temporary file inside the case folder is ever deleted; the evidence is never written."""
    found = []
    for relative in SHELL_FILES:
        for number, line in enumerate((ROOT / relative).read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
            if re.search(r"\b(rm|rmdir|mv|shred|dd|truncate)\b", code):
                found.append(code.strip())
    assert found == ['rm -f -- "$dir/.combined.tmp"'], found


def test_no_secrets_or_local_paths_in_text_files():
    patterns = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"xox[baprs]-[A-Za-z0-9-]+"]
    skip_parts = {".git", ".pytest_cache", "__pycache__", "dfir-cases"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or skip_parts & set(path.relative_to(ROOT).parts) or path.suffix == ".bin":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            assert not re.search(pattern, text), f"possible secret in {path.relative_to(ROOT)}"
        for marker in LOCAL_PATH_MARKERS:
            assert marker not in text, f"local path leaked in {path.relative_to(ROOT)}"


def test_no_backup_or_cache_files():
    names = [p.name for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    assert not [n for n in names if n.endswith((".orig", ".bak", ".swp", ".pyc", ".DS_Store"))]


# --- the synthetic evidence ----------------------------------------------------------------------


def test_demo_evidence_hash_matches_the_committed_hash_file():
    recorded = (ROOT / "demo-case/evidence/ws01_triage_synthetic.bin.sha256").read_text().split()[0]
    assert hashlib.sha256(DEMO_EVIDENCE.read_bytes()).hexdigest() == recorded


def test_demo_evidence_layout_is_the_ground_truth():
    layout = json.loads((ROOT / "demo-case/evidence/evidence_layout.json").read_text())
    blob = DEMO_EVIDENCE.read_bytes()
    assert layout["synthetic"] is True and layout["size_bytes"] == len(blob)
    signatures = {"PNG image": b"\x89PNG\r\n\x1a\n", "PDF document": b"%PDF-", "ZIP archive": b"PK\x03\x04"}
    for item in layout["objects"]:
        data = blob[item["offset"]:item["offset"] + item["length"]]
        assert len(data) == item["length"]
        if item["type"] in signatures:
            assert data.startswith(signatures[item["type"]]), item["name"]
    kinds = {item["type"] for item in layout["objects"]}
    assert {"PNG image", "PDF document", "ZIP archive", "UTF-16LE text"} <= kinds


def test_demo_evidence_can_be_rebuilt_byte_for_byte(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "demo-case/tools/build_synthetic_evidence.py"), "--out-dir", str(tmp_path)],
                   check=True, capture_output=True)
    assert (tmp_path / DEMO_EVIDENCE.name).read_bytes() == DEMO_EVIDENCE.read_bytes()
    assert (tmp_path / "evidence_layout.json").read_text() == (ROOT / "demo-case/evidence/evidence_layout.json").read_text()


def test_demo_evidence_is_harmless():
    blob = DEMO_EVIDENCE.read_bytes()
    assert not blob.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"#!"))  # no executable header
    assert b"This program cannot be run in DOS mode" not in blob
    assert b"EICAR" not in blob  # no antivirus test string, so scanners will not flag the repository
    assert b"SYNTHETIC" in blob
    assert len(blob) < 100_000


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shellcheck_is_clean():
    completed = subprocess.run(["shellcheck", "-x", *SHELL_FILES], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout


@pytest.mark.skipif(shutil.which("shfmt") is None, reason="shfmt is not installed")
def test_shfmt_formatting_is_clean():
    completed = subprocess.run(["shfmt", "-d", "-i", "4", "-ci", *SHELL_FILES], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout
