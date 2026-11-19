"""The core workflow on the synthetic evidence: hashing, integrity, metadata, strings, indicators."""

import base64
import hashlib
import json
import re

from conftest import DEMO_EVIDENCE, ROOT, sha256_hex

LAYOUT = json.loads((ROOT / "demo-case" / "evidence" / "evidence_layout.json").read_text())


def test_case_directory_layout(triage_demo):
    result = triage_demo("--md5")
    assert result.returncode == 0, result.stderr
    for relative in ("case_info.txt", "hashes/evidence.sha256", "hashes/evidence.after.sha256", "hashes/evidence.md5",
                     "metadata/file_attributes.txt", "metadata/file_type.txt", "metadata/mime_type.txt",
                     "metadata/first_64_bytes.hex.txt", "strings/strings_ascii.txt", "strings/strings_utf16le_approx.txt",
                     "strings/iocs.tsv", "logs/run.log", "logs/status.tsv", "logs/commands.txt", "logs/custody.tsv",
                     "logs/tool_versions.tsv", "report/case_report.md"):
        assert result.exists(relative), relative
    assert not result.exists("evidence")  # no copy unless --copy-evidence
    assert not list(result.case_dir.rglob(".combined.tmp"))


def test_hashes_are_correct_and_use_the_sha256sum_format(triage_demo):
    result = triage_demo("--md5")
    expected = sha256_hex(DEMO_EVIDENCE)
    assert result.read("hashes/evidence.sha256") == f"{expected}  {DEMO_EVIDENCE.name}\n"
    assert result.read("hashes/evidence.after.sha256").split()[0] == expected
    assert result.read("hashes/evidence.md5").split()[0] == hashlib.md5(DEMO_EVIDENCE.read_bytes()).hexdigest()
    assert expected == (ROOT / "demo-case/evidence/ws01_triage_synthetic.bin.sha256").read_text().split()[0]


def test_integrity_is_verified_and_recorded(triage_demo):
    result = triage_demo()
    assert "VERIFIED - evidence unchanged" in result.report()
    events = [line.split("\t")[1] for line in result.read("logs/custody.tsv").splitlines()[1:]]
    assert events == ["CASE_OPENED", "EVIDENCE_HASHED_BEFORE", "INTEGRITY_VERIFIED", "REPORT_WRITTEN"]


def test_evidence_is_not_modified(run_triage, tmp_path):
    evidence = tmp_path / "e.bin"
    evidence.write_bytes(DEMO_EVIDENCE.read_bytes())
    before = (sha256_hex(evidence), evidence.stat().st_mtime_ns, evidence.stat().st_mode)
    result = run_triage("--evidence", evidence, "--quiet", case_id="C1")
    assert result.returncode == 0, result.stderr
    assert (sha256_hex(evidence), evidence.stat().st_mtime_ns, evidence.stat().st_mode) == before


def test_only_the_case_directory_is_written(run_triage, tmp_path):
    work = tmp_path / "workspace"
    work.mkdir()
    (work / "e.bin").write_bytes(b"hello")
    run_triage("--evidence", "e.bin", "--quiet", case_id="C1", cwd=work, output_dir=tmp_path / "cases")
    assert sorted(p.name for p in work.iterdir()) == ["e.bin"]
    assert [p.name for p in (tmp_path / "cases").iterdir()] == ["C1"]


def test_without_forensic_tools_the_modules_are_skipped_not_failed(triage_demo):
    result = triage_demo()
    assert result.returncode == 0
    assert result.statuses() == {"metadata": "OK", "strings": "OK", "binwalk": "SKIPPED", "foremost": "SKIPPED",
                                 "bulk_extractor": "SKIPPED"}
    notes = {row[0]: row[5] for row in result.status_rows()}
    assert "sudo apt install binwalk" in notes["binwalk"]  # the hint is shown, never executed
    assert "not installed" in notes["foremost"]


def test_file_attributes_are_recorded_before_reading(triage_demo):
    attributes = dict(line.split("=", 1) for line in triage_demo().read("metadata/file_attributes.txt").splitlines())
    assert attributes["size_bytes"] == str(DEMO_EVIDENCE.stat().st_size)
    assert attributes["modified_utc"].endswith("Z") and attributes["permissions"].startswith("-")


def test_file_type_and_magic_bytes(triage_demo):
    result = triage_demo()
    assert result.read("metadata/file_type.txt").strip() == "data"
    assert result.read("metadata/mime_type.txt").strip() == "application/octet-stream"
    first_line = result.read("metadata/first_64_bytes.hex.txt").splitlines()[0]
    assert first_line.split()[1:5] == ["48", "41", "52", "42"]  # "HARB"


def test_indicators_are_extracted_from_strings(triage_demo):
    rows = [line.split("\t") for line in triage_demo().read("strings/iocs.tsv").splitlines()[1:]]
    found = {(kind, value): int(count) for count, kind, value in rows}
    assert found[("ipv4", "203.0.113.45")] >= 3
    assert ("ipv4", "10.10.10.20") in found
    assert ("url", "http://203.0.113.45/stage2") in found
    assert ("email", "billing@invoices-harbor.test") in found


def test_utf16_command_line_is_recovered_and_decodes_to_the_harmless_message(triage_demo):
    result = triage_demo()
    lines = [line for line in result.read("strings/strings_utf16le_approx.txt").splitlines() if "-EncodedCommand" in line]
    assert lines, "the UTF-16LE command line was not found"
    encoded = re.search(r"-EncodedCommand (\S+)", lines[0]).group(1)
    assert base64.b64decode(encoded).decode("utf-16-le") == 'Write-Output "synthetic training event - harmless"'


def test_invalid_ip_addresses_are_not_reported_as_indicators(run_triage, tmp_path):
    evidence = tmp_path / "e.txt"
    evidence.write_text("good 192.0.2.7 bad 999.1.1.1 also 300.2.3.4 and 1.2.3\n")
    result = run_triage("--evidence", evidence, "--quiet", "--modules", "strings", case_id="C1")
    values = [line.split("\t")[2] for line in result.read("strings/iocs.tsv").splitlines()[1:]]
    assert values == ["192.0.2.7"]


def test_strings_limit_and_note(run_triage, tmp_path):
    evidence = tmp_path / "big.bin"
    evidence.write_bytes(b"EARLY-MARKER-STRING\n" + b"\x00" * (1024 * 1024 + 4096) + b"LATE-MARKER-STRING\n")
    result = run_triage("--evidence", evidence, "--quiet", "--modules", "strings", "--strings-limit-mb", "1", case_id="C1")
    assert result.returncode == 0, result.stderr
    text = result.read("strings/strings_ascii.txt")
    assert "EARLY-MARKER-STRING" in text and "LATE-MARKER-STRING" not in text
    assert "only the first 1 MB" in {row[0]: row[5] for row in result.status_rows()}["strings"]


def test_minimum_string_length(run_triage, tmp_path):
    evidence = tmp_path / "e.bin"
    evidence.write_bytes(b"\x00abcdefghij\x00abc\x00")
    result = run_triage("--evidence", evidence, "--quiet", "--modules", "strings", "--strings-min-length", "5", case_id="C1")
    assert result.read("strings/strings_ascii.txt").split() == ["abcdefghij"]


def test_empty_evidence_file(run_triage, tmp_path):
    evidence = tmp_path / "empty.bin"
    evidence.write_bytes(b"")
    result = run_triage("--evidence", evidence, "--quiet", case_id="C1")
    assert result.returncode == 0, result.stderr
    assert result.read("hashes/evidence.sha256").split()[0] == hashlib.sha256(b"").hexdigest()
    assert result.read("metadata/file_type.txt").strip() == "empty"
    assert "| Size | 0 bytes |" in result.report()


def test_copy_evidence_makes_a_verified_read_only_copy(run_triage, stubs, tmp_path):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--copy-evidence", case_id="C1", path_dirs=[stubs])
    assert result.returncode == 0, result.stderr
    copy = result.case_dir / "evidence" / DEMO_EVIDENCE.name
    assert copy.read_bytes() == DEMO_EVIDENCE.read_bytes()
    assert oct(copy.stat().st_mode & 0o777) == "0o400"
    assert "EVIDENCE_COPIED" in result.read("logs/custody.tsv")
    assert str(copy) in (tmp_path / "stub.log").read_text()  # the tools were pointed at the copy, not the original


def test_md5_is_optional(triage_demo):
    assert not triage_demo().exists("hashes/evidence.md5")


def test_modules_can_be_selected(triage_demo):
    result = triage_demo("--modules", "strings")
    assert result.statuses() == {"strings": "OK"}
    assert not result.exists("metadata/file_type.txt")
    assert result.exists("metadata/file_attributes.txt")  # attributes and hashes are always recorded


def test_commands_are_recorded_exactly(triage_demo):
    commands = triage_demo().read("logs/commands.txt")
    assert "file -b -- " in commands and "strings -a -n 6" in commands


def test_run_log_has_timestamps(triage_demo):
    lines = triage_demo().read("logs/run.log").splitlines()
    assert lines and all(re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z ", line) for line in lines)
