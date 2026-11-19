"""Command line behaviour: help, option validation, evidence and output path checks, dry run."""

import os
import stat

import pytest

from conftest import DEMO_EVIDENCE, TRIAGE, sha256_hex


def test_help_version_and_list_modules(run_triage, stubs):
    helped = run_triage("--help", output_dir=False)
    assert helped.returncode == 0
    for text in ("--evidence", "--dry-run", "--timeout", "EXIT STATUS", "never overwritten"):
        assert text in helped.stdout
    version = run_triage("--version", output_dir=False)
    assert version.stdout.strip() == "dfir-triage 1.0.0"
    missing = run_triage("--list-modules", output_dir=False)
    assert missing.returncode == 0
    assert "metadata        available" in missing.stdout
    assert "binwalk         MISSING" in missing.stdout
    present = run_triage("--list-modules", output_dir=False, path_dirs=[stubs])
    assert "binwalk         available" in present.stdout
    assert "volatility      available" in present.stdout  # the stub is called "vol"


def test_no_arguments_prints_usage_and_fails(run_triage):
    result = run_triage(output_dir=False)
    assert result.returncode == 2
    assert "USAGE" in result.stderr


@pytest.mark.parametrize(
    "args, message",
    [
        (["--bogus"], "unknown option"),
        (["--evidence"], "needs a value"),
        (["--dry-run"], "no evidence given"),
        (["--evidence", str(DEMO_EVIDENCE), "--modules", "metadata,nonsense"], "unknown module 'nonsense'"),
        (["--evidence", str(DEMO_EVIDENCE), "--modules", ","], "empty module name"),
        (["--evidence", str(DEMO_EVIDENCE), "--timeout", "abc"], "whole number"),
        (["--evidence", str(DEMO_EVIDENCE), "--timeout", "-1"], "whole number"),
        (["--evidence", str(DEMO_EVIDENCE), "--strings-limit-mb", "0"], "between"),
        (["--evidence", str(DEMO_EVIDENCE), "--strings-min-length", "1"], "between"),
        (["--evidence", str(DEMO_EVIDENCE), "--vol-plugins", "windows.info;rm"], "invalid Volatility plugin"),
        (["--evidence", str(DEMO_EVIDENCE), "--analyst", "x" * 81], "longer than 80"),
    ],
)
def test_invalid_usage_exits_with_status_2(run_triage, args, message):
    result = run_triage(*args, output_dir=False)
    assert result.returncode == 2, result.stderr
    assert message in result.stderr


@pytest.mark.parametrize("bad_id", ["../escape", "/abs/path", "has space", "-leading-dash", "a" * 65, ".hidden", "x/y", "semi;colon", "dollar$HOME"])
def test_unsafe_case_ids_are_rejected(run_triage, tmp_path, bad_id):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--case-id", bad_id, output_dir=tmp_path / "cases")
    assert result.returncode == 2
    assert "invalid --case-id" in result.stderr
    assert not (tmp_path / "cases").exists()


def test_missing_evidence_exits_with_status_3(run_triage, tmp_path):
    result = run_triage("--evidence", tmp_path / "nope.bin", case_id="C1")
    assert result.returncode == 3
    assert "does not exist" in result.stderr
    assert not (tmp_path / "cases").exists()


def test_directory_and_fifo_are_not_accepted_as_evidence(run_triage, tmp_path):
    directory = tmp_path / "a-directory"
    directory.mkdir()
    assert run_triage("--evidence", directory, case_id="C1").returncode == 3
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    result = run_triage("--evidence", fifo, case_id="C2")
    assert result.returncode == 3
    assert "not a regular file" in result.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_evidence_exits_with_status_3(run_triage, tmp_path):
    locked = tmp_path / "locked.bin"
    locked.write_bytes(b"secret")
    locked.chmod(0)
    result = run_triage("--evidence", locked, case_id="C1")
    assert result.returncode == 3
    assert "not readable" in result.stderr


def test_existing_case_is_never_overwritten(triage_demo, run_triage, tmp_path):
    first = triage_demo(case_id="CASE-A")
    assert first.returncode == 0, first.stderr
    marker = first.case_dir / "my-notes.txt"
    marker.write_text("analyst notes")
    second = triage_demo(case_id="CASE-A")
    assert second.returncode == 2
    assert "already exists" in second.stderr
    assert marker.read_text() == "analyst notes"


def test_output_path_that_is_a_file_is_rejected(run_triage, tmp_path):
    target = tmp_path / "a-file"
    target.write_text("keep me")
    result = run_triage("--evidence", DEMO_EVIDENCE, "--output-dir", target, case_id="C1", output_dir=target)
    assert result.returncode == 2
    assert target.read_text() == "keep me"


def test_dry_run_changes_nothing(run_triage, stubs, tmp_path):
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(DEMO_EVIDENCE.read_bytes())
    before = (sha256_hex(evidence), evidence.stat().st_mtime_ns)
    result = run_triage("--evidence", evidence, "--dry-run", case_id="CASE-DRY", path_dirs=[stubs])
    assert result.returncode == 0, result.stderr
    assert "dry run" in result.stdout
    assert "CASE-DRY" in result.stdout and str(evidence) in result.stdout
    assert "binwalk         available" in result.stdout
    assert not (tmp_path / "cases").exists()  # not even the output directory is created
    assert (sha256_hex(evidence), evidence.stat().st_mtime_ns) == before
    assert not (tmp_path / "stub.log").exists()  # no external program was started


def test_dry_run_reports_missing_tools(run_triage):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--dry-run", case_id="C1")
    assert "binwalk         MISSING" in result.stdout


def test_paths_with_spaces_and_non_ascii_characters(run_triage, tmp_path):
    folder = tmp_path / "ראיות מקרה 1"
    folder.mkdir()
    evidence = folder / "my evidence ($1) 'quoted'.bin"
    evidence.write_bytes(DEMO_EVIDENCE.read_bytes())
    out = tmp_path / "תיקיות תוצאה"
    result = run_triage("--evidence", evidence, "--quiet", case_id="CASE-SPACES", output_dir=out)
    assert result.returncode == 0, result.stderr
    assert result.exists("hashes/evidence.sha256")
    assert result.read("hashes/evidence.sha256").split()[0] == sha256_hex(DEMO_EVIDENCE)
    assert "my evidence" in result.report()


def test_evidence_file_name_starting_with_a_dash(run_triage, tmp_path):
    evidence = tmp_path / "-weird.bin"
    evidence.write_bytes(b"data")
    result = run_triage("--evidence", evidence, "--quiet", case_id="CASE-DASH")
    assert result.returncode == 0, result.stderr


def test_relative_and_symlinked_evidence_paths(run_triage, tmp_path):
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "e.bin").write_bytes(b"abc")
    (tmp_path / "link.bin").symlink_to(tmp_path / "work" / "e.bin")
    relative = run_triage("--evidence", "work/e.bin", "--quiet", case_id="REL")
    assert relative.returncode == 0, relative.stderr
    linked = run_triage("--evidence", tmp_path / "link.bin", "--quiet", case_id="LINK")
    assert linked.returncode == 0, linked.stderr


def test_default_case_id_has_a_utc_timestamp(run_triage, tmp_path):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet")
    assert result.returncode == 0, result.stderr
    names = [p.name for p in (tmp_path / "cases").iterdir()]
    assert len(names) == 1 and names[0].startswith("CASE-") and len(names[0]) == len("CASE-20260314-101500")


def test_case_files_are_private(triage_demo):
    result = triage_demo()
    assert stat.S_IMODE(result.case_dir.stat().st_mode) == 0o700
    for path in result.case_dir.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode in (0o700, 0o600), (path, oct(mode))


def test_script_works_through_a_symbolic_link(tmp_path):
    import subprocess

    link = tmp_path / "on-path" / "dfir-triage"
    link.parent.mkdir()
    link.symlink_to(TRIAGE)
    completed = subprocess.run([str(link), "--version"], capture_output=True, text=True)
    assert completed.stdout.strip() == "dfir-triage 1.0.0"


def test_analyst_name_comes_from_option_or_environment(triage_demo):
    assert "| Analyst | Ada Example |" in triage_demo("--analyst", "Ada Example").report()
    from_env = triage_demo(case_id="ENV-CASE", env_extra={"DFIR_ANALYST": "Env Analyst"})
    assert "| Analyst | Env Analyst |" in from_env.report()
