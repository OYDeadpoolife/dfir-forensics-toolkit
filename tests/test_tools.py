"""External tool integration, tested with stub programs (see conftest.py for why).

These tests prove that the toolkit calls the programs with the intended arguments, keeps their
output, records failures and timeouts and carries on. They do not prove that the real
binwalk, foremost, bulk_extractor or Volatility work: that needs a manual check.
"""

import shutil
import time

import pytest

from conftest import DEMO_EVIDENCE, make_minimal_path, sha256_hex, write_stub

ALL_EXTERNAL = "metadata,strings,binwalk,foremost,bulk_extractor"


def stub_calls(tmp_path):
    return (tmp_path / "stub.log").read_text().splitlines()


def test_available_tools_are_run_with_the_right_arguments(triage_demo, stubs, tmp_path):
    result = triage_demo(path_dirs=[stubs])
    assert result.returncode == 0, result.stderr
    assert set(result.statuses().values()) == {"OK"}
    calls = stub_calls(tmp_path)
    case = str(result.case_dir)
    assert f"{DEMO_EVIDENCE}" in calls  # binwalk: a plain scan of the evidence
    assert f"-i {DEMO_EVIDENCE} -o {case}/foremost/carved" in calls
    assert f"-o {case}/bulk_extractor/features {DEMO_EVIDENCE}" in calls
    assert "PNG image" in result.read("binwalk/binwalk.stdout.txt")
    assert result.read("foremost/carved/audit.txt").startswith("Foremost stub")
    assert (result.case_dir / "bulk_extractor/features/email.txt").exists()


def test_tool_versions_are_recorded(triage_demo, stubs):
    result = triage_demo(path_dirs=[stubs])
    versions = {line.split("\t")[0]: line.split("\t")[2] for line in result.read("logs/tool_versions.tsv").splitlines()}
    assert versions["binwalk"] == "binwalk stub 1.2.3"
    assert versions["foremost"] == "foremost stub 1.2.3"
    assert "binwalk stub 1.2.3" in result.report()


def test_a_failing_tool_is_recorded_and_the_other_modules_still_run(run_triage, stubs, tmp_path):
    write_stub(stubs, "binwalk", 'echo "binwalk: cannot read signature file" >&2; exit 3')
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", case_id="C1", path_dirs=[stubs])
    assert result.returncode == 4
    statuses = result.statuses()
    assert statuses["binwalk"] == "FAILED"
    assert statuses["foremost"] == "OK" and statuses["strings"] == "OK"
    row = [r for r in result.status_rows() if r[0] == "binwalk"][0]
    assert row[2] == "3"
    assert "cannot read signature file" in result.read("binwalk/binwalk.stderr.txt")
    assert "VERIFIED" in result.report()  # integrity is still checked and reported


@pytest.mark.parametrize("use_system_timeout", [False, True])
def test_a_hanging_tool_is_stopped_by_the_timeout(run_triage, stubs, tmp_path, use_system_timeout):
    system_timeout = shutil.which("timeout") or shutil.which("gtimeout")
    if use_system_timeout and not system_timeout:
        pytest.skip("neither timeout nor gtimeout is installed")
    write_stub(stubs, "foremost", "sleep 60")
    extra = {}
    if use_system_timeout:
        make_minimal_path(tmp_path / "minimal-path")
        (tmp_path / "minimal-path" / "timeout").symlink_to(system_timeout)
    started = time.time()
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--timeout", "2", "--modules", "foremost", case_id="C1",
                        path_dirs=[stubs], env_extra=extra)
    assert time.time() - started < 30
    assert result.returncode == 4
    assert result.statuses() == {"foremost": "TIMEOUT"}
    assert "stopped after 2 seconds" in result.status_rows()[0][5]


def test_timeout_zero_means_no_limit(run_triage, stubs):
    write_stub(stubs, "binwalk", "sleep 1; echo done")
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--timeout", "0", "--modules", "binwalk", case_id="C1", path_dirs=[stubs])
    assert result.returncode == 0 and result.statuses() == {"binwalk": "OK"}


def test_a_tool_that_modifies_the_evidence_is_detected(run_triage, stubs, tmp_path):
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(DEMO_EVIDENCE.read_bytes())
    # A misbehaving "tool" that appends a byte to the evidence it was given.
    write_stub(stubs, "binwalk", 'echo x >> "${@: -1}"')
    result = run_triage("--evidence", evidence, "--quiet", "--modules", "binwalk", case_id="C1", path_dirs=[stubs])
    assert result.returncode == 5
    assert "FAILED - evidence changed during analysis" in result.report()
    events = [line.split("\t")[1] for line in result.read("logs/custody.tsv").splitlines()]
    assert "INTEGRITY_FAILED" in events
    before = result.read("hashes/evidence.sha256").split()[0]
    after = result.read("hashes/evidence.after.sha256").split()[0]
    assert before != after and after == sha256_hex(evidence)
    assert "changed during the run" in result.stderr


def test_with_copy_evidence_the_original_is_never_touched_by_tools(run_triage, stubs, tmp_path):
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(DEMO_EVIDENCE.read_bytes())
    write_stub(stubs, "binwalk", 'echo x >> "${@: -1}" 2>/dev/null; exit 0')
    result = run_triage("--evidence", evidence, "--quiet", "--copy-evidence", "--modules", "binwalk", case_id="C1", path_dirs=[stubs])
    assert result.returncode == 0, result.stderr  # the append fails on the read-only copy, the original stays intact
    assert sha256_hex(evidence) == sha256_hex(DEMO_EVIDENCE)


def test_volatility_runs_each_plugin_into_its_own_file(run_triage, stubs, tmp_path):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--modules", "volatility",
                        "--vol-plugins", "windows.info.Info,windows.pslist.PsList", case_id="C1", path_dirs=[stubs])
    assert result.returncode == 0, result.stderr
    assert result.read("volatility/windows.info.Info.txt").strip() == "output of windows.info.Info"
    assert result.read("volatility/windows.pslist.PsList.txt").strip() == "output of windows.pslist.PsList"
    assert f"-q -f {DEMO_EVIDENCE} windows.info.Info" in stub_calls(tmp_path)
    assert result.statuses() == {"volatility": "OK"}


def test_volatility_plugin_failure_is_reported_per_plugin(run_triage, stubs):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--modules", "volatility", case_id="C1", path_dirs=[stubs],
                        env_extra={"STUB_FAIL_PLUGIN": "netscan"})
    assert result.returncode == 4
    note = result.status_rows()[0][5]
    assert "1 of 5 plugin(s) failed" in note and "windows.netscan.NetScan(exit 2)" in note
    assert "Unable to validate" in result.read("volatility/windows.netscan.NetScan.stderr.txt")
    assert (result.case_dir / "volatility/windows.pslist.PsList.txt").exists()  # the other plugins still ran


def test_volatility_is_not_part_of_auto(triage_demo, stubs):
    assert "volatility" not in triage_demo(path_dirs=[stubs]).statuses()


def test_volatility_missing_is_skipped_with_a_hint(run_triage):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--modules", "volatility", case_id="C1")
    assert result.returncode == 0
    assert "pip install volatility3" in result.status_rows()[0][5]


def test_volatility_command_can_be_chosen_with_an_environment_variable(run_triage, tmp_path):
    custom = write_stub(tmp_path / "elsewhere", "my-vol3", 'echo "custom ${@: -1}"')
    result = run_triage("--evidence", DEMO_EVIDENCE, "--quiet", "--modules", "volatility", "--vol-plugins", "windows.info.Info",
                        case_id="C1", env_extra={"DFIR_VOLATILITY": str(custom)})
    assert result.statuses() == {"volatility": "OK"}
    assert result.read("volatility/windows.info.Info.txt").strip() == "custom windows.info.Info"


def test_small_evidence_triggers_a_volatility_warning(run_triage, stubs):
    result = run_triage("--evidence", DEMO_EVIDENCE, "--modules", "volatility", case_id="C1", path_dirs=[stubs])
    assert "real memory images are much larger" in result.stderr
