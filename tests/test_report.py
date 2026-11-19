"""The Markdown case report: structure, honesty about skipped modules, hostile input."""

import re

from conftest import DEMO_EVIDENCE, sha256_hex


def test_report_sections_and_facts(triage_demo):
    report = triage_demo("--analyst", "Ada Example").report()
    for heading in ("# Case report: CASE-TEST-001", "## 1. Case information", "## 2. Evidence", "## 3. Execution summary",
                    "## 4. Tool versions", "## 5. Output of the automated modules", "## 6. Files in this case",
                    "## 7. Analyst section (complete by hand)", "## 8. What this report cannot tell you"):
        assert heading in report
    assert sha256_hex(DEMO_EVIDENCE) in report
    assert "| **Integrity check** | **VERIFIED - evidence unchanged** |" in report
    assert "It contains no conclusions" in report


def test_skipped_modules_are_stated_plainly(triage_demo):
    report = triage_demo().report()
    assert "*binwalk was skipped: binwalk is not installed" in report
    assert "| binwalk | SKIPPED | - |" in report
    assert "nothing was installed automatically" in report
    assert "No external program was run." in report


def test_module_output_appears_when_the_tools_ran(triage_demo, stubs):
    report = triage_demo(path_dirs=[stubs]).report()
    assert "PNG image, 1 x 1" in report
    assert "Foremost stub audit" in report
    assert "binwalk stub 1.2.3" in report  # the version table lists the tool


def test_unrequested_modules_are_labelled_as_such(triage_demo):
    report = triage_demo("--modules", "strings").report()
    assert "*binwalk was not requested for this run.*" in report


def test_indicators_are_shown_in_a_code_block(triage_demo):
    report = triage_demo().report()
    block = report.split("### 5.2 Indicators found in strings")[1].split("###")[0]
    assert "~~~~text" in block and "203.0.113.45" in block


def test_hostile_text_cannot_break_the_report(run_triage, tmp_path):
    evidence = tmp_path / "e.bin"
    evidence.write_bytes(b"~~~~\n~~~~~~~~ close the fence\n# Injected heading\n<script>alert(1)</script> http://192.0.2.9/x`tick`\n")
    result = run_triage("--evidence", evidence, "--quiet", "--analyst", "Eve | <b>Bold</b>\nSecond line", case_id="C1")
    report = result.report()
    fences = [line for line in report.splitlines() if line.startswith("~~~~")]
    assert len(fences) % 2 == 0  # every opening fence has its closing fence
    assert all(line in ("~~~~", "~~~~text") for line in fences)  # nothing from the evidence became a fence
    assert "| Analyst | Eve &#124; &lt;b&gt;Bold&lt;/b&gt; Second line |" in report
    assert "# Injected heading" not in report.split("### 5.2")[0]


def test_case_id_and_command_line_are_in_the_report(triage_demo):
    report = triage_demo("--md5").report()
    assert re.search(r"\| Command line \| dfir-triage .*--md5", report)
    assert "MD5 (legacy, not for integrity)" in report


def test_command_line_with_non_ascii_path_survives_a_utf8_locale(run_triage, tmp_path):
    """Regression test: bash 3.2 corrupted such arguments under a UTF-8 locale and the cell came out empty."""
    folder = tmp_path / "ראיות"
    folder.mkdir()
    evidence = folder / "e.bin"
    evidence.write_bytes(b"data")
    for locale in ("en_US.UTF-8", "C", ""):
        result = run_triage("--evidence", evidence, "--quiet", "--md5", case_id=f"C-{locale or 'default'}".replace(".", "-"),
                            env_extra={"LANG": locale, "LC_ALL": locale} if locale else {})
        assert result.returncode == 0, result.stderr
        row = [line for line in result.report().splitlines() if line.startswith("| Command line |")][0]
        assert "--md5" in row and "--evidence" in row, (locale, row)
        assert "e.bin" in [line for line in result.report().splitlines() if line.startswith("| File name |")][0]
