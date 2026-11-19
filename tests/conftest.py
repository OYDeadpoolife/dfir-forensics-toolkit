"""Shared helpers for the dfir-triage test suite.

The tests run the real command line tool as a subprocess. External forensic programs are not
installed on most machines, so integration with binwalk, foremost, bulk_extractor and
Volatility is tested with small *stub* programs that imitate how those tools are called
(arguments, output directories, exit codes). That proves the toolkit's orchestration; it does
NOT prove the real tools work on real evidence. See TEST_RESULTS.md.
"""

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TRIAGE = ROOT / "bin" / "dfir-triage"
DEMO_EVIDENCE = ROOT / "demo-case" / "evidence" / "ws01_triage_synthetic.bin"

# Programs the toolkit itself needs. The "minimal PATH" contains only these, so the optional
# forensic tools are guaranteed to be missing, whatever is installed on the machine.
ESSENTIAL_COMMANDS = [
    "bash", "env", "awk", "sed", "grep", "sort", "uniq", "head", "tail", "tr", "wc", "cat", "date", "mkdir", "rm",
    "cp", "chmod", "mv", "dirname", "basename", "readlink", "uname", "od", "file", "strings", "stat", "find", "ls",
    "cut", "kill", "sleep", "id", "sha256sum", "shasum", "md5sum", "md5", "openssl", "touch", "rmdir", "mktemp",
]


def sha256_hex(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Result:
    """Outcome of one dfir-triage run, with helpers to read the case directory."""

    def __init__(self, completed, case_dir):
        self.returncode = completed.returncode
        self.stdout = completed.stdout.decode("utf-8", "replace")
        self.stderr = completed.stderr.decode("utf-8", "replace")
        self.case_dir = case_dir

    def read(self, relative):
        return (self.case_dir / relative).read_text(encoding="utf-8", errors="replace")

    def exists(self, relative):
        return (self.case_dir / relative).exists()

    def statuses(self):
        """Module name -> status, from logs/status.tsv."""
        rows = self.read("logs/status.tsv").splitlines()[1:]
        return {row.split("\t")[0]: row.split("\t")[1] for row in rows}

    def status_rows(self):
        rows = self.read("logs/status.tsv").splitlines()[1:]
        return [row.split("\t") for row in rows]

    def report(self):
        return self.read("report/case_report.md")


def make_minimal_path(directory):
    """A directory of symlinks to the essential programs only."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in ESSENTIAL_COMMANDS:
        found = shutil.which(name)
        if found and not (directory / name).exists():
            (directory / name).symlink_to(found)
    return directory


def write_stub(directory, name, body):
    """Create an executable stub program. `body` is bash code that runs after the version check."""
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / name
    script.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "${1:-}" == "--version" || "${1:-}" == "-V" || "${1:-}" == "-h" ]]; then echo "' + name + ' stub 1.2.3"; exit 0; fi\n'
        'printf "%s\\n" "$*" >> "${STUB_LOG:-/dev/null}"\n' + body + "\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


STUB_BODIES = {
    # A signature scan prints a table to stdout.
    "binwalk": 'echo "DECIMAL       HEXADECIMAL     DESCRIPTION"; echo "11776         0x2E00          PNG image, 1 x 1"',
    # foremost and bulk_extractor create the output directory named after -o, as the real programs do.
    "foremost": 'while [[ $# -gt 0 ]]; do if [[ $1 == -o ]]; then mkdir -p "$2"; echo "Foremost stub audit" > "$2/audit.txt"; fi; shift; done',
    "bulk_extractor": 'while [[ $# -gt 0 ]]; do if [[ $1 == -o ]]; then mkdir -p "$2"; echo "feature" > "$2/email.txt"; fi; shift; done; echo "bulk_extractor stub done"',
    # A Volatility 3 stub: prints the plugin name; fails when STUB_FAIL_PLUGIN matches.
    "vol": 'plugin="${@: -1}"; if [[ -n "${STUB_FAIL_PLUGIN:-}" && "$plugin" == *"$STUB_FAIL_PLUGIN"* ]]; then echo "Unable to validate the plugin requirements" >&2; exit 2; fi; echo "output of $plugin"',
}


@pytest.fixture
def minimal_path(tmp_path):
    return make_minimal_path(tmp_path / "minimal-path")


@pytest.fixture
def stubs(tmp_path):
    """Stub forensic programs; returns the directory that holds them."""
    directory = tmp_path / "stubs"
    for name, body in STUB_BODIES.items():
        write_stub(directory, name, body)
    return directory


@pytest.fixture
def run_triage(tmp_path, minimal_path):
    """Run bin/dfir-triage. By default only the essential programs are on PATH."""

    def run(*args, path_dirs=None, env_extra=None, cwd=None, case_id=None, output_dir=None, check_case=True):
        env = dict(os.environ)
        env.update(NO_COLOR="1", TMPDIR=str(tmp_path), STUB_LOG=str(tmp_path / "stub.log"))
        env.pop("DFIR_VOLATILITY", None)
        directories = [str(p) for p in (path_dirs or [])] + [str(minimal_path)]
        env["PATH"] = os.pathsep.join(directories)
        env.update(env_extra or {})
        out = Path(output_dir) if output_dir else tmp_path / "cases"
        command = [str(TRIAGE), *map(str, args)]
        if case_id:
            command += ["--case-id", case_id]
        if output_dir is not False and "--output-dir" not in args and "-o" not in args:
            command += ["--output-dir", str(out)]
        completed = subprocess.run(command, capture_output=True, env=env, cwd=str(cwd or tmp_path), timeout=180)
        return Result(completed, out / case_id if case_id else None)

    return run


@pytest.fixture
def triage_demo(run_triage):
    """Run the toolkit on the bundled synthetic evidence."""

    def run(*extra, **kwargs):
        return run_triage("--evidence", DEMO_EVIDENCE, "--quiet", *extra, case_id=kwargs.pop("case_id", "CASE-TEST-001"), **kwargs)

    return run
