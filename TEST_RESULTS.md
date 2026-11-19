# Test results — dfir-forensics-toolkit (`dfir-triage` 1.0.0)

Last full run: **2026-10-03**. Result: **112 passed, 1 skipped, 0 failed** (`python3 -m pytest`, about 35 seconds), repeated with
`LANG=LC_ALL=en_US.UTF-8` with the same result.

GitHub Actions: **2026-11-19**. Result: **Ubuntu 113 passed, 0 skipped; macOS 112 passed, 1 skipped**. The first run failed; see "FAIL" below.

The one skipped test is `test_a_hanging_tool_is_stopped_by_the_timeout[True]`: it checks the code path that uses the system
`timeout` command, which this macOS machine does not have. The other path (the built-in polling fallback) **was** tested.

## Environment of that run

| Item | Value |
|---|---|
| Operating system | macOS 15.7.4 (arm64) |
| Bash | GNU bash 3.2.57 (the macOS default, the oldest supported version) |
| Tools | BSD `file`, `strings`, `stat`, `date`, `od`, `sha256sum`/`shasum`, awk 20200816 |
| Python / pytest | Python 3.9.6, pytest 8.4.2 |
| ShellCheck / shfmt | ShellCheck 0.11.0, shfmt 3.14.1 (pip, isolated virtual environment) |

## PASS — executed and successful

| Area | Tests | What was verified |
|---|---|---|
| Command line (`test_cli.py`) | 36 | Help, version, `--list-modules`; 11 invalid-option cases (exit 2); 9 unsafe case IDs rejected (`../x`, absolute paths, spaces, `;`, `$`...); missing / directory / FIFO / unreadable evidence (exit 3); existing case never overwritten; dry run creates nothing and starts no program; **paths with spaces, quotes, `$`, Hebrew letters and a leading dash**; relative and symbolic-link paths; private permissions (`0700`/`0600`); analyst from option or environment |
| Core workflow (`test_workflow.py`) | 19 | Case layout; **SHA-256 and MD5 equal Python's `hashlib`**; `sha256sum` file format; integrity verified and recorded in the custody log; evidence bytes, time and mode unchanged after a run; only the case folder is written; missing tools are `SKIPPED` with an install hint, never run; file attributes; file type and magic bytes; indicators extracted (invalid IPs such as `999.1.1.1` rejected); UTF-16LE command recovered and decoded; strings size limit and minimum length; **empty evidence file**; `--copy-evidence` (verified, read-only, tools use the copy); module selection |
| External tools with **stubs** (`test_tools.py`) | 14 | Correct arguments for binwalk, foremost, bulk_extractor and Volatility; output and versions captured; a **failing** tool is `FAILED` (exit 4) and the others still run; a **hanging** tool is stopped by `--timeout` (built-in fallback path); `--timeout 0`; a tool that **modifies the evidence** is detected (exit 5); with `--copy-evidence` the original is untouched; Volatility per-plugin files and per-plugin failure report; `DFIR_VOLATILITY`; Volatility not part of `auto` |
| Report (`test_report.py`) | 8 | All sections present; skipped and unrequested modules stated plainly; hostile evidence text (fence markers, HTML, headings, backticks) and hostile analyst names cannot break the Markdown; **regression test for the UTF-8 locale bug** (below) |
| Repository (`test_static.py`) | 36 | Required files exist and are not empty; no `sudo`/package manager/`curl`/`eval` in the code; only one deleting command (a temporary file inside the case); no secrets or personal paths; demo evidence hash matches, ground-truth layout matches the file, **rebuilds byte-for-byte**, has no executable header or antivirus test string; **ShellCheck clean; shfmt clean** |

### GitHub Actions (2026-11-19)

Commit `054c4fc`, run: <https://github.com/OYDeadpoolife/dfir-forensics-toolkit/actions/runs/44528257133>. This was the first run on Linux.

| Runner | Bash | Python | Result |
|---|---|---|---|
| `ubuntu-latest` | 5.3.9 | 3.12.16 | **113 passed, 0 skipped.** The test of the system `timeout` code path, skipped on the author's Mac, ran and passed here |
| `macos-latest` | 3.2.57 | 3.12.10 | **112 passed, 1 skipped** (the same `timeout` test as locally) |

ShellCheck 0.11.0 ran on both. Only the built-in modules and the stub programs were exercised; the real `binwalk`, `foremost`, `bulk_extractor`
and Volatility were not installed on the runners (see NOT TESTED).

### Mutation check (does the suite really catch bugs?)

Four deliberate bugs were introduced one at a time into a copy of the project and the suite failed each time: the integrity comparison
forced to "equal" (caught by the tampering-tool test), the "case already exists" protection removed, the timeout limit multiplied by 100,
and the first hash no longer taken before the modules ran.

### Bugs found while building (nothing hidden)

* A manual first run showed a real bug: the module list was split with a global `IFS=,`, so every valid module name was reported as
  unknown. Fixed in `parse_module_list`.
* While writing the report tests, running under a UTF-8 locale showed that bash 3.2's `printf %q` corrupts Hebrew characters, which
  made the "Command line" cell of the report empty. The fix (quote under `LC_ALL=C`) and a regression test that runs three locales
  are included. This one matters on a machine like the author's, whose project path contains Hebrew.
* The rest of the early failures were wrong expectations in the tests themselves (an empty argument list that prints the usage text
  instead of the "no evidence" message; a comma-only module list, where the code now says "empty module name"; a Windows-path privacy
  marker that also matched the fictional `C:\Users\jdoe`). They were corrected in the tests, and no test was skipped or weakened to get a pass.

## FAIL — executed and failed

None in the last local run. **The first GitHub Actions run (2026-11-19, commit `f40fd9f`) failed on both runners with one failing test.**
`test_no_backup_or_cache_files` counted `.pyc` files that the test run itself writes under `__pycache__` (they are git-ignored and never published).
This had not shown up locally, where no bytecode was written. The test now ignores `__pycache__` and `.pytest_cache`. Fixed in commit `054c4fc`; both jobs have been green since.

## NOT TESTED — environment not available to the author when this was written

| Item | Why |
|---|---|
| The **real** `binwalk`, `foremost`, `bulk_extractor` | Not installed. Only stubs were used (see `docs/tool-integration.md`) |
| **Volatility 3** on a real memory image | Not installed; no memory image available |
| Linux on a real machine or VM (GNU `stat`, `date`, `file`, `strings`, `timeout`) | The suite passes on the Ubuntu GitHub Actions runner (see the CI section above); it was not run on a real Linux machine or VM |
| Very large evidence (gigabytes) | Only files up to a few MB were used; streaming and the strings limit are by design, not measured |
| Windows (native) | Not supported; use Linux, macOS or WSL |

## MANUAL VERIFICATION REQUIRED — to be done on your own Linux machine

Follow `docs/tool-integration.md` ("Manual verification on your own Linux machine"). In short:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
python3 -m pytest -q                                   # expect the same pass count; no skipped test where timeout exists
sudo apt install -y binwalk foremost bulk-extractor    # installs 3 packages on that VM; needs your approval
./bin/dfir-triage --list-modules                       # binwalk, foremost, bulk_extractor should be "available"
./bin/dfir-triage -e demo-case/evidence/ws01_triage_synthetic.bin -c CASE-LINUX-001
```

Record the real outcome here as PASS or FAIL, with the tool versions, and compare the results with the ground-truth table in
`docs/tool-integration.md`.
