# Usage

```text
dfir-triage --evidence FILE [options]
dfir-triage --list-modules
dfir-triage --help | --version
```

## Options

| Option | Meaning | Default |
|---|---|---|
| `-e, --evidence FILE` | The evidence file. It must be a regular, readable file (not a directory, device or pipe). It is only read. | required |
| `-o, --output-dir DIR` | Folder in which case folders are created | `./dfir-cases` |
| `-c, --case-id ID` | Case folder name: 1-64 characters `A-Z a-z 0-9 . _ -`, starting with a letter or digit. An existing folder is never overwritten. | `CASE-<UTC date-time>` |
| `-a, --analyst NAME` | Analyst name in the report (up to 80 characters) | environment variable `DFIR_ANALYST`, else "not specified" |
| `-m, --modules LIST` | Comma-separated: `metadata`, `strings`, `binwalk`, `foremost`, `bulk_extractor`, `volatility`, or `auto` | `auto` (everything except `volatility`) |
| `--timeout SECONDS` | Time limit for each external program; `0` = none | 1800 |
| `--strings-limit-mb N` | Scan at most the first N MB for strings | 256 |
| `--strings-min-length N` | Shortest ASCII string to keep | 6 |
| `--vol-plugins LIST` | Volatility 3 plugins, comma or space separated | `windows.info.Info windows.pslist.PsList windows.pstree.PsTree windows.cmdline.CmdLine windows.netscan.NetScan` |
| `--md5` | Also record an MD5 hash (legacy; the integrity check uses SHA-256) | off |
| `--copy-evidence` | Analyse a read-only copy stored in the case folder (verified against the original hash) | off |
| `--dry-run` | Validate, print the plan, create and write nothing | off |
| `--list-modules` | Show which modules can run here | |
| `-q, --quiet` / `--no-color` | Less output / no colours (`NO_COLOR` also works) | |

Environment variables: `DFIR_ANALYST` (default analyst name), `DFIR_VOLATILITY` (path or name of the Volatility 3
program if it is not called `vol`, `volatility3` or `vol.py`), `NO_COLOR`.

## Exit status

| Code | Meaning |
|---|---|
| 0 | Success. Skipped modules (program not installed) do not change this |
| 1 | The case could not be created or finished |
| 2 | Invalid options or case ID, or the case folder already exists |
| 3 | Evidence file missing, unreadable or not a regular file |
| 4 | The case finished, but at least one module is `FAILED` or `TIMEOUT` |
| 5 | **The evidence hash changed during the run.** Do not trust the results |

## Modules

| Module | Needs | What it does | Writes to |
|---|---|---|---|
| `metadata` | `file` | File type, MIME type, first 64 bytes in hex | `metadata/` |
| `strings` | `strings` | ASCII strings, approximate UTF-16LE strings, indicators (valid IPv4, URLs, e-mail addresses) | `strings/` |
| `binwalk` | `binwalk` | A signature scan (lists embedded file types and offsets; extracts nothing) | `binwalk/` |
| `foremost` | `foremost` | Carves files by signature into `foremost/carved/` | `foremost/` |
| `bulk_extractor` | `bulk_extractor` | Extracts features (e-mail, URLs, IPs, ...) into `bulk_extractor/features/` | `bulk_extractor/` |
| `volatility` | Volatility 3 | One output file per plugin | `volatility/` |

File times and hashes are always recorded; they are not optional modules.

## Case folder layout

```text
CASE-ID/
├── case_info.txt                 case ID, analyst, start time, evidence path, system, command line
├── hashes/
│   ├── evidence.sha256           "<hash>  <file name>" (works with sha256sum -c)
│   ├── evidence.after.sha256     the hash taken after all modules ran
│   └── evidence.md5              only with --md5
├── metadata/                     file_attributes.txt (times, owner), file type, MIME type, first bytes
├── strings/                      strings_ascii.txt, strings_utf16le_approx.txt, iocs.tsv
├── binwalk/ foremost/ bulk_extractor/ volatility/   only if the module ran
├── evidence/                     only with --copy-evidence: read-only working copy
├── logs/
│   ├── run.log                   timestamped log
│   ├── status.tsv                module, status, exit code, start, end, note
│   ├── commands.txt              the exact commands that were run
│   ├── tool_versions.tsv         program path and reported version
│   └── custody.tsv               chain-of-custody events (case opened, hashed, verified, report written)
└── report/case_report.md         the case report
```

Status values in `status.tsv`: **OK**, **FAILED** (the program returned an error), **TIMEOUT** (stopped by `--timeout`),
**SKIPPED** (the program is not installed; nothing was installed).

## Notes on specific options

* **`--copy-evidence`** needs as much free disk space as the evidence. The copy is made read-only (`0400`) and its hash is
  checked against the original before any tool uses it. The original is still hashed again at the end.
* **`--timeout`** stops the program the toolkit started. If that program started child processes, they may keep running.
* **`--strings-limit-mb`** exists because strings of a multi-gigabyte image can be larger than the disk you have. The report
  notes when a file was only partly scanned.
* **Indicators are leads.** The IPv4 pattern also matches version numbers such as `1.2.3.4`; octets above 255 are dropped.
