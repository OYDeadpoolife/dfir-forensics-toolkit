# Demo case: "Harbor Lab" workstation WS01 (fictional)

This folder contains one complete, **fictional** investigation, built to show how `dfir-triage` and a human analyst work
together. Everything here is invented: the organisation, the people, the addresses (reserved documentation ranges such as
`203.0.113.0/24`) and the evidence. **Nothing here is a real incident or real forensic evidence, and the evidence contains no malware.**

## What is in this folder

| Path | What it is | Verified? |
|---|---|---|
| `evidence/ws01_triage_synthetic.bin` | Synthetic evidence: a 34 KB blob imitating a slice of a disk, with a PNG, a PDF, a ZIP, a text log and a UTF-16LE command line | Built by `tools/build_synthetic_evidence.py`; rebuilt byte-for-byte by a test |
| `evidence/ws01_triage_synthetic.bin.sha256` | Its SHA-256, `sha256sum -c` compatible | Yes |
| `evidence/evidence_layout.json` | **Ground truth**: what is stored at which offset | Checked by a test against the file |
| `tools/build_synthetic_evidence.py` | Rebuilds the evidence deterministically | Yes |
| `example-run/CASE-DEMO-001/` | The real output of `dfir-triage` on this evidence, run on macOS on 2026-10-03 | **Real run.** `binwalk`, `foremost` and `bulk_extractor` were not installed, so those modules are `SKIPPED` |
| `case-file/` | The analyst's documents (below) | Written by hand for this exercise |

## The case file (read in this order)

1. [01-case-summary.md](case-file/01-case-summary.md)
2. [02-evidence-inventory.md](case-file/02-evidence-inventory.md)
3. [03-investigation-questions.md](case-file/03-investigation-questions.md)
4. [04-commands-and-expected-output.md](case-file/04-commands-and-expected-output.md)
5. [05-analyst-notes.md](case-file/05-analyst-notes.md)
6. [06-timeline.md](case-file/06-timeline.md)
7. [07-findings.md](case-file/07-findings.md)
8. [08-limitations.md](case-file/08-limitations.md)
9. [INCIDENT-REPORT.md](case-file/INCIDENT-REPORT.md) — the final report

## Try it yourself

```bash
./bin/dfir-triage --evidence demo-case/evidence/ws01_triage_synthetic.bin --case-id CASE-DEMO-001
sha256sum -c demo-case/evidence/ws01_triage_synthetic.bin.sha256      # run from inside demo-case/evidence/
```

## How to read the "verified" labels

* **EXECUTED** — the command was run when this was written and the output shown is real.
* **NOT VERIFIED** — the command could not be run (the program was not installed). The expected result is derived from the
  ground truth in `evidence_layout.json` and must be confirmed on your own machine.

## Link to the other projects

The same fictional incident appears in the SOC detection lab (Sysmon events for WS01), the firewall lab (traffic to
`203.0.113.45`) and the log-analysis toolkit (the SSH attack on `web01`). The timeline here shows how they fit together.
The data in each repository is a separate, small copy, so every repository works on its own.
