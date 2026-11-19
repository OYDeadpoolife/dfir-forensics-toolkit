# Forensics workflow

This document explains where `dfir-triage` fits in a digital-forensics investigation and which good practices it
automates. It is a learning aid for a junior analyst, not legal advice or a replacement for your organisation's procedures.

## The stages of an investigation

| Stage | What a person does | What `dfir-triage` contributes |
|---|---|---|
| 1. Authorisation and scoping | Confirm you are allowed to examine this evidence; define the questions | Nothing: this is your responsibility. The tool only accepts a file you give it |
| 2. Preservation | Acquire the evidence without changing the source; record who, when, how | Records a chain-of-custody log (`logs/custody.tsv`) and optionally makes a verified read-only working copy |
| 3. Integrity | Hash the evidence so any later change is detectable | SHA-256 **before** and **after** every run; a mismatch makes the run exit with status 5 |
| 4. Examination | Identify and extract what is in the evidence | File type, magic bytes, strings, indicators; optional `binwalk`, `foremost`, `bulk_extractor`; optional Volatility 3 |
| 5. Analysis | Interpret the results; answer the questions; build a timeline | Not automated. The report states facts only; you write the conclusions (`templates/analyst-report-template.md`) |
| 6. Reporting | Explain what was done, found and not found | `case_report.md`: what ran, with which versions, results, and a list of what the report cannot tell you |

## Principles built into the tool

1. **Read-only.** The evidence is opened for reading only. Every tool writes into the case folder, never next to the evidence.
2. **Hash first, hash last.** The first hash is taken before any module starts; the second after the last one. Evidence that
   changed is flagged loudly and the exit status is 5.
3. **Timestamps before content.** Reading a file can update its access time on some systems, so the file's times are
   recorded with `stat` *before* anything reads the content.
4. **Everything in UTC.** Every timestamp the tool writes is UTC (`...Z`), so notes from different time zones can be combined.
5. **Record the exact commands and versions.** `logs/commands.txt` and `logs/tool_versions.tsv` let a colleague repeat the work.
6. **Never overwrite a case.** A case folder that already exists is refused.
7. **Fail visibly, not silently.** A missing program is `SKIPPED` with an install hint (never installed automatically);
   a tool that fails or runs too long is `FAILED` or `TIMEOUT` and the other modules still run.
8. **Separate facts from conclusions.** The generated report contains no conclusions.
9. **Least privilege.** No root, no `sudo`. If you need privileges to *acquire* evidence, do that with proper tools, outside this one.
10. **Treat evidence content as hostile.** Text from the evidence is only placed in fenced code blocks or escaped table cells.

## Working with the tool, step by step

1. Hash the source yourself if you can, and keep your own notes (who gave you the evidence, when, from which system).
2. `dfir-triage --evidence FILE --dry-run` to see the plan and which modules can run.
3. Run it for real with a case ID that follows your organisation's naming (`CASE-2026-014`).
4. Read `report/case_report.md`: check the **Integrity check** line first, then the execution summary (any `FAILED`,
   `TIMEOUT` or `SKIPPED` modules?), then the module output.
5. Follow up the leads by hand: carve with the offsets from `binwalk`, decode what you found, look for the same
   indicators in the SIEM and the firewall logs.
6. Write your analyst report from the template. Keep the case folder (it is your working record).

## Where this fits with the other projects

```text
03 pfSense lab   -> firewall logs show WS01 talking to 203.0.113.45
01 SOC lab       -> Sysmon shows Word starting PowerShell; the same IP in the Linux SSH logs
02 seclog        -> the SSH brute force and the account chain on web01, from auth.log
04 dfir-triage   -> examine evidence taken from WS01: what exactly was run, what was dropped, what was contacted
```

The demo case in `demo-case/` follows that story with synthetic evidence.

## Good practice this tool does not replace

* Use a hardware or software **write blocker** when acquiring from a physical disk.
* Acquire memory with a recognised tool, and document the acquisition.
* Do not run suspected malware on a machine that is connected to anything that matters. This tool never executes the evidence.
* Follow legal and organisational requirements for evidence handling.
