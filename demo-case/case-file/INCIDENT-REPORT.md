# Incident report — Harbor Lab, workstation WS01

> **Fictional training document.** Organisation, people, systems and addresses are invented; the evidence is synthetic and harmless.
> It shows the structure of a final report, not a real investigation.

| Field | Value |
|---|---|
| Case ID | CASE-DEMO-001 |
| Prepared by | *<analyst name>* (training exercise) |
| Report status | Draft for review |
| Incident date (fictional) | 2026-03-14 |
| Classification | Internal (fictional) |

## 1. Executive summary

On 2026-03-14 a user on workstation WS01 opened a Word document, `Invoice_March.docm`. The document started a hidden PowerShell command
that contacted the external address `203.0.113.45` and created a script in the user's Temp folder. The host then contacted the same address
about once a minute. The same address had guessed SSH passwords against the server `web01` earlier that morning and gained access to
a service account. We assess with **medium confidence** that both events belong to one incident. The examined evidence is intact.

In this exercise the commands and scripts are harmless text, so there was no real impact.

## 2. Scope and method

One triage file (E1, SHA-256 `1fc14ac27d961449d3ca45ae9e9100e0ba930a9547f899e4987a54a79c708bc6`) was examined read-only with `dfir-triage`
1.0.0 (metadata, strings, indicator extraction) and manual carving. The file's hash was identical before and after (chain-of-custody log
in the case folder). Nothing in the file was executed.

## 3. Findings

| ID | Finding | Confidence |
|---|---|---|
| F0 | The evidence is intact | high |
| F1 | A hidden, encoded PowerShell command was run from Word (decoded: a harmless message) | high / medium for intent |
| F2 | A script `harbor_update.js` was created and started; a copy with the staging URL is embedded in the evidence | medium |
| F3 | The external address `203.0.113.45` recurs in the log, the script and the strings | high (involvement), low (ownership) |
| F4 | The same address attacked `web01` over SSH earlier that day | medium |

Details and evidence references: `case-file/07-findings.md`. Timeline: `case-file/06-timeline.md`.

## 4. Indicators of compromise

| Type | Value | Context |
|---|---|---|
| IPv4 | `203.0.113.45` | Contacted on 443 about every 60 s; also the source of the SSH attack |
| URL | `http://203.0.113.45/stage2` | Staging URL in `harbor_update.js` |
| File | `C:\Users\jdoe\AppData\Local\Temp\harbor_update.js` | Script created at 11:30:17 |
| File | `Invoice_March.docm` | Document that started the chain |
| E-mail | `billing@invoices-harbor.test` | Appears in `notes.txt`; role unknown |
| Account | `support01` | Created on `web01` at 10:11:20 (see project 02) |

## 5. Impact assessment (fictional)

Possible impact if this were real: access to a service account and an administrator account on `web01`; a new privileged account
(`support01`); a workstation with an active outbound channel. Nothing in the evidence shows data theft; the evidence is too small to rule it out.

## 6. Recommendations

**Immediate**
1. Isolate WS01 from the network; keep it powered on if volatile memory may be needed.
2. Block `203.0.113.45` at the firewall and search proxy and DNS logs for it.
3. Disable and review `support01` on `web01`; reset the passwords of `svc-backup`, `labadmin` and `jdoe`.
4. Take a full forensic image and a memory image of WS01 before cleaning it.

**Short term**
5. Disable password authentication for SSH on `web01`; remove the `svc-backup` password login; use keys.
6. Block Office applications from starting child processes where possible; restrict encoded PowerShell with logging.

**Detection**
7. Alert on Office → `cmd.exe`/`powershell.exe` with `-EncodedCommand` and on regular outbound beacons (see the SOC lab project).

## 7. Limitations

See `case-file/08-limitations.md`. In short: synthetic evidence, partial toolset, a small data slice, indicators are leads, no attribution.

## 8. Appendices

* Appendix A — Case folder: `example-run/CASE-DEMO-001/` (hashes, logs, status, custody, report)
* Appendix B — Commands and outputs: `case-file/04-commands-and-expected-output.md`
* Appendix C — Tool versions: `logs/tool_versions.tsv` (empty: no external program was available in the run)
