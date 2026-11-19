# 01 — Case summary

> **Fictional training case.** All names, systems and addresses are invented. The evidence is synthetic and harmless.

| Field | Value |
|---|---|
| Case ID | CASE-DEMO-001 |
| Organisation (fictional) | Harbor Lab |
| Analyst | *<your name>* (training exercise) |
| Incident date (fictional) | 2026-03-14 |
| Triage run documented here | 2026-10-03, macOS, `dfir-triage` 1.0.0 (a real run on the synthetic evidence) |
| System of interest | Workstation `WS01` (`10.10.10.20`), user `HARBOR\jdoe` |
| Evidence | One triage file taken from WS01: `ws01_triage_synthetic.bin` |

## How the case started (fictional)

At about 11:40 UTC on 2026-03-14 the SOC saw a Sysmon alert on WS01: Microsoft Word had started `cmd.exe`, which started
PowerShell with an encoded command, and the machine then connected repeatedly to the external address `203.0.113.45`. The
same address had been guessing SSH passwords against the server `web01` earlier that morning. The SOC asked for a
forensic look at what remained on WS01.

A triage file was taken from WS01 and handed to the analyst.

## Scope and authorisation (fictional)

* Examine the triage file only. Do not execute anything found in it.
* Questions to answer: what ran, what was dropped, what was contacted, and is the evidence intact? (See file 03.)
* Out of scope: attributing the activity to a person or group, and any action on live systems.

## Outcome in one paragraph

The evidence is intact (SHA-256 identical before and after). It shows that a downloaded Word document led to a hidden,
encoded PowerShell command, that a script named `harbor_update.js` was written to the user's Temp folder, and that the host
contacted `203.0.113.45` on port 443 about once a minute. The encoded command decodes to a harmless message in this
exercise. The full reasoning, confidence levels and limits are in files 05 to 08 and in `INCIDENT-REPORT.md`.
