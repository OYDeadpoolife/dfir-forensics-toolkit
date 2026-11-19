# 07 — Findings

Confidence: **high** = directly shown in the evidence and consistent across sources; **medium** = shown, but depends on an
assumption; **low** = plausible, weakly supported.

## F0 — The evidence is intact
* **Observation:** SHA-256 before and after the analysis are identical (`1fc14ac2…8bc6`) and match the hand-over hash.
* **Confidence:** high.

## F1 — A hidden, encoded PowerShell command was recorded
* **Observation:** The artifact log shows Word → `cmd.exe` → `powershell.exe` at 11:30:14. A UTF-16LE command line at offset
  0x7600 contains `-NoProfile -WindowStyle Hidden -EncodedCommand`. The encoded part decodes to
  `Write-Output "synthetic training event - harmless"`.
* **Interpretation:** The pattern (Office application starting a shell that starts a hidden, encoded PowerShell) is typical of
  document-based initial access (MITRE ATT&CK T1204.002, T1059.001, T1027). Here the payload is harmless by design.
* **Confidence:** high for *what was run*; medium for *intent*.

## F2 — Files embedded in the evidence
* **Observation:** A PNG (0x2E00), a PDF (0x4400) and a ZIP (0x6200). The ZIP contains `notes.txt` and `harbor_update.js`, both plain
  text. The script's content is comments plus `var synthetic = true;`.
* **Interpretation:** `harbor_update.js` matches the file the log says was created in the user's Temp folder at 11:30:17 and then
  started by `wscript.exe` (T1059.007). The copy in the ZIP is harmless text.
* **Confidence:** medium. Carving by hand used ground-truth offsets; `binwalk` and `foremost` results are **not verified**.

## F3 — One external address recurs
* **Observation:** `203.0.113.45` appears in the activity log (connections), in `harbor_update.js` (as `http://203.0.113.45/stage2`)
  and in the strings. The e-mail address `billing@invoices-harbor.test` appears in `notes.txt`.
* **Interpretation:** `203.0.113.45` is the best indicator to block and to search for elsewhere (T1071.001 for the repeated HTTPS
  connections; T1105 for the staging URL). Whether the e-mail address is the delivery route is unknown.
* **Confidence:** high that the address is involved; low for any statement about its owner.

## F4 — Link to the SSH attack on `web01`
* **Observation:** The same address guessed SSH passwords against `web01` at 10:02 and logged in as `svc-backup` at 10:06 (project 02).
* **Interpretation:** The same infrastructure was used against both systems. This supports treating the two events as one incident.
* **Confidence:** medium. A shared address can also be a shared proxy.

## What was not found
No evidence of data being copied out, no persistence on WS01 and no second-stage payload — **but this file cannot show their
absence**: it is a small slice of data. See `08-limitations.md`.
