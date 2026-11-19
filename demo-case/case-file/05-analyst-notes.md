# 05 — Analyst notes (working notes, in the order thoughts occurred)

> Fictional exercise. These notes show *how* an analyst thinks: observation first, interpretation second, doubts written down.

**Start.** Before opening anything I checked what I had been given: one file, 34,304 bytes, and a hash from the hand-over.
Ran `dfir-triage` with `--dry-run` first to see which modules could run here: only `metadata` and `strings`. The carving tools are
not installed on this machine. I decided not to install anything on a machine I do not control for this task and to record the
gap instead; the report says so under "SKIPPED".

**Integrity.** SHA-256 before and after the run are identical and match the hash from the hand-over. The evidence was not changed by
my work. (If the two hashes had differed, I would have stopped and discarded the results.)

**File type.** `file` says only `data`: there is no recognisable header at the start. The first 16 bytes are the ASCII text
`HARBOR-SYNTH-001` followed by zero bytes. That is a label, not a known format. So I cannot say what produced this file; the content
must be examined by looking inside.

**Strings.** The ASCII strings contain a readable activity log with UTC timestamps, a few paths under `C:\Users\jdoe\...` and an
address, `203.0.113.45`. The indicator list shows one external address, one internal address (`10.10.10.20`, presumably WS01), one
URL (`http://203.0.113.45/stage2`) and one e-mail address (`billing@invoices-harbor.test`).
*Doubt:* the counts are doubled by my own two passes (ASCII and UTF-16 approximation), so "6 occurrences" really means 3 places.

**UTF-16.** In the approximate UTF-16LE strings there is a PowerShell command line with `-NoProfile -WindowStyle Hidden
-EncodedCommand ...`. Hidden window plus an encoded command is a common way to hide what is run; it is not proof of malice
(administration tools also do this). Decoded as text it is `Write-Output "synthetic training event - harmless"`. I did not run it.

**Embedded files.** Without carving tools I located the objects using the offsets from the generator's ground truth file (a real
analyst would use `binwalk`/`foremost`; **NOT VERIFIED** here). `dd` plus `file` confirm a PNG, a PDF and a ZIP. Listing the ZIP shows
`notes.txt` and `harbor_update.js`; reading them (no execution) shows that both are harmless text. The script contains the URL
`http://203.0.113.45/stage2` in a comment, the same address as in the activity log.

**Correlation.** The activity log says WS01 connected to `203.0.113.45:443` right after PowerShell started and then about once per
minute. In the other projects of this exercise, the same address (a) guessed SSH passwords against `web01` at 10:02, (b) appears in
WS01's Sysmon network events, and (c) appears as an allowed outbound connection in the firewall log. Three independent sources
for the same address make it a strong lead. It does not tell us who is behind it.

**Open questions.** Where did `Invoice_March.docm` come from (e-mail? download?). Did anything leave WS01 besides the connections
(no evidence either way in this file)? Did the script run to completion? These cannot be answered from E1 alone.
