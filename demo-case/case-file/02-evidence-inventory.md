# 02 — Evidence inventory

| Item | Description | Source | SHA-256 | Size |
|---|---|---|---|---|
| E1 | `ws01_triage_synthetic.bin` — synthetic triage file imitating a slice of data from WS01 | Fictional workstation WS01, handed over at 11:40 UTC on 2026-03-14 | `1fc14ac27d961449d3ca45ae9e9100e0ba930a9547f899e4987a54a79c708bc6` | 34,304 bytes |

Verification (**EXECUTED**): `sha256sum -c ws01_triage_synthetic.bin.sha256` prints `ws01_triage_synthetic.bin: OK`, and
`dfir-triage` recorded the same hash before and after its run (`hashes/evidence.sha256`, `hashes/evidence.after.sha256`).

## What is inside E1 (ground truth)

This list comes from the generator, `evidence_layout.json`. A real analyst would not have it; here it lets us check the
tools' results.

| Offset (decimal / hex) | Length | Object |
|---|---|---|
| 0 / 0x0 | 20 | Header text `HARBOR-SYNTH-001` |
| 4608 / 0x1200 | 753 | Text: "synthetic artifact log" with UTC timestamps |
| 11776 / 0x2E00 | 70 | PNG image (1x1 pixel) |
| 17408 / 0x4400 | 474 | PDF document |
| 25088 / 0x6200 | 574 | ZIP archive containing `notes.txt` and `harbor_update.js` |
| 30208 / 0x7600 | 396 | UTF-16LE text: a PowerShell command line |
| 33792 / 0x8400 | 26 | Footer text |
| everything between | | Pseudo-random filler bytes (deterministic) |

The file contains no program code and no antivirus test string. A test checks that it does not start with an executable header.

## Chain of custody (fictional, plus the real tool log)

| Time (UTC) | Event | Source |
|---|---|---|
| 2026-03-14 11:40 | Triage file handed to the analyst (fictional) | Case notes |
| 2026-10-03 13:45:53 | Case opened and evidence hashed (real run) | `logs/custody.tsv` |
| 2026-10-03 13:45:53 | Integrity verified | `logs/custody.tsv` |
| 2026-10-03 13:45:54 | Report written | `logs/custody.tsv` |

The two different dates are intentional: the incident is fictional and dated March 2026; the tool was really run in October 2026.
