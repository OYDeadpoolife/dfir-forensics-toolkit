# Glossary (plain language)

If you are new to forensics terms, this page explains the words used in this repository.

| Term | Meaning |
|---|---|
| Digital forensics / DFIR | Examining computers and storage after a security incident to find out what happened (Digital Forensics and Incident Response). |
| Evidence | The file under examination, here a disk or memory image. Investigators work on copies. |
| Disk image / memory image | A bit-for-bit copy of a disk, or of what was in a computer's memory at one moment. |
| Read-only | The tool only reads the evidence and never changes it. |
| Hash / SHA-256 | A digital fingerprint of a file. If even one byte changes, the fingerprint changes completely. |
| Integrity | The proof that the evidence did not change: the fingerprint taken before equals the fingerprint taken after. |
| Chain of custody | The written record of who handled the evidence, when, and what was done. The tool writes a custody log. |
| Case folder | The new folder the tool creates for one investigation. It holds hashes, logs, metadata, strings and the report. |
| Metadata | Facts about a file: its type, size and timestamps. |
| Strings / indicators | "Strings" are readable text found inside a binary file. "Indicators" are details worth following up, such as IP addresses, web addresses and e-mail addresses. |
| Module | One analysis step of the tool. A module whose program is not installed is recorded as `SKIPPED`. |
| binwalk, foremost, bulk_extractor | Optional third-party programs that look for embedded files, recover files and extract data such as addresses. They are not part of this repository and were tested here only with stand-in (stub) programs. |
| Volatility 3 | A well-known tool for analysing memory images. It is optional and its integration is not verified in this repository. |
| UTC | The universal time zone used for every timestamp, so times from different machines can be compared. |
| Synthetic data | Made-up data. The demo evidence file is synthetic. |
