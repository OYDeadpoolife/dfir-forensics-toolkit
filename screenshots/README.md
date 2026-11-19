# Screenshot guide

These files do not exist yet. Take real screenshots on your own machine after running the commands below, save them in this
folder with exactly these names, and remove the comment markers around the matching lines in the main `README.md`.
A screenshot must show a real run; do not edit or fabricate results.

| File | Open | Run | What must be visible |
|---|---|---|---|
| `01-triage-run.png` | A terminal in the repository folder, wide enough for 100 columns | `./bin/dfir-triage --evidence demo-case/evidence/ws01_triage_synthetic.bin --case-id CASE-SHOT-001` | The final summary: SHA-256, `Integrity: VERIFIED - evidence unchanged`, the module list with `OK` and `SKIPPED` |
| `02-case-report.png` | The generated `dfir-cases/CASE-SHOT-001/report/case_report.md` in a Markdown viewer | open the file | Section 2 (evidence table with before/after hashes and the integrity line) and section 3 (execution summary) |
| `03-case-folder.png` | A terminal | `find dfir-cases/CASE-SHOT-001 -type f \| sort` | The case folder layout: `hashes/`, `logs/`, `metadata/`, `strings/`, `report/` |
| `04-test-results.png` | A terminal with the virtual environment active | `python3 -m pytest -q` | The last line with the number of passed tests and no failures |
| `05-linux-tools.png` (optional, only after the manual check in `docs/tool-integration.md`) | A Linux VM terminal | `./bin/dfir-triage --list-modules` and then a run with the tools installed | `binwalk`, `foremost`, `bulk_extractor` shown as `available` / `OK`. **Only take this if it is true on your machine.** |

Embed in `README.md` with: `![dfir-triage run](screenshots/01-triage-run.png)`

Before uploading, check each image for personal information (your user name in the prompt or path, real host names).
Crop or blur anything that is not part of the demo.
