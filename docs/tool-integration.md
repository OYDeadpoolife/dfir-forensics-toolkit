# Tool integration: what is verified and what is not

`dfir-triage` calls other programs. This page states honestly, for each one, how it is called and how far that has been
verified. **Nothing is marked verified unless it was actually executed.**

| Component | Call made by the toolkit | Verified here? |
|---|---|---|
| `file`, `strings`, `od`, `stat`, `sha256sum`/`shasum`, `grep`, `awk` | Built-in modules | **Yes**, executed on macOS 15 (BSD tools). The GNU/Linux variants are exercised by the CI workflow, which has **not run yet** |
| `binwalk` | `binwalk EVIDENCE` | **No.** Tested only with a stub program (arguments, output capture, failure and timeout handling) |
| `foremost` | `foremost -i EVIDENCE -o CASE/foremost/carved` | **No.** Stub only |
| `bulk_extractor` | `bulk_extractor -o CASE/bulk_extractor/features EVIDENCE` | **No.** Stub only |
| Volatility 3 | `vol -q -f EVIDENCE <plugin>` for each plugin | **No.** Stub only. No memory image was available |

A stub proves that the toolkit starts the program with these arguments, keeps its output, and records success, failure or
timeout. It does **not** prove that the real program accepts these arguments or produces useful output with your version.

## Manual verification on your own Linux machine

Use a Linux virtual machine (for example Ubuntu or Kali in UTM or VMware). Installing packages needs administrator rights
and changes that machine, so do it deliberately and only on a lab VM.

```bash
sudo apt update
sudo apt install -y binwalk foremost bulk-extractor file binutils    # installs 5 packages (needs your approval)
git clone https://github.com/OYDeadpoolife/dfir-forensics-toolkit.git && cd dfir-forensics-toolkit
./bin/dfir-triage --list-modules                                    # all three should say "available"
./bin/dfir-triage -e demo-case/evidence/ws01_triage_synthetic.bin -c CASE-LINUX-001 -a "Your Name"
cat dfir-cases/CASE-LINUX-001/binwalk/binwalk.stdout.txt
ls -R dfir-cases/CASE-LINUX-001/foremost/carved | head -30
ls dfir-cases/CASE-LINUX-001/bulk_extractor/features | head
```

### What you should see (ground truth)

The synthetic evidence was built from a known layout (`demo-case/evidence/evidence_layout.json`), so you can check each tool:

| Offset (decimal / hex) | Object | binwalk should list | foremost should carve |
|---|---|---|---|
| 11776 / 0x2E00 | PNG image (70 bytes) | a PNG image at 11776 | one `.png` |
| 17408 / 0x4400 | PDF document (474 bytes) | a PDF document at 17408 | one `.pdf` |
| 25088 / 0x6200 | ZIP archive (574 bytes) | a Zip archive at 25088 (entries `notes.txt`, `harbor_update.js`) | one `.zip` |

`bulk_extractor` should report the address `203.0.113.45`, the URL `http://203.0.113.45/stage2` and the e-mail address
`billing@invoices-harbor.test` in its feature files. The exact wording and extra detections depend on the tool version, and
random filler bytes may produce a few spurious signature hits: compare against the table, then note the real result in
`TEST_RESULTS.md` as **PASS** or **FAIL** with the tool version.

## Volatility 3 notes

* Volatility **3** only. The older Volatility 2 uses different commands (`--profile`) and is not supported.
* Install into a virtual environment, for example `python3 -m venv ~/vol3 && ~/vol3/bin/pip install volatility3`, then
  either put `~/vol3/bin` on `PATH` (the program is called `vol`) or set `DFIR_VOLATILITY=~/vol3/bin/vol`.
* Windows images need symbol tables, which Volatility downloads from Microsoft the first time. That needs internet access
  and can take minutes.
* A memory image is required. The demo evidence is **not** a memory image; use `--modules metadata,strings` for it.
  Public sample images exist, but check their licence and size before using or committing one. Never commit memory images.
* The default plugins are `windows.info.Info`, `windows.pslist.PsList`, `windows.pstree.PsTree`, `windows.cmdline.CmdLine`
  and `windows.netscan.NetScan`; change them with `--vol-plugins`. A plugin that fails is reported by name; the others still run.

## When a tool misbehaves

| Symptom | What happens | What to do |
|---|---|---|
| Program not installed | `SKIPPED` with an install hint | Install it yourself if you want that module |
| Program exits with an error | `FAILED`, exit code and the program's stderr are kept in `<module>/<module>.stderr.txt` | Read that file; fix the cause; run a new case |
| Program runs too long | `TIMEOUT` after `--timeout` seconds | Raise `--timeout`, or analyse a smaller piece of the evidence |
| Program changes the evidence (should never happen) | Integrity check fails, exit status 5 | Discard the results, restore the evidence from a trusted copy, report the tool bug |
