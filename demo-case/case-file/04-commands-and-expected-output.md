# 04 — Commands and expected output

Each step shows the command, the output and its status. **EXECUTED** means the command was run when this was written and the output
is real (macOS 15, `dfir-triage` 1.0.0). **NOT VERIFIED** means the program was not available; the expectation comes from the
ground truth and must be confirmed. Commands start in the repository root unless stated.

## 1. See what can run (EXECUTED)

```bash
./bin/dfir-triage --list-modules
```

```text
metadata        available  (/usr/bin/file)
strings         available  (/usr/bin/strings)
binwalk         MISSING    (needs: binwalk)
foremost        MISSING    (needs: foremost)
bulk_extractor  MISSING    (needs: bulk_extractor)
volatility      MISSING    (needs: vol / volatility3 / vol.py)
```

## 2. Dry run: nothing is created (EXECUTED)

```bash
./bin/dfir-triage --evidence evidence/ws01_triage_synthetic.bin --output-dir cases --case-id CASE-DEMO-001 \
    --analyst "Training exercise" --dry-run
```

```text
dfir-triage: dry run - nothing is created or written, the evidence is not read.
  Case ID      : CASE-DEMO-001
  Case folder  : cases/CASE-DEMO-001 (would be created)
  Evidence     : /private/tmp/dfir-demo/evidence/ws01_triage_synthetic.bin (34304 bytes; only read, never modified)
  ...
```

## 3. The real run (EXECUTED)

```bash
./bin/dfir-triage --evidence evidence/ws01_triage_synthetic.bin --output-dir cases --case-id CASE-DEMO-001 \
    --analyst "Training exercise"
```

Result: exit status 0, integrity `VERIFIED - evidence unchanged`, `metadata` and `strings` `OK`, `binwalk`, `foremost` and
`bulk_extractor` `SKIPPED` (programs not installed). The complete folder is in `example-run/CASE-DEMO-001/`.

## 4. Verify the hash yourself (EXECUTED)

```bash
cd evidence && sha256sum -c ws01_triage_synthetic.bin.sha256
```

```text
ws01_triage_synthetic.bin: OK
```

## 5. Indicators found in strings (EXECUTED)

```bash
cat cases/CASE-DEMO-001/strings/iocs.tsv
```

```text
count	type	value
6	ipv4	203.0.113.45
4	ipv4	10.10.10.20
2	url	http://203.0.113.45/stage2
2	email	billing@invoices-harbor.test
```

The counts are doubled because the ASCII pass and the approximate UTF-16LE pass both see the same text.

## 6. Decode the PowerShell command (EXECUTED)

The UTF-16LE strings file contains the command line as Windows stores it:

```bash
grep -a -o -- '-EncodedCommand [A-Za-z0-9+/=]*' cases/CASE-DEMO-001/strings/strings_utf16le_approx.txt | head -1
```

```text
-EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHMAeQBuAHQAaABlAHQAaQBjACAAdAByAGEAaQBuAGkAbgBnACAAZQB2AGUAbgB0ACAALQAgAGgAYQByAG0AbABlAHMAcwAiAA==
```

PowerShell's `-EncodedCommand` is base64 of UTF-16LE text. Decode it **as text only; never run it**:

```bash
echo VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAHMAeQBuAHQAaABlAHQAaQBjACAAdAByAGEAaQBuAGkAbgBnACAAZQB2AGUAbgB0ACAALQAgAGgAYQByAG0AbABlAHMAcwAiAA== \
    | base64 -d | iconv -f UTF-16LE -t UTF-8
```

```text
Write-Output "synthetic training event - harmless"
```

(`base64 -d` and `iconv` were **EXECUTED** on macOS. On a Windows machine the equivalent PowerShell is
`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<base64>"))` — **NOT VERIFIED** here.)

## 7. Carve the embedded files by hand (EXECUTED)

The offsets come from `evidence_layout.json` (in a real case they would come from `binwalk` or `foremost`).

```bash
dd if=evidence/ws01_triage_synthetic.bin of=carved.png bs=1 skip=11776 count=70 2>/dev/null
file carved.png
dd if=evidence/ws01_triage_synthetic.bin of=carved.zip bs=1 skip=25088 count=574 2>/dev/null
file carved.zip
unzip -l carved.zip
unzip -p carved.zip harbor_update.js
```

```text
carved.png: PNG image data, 1 x 1, 8-bit/color RGBA, non-interlaced
carved.zip: Zip archive data, at least v2.0 to extract, compression method=store
Archive:  carved.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      111  03-14-2026 11:30   notes.txt
      239  03-14-2026 11:30   harbor_update.js
---------                     -------
      350                     2 files
// SYNTHETIC SAMPLE - harmless text, not a real script.
// It exists only so that a file-carving tool has something to find.
// Fictional staging address used in the Harbor Lab scenario:
// http://203.0.113.45/stage2
var synthetic = true;
```

`unzip -p` only prints the file to the terminal; nothing is executed.

## 8. Automated carving and signature scan (NOT VERIFIED)

```bash
./bin/dfir-triage --evidence evidence/ws01_triage_synthetic.bin --case-id CASE-DEMO-002 --modules binwalk,foremost,bulk_extractor
```

Expected (from the ground truth): `binwalk` lists a PNG at 11776, a PDF at 17408 and a Zip archive at 25088; `foremost` carves one
`.png`, one `.pdf` and one `.zip`; `bulk_extractor` reports `203.0.113.45`, the URL and the e-mail address. Random filler may
cause a few extra weak hits. **Confirm on a Linux machine with the tools installed** (see `docs/tool-integration.md`) and
record the real output.

## 9. Memory analysis (NOT VERIFIED, not applicable to this evidence)

```bash
./bin/dfir-triage --evidence memory.raw --case-id CASE-MEM-001 --modules metadata,strings,volatility
```

The demo evidence is not a memory image, so Volatility is not run on it. See `docs/tool-integration.md` for what is needed.
