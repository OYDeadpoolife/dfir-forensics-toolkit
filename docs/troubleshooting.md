# Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `evidence file does not exist` / `is not a regular file` (exit 3) | Wrong path, or a directory, device or pipe was given | Pass the path of a single regular file. To examine a disk, first create an image file with an acquisition tool |
| `evidence file is not readable` (exit 3) | Permissions | Read access is required. Use an account that may read it; do not change the evidence's permissions |
| `invalid --case-id` (exit 2) | Characters outside `A-Z a-z 0-9 . _ -`, or longer than 64 | Use something like `CASE-2026-014` |
| `case directory already exists` (exit 2) | A case with that ID already exists | Choose a new ID. Cases are never overwritten |
| Module shows `SKIPPED` | The program is not installed | See the install hint in `status.tsv` or the report; install it yourself if you want the module |
| Module shows `FAILED` | The program returned an error | Read `<module>/<module>.stderr.txt` and `logs/commands.txt`; run the command by hand |
| Module shows `TIMEOUT` | The time limit was reached | Increase `--timeout`, or analyse a smaller part |
| Exit status 5, "evidence changed" | Something modified the evidence during the run | Discard the results; check the file's origin; restore from a trusted copy; use `--copy-evidence` |
| Exit status 4 | At least one module failed or timed out | Look at the execution summary in the report |
| Strings output is empty | The file has no printable strings, or `--strings-min-length` is too high | Lower the minimum; check `file_type.txt` |
| `strings: only the first N MB were scanned` | The file is larger than `--strings-limit-mb` | Raise the limit if you have the disk space |
| Hebrew or other non-ASCII characters show as `?` in the strings output | Text taken from the evidence is reduced to printable ASCII for safety | Use the raw file if you need the exact bytes |
| Volatility plugins fail on a small file | The file is not a memory image | Use `--modules metadata,strings` for it |
| Volatility cannot download symbols | No internet access from that machine | Allow access to the symbol server or provide symbol tables manually (see the Volatility 3 documentation) |
| `Permission denied` when running `./bin/dfir-triage` | The file lost its executable bit (this happens when files are uploaded through GitHub's web page) | `chmod +x bin/dfir-triage`, or run `bash bin/dfir-triage ...` |
| `no SHA-256 tool found` | Neither `sha256sum`, `shasum` nor `openssl` is installed | Install one of them (they are part of every default Linux and macOS system) |

## Looking inside a case

```bash
column -t -s $'\t' dfir-cases/CASE-ID/logs/status.tsv      # module results
cat dfir-cases/CASE-ID/logs/commands.txt                   # exact commands that were run
cat dfir-cases/CASE-ID/logs/custody.tsv                    # chain-of-custody events
(cd evidence-folder && sha256sum -c /path/to/dfir-cases/CASE-ID/hashes/evidence.sha256)   # re-verify the evidence yourself
```
