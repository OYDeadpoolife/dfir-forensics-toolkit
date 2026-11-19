# Design notes

## Origin

The project started from a small course script called "Windows Forensics" (2025). That script installed packages with
`sudo` on every start, refused to run without root, and asked for a file name. This toolkit keeps the *idea* (point a script at
a forensic sample and let it run the usual tools) and is otherwise a new design. No code was reused.

## What was deliberately designed differently

| Concern | Decision |
|---|---|
| Automatic installation | Never. A missing program is recorded as `SKIPPED` with an install hint that the user may run |
| Root / `sudo` | Never needed, never requested. A test fails if `sudo` appears in the code |
| Overwriting results | A case folder that exists is refused, so the hashes and logs of an earlier case can never be overwritten |
| Unsafe expansion | Every variable is quoted; paths are passed after `--`; the tests use file names with spaces, quotes, `$`, Hebrew letters and a leading dash |
| Input and output paths | The evidence must be a regular file; the case ID is restricted to a safe character set, so `../` tricks are impossible |
| Error handling | One `die` function with documented exit codes; a failing module never stops the others |
| Logging | `run.log` (timestamped), `status.tsv`, `commands.txt`, `custody.tsv` |
| Long-running tools | Time limit per program (`--timeout`) with a fallback for systems without `timeout` |
| Large evidence | Streaming hashing; `--strings-limit-mb`; no copy unless requested |
| Repeated code | One runner for external tools; one status function; one set of validators |
| Portability | Bash 3.2 compatible; `stat`, `date`, `md5` differences between GNU and BSD are handled in one place each |

## Interesting implementation details (good for interviews)

* **Timestamps before reading.** `capture_file_attributes` runs `stat` before the first hash, because reading can update the
  access time on some file systems.
* **Integrity as a first-class result.** A tool that modifies the evidence is detected by the second hash. The test suite
  contains a stub "tool" that appends a byte to the evidence and checks for exit status 5.
* **UTF-16LE strings.** Windows stores much text as UTF-16LE. Deleting the zero bytes and running `strings` recovers it without
  GNU-only options. It is an approximation (neighbouring strings can be merged) and is labelled as such.
* **Timeout without `timeout`.** macOS has no `timeout`. When neither `timeout` nor `gtimeout` exists, a polling loop
  checks the process five times per second and stops it after the limit. Both paths are tested where the system allows.
* **A real bug found by testing.** In bash 3.2, `printf %q` corrupts multi-byte characters (Hebrew) in a UTF-8 locale, which
  made the report's command-line cell empty. The fix runs the quoting under `LC_ALL=C`; a regression test runs the tool in
  three locales.
* **Hostile content.** Strings from the evidence are placed only in fenced code blocks (with a fence the content cannot
  close) or escaped table cells. A test feeds fence markers, HTML and Markdown headings through the report.

## What is intentionally missing

File-system parsing, registry and event-log parsing, timelines and E01 support are out of scope for a triage tool; see the
future improvements in the README.
