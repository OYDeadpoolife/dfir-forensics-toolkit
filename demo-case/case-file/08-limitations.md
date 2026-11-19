# 08 — Limitations

1. **Synthetic evidence.** The file was generated for training. It is not a real disk or memory image and contains a text "artifact
   log" that a real system would not store in this form. Conclusions here demonstrate method, not real-world findings.
2. **Partial toolset.** `binwalk`, `foremost` and `bulk_extractor` were not installed, so signature scanning and carving were done by hand
   with known offsets. Volatility was not run (there is no memory image). Those integrations are **not verified**.
3. **Small slice.** Even in a real case, a triage file shows only part of a system. Absence of evidence here is not evidence of absence.
4. **Strings are leads.** Indicator extraction is pattern matching. An address in a file does not prove a connection was made, and a
   version number can look like an IP address.
5. **UTF-16LE text is approximate.** Removing zero bytes can merge neighbouring strings.
6. **No attribution.** Nothing here identifies a person or group. An IP address is not an identity.
7. **Time.** All times are UTC as written in the artifact log; clock accuracy of the source system is unknown.
8. **Correlation with other projects** relies on the shared fictional scenario; those data are not part of E1.
9. **Method.** Nothing in the file was executed. Behaviour of the script is inferred from its text, not observed.
