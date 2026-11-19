# Analyst report — <CASE ID>

> Complete this by hand after reading the generated `report/case_report.md`. Delete the guidance in italics.
> Facts and conclusions must stay separate: say what you observed, then what you think it means and how sure you are.

| Field | Value |
|---|---|
| Case ID | |
| Analyst | |
| Date of report (UTC) | |
| Reviewed by | |
| Classification | *e.g. internal, confidential* |

## 1. Summary for a non-technical reader

*Three to five sentences: what was examined, what was found, how serious it is, what should happen next.*

## 2. Scope and authorisation

*Who authorised the examination? What was in scope? What was explicitly out of scope?*

## 3. Evidence inventory

| Item | Description | Source system | Acquired by / when | SHA-256 | Integrity check result |
|---|---|---|---|---|---|
| E1 | | | | | *copy from the case report* |

## 4. Chain of custody

*Who held the evidence, when, and what happened to it. Attach `logs/custody.tsv`.*

| Time (UTC) | Person | Action | Notes |
|---|---|---|---|
| | | | |

## 5. Investigation questions

| # | Question | Answer (one sentence) | Supporting evidence (file, offset, line) | Confidence |
|---|---|---|---|---|
| Q1 | | | | high / medium / low |

## 6. Timeline

*All times in UTC. Mark the source of each entry. Keep observed events apart from inferences.*

| Time (UTC) | Event | Source (file / offset / log) | Observed or inferred |
|---|---|---|---|
| | | | |

## 7. Findings

*One finding per heading. For each: what you saw, where, why it matters, how confident you are, what would change your mind.*

### F1 — <title>

* **Observation:**
* **Evidence:**
* **Interpretation:**
* **Confidence:**
* **Alternative explanations:**

## 8. Indicators of compromise

| Type | Value | Where found | Context |
|---|---|---|---|
| | | | |

## 9. Limitations

*What could not be checked, which tools were unavailable, what assumptions you made, what the evidence cannot show.*

## 10. Recommendations

*Containment, eradication, recovery, detection improvements. Separate urgent actions from long-term ones.*

## 11. Tools and versions

*Copy from `logs/tool_versions.tsv`. Include the dfir-triage version and any manual tools you used.*

## 12. Appendices

* Generated case report and case folder
* Commands run by hand (with the output)
