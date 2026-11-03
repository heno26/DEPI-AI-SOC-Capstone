# Windows Testing Summary — DEPI Week 2 (Windows scope)

**Current scope:** Windows only; **Linux logs and Wazuh alert triage are still outstanding**.  
**Completed Windows cases:** 4 focused attack scenarios + 3 benign candidates = 7.  
**Latest documented regression:** 113 tests passed (observed in saved PowerShell output; not rerun by this documentation tool).  
**Local AI:** Mistral 7B Instruct; human analyst remains the final arbiter.

## Deliverables

- `Windows-Attack-Evaluation.md`: qualitative findings from RT-01–RT-04.
- `Windows-Benign-Evaluation.md`: comparison and review findings for BT-01–BT-03.
- Case-specific evidence-linked documents and verified timelines for the four attack cases.
- Three separate post-fix benign case studies, referencing focused logs and recorded human reviews.
- `Windows-Finalization-Manifest.json`: hashes of inspected inputs and generated outputs.

## Key technical learning

1. Evidence IDs can differ between full original logs and focused input; preserve the explicit mapping.
2. Validate event semantics: process creation is not termination, `4624` Logon Type 5 is service logon, `4672` privileges alone are not exploitation, and `7036` state changes alone do not prove concealment.
3. Guard timestamp parsing and cite original event timestamps, not generated model values.
4. Automated validation is a review aid, not an incident-confirmation engine. All seven cases require interpretable human adjudication.
5. Source hashes and unchanged original analyses/reviews preserve provenance and auditability.

## Next phases

- **Linux:** focused attack/benign log analysis using the existing parser + analyst review flow.
- **Wazuh:** alert triage and source-evidence correlation.
- **Week 2 integrated report:** finish only after Linux and Wazuh testing. This document is **not** the final Week 2 report.

## Evaluation caution

These seven selected case studies and three unverified-benign baseline candidates do not yield a statistically meaningful operational detection or false-positive rate.
