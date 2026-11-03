# Windows Benign Candidate Evaluation — BT-01 through BT-03

**Design:** Three intentionally selected Windows baseline candidates, each analyzed with local Mistral and reviewed by a human analyst.

| Test | Events | Initial flags | Post-fix live flags | Human review |
|---|---:|---:|---:|---|
| BT-01 | 6 | 0 | 2 | Corrected |
| BT-02 | 4 | 3 | 1 | Corrected |
| BT-03 | 6 | 0 | 2 | Corrected |

## Review findings

- **BT-01:** The post-fix report twice claimed that the executable ran under System32; both path assertions contradict the Image fields. **Analyst finding:** Both medium process_image_path_mismatch flags were confirmed by the analyst. A prior report also inferred process stops from Event ID 1 alone.
- **BT-02:** The new analysis correctly identifies service logons, but calls SYSTEM privilege assignment unusual without a historical baseline. **Analyst finding:** One medium finding_without_evidence_ref flag was reviewed as Needs Follow-up; the unsupported abnormality assessment remains unverified.
- **BT-03:** The post-fix report generalized single transitions to repeated start/stop cycles and speculated about malicious concealment without independent support. **Analyst finding:** Both low service_start_stop_overgeneralization flags were confirmed by the analyst for the unsupported repetition claims; conditional hypotheses alone are not fabricated events.

## Validity constraints

- **Zero validator flags does not prove model correctness.** Initial BT-01 and BT-03 generated no flags while human review found unsupported assertions.
- Flag counts represent candidate review signals. A larger count does not imply better precision without adjudication.
- The three Windows baseline samples are *benign candidates*, not an independently labelled ground-truth set.
- **Do not report a numerical false-positive rate, precision, recall, specificity or accuracy** from these three cases.
- Human-reviewed corrected outputs support targeted validator evaluation and regression tests.
