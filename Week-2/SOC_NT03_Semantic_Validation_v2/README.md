# NT-03 Semantic Validator v2 — guarded, evidence-based update

## Why this patch

Step 19 confirmed that existing calls are connected correctly: `Core.analysis` calls `grounded_detection.review_requests`, which calls `network_grounding.review_requests`, which calls `network_semantics` and `tcp_retry_grounding`. The missing flags were caused by **report-section aliases and incomplete semantic coverage**, not a missing integration call.

This patch handles three specific, generalizable review gaps:

1. Recognize `## SUSPICIOUS ACTIVITY` as `SUSPICIOUS ACTIVITIES` while leaving genuinely omitted mandatory sections flagged.
2. Differentiate an AI report that *mentions* retry-like activity from one that supplies grounding (count of groups, count of source rows, examples of source ports, matching inter-arrival interval). The detector and AI conclusion remain independent.
3. Inspect two conservative TCP claims without inventing intent: (a) unconditional denial of any established data-bearing TCP connection despite `SF` and positive `orig_bytes`+`resp_bytes`; (b) an explicit **source-port list** grouped as if all belong to destination port `N`, where a listed port is observed only on a *different* destination port and at least two listed ports genuinely belong to the claimed target.

The changes neither classify C2 automatically nor equate `SF` with successful malware or data exfiltration. If evidence is ambiguous, validation requests human review. Does not hardcode case IP, ports, counts, intervals or hashes.

## Precise changes

- `Core/analysis.py` — modify one alias map (no other pipeline changes).
- `Core/network_semantics.py` — add two limited semantic checks while retaining existing cited-row/port/direction checks.
- `Core/tcp_retry_grounding.py` — extend one review function to grade missing quantitative support (no changes to detection logic).
- `Testing/test_nt03_semantic_validation_v2.py` — 24 new unit tests.

No changes to `Core/network_grounding.py`, `Core/grounded_detection.py`, `Core/validator.py`, original Zeek logs, saved `Results`, or existing human reviews.

## From the original `Week-2` PowerShell folder

Extract ZIP to project root once, then run **read-only preflight**:

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -m SOC_NT03_Semantic_Validation_v2.upgrade --check
```

Only after the SHA-256 compatibility check returns READY, install:

```powershell
python -m SOC_NT03_Semantic_Validation_v2.upgrade --install
```

Installer refuses to modify a non-matching version, requires `293` passing existing tests, backs up 3 Core files with SHA-256 verification, installs 3 patches + one new test, then requires `317` passing tests. On error, restores changed Core files and removes the newly introduced test. Backup retained in `Feedback-Backups/NT03-Semantic-v2-*`. All files remain in the project for now; consolidate only after Week 2.

To reproduce the semantic findings on **saved** Mistral text without changing any saved artifacts:

```powershell
python -m SOC_NT03_Semantic_Validation_v2.upgrade --replay AN-20261021-132533-02e7
```

We expect the singular heading to be recognized, a `network_tcp_retry_missing_quantification` medium request, a high `network_observed_tcp_data_contradiction` review request, and a medium `network_source_port_group_mismatch` review request. Some legacy mandatory missing-section flags remain. These are **review requests, not certified hallucination verdicts**. The replay does **not** rewrite old `analysis.json` or overwrite review status.

## Test disclosure

Local synthetic/reconstructed-project testing uses supplied Core and upgrade sources; it does not replicate the user's full installed system, so only the user's `--install` can establish the full `293 -> 317` project regression PASS.
