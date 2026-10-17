# Week 1 — Supplemental review patch (TC-08 to TC-13)

This ZIP contains ONLY **review documents**, not a replacement project. Nothing on the user's computer was changed.

## What is inside

- `Testing/AI-Accuracy-Review.md` — prior original 7-case review retained; supplemental summary appended.
- `Testing/Additional-6-Accuracy-Review.md` — separate, detailed 18-response manual review against supplied synthetic logs.
- `Testing/Additional-6-Manual-Review.csv` — machine-readable per-case draft scoring and reviewer notes.
- `Benchmarks/Model-Benchmark.md` — earlier benchmark retained; six-case addendum appended.
- `Week-1-Final-Report.md` — earlier report retained; additional results and limitations added.

## Manual install — keep your arrangement

1. Make a backup of the current `Week-1` folder, or at least the three report files.
2. Copy the patch's files into the equivalent paths of your existing Week-1 folder; **replace only the three named markdown reports** above.
3. The two NEW review files belong in `Testing/`.
4. Do NOT overwrite or merge any old `Benchmarks/results` folders. Keep the three local run folders:
    - `run_20261016_161056` (Llama)
    - `run_20261016_161459` (Mistral)
    - `run_20261016_162058` (Phi-3)
5. Keep your existing `Testing/Test-Cases.json` with all 13 cases; do not replace it with the patch.
6. Keep the screenshots in Evidence, including additional-run screenshots 11–15, and verify student details and final sign-off.

## Integrity and caveats

- The 18 additional responses all executed successfully, but many contain substantive SOC mistakes.
- Manual 1–5 scores are **qualitative reviewer judgments**, not objective accuracy percentages.
- Automatic 92% keyword recall does not guarantee correct threat identification. Modified/malformed indicators may evade the IP regex.
- Old baseline metrics were not overwritten; two original requests required changed-setting diagnostic retries.
- The dataset is synthetic and small; no autonomous containment, escalation, or production SOC readiness is claimed.
