# Local Model Benchmark — Executed Results and Manual Assessment

**Project:** DEPI Project 5 · Week 1 · Executed on user’s Windows 11 laptop on 16 October 2026.

## Test configuration

- **Baseline:** Ollama local API, 7 synthetic cases × 3 local models, `temperature=0`, `seed=42`, `num_ctx=4096`, max output 800 tokens.
- GPU: RTX 3050 (6 GB). Model sizes and offload below are **measurements from the script**, not peak system-wide utilization.
- Source: `Benchmarks/results/run_20261016_061045/{results.csv,summary.csv,raw/}`.
- Script used for original full run: `Benchmarks/benchmark-original.py`; patched script for future runs: `Benchmarks/benchmark.py`.

## Baseline only — do not merge different decoding settings

| Metric | Llama 3.2 (3B) | Mistral 7B Instruct | Phi-3 Mini |
|---|---:|---:|---:|
| Completed / attempted | 7/7 | 6/7 | 6/7 |
| Mean wall time (s, successful only) | 12.57 | 31.71 | 22.10 |
| Mean tokens/s | 48.99 | 23.10 | 42.32 |
| Automatic expected-keyword recall | 0.69 | 0.75 | 0.73 |
| Automatically flagged forbidden claims | 0 | 0 | 0 |
| Automatically flagged unsupported indicators | 0 | 0 | 1 |
| Total model memory (GB) | 2.56 | 4.86 | 3.81 |
| Model VRAM (GB) | 2.56 | 4.30 | 3.81 |
| Layers offloaded to GPU (%) | 100 | 89 | 100 |

**Critical caveats:** Automatic recall is a keyword check, not correctness. Manual inspection revealed serious incorrect interpretations despite acceptable automatic scores; the six-run means exclude one failed case each. Multiple responses have `done_reason=length` and are incomplete.

## Failed baseline requests and diagnostic recovery

| Model | Case | Baseline failure | Retry outcome | Retry settings | Evidence directory |
|---|---|---|---|---|---|
| Mistral | TC-06 | HTTP 500, “prediction aborted, token repeat limit reached” | 26.03 s; 23.05 tok/s; 4/4 keyword matches; no auto-flagged IOCs | temperature 0.2, repeat_penalty 1.15 | `run_20261016_063533` |
| Phi-3 | TC-05 | HTTP 500, same token repetition error | 15.76 s; 41.60 tok/s; 5/6 keyword matches; **1 invented IOC** | temperature 0.2, repeat_penalty 1.15 | `run_20261016_063843` |

A repeated HTTP 500 is a **model-generation reliability finding**; the retries demonstrate successful completion with different decoding settings **on those specific attempts only**. Original results are retained in the baseline folder.

## Manual review — safety-critical observations

- **Llama 3.2:** high throughput and 100% GPU offload, but critical misses in TC-01 and TC-03; TC-02 misread 4625.
- **Mistral 7B:** strongest qualitative scores in this limited review but over-escalated TC-04, misunderstood TC-02, and had a baseline repetition failure.
- **Phi-3:** can recognize both suspicious and benign patterns, but invented/mangled IOCs and log references; not suitable for unvalidated IOC extraction.

## Manual qualitative review (single reviewer)

| Model | Mean score /5 | Notes |
|---|---:|---|
| Llama 3.2 | 2.00 | 7 original cases; severe false negatives on TC-01/03 |
| Mistral 7B | 2.86 | 6 originals + 1 **modified-settings** retry |
| Phi-3 Mini | 2.43 | 6 originals + 1 **modified-settings** retry |

These values are judgments recorded in `Testing/AI-Accuracy-Review.md`, **not** objective accuracy percentages. The mix of settings is explicitly shown, so do not produce a definitive weighted score pretending identical conditions.

## Recommendation for Week 2 (provisional)

- **Simple integration baseline:** `llama3.2:3b` for local FastAPI/Ollama prototype because all 7 original tests completed, it is fastest (12.57 s mean) and its model fits fully in 6 GB GPU memory.
- **Do not use it for unsupervised triage.** Llama missed serious malicious activity. Before evaluating Week-2 use, improve the prompts and rerun TC-01/02/03/04 with a clear acceptance checklist.
- **Manual comparison candidate:** Mistral 7B for complicated analyst drafts when its slower speed is acceptable and output/repetition issues are controlled.
- **No production recommendation yet.** All three require human verification, especially log semantics and IOC fidelity.

## Minimum acceptance gates for next stage

1. Detect SSH failure → success → suspicious download in TC-01.
2. Interpret Windows 4625/4624/4732 correctly in TC-02.
3. Recommend escalation for Word → encoded PowerShell in TC-03.
4. Avoid inappropriate escalation of scheduled Nessus activity in TC-04.
5. Never invent/reformat IOCs in TC-05 and never invent incident impact in TC-06.

## Outstanding evidence

- User-reported evidence screenshots are **not contained** in `results.zip`; copy them to `Evidence/` before submission.
- Compare system RAM/GPU utilization from Task Manager screenshot 10 against Ollama resource metrics; do not claim recorded peak usage from this CSV alone.


## Supplementary benchmark — six additional security log scenarios (TC-08–TC-13)

Six additional synthetic log scenarios were merged into the student’s `Testing/Test-Cases.json`, expanding the dataset to **13 cases**. The student ran **18 additional requests**, all using the *baseline* settings (`temperature=0`, `seed=42`, `num_ctx=4096`, `num_predict=800`). Original TC-01–07 benchmarks and diagnostic retries are preserved separately.

| Metric | Llama 3.2 | Mistral 7B | Phi-3 Mini |
|---|---:|---:|---:|
| Completed / attempted | 6/6 | 6/6 | 6/6 |
| Mean response time (s) | 12.11 | 32.19 | 22.56 |
| Mean tokens/s | 53.27 | 22.76 | 42.55 |
| Keyword-based auto recall | 0.92 | 0.92 | 0.88 |
| Auto-flagged unsupported indicators | 0 | 0 | 1 |
| Model memory (GB) | 2.56 | 4.86 | 3.81 |
| VRAM (GB) | 2.56 | 4.30 | 3.81 |
| GPU offload (%) | 100 | 89 | 100 |
| **Manual quality mean (1–5; six cases)** | **1.50** | **2.67** | **1.67** |

Results folders:

- `Benchmarks/results/run_20261016_161056/` — Llama.
- `Benchmarks/results/run_20261016_161459/` — Mistral.
- `Benchmarks/results/run_20261016_162058/` — Phi-3.

### Important discrepancy: keyword success is not SOC accuracy

Llama scored 4/4 automatic findings for TC-08 but says `SUSPICIOUS ACTIVITY: None identified` and falsely claims the input omitted the IP/hostname. On TC-09, it says None identified/Low despite the EDR block of an LSASS access attempt. All three poorly handle AWS privilege changes (TC-11) and the DNS tunneling hypothesis (TC-10). Mistral claims in TC-12 that there is no standard-hours restriction even though the source explicitly specifies `09:00-17:00`. Phi-3 changes IP and timestamp literals in multiple cases; some alterations are missed by the automatic checker.

**Selection after expanded review:** Llama remains a workable **fast technical integration baseline** only, not the most dependable security analyst. Mistral has the strongest mean manual quality of these three under this *small six-case synthetic set*, but its missed high-risk AWS case and the RDP-policy contradiction prevent autonomous triage. Phi-3 requires strict IOC integrity checks. All options require human review and prompt/evidence validation before Week-2 SOC usage.

Refer to `Testing/Additional-6-Accuracy-Review.md` for an auditable case-by-case assessment. These subjective ratings are not formal accuracy percentages.
