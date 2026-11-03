# DEPI P5 — Unified SOC v0.4 candidate (QA-focused)

**Status: candidate, not production-approved.** This is a single-file add-on and one optional QA test. Nothing in `Core/` is replaced.

## Basis of the change

Reviewed the real 2026-10-24 mixed QA run: 56 records (Windows 4, Linux 21, Network 31), 5 local Mistral calls, 22 automated flags. Two AI drafts contain incompletion placeholders. The reported source-citation collisions occurred because mixed-file `E###` IDs did not match original per-file `E###` identifiers embedded inside the records. Some AI timelines also reported timestamps without adequate record support.

## Targeted changes

- Replace the upstream prompt template's hard-coded `[E003]` example with the **current AI batch's first canonical ref** at runtime. Keep the on-disk prompt unchanged; record the effective prompt hash and original source-file hash.
- Hide *only explicit legacy source-reference fields* (`evidence_id`, `evidence_ref`, `ref`) in copies used for model inference; retain canonical `[E###]` assigned by the Core parser. The unified manifest retains both canonical and original per-file IDs. Unknown or non-reference source strings remain as log data.
- Redact source JSON by parsing the JSON and then serializing redacted values. This prevents a password-redaction regular expression from breaking the JSON syntax. Input files are never overwritten.
- Add an entire-input, **Python/source-derived evidence timeline** to `report.md`, with canonical evidence refs, source timestamps exactly as recorded, and per-file provenance. It is not a newly established single incident and does not imply success of a command or attack.
- Add a top-level `acceptance_gate`: any high-severity validation flag or incomplete AI batch blocks report acceptance pending correction. This **does not** alter the separate manual SOC analyst approval process.
- Ask the model for a short but complete report with up to 3 example timeline rows; avoid placeholders, and rely on the separate Python-generated complete audit trail.
- Keep the existing per-family whole-file deterministic baseline and the 5-call batching logic. No changes to `Core` or to the existing OpenObserve receiver.

## Install without overwriting earlier versions

From `D:\Desktop\w\Week-2`:

1. Copy `unified_soc_v04_candidate.py` into the Week-2 directory, next to the existing `app.py` and `config.py`.
2. Copy `test_unified_v04_qa.py` into the Week-2 directory, next to `test_unified_soc.py`.
3. Run offline tests:

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B -m unittest -v test_unified_v04_qa
```

Expected: `Ran 8 tests` then `OK`. These use mock model output; **they do not run real Mistral**.

4. Optionally inspect the existing mixed-file input, with no AI:

```powershell
python -B unified_soc_v04_candidate.py inspect "Data\Mixed-Win-Linux-Net-QA.json"
```

5. Run the **real local Mistral** integration test only when ready. This creates *new* result folders (original inputs and prior results are untouched):

```powershell
python -B unified_soc_v04_candidate.py analyze "Data\Mixed-Win-Linux-Net-QA.json"
if ($LASTEXITCODE -ne 0) { throw "STOP: V0.4 MIXED ANALYSIS FAILED" }
```

To review its result, upload the newly generated `Results\UNIFIED-...\manifest.json` and `Results\UNIFIED-...\report.md`. The goal is to examine the **specific remaining** validation flags and model narratives, not to demand zero flags artificially.

### Remaining limitations

- This mix of logs is a *QA replay of independent cases spanning different years*, not a correlated security incident.
- A deterministic baseline proves only the supported observed input pattern, not malicious intent, authorization, tunnel success, or a verified original Zeek capture. NT01 aggregate provenance still needs separate source verification.
- Legacy references embedded in free prose without explicit `ref=`/`evidence_id=` labels may remain and should be reviewed. The model may still fabricate references; the existing validator flags many of those cases.
- An independent deterministic timeline improves the report but does not retroactively correct the verbatim AI draft. Human review remains mandatory.
- No live Ollama runs were performed in the offline creation/test environment.
