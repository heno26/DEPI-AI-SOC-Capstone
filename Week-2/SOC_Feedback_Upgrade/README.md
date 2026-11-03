# SOC Feedback Upgrade — Week 2 (DEPI Project 5)

**Purpose:** improve local SOC log analysis by detecting specific semantic inconsistencies, and make future model prompts benefit from **human-reviewed, curated lessons**. This is **not** model fine-tuning. It does **not** approve incidents, retrain Ollama, rewrite saved reports, or take containment actions.

## Installation (Windows PowerShell, from `D:\Desktop\w\Week-2`)

```powershell
# After extracting SOC_Feedback_Upgrade.zip in the Week-2 root:
python .\SOC_Feedback_Upgrade\install.py --check
python .\SOC_Feedback_Upgrade\install.py --install
```

**Guardrails:** Installer first checks unique code anchors and refuses existing `Core/feedback_*` modules or lessons; backs up `Core/analysis.py` and `Core/validator.py` under `Feedback-Backups/install-*`; runs the **existing regression suite first** (requires >=113 passing tests by default); installs only two small code hooks and three new files; runs the whole regression suite again (24 extra tests); automatically rolls the core files and new modules/tests back on failure. Original `Data/`, `Results/`, `Core/log_parser.py`, `app.py` and stored human reviews are not modified. A new `Prompts/Validated-SOC-Lessons.json` is generated only after successful regression.

**Current source code caveat:** This package was tested against a project code snapshot and with the prior Windows benign semantic hook layered onto that snapshot. The installed Week-2 copy may have evolved. The guarded `--check` is mandatory: if an anchor differs, **STOP and inspect the current file; do not force changes**.

## What it adds

### Semantic review flags

- `unsupported_command_tool`: a report claims netcat/nc for a Bash `/dev/tcp/` command with no matching executable in command evidence. Negative statements are excluded.
- `private_ip_scope_review`: potentially incorrect labeling of non-public IPv4 as *external/public*. Private can still mean "outside this endpoint"; this is a **review request**, not a categorical verdict.
- `network_success_not_established`: definitive assertion of established/connected reverse shell without network telemetry. Conditional possibilities are excluded.
- `duplicate_event_overcount_review`: claim of independent executions despite duplicate source records and one unique event.
- `unverified_administrator_attribution`: PROCTITLE-only records described as executed by system administrators without identity evidence.
- `privilege_escalation_outcome_unsupported`: claims of successful privilege escalation from PROCTITLE-only records.
- `unsupported_benign_assessment_review`: confidently benign classification where sensitive Auditd `setcap`/SUID commands lack operational context.
- Extra **risk signals for investigation**: shell `/dev/tcp` redirection and recorded `setcap`/SUID changes. This can help detect false "none suspicious" narratives but never proves compromise.
- `.service` tokens in `systemctl`/systemd contexts are **not** treated as DNS IOCs; real `.service` URLs remain eligible for IOC extraction.

### Human-gated feedback

- The model receives small, bounded, **case-matched factual guardrails** for observed Linux log types, even before a review has been saved.
- The `Validated-SOC-Lessons.json` file activates additional **curated** lessons only when corresponding saved case analyses have an analyst's `Approved`/`Corrected` review with review text. This avoids learning directly from potentially malicious/unverified logs or free-form review text.
- The actual prompt includes selected lessons through the existing `{{REFERENCE}}` block; each new analysis record includes `prompt.feedback` (knowledge-base SHA-256 and applied lesson IDs) for provenance.
- No automatic human-review status change, rule deployment, or model-weight modification.

**Known cases:** `LT01_SSH_TIME` (SSH timestamp uncertainty), `LT02_AUDITD_OUTCOME` (Auditd execution limitations), and `LT03_REVERSE_SHELL` (netcat, private IP, connection outcome, duplicate evidence). This is a small curated catalog; new lessons require analyst approval **and a deliberate code change** to the allowlist, rather than automatically trusting arbitrary model/analyst wording.

## Replay on LT-03 (no Ollama, no file changes)

```powershell
python .\SOC_Feedback_Upgrade\replay_validation.py AN-20261018-231218-e901
```

Expected: the saved original report had **0 original automated flags**, but the new checks should produce review requests such as `unsupported_command_tool` and `private_ip_scope_review` when the corresponding claims are present in saved sections. This is a **replay of proposed flags**, not a replacement for its original human review.

## Activate the LT-03 reviewed lesson

If `AN-20261018-231218-e901` still shows Pending Review, use the built-in reviewer first:

```powershell
python app.py review AN-20261018-231218-e901
python .\SOC_Feedback_Upgrade\sync_feedback.py
```

The feedback sync will only activate the lesson if a genuine saved review exists and is `Corrected` or `Approved` with an analyst and review notes. Prior versions of the KB are saved to `Feedback-Backups/KB-*.json`. To preview without writing:

```powershell
python .\SOC_Feedback_Upgrade\sync_feedback.py --dry-run
```

## Live post-upgrade test

```powershell
python app.py analyze "Data\Real-Datasets\Linux-Attacks\LT-03-Suspicious-Execution\LT-03-focused.json" --source-type linux --num-ctx 8192 --num-predict 2500 --no-review
```

Compare new model behavior against analysis `AN-20261018-231218-e901`, using identical focused data SHA-256 and generation settings. Inspect both **AI conclusions and validator flags**. Zero flags is not proof of correctness. Do not assume the model cannot hallucinate after one correction.

## Acceptance criteria

1. Before installation, full regression >=113 PASS.
2. After installation, full regression >= before+24 PASS (e.g. 113 -> 137).
3. Replay flags unsupported tool and IP scope in the old LT-03 output; no legacy AI output is edited.
4. New LT-03 AI analysis explicitly recognizes Bash `/dev/tcp` and properly limits claims about network success; analyst assesses output.
5. Rerunning feedback sync after LT-03 review activates `LT03_REVERSE_SHELL` and records review provenance. Never insert raw review text into a prompt.
6. Windows, LT-01, LT-02 and Wazuh parser / validator regression continue to PASS.

## Risk and scope

These are conservative keyword+context heuristics; they can produce both false positives and false negatives. Dedicated source evidence (e.g. Sysmon Event ID 3 / network flow, Auditd SYSCALL, file metadata) is still necessary to confirm actual outcomes. Analyst validation is always required. The process is deterministic and local; no data is sent to an external service by these scripts.
