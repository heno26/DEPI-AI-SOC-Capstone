# Evidence and Screenshot Checklist

**No screenshots have been created.** Capture each item yourself on your Windows machine. Mark them as you go. Redact tokens, emails, Cloud IDs and API keys before saving.
Name files `NN-short-name.png` inside this folder.

| # | Screenshot | How to capture it | Done |
|---|---|---|---|
| 01 | Week 2 folder structure | File Explorer or `tree /F Week-2` in PowerShell | [ ] |
| 02 | Ollama and Mistral running | `ollama list`, then `ollama ps` while a run is active, then `python app.py check` | [ ] |
| 03 | Windows log analysis | `python app.py analyze Data\Windows\SYNTHETIC_TC-02_...log` output incl. flags | [ ] |
| 04 | Linux log analysis | same with `Data\Linux\SYNTHETIC_TC-01_...log` | [ ] |
| 05 | Network log analysis | same with `Data\Network\SYNTHETIC_W2-02_...log` | [ ] |
| 06 | Wazuh JSON alert import | `python app.py triage Data\Wazuh\SYNTHETIC_wazuh_alerts_array.json` showing the loaded summary + SHA-256 (caption it: **synthetic Wazuh-format fixture**) | [ ] |
| 07 | AI alert triage output | triage result showing original severity vs AI priority | [ ] |
| 08 | Incident timeline and IOC context | the "Evidence-based timeline" and "IOC context" parts of `report.md` or the console | [ ] |
| 09 | Hallucination validation | the flag list; ideally a run with a flag + your disposition | [ ] |
| 10 | Human analyst review | the review prompts and `Review saved. Status: ...` | [ ] |
| 11 | Detection improvement notes | `python app.py detect ...` output | [ ] |
| 12 | Saved analysis results | `dir Results` and an opened `report.md`; `Validation\validation_log.csv` | [ ] |
| 13 | Offline AI demonstration | Wi-Fi off in the taskbar + a successful run | [ ] |
| 14 | Genuine Wazuh Cloud alerts | **Only after real collection.** Dashboard alert list, redacted | [ ] **NOT YET POSSIBLE** |

Extra evidence worth keeping: unit test output, `week1_replay_validation.md`, `local_llm_run_*.csv`, the lab-activity log and raw-file SHA-256 list (from the Wazuh guide).
