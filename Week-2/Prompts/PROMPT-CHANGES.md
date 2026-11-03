# Week 2 Prompt Changes (version w2-1.0)

Week 1 prompts in `Week-1/SOC-Prompts/` are **unchanged**. Week 2 prompts are new files derived from them.
No claim is made that these changes fix the problems; effectiveness must be measured with the local tests
(see `Documentation/Week-2-Testing-Guide.md`).

| Week 1 weakness (source: Week-1 review files) | Week 2 change | How it is checked |
|---|---|---|
| Windows Event IDs misread (4625 treated as success, TC-02) | Fixed REFERENCE block injected by code only for Event IDs present; code-computed failed-logon counts | `eventid_semantic_mismatch` flag (heuristic) |
| Suspicious activity reported as "None identified" (Llama TC-01/08/09; Mistral TC-11) | "None identified" allowed only after checking every line; code lists risk signals | `none_claim_vs_signals` flag |
| Over-escalation of authorized activity (TC-04, TC-13) | Explicit instruction to use approved-change/asset/window context; benign evidence section | Triage consistency flags |
| Treating approved-but-out-of-window activity as clean (Mistral TC-12) | Instruction: approved source but outside allowed window = needs verification | Manual review |
| Invented/altered IPs, timestamps, hostnames (Phi-3 TC-05/07/08/11-13) | Copy-exactly rule; exact-string validator for IPs, dates, times, entities | `unsupported_ip`, `malformed_ip_like`, `unsupported_timestamp`, `unsupported_entity` |
| Defang removed from IOCs (Llama TC-05) | Keep-defanged rule | `ioc_format_altered` flag |
| Attempt vs. compromise confusion (blocked SQLi/LSASS, DNS) | Blocked/403/download rules; "confirmed" restricted | `unsupported_conclusion` flag |
| Several verdicts printed / unclear structure (Llama TC-03) | "Exactly one verdict / priority" | Parser warns if not exactly one allowed value |
| Outputs cut off at 800 tokens | Higher `num_predict`; shorter sections; truncation detected | `output_truncated` flag |
| Instructions hidden in logs | Per-run random delimiters; untrusted-data rule; input scan for injection phrases | `prompt_injection_in_input` warning |
| Findings without support | Mandatory `[E###]` references (each event gets a reference) | `nonexistent_evidence_ref`, `finding_without_evidence_ref` |
