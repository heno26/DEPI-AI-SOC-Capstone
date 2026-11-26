# AI-Assisted Reporting Workflow

**Project:** DEPI Project 5 - AI-Assisted SOC Automation & Full Incident Response Capstone
**Week:** 4 - Full Capstone IR Simulation & Reporting
**Scenario:** W4-TT-01 - Composite multi-stage intrusion - tabletop simulation
**Generated:** 2026-11-26T02:47:58+00:00 by `Week-4/IR/build_reports.py` from `Week-4/Output/` (data generated 2026-11-26T02:47:58+00:00)
**Status:** DRAFT - acceptance pending human sign-off


## Workflow

```
Week-2 evidence + Week-3 tickets
        |
        v
correlate.py ---------> Output/incident.json  (cases, timeline, observables, ATT&CK)
        |
        v
ir_lifecycle.py ------> Output/ir_lifecycle.json (NIST phases, proposals, decisions)
        |
        v
ai_report_drafter.py
   1. builds a numbered fact sheet [E001..] from the two files (code, no hand-typed values)
   2. fills a prompt (Week-1 Incident-Report prompt reused; Week-4 prompts in Week-4/Prompts)
   3. calls LOCAL Ollama via Week-2 Core/ollama_client.py (loopback only, 1 controlled retry)
   4. validates the text with Week-2 Core/validator.py against the fact sheet
   5. saves Output/ai_drafts/<id>.json  (review status: Pending Review)
        |
        v
Human analyst: ir_cli.py review --draft <id> --status Approved|Corrected|Rejected
   (Corrected text goes in Output/ai_drafts/<id>.corrected.md)
        |
        v
build_reports.py + build_dashboard.py -> Reports/*.md, Dashboard/index.html
```

## Human gates

1. No draft is used as final text until an analyst records a review.
2. Validator flags are requests for review, not proof of hallucination; passing them is not proof of correctness.
3. Response proposals are never executed by the pipeline; decisions are recorded in `Simulation/analyst_decisions.jsonl`.
4. Model, prompt hash, options, attempts, timing and flags are saved with every draft for audit.


## Draft runs

| Draft | Model | Prompt | Facts | Seconds | Tok/s | Done | Flags | Review |
|---|---|---|---|---|---|---|---|---|
| exec_briefing | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/executive_briefing.txt | 18 | 243.33 | 2.06 | stop | 0 | Approved |
| incident_report | Mistral:7b-instruct-v0.3-q4_K_S | Week-1/SOC-Prompts/Incident-Report.txt | 42 | 688.65 | 1.96 | stop | 0 | Corrected |
| lessons_learned | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/lessons_learned.txt | 25 | 462.08 | 2.16 | stop | 1 | Corrected |
| stage_S1 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 6 | 291.86 | 1.99 | stop | 0 | Approved |
| stage_S2 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 16 | 270.98 | 1.99 | stop | 0 | Approved |
| stage_S3 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 14 | 230.39 | 2.03 | stop | 0 | Corrected |
| stage_S4 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 17 | 359.34 | 2.0 | stop | 0 | Corrected |
| stage_S5 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 10 | 223.84 | 2.16 | stop | 0 | Corrected |
| stage_S6 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 8 | 234.29 | 2.34 | stop | 0 | Approved |
| stage_S7 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 7 | 144.14 | 2.56 | stop | 0 | Corrected |
| stage_S8 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 16 | 394.67 | 1.99 | stop | 0 | Approved |
| stage_S9 | Mistral:7b-instruct-v0.3-q4_K_S | Week-4/Prompts/stage_summary.txt | 14 | 2556.61 | 0.16 | stop | 1 | Corrected |


**Validator checks raised on drafts:** `possible_unsupported_hostname` x1, `unsupported_domain` x1
