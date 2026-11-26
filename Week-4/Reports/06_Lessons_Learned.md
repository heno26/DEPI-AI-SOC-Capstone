# Lessons Learned

**Project:** DEPI Project 5 - AI-Assisted SOC Automation & Full Incident Response Capstone
**Week:** 4 - Full Capstone IR Simulation & Reporting
**Scenario:** W4-TT-01 - Composite multi-stage intrusion - tabletop simulation
**Generated:** 2026-11-26T02:47:58+00:00 by `Week-4/IR/build_reports.py` from `Week-4/Output/` (data generated 2026-11-26T02:47:58+00:00)
**Status:** DRAFT - acceptance pending human sign-off


## Data-derived observations

- Week-1: the best manual-quality model was `mistral:7b-instruct-v0.3-q4_K_S` at 2.77/5 - no local model is suitable for autonomous triage; keyword recall overstated quality.
- Week-2: 158 validator review requests across 53 runs; most frequent: `missing_section` (46), `finding_without_evidence_ref` (37), `timeline_timestamp_mismatch` (26).
- Week-2: 26 of 27 reviewed AI analyses needed correction; human review remained the final gate.
- Week-3: all 7 SOAR tickets are still `Pending Review`; Tier-2 automation stayed blocked.
- Week-4: correlation across separate datasets found 3 shared observables (183.62.140.253 in LT-01, SIEM-AUTH-002; 192.168.16.132 in NT-01, NT-02; 192.168.16.1 in NT-01, NT-02).
- Threat-intelligence enrichment is a stub: no indicator reputation could be checked.


## Open gates

- Human approval pending: AI triage results require SOC analyst validation. REVIEW_REQUIRED and related review states are not final analyst sign-off.
- HTTP evidence correlation: The HTTP case includes a 112-request source group against a threshold of 80. The exact row-level join between the saved firing trigger and that group has not been proven.
- Updated SIEM05 regression: Controlled Ollama reanalysis does not constitute an updated receiver-to-report end-to-end regression. This acceptance check remains pending.
- Replay scope: Historical lab datasets and replay timestamps must not be represented as production monitoring or confirmed incidents.
- Unified SOC candidate: The v0.4 QA candidate and its recorded tests do not constitute production approval.
- No automatic remediation: Week-3 SOAR and Week-4 full incident response have not been implemented in Week-2.
- Week-2 acceptance is PENDING (6 gates). Week 3 automates *triage and enrichment*, not the acceptance-pending conclusions. PB-04 is Tier-0-only for this reason.
- HTTP correlation gap (Week-2 gate 2). PB-03's propose tier is limited to WAF review, not source blocking.
- Exchange receiver hard-codes `REVIEW_REQUIRED`. PB-04 cannot propose response actions.
- No live TheHive, no live TI, no live Wazuh. All stubs; documented as untested.
- Exchange `event_id` is replay-time-dependent. Exchange tickets are not stable across replays; documented, not fixed.
- XSS receiver self-checks are weaker than AUTH/MAL. PB-03 gets the strictest human gate.


### Lessons-learned narrative (local AI draft)

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 462.08 s | *tokens/s:* 2.16 | *validator flags:* 1 (high 0, medium 0, low 1) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/lessons_learned.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/lessons_learned.corrected.md`). Original AI text kept in the JSON file.

1. WHAT WORKED
   - The AI models, llama3.2:3b, mistral:7b-instruct-v0.3-q4_K_S, and phi3:mini, were able to process a significant number of tokens per second [E001, E002, E003].
   - Week-2 ran 53 local Mistral analysis runs and the validator raised 158 review flags for analysts [E004].
   - Human review caught AI errors: of 27 reviewed runs, 26 were corrected; analysts recorded 109 correct and 68 incorrect AI findings [E005].
   - The OpenObserve trigger to AI-triage record showed a mean response time of 37.0 seconds over 4 alerts during historical replay [E007].
   - Week-3 automated triage and enrichment processes were implemented, with Tier-2 actions hard-blocked [E008, E015].
   - Week-4 correlation linked separate datasets through shared observables: 183.62.140.253 (LT-01, SIEM-AUTH-002) and 192.168.16.132 (NT-01, NT-02) [E021, E022].

2. WHAT DID NOT WORK
   - The manual quality scores for all AI models were low, with llama3.2:3b having a mean score of 1.77/5, mistral:7b-instruct-v0.3-q4_K_S scoring 2.77/5, and phi3:mini scoring 2.08/5 [E001, E002, E003].
   - Automatic keyword recall (0.69-0.75) looked better than the manual quality scores; keyword recall is not an accuracy measure [E001, E002, E003].
   - Week-2 and Week-3 open gates (human approval, HTTP evidence correlation, SIEM05 regression, Exchange REVIEW_REQUIRED, unstable Exchange event_id) remain open [E009, E010, E011, E015, E016, E017, E019].
   - Only 8 of 16 Week-4 read-only checks could be answered from repository data; the rest need systems or records not in the lab data [E024].
   - There is no live threat-intelligence feed, resulting in every indicator reputation being 'not checked' [E025].

3. AI ASSISTANCE LESSONS
   - Recommendation: judge local models by manual review, not keyword recall; the best manual quality score was 2.77/5 (Mistral) [E001, E002, E003].
   - Recommendation: keep human review mandatory; in Week-2, 26 of 27 reviewed AI analyses needed correction [E005].

4. DETECTION AND VISIBILITY GAPS
   - The HTTP alert-to-request row-level join is still unproven [E010].
   - 8 of 16 read-only checks lacked the needed data (e.g. change records, endpoint telemetry, Exchange server files) [E024].
   - No live threat-intelligence feed: indicator reputation is never checked [E025].
   - Recommendation: use the cross-dataset overlaps as investigation leads [E021, E022].

5. PROCESS IMPROVEMENTS
   - Continue to conduct regular benchmarking of AI models and make improvements based on the results.
   - Improve the efficiency of human review processes by addressing the open gates from Week-2.
   - Recommendation: connect the Week-3 stubs to live TheHive and threat-intelligence services [E018].

6. OPEN ITEMS
   - Human sign-off on the Week-2 alerts and the 7 Week-3 tickets [E009, E008].
   - HTTP evidence correlation and the updated SIEM05 regression [E010, E011].
   - Live threat-intelligence feed [E025].

7. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.

<details><summary>Validator flags</summary>

| ID | Check | Severity | Value | Message |
|---|---|---|---|---|
| F001 | possible_unsupported_hostname | low | llama3 | Host-like token not found in the source (heuristic; may be ordinary text such as 'ssh2'). |

</details>


## Human sign-off

| Role | Name | Decision (Approved / Corrected / Rejected) | Date | Signature |
|---|---|---|---|---|
| SOC analyst |  |  |  |  |
| IR lead |  |  |  |  |
| Project supervisor |  |  |  |  |
