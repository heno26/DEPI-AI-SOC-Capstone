# Week 1 raw outputs replayed through the Week 2 validator

**Replay of existing Week 1 outputs. No model was run. Not an accuracy benchmark.** Flags are review requests.

| Run | Model | Case | High | Medium | Low | High/medium flagged values (exact) |
|---|---|---|---|---|---|---|
| run_20261016_060908 | llama3.2_3b | TC-03 | 0 | 0 | 0 |  |
| run_20261016_061045 | llama3.2_3b | TC-01 | 0 | 0 | 0 |  |
| run_20261016_061045 | llama3.2_3b | TC-02 | 0 | 0 | 0 |  |
| run_20261016_061045 | llama3.2_3b | TC-03 | 0 | 0 | 0 |  |
| run_20261016_061045 | llama3.2_3b | TC-04 | 0 | 0 | 0 |  |
| run_20261016_061045 | llama3.2_3b | TC-05 | 0 | 0 | 3 |  |
| run_20261016_061045 | llama3.2_3b | TC-06 | 0 | 0 | 0 |  |
| run_20261016_061045 | llama3.2_3b | TC-07 | 0 | 0 | 0 |  |
| run_20261016_061045 | mistral_7b-instruct-v0.3-q4_K_S | TC-01 | 0 | 0 | 0 |  |
| run_20261016_061045 | mistral_7b-instruct-v0.3-q4_K_S | TC-02 | 0 | 1 | 0 | eventid_semantic_mismatch: `- Logon event for svc_backup with a succ` |
| run_20261016_061045 | mistral_7b-instruct-v0.3-q4_K_S | TC-03 | 0 | 1 | 0 | unsupported_conclusion: `script was executed` |
| run_20261016_061045 | mistral_7b-instruct-v0.3-q4_K_S | TC-04 | 0 | 0 | 0 |  |
| run_20261016_061045 | mistral_7b-instruct-v0.3-q4_K_S | TC-05 | 0 | 0 | 0 |  |
| run_20261016_061045 | mistral_7b-instruct-v0.3-q4_K_S | TC-07 | 0 | 0 | 0 |  |
| run_20261016_061045 | phi3_mini | TC-01 | 0 | 2 | 0 | unsupported_conclusion: `downloads and runs`; unsupported_conclusion: `downloaded and executed` |
| run_20261016_061045 | phi3_mini | TC-02 | 1 | 0 | 0 | unsupported_timestamp: `20260-10-14` |
| run_20261016_061045 | phi3_mini | TC-03 | 0 | 0 | 0 |  |
| run_20261016_061045 | phi3_mini | TC-04 | 0 | 0 | 0 |  |
| run_20261016_061045 | phi3_mini | TC-06 | 0 | 0 | 0 |  |
| run_20261016_061045 | phi3_mini | TC-07 | 1 | 0 | 0 | unsupported_ip: `10.00.0.15` |
| run_20261016_063533 | mistral_7b-instruct-v0.3-q4_K_S | TC-06 | 0 | 0 | 0 |  |
| run_20261016_063843 | phi3_mini | TC-05 | 1 | 0 | 0 | unsupported_ip: `192.008.0.34` |
| run_20261016_160720 | llama3.2_3b | TC-08 | 0 | 0 | 0 |  |
| run_20261016_161056 | llama3.2_3b | TC-08 | 0 | 0 | 0 |  |
| run_20261016_161056 | llama3.2_3b | TC-09 | 0 | 0 | 0 |  |
| run_20261016_161056 | llama3.2_3b | TC-10 | 0 | 0 | 0 |  |
| run_20261016_161056 | llama3.2_3b | TC-11 | 0 | 0 | 0 |  |
| run_20261016_161056 | llama3.2_3b | TC-12 | 0 | 0 | 0 |  |
| run_20261016_161056 | llama3.2_3b | TC-13 | 0 | 0 | 0 |  |
| run_20261016_161459 | mistral_7b-instruct-v0.3-q4_K_S | TC-08 | 0 | 0 | 0 |  |
| run_20261016_161459 | mistral_7b-instruct-v0.3-q4_K_S | TC-09 | 0 | 0 | 0 |  |
| run_20261016_161459 | mistral_7b-instruct-v0.3-q4_K_S | TC-10 | 0 | 0 | 0 |  |
| run_20261016_161459 | mistral_7b-instruct-v0.3-q4_K_S | TC-11 | 0 | 0 | 0 |  |
| run_20261016_161459 | mistral_7b-instruct-v0.3-q4_K_S | TC-12 | 0 | 0 | 0 |  |
| run_20261016_161459 | mistral_7b-instruct-v0.3-q4_K_S | TC-13 | 0 | 1 | 0 | unsupported_conclusion: `file was executed` |
| run_20261016_162058 | phi3_mini | TC-08 | 1 | 0 | 0 | unsupported_ip: `203.00.113.61` |
| run_20261016_162058 | phi3_mini | TC-09 | 0 | 0 | 0 |  |
| run_20261016_162058 | phi3_mini | TC-10 | 0 | 0 | 0 |  |
| run_20261016_162058 | phi3_mini | TC-11 | 0 | 1 | 0 | malformed_ip_like: `203.00113.90` |
| run_20261016_162058 | phi3_mini | TC-12 | 1 | 0 | 0 | unsupported_timestamp: `20260-10-14` |
| run_20261016_162058 | phi3_mini | TC-13 | 2 | 0 | 0 | unsupported_timestamp: `2026-100-14`; unsupported_timestamp: `20260-10-14` |
