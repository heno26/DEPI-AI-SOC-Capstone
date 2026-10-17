# Privacy and Ethics Checklist — Evidence-aware Review

**Status:** Partially verified using prior conversation screenshots and the provided result files. Student must attach screenshots and sign off before DEPI submission.

| Control | Status | Supporting evidence / limitation |
|---|---|---|
| Use only locally hosted models | Observed | Ollama REST API uses `http://localhost:11434` in `benchmark.py`, and benchmark results show local model tags. This alone does not audit all outbound network traffic. |
| API listens only on loopback | Observed in earlier screenshot | `Get-NetTCPConnection -LocalPort 11434 -State Listen` showed `127.0.0.1:11434`; attach `06-Privacy-Verification.png`. |
| Model inference with internet disabled | Reported / partial | Earlier screenshot showed an Ollama answer and external 1.1.1.1:443 test `False`; confirm adapter really disconnected and attach `05-Offline-Test.png`. |
| Local model and GPU use | Observed in earlier screenshots / recorded metrics | `ollama ps` showed 100% GPU offload for Llama; `summary.csv` gives offload for all three. Add screenshot `04` and `10`. |
| Only synthetic test data | Verified for supplied fixtures | `Testing/Test-Cases.json` contains synthetic cases with documentation/private IP ranges. |
| No production credentials / private keys | No issues seen in supplied fixtures | Do not use unredacted production logs or publish secrets; test case samples only. |
| Human analyst validates every AI response | Required and reviewed | Manual validation in `Testing/AI-Accuracy-Review.md` uncovered false negatives and invented IOCs. |
| No autonomous containment / escalation | Required | Never allow the model to isolate hosts, block indicators or make final incident decisions without human approval. |
| No cloud AI services used at runtime | Partially verified | Local Ollama benchmark script does not call cloud APIs; this is not a whole-system network audit. |
| Data retention and file access | Action needed | Keep raw alerts, responses and reports private; do not publish sensitive files or commit them to a public repo. |

## Verification follow-ups

1. Place the locally captured evidence screenshots in `Evidence/` and verify their content.
2. If needed, repeat the offline test with Wi-Fi/Ethernet explicitly disabled (not just one failed TCP connection).
3. Verify system/device access controls before using any non-synthetic data.
4. Add name/date and explicit sign-off below.



Overall result: **Pending student evidence attachment and sign-off**
