# DEPI P5 — NT-01 Semantic Attribution Upgrade v2

## Status and scope

Use this **after** the post-grounding NT-01 human review is recorded as `Corrected` (`AN-20261020-013537-8c86`). This patch addresses the concrete AI-report errors verified against Zeek source records: incorrect source/destination directions, confusion between source and destination ports, and the invalid assumption that internal/private traffic implies benignness.

The report is **not** automatically approved or rewritten. The patch adds review requests; a human analyst is always the decision maker. It does not affect original capture logs, the focused input, preexisting Results, human reviews, any completed Windows/Linux evaluations or the SIEM components.

## Commands (PowerShell, from the Week-2 root)

```powershell
Expand-Archive -LiteralPath ".\SOC_Network_Semantic_v2.zip" -DestinationPath "."
python .\SOC_Network_Semantic_v2\upgrade.py --check
# Only if check displays READY, continue:
python .\SOC_Network_Semantic_v2\upgrade.py --install
python -m SOC_Network_Semantic_v2.demo --replay AN-20261020-013537-8c86
```

The installer requires an **exact source SHA-256** from the shipped Network Grounding v1 `Core/network_grounding.py`. If your project file was updated independently, the installer refuses to patch; **do not bypass the check**. A successful test run should show the existing test suite (previously observed: 196) plus **27 new focused tests** (if still 196, expected total **223**). The live output is the authority; do not claim the new total until it appears.

If the replay script cannot automatically find the AI report in the saved JSON structure, it stops without changing anything. You can pass a saved text/Markdown report with `--report-file`; don't paste report text into project source files.

## Added semantic review requests

| Rule | When raised | Severity | Important limitation |
|---|---|---|---|
| `network_direction_mismatch` | A report explicitly cites `[E###]` and states `from <IP> to <IP>`, but a **raw Zeek source-row** record has another direction. | High | Does not attempt to infer directions from unreferenced prose. |
| `network_port_role_mismatch` | A report calls the source port a destination/on-port for a referenced source-row record. | Medium | Does not guess whether unrelated numbers refer to ports. |
| `private_network_not_benign` | Report explicitly uses private/internal same-network placement as a *reason* to conclude traffic is safe/not malicious. | Medium | Private addresses themselves are neutral; benign vs unauthorized intent is not determined. |

The installer patches `Core/network_grounding.py`, creates `Core/network_semantics.py` and `Testing/test_network_semantics.py`, and backs up the original module under `Feedback-Backups`. Existing rule `NETWORK_VERTICAL_PORT_SCAN` stays in place. **All historical reports remain unchanged.**

### Validated E002 / E011 / E031 examples

- **E002**: `192.168.16.130:49949 -> 192.168.16.1:53`, UDP DNS.
- **E011**: `192.168.16.132:44372 -> 192.168.16.130:64112`, TCP, `REJ`.
- **E031**: `192.168.16.130:51814 -> 192.168.16.1:53`, UDP DNS.
- **E001**: computed full-source aggregate of the vertical TCP scan; **never** a raw flow.

Full-source findings previously verified: **65,747** TCP Zeek connection records on the scan pair, **65,535** distinct target destination ports, approximately **738.269 seconds**. High confidence applies to the *scan pattern*, not to a claim of unauthorized intent or successful compromise.

## Pre-delivery verification

1. Show original vs corrected baseline analysis and deterministic grounded detection.
2. Run this new read-only replay and capture the added flags.
3. Keep the `Corrected` review on the **historical** analysis as a preserved artifact.
4. After upgrading the validator, the final NT-01 case study should include a source-derived timeline, exact evidence attribution, reviewer corrections and limitations.

**Caution:** This is a conservative pattern-and-evidence validator, not a full natural-language inference engine. `0 flags` never proves that an AI report is correct. Positive findings should be verified by the analyst.
