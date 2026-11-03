# LT-01 — SSH Authentication Failure Cluster: Final Case Study

## Scope and evidence provenance

- **Test case:** LT-01 — Suspected SSH Brute Force / Password Guessing.
- **Data source:** Recorded OpenSSH dataset, `logpai/loghub`, `OpenSSH_2k.log` (local preserved copy: `Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/OpenSSH_2k-original.log`).
- **Focused input:** `Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/LT-01-focused.log` (**42** log lines).
- **Evidence mapping:** `Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/LT-01-evidence-mapping.csv`; original source line numbers and per-line SHA-256 checks verified.
- **Host recorded:** `LabSZ`.
- **Observed log time window:** `Dec 10 10:54:27` through `Dec 10 10:54:52`. **Year and timezone are not present in these records and are not inferred.**
- **AI analysis:** `AN-20261018-183730-901f`; local Mistral 7B.
- **Human review:** `Corrected`, per analyst's saved review CLI result. The exact saved-review JSON schema was not independently checked by this documentation script.

## Verified observations

1. The complete provided dataset contains **2,000** OpenSSH log lines and **519** parseable `Failed password` lines; **286** of those name the investigated IP **`183.62.140.253`**.
2. The deliberately selected **42-event focused excerpt** contains **13** explicit `Failed password` lines and **no `Accepted password` or `Accepted publickey` lines**. Absence of acceptance in the excerpt does **not** establish the absence of successful logons elsewhere.
3. The focused failed-password records refer to: `dff` (1 failed password lines), `root` (11 failed password lines), `zhangyan` (1 failed password lines). Log messages with `invalid user` do not prove those are valid system accounts.
4. Multiple failed authentication records against different usernames in a short recorded window are **consistent with suspected SSH password-guessing/brute-force behavior**. Intent, approval context, source-IP reputation, account compromise, and campaign scope are not independently established.

## Model validation and human correction

- **Automated validation:** 6 flags in the original saved analysis: 3 medium severity missing-evidence-reference findings and 3 high severity timeline timestamp mismatches.
- **Analyst disposition:** medium missing-reference flags marked **needs follow-up**; three timestamp mismatches marked **confirmed hallucination / error**. Overall human review: **Corrected**.
- **Timestamp correction (from original source lines and mapping):**
  - `E003`: **Dec 10 10:54:29**, not the model's **Dec 10 10:54:27**.
  - `E009`: **Dec 10 10:54:31**, not the model's **Dec 10 10:54:29**.
  - `E012`: **Dec 10 10:54:33**, not the model's **Dec 10 10:54:31**.
- The attached **verified timeline CSV** includes all 42 selected events in source order and retains each event's timestamp exactly as recorded; it does not rewrite the original AI output.

## Investigation outcome

**Disposition:** Suspicious SSH authentication failure cluster — further investigation warranted. **Successful compromise is not established by this excerpt.**

**Priority next steps:** Inspect full authentication and session history around the cluster for successful logons or correlated session activity; review account validity and authorized testing; enrich the observed source IP using trusted intelligence; investigate additional hosts and time windows. Treat the investigated IP as an **observed indicator**, not automatically as a confirmed malicious IOC.

## Integrity and traceability

- Original source SHA-256: `1e4912727fa88245113d41b16a0cd25ceadba7f931e1c406542885b91254264f`.
- Focused dataset SHA-256: `8b3991a3e08962be1a1686e221d73ef40c6a08e145e618e24f8ca8684f44319b`.
- Source, selected log lines, mapping and local analyst results were **read but not modified** by this finalization script.
- Full evidence mapping, source line hashes, and event-by-event timestamps are preserved in the timeline and original mapping file.
