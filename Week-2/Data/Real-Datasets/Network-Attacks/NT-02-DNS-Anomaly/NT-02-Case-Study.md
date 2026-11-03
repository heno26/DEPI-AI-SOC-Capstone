# NT-02 — Source-Verified Suspicious DNS Activity Case Study

**Project:** DEPI P5 — AI-assisted SOC log analysis  
**Source:** Zeek `dns.log` from the pinned `dikshitdhawan/NTA-Zeek-Threat-Detection-Lab` repository  
**Original source SHA-256:** `a5a31f5be2a6bfdcce1ab1f2d43e34a2b1ff49bee4d3737560c8b9b6e6775942`  
**Scope:** 581 original DNS records, 26 model-visible focused entries (two verified computed aggregates and 24 selected original Zeek rows).

## Evidence provenance and boundaries

Original source bytes, Git blob provenance, pinned commit, Zeek syntax and all four source-derived artifacts were verified again via the existing `NT02_Prepare_Focused_Evidence.py` derivation logic. The independently checked 24 selected raw Zeek rows preserve source line number, logical-line SHA-256, UID, epoch/UTC timestamp, originating client and resolver IP/port, query, query type and response code. **E001 is the full-source computed aggregate; E002 is the DNS-cluster computed aggregate. Neither is an observed individual DNS request.** E003–E026 are original source DNS entries.

## Verified DNS behavior

| Measure | Verified value |
|---|---|
| Original DNS records | **581** (258 distinct exact queries) |
| Client → resolver for burst | `192.168.16.132` → `192.168.16.131` |
| Pattern | Sequential `chunkNNN-hex.lab.test` subdomains |
| Matching burst DNS records | **250** |
| Distinct exact queries in burst | **250** |
| Burst first observation UTC | `2026-05-26T16:05:30.002227Z` |
| Burst last observation UTC | `2026-05-26T16:05:33.555093Z` |
| Burst interval | **3.552866 seconds** |
| Burst query type / response | 250 `A` records; 250 `NOERROR` |
| Full-source query types | 401 `A`; 180 `AAAA` |
| Full-source rcode values | 255 `NOERROR`; 326 `-` (not recorded) |
| Observed NXDOMAIN | **0** |
| Rule / confidence in observed pattern | `NETWORK_DNS_CHUNK_BURST` / **HIGH** |
| Confirmed tunneling or exfiltration | **NOT ESTABLISHED** |
| Authorization or actor intent | **UNKNOWN** |

**Interpretation:** The short high-diversity sequence supports a high-confidence observation of a chunk-style DNS query burst and an indicator compatible with DNS tunneling-like behavior. Hex-looking labels are not necessarily cryptographic hashes or recovered exfiltrated data. A `NOERROR` response is not confirmation of exfiltration. The `.test` suffix suggests test-style names and does not determine authorization or maliciousness; private addresses do not establish benign activity.

## Client / resolver attribution and context

`E024` is an original Zeek query at line **437**: client `192.168.16.132` → resolver `192.168.16.131`, `chunk250-ef566286fc3a33e1c288d41c.lab.test`. The baseline AI output incorrectly attributed this DNS query to `.131` as its initiating host. Not all entries come from the same client: the full source contains context rows from `.131` to `.1`, and their presence must not be recast as the 250-query burst.

## AI assessment, validation and human review

- **Baseline Mistral:** `AN-20261020-024440-4bee`. Identified chunk-style DNS queries, but did not quantify the 250-query / 3.552866-second burst and did not clearly characterize DNS tunneling-like risk. Source/client attribution and report structure had errors; the original report is preserved.
- **Post-grounding Mistral:** `AN-20261020-033312-7c54`. Identified concentrated, diverse sequential DNS queries and potential DNS tunneling, but still omitted the source-verified 250 count, distinct 250 count and interval. Its timeline included an ellipsis placeholder and positioned computed aggregate E001 as if it were an individual event; the original report is preserved.
- **Deterministic detection:** `NETWORK_DNS_CHUNK_BURST` saved within `grounding.behavioral_findings` of the post-grounding analysis with HIGH confidence in the observed pattern. This is not proof of exfiltration, operator identity or malicious intent.
- **Live validator fix:** Existing test suite passed **275 tests** during installation, as reported by the project CLI. This finalization step does **not** rerun the full regression suite.
- **Post-fix read-only replay:** Reproduced **1 network review request(s)**, including `network_dns_chunk_burst_missing_quantification` in semantic substance (actual flag name `network_dns_chunk_burst_missing_quantification`), without the inappropriate vertical-TCP-port-scan flag. This replay is not a rewrite of the historical saved AI validation fields.
- **Analyst review:** Both baseline and post-grounding review commands were **CLI-reported `Corrected`**. This finalization script does not inspect or certify the application's internal human-review storage schema.

## Verified source timeline

`NT-02-Verified-Timeline.csv` contains **24 chronologically sorted original Zeek DNS rows** E003–E026 with exact source-row provenance and client→resolver direction. The two computed aggregates E001/E002 are **not** represented as fabricated timeline DNS requests. Sampling is not an exhaustive timeline of all 581 DNS rows or the entire 250-query burst; summary counts come from full-source derivation.

## Investigation limits and next evidence

Seek permission/test authorization records; identify the DNS-originating process and resolver owner; inspect DNS server responses and relevant capture data; confirm whether any data was encoded or reconstructed; and correlate endpoint/network activity. No proof of successful tunneling, data theft, compromise or malicious intent can be inferred solely from the DNS log, despite the strong observed burst pattern.

## File safety

The original source, manifests, focused evidence, `Core`, `Results` and existing human reviews are read-only during finalization. New documents are written using exclusive creation after an explicit operator confirmation; previous documents are never overwritten.
