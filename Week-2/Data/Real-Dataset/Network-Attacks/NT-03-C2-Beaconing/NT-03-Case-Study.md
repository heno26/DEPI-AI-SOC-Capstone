# NT-03 ? Network TCP Retry-Like Behavior Investigation

**Project:** DEPI P5 ? AI-Assisted SOC Log Analysis  
**Case:** NT-03  
**Dataset:** Stratosphere IPS IoT-23  
**Capture:** CTU-IoT-Malware-Capture-44-1  
**Evidence Type:** Zeek conn.log  
**Investigation Status:** Technical Verification Complete  
**Human Review Status:** Corrected  

---

## 1. Executive Summary

NT-03 investigates repeated TCP connection records observed in
the IoT-23 network dataset.

The investigation identified 24 TCP/80 connection records
from 192.168.1.199 to 46.101.251.172.

Four source-port reuse groups contain 17 original Zeek records
showing S0-before-SF connection-state sequences.

These observations support investigation of retry-like
connection behavior.

They do not independently establish periodic beaconing,
exponential backoff, malicious command-and-control activity,
successful exploitation, or compromise.

The local Mistral model was evaluated before and after
installation of source-grounded TCP detection.

The post-grounding analysis preserved one verified behavioral
finding but still contained factual and structural errors.

Semantic Validation V2 subsequently identified three
additional review issues in the saved AI report.

---

## 2. Dataset Provenance

Dataset: Stratosphere IPS IoT-23

Capture: CTU-IoT-Malware-Capture-44-1

Source file: bro/conn.log.labeled

Source URL:

https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled

Original file size: 31,179 bytes

Original source SHA-256:

`12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f`

The original labeled dataset was preserved without modification.

Source-supplied labels were withheld from the focused AI
evidence and were not used to select the investigated flow.

These labels are evaluation metadata, not independent proof
of beaconing.

---

## 3. Original Network Inventory

| Metric | Verified Value |
|---|---:|
| Original connection records | 237 |
| TCP records | 27 |
| UDP records | 210 |
| SF records | 149 |
| S0 records | 86 |
| Target TCP/80 records | 24 |
| Target SF records | 11 |
| Target S0 records | 13 |

### Primary Investigated Flow

Source: `192.168.1.199`

Destination: `46.101.251.172`

Destination Port: `80/TCP`

Observed connection states include S0 and SF.

Positive traffic byte counts are present in completed
connection records.

These observations contradict a blanket assertion that
no completed connections or data transfer were observed.

They do not establish the application-level content,
malware execution, or successful C2 activity.

---

## 4. TCP Source-Port Reuse Investigation

Four repeated source-port groups were identified.

| Source Port | Original Records | State Sequence |
|---|---:|---|
| 59224 | 4 | S0 -> S0 -> S0 -> SF |
| 59228 | 4 | S0 -> S0 -> S0 -> SF |
| 59236 | 5 | S0 -> S0 -> S0 -> S0 -> SF |
| 59240 | 4 | S0 -> S0 -> S0 -> SF |

Total repeated groups: **4**

Total records in these groups: **17**

The observed intervals contain recurring gaps around
7?9 seconds and 16.64 seconds, with one larger interval
around 32.64 seconds.

The overall target-flow mean interval was approximately
7.73 seconds, with a coefficient of variation near 0.979.

These observations support a retry-like behavioral hypothesis.

Repeated source-port records do not necessarily represent
independent connection attempts, and do not prove a
specific retry algorithm or periodic C2 beaconing.

---

## 5. Focused Evidence Construction

The focused dataset contains **25 events**.

`E001` is a verified full-source computed aggregate.

`E002` is a computed target-flow aggregate.

`E003?E025` are **23 original Zeek records**.

The computed aggregates are not individual raw connections.

All original selected records retain evidence lineage
through original source-line references, Zeek UIDs,
timestamps and source-line SHA-256 hashes.

The verified timeline is saved in:

`NT-03-Verified-Timeline.csv`

Timeline SHA-256:

`026ea56f226ba5e10a729e96ab62ffa6ed1fe82f914e5e561a5a0d96b8352d30`

---

## 6. Baseline AI Evaluation

Analysis ID: `AN-20261021-121055-9c32`

Model: `mistral:7b-instruct-v0.3-q4_K_S`

Human Review: **Corrected**

The baseline report recognized repeated TCP connections
and discussed potentially suspicious network activity.

However, it did not characterize the four verified
source-port reuse groups and their timing behavior
with sufficient precision.

It also contained incomplete required report sections
and unsupported behavioral interpretations.

Saved automated validation reported seven
medium-severity structural flags.

---

## 7. Grounded Detection Upgrade

The deterministic detection rule is:

`NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE`

It identifies repeated same-four-tuple connection records
and preserves source-backed evidence references.

Observed results:

- Four repeated source-port groups.
- Seventeen supporting original records.
- High confidence in the observed repeated pattern.
- No automatic C2 or malware verdict.

The source-grounded finding was verified in the saved
analysis record and in a read-only historical replay.

---

## 8. Post-Grounding AI Evaluation

Analysis ID: `AN-20261021-132533-02e7`

Model: `mistral:7b-instruct-v0.3-q4_K_S`

Human Review: **Corrected**

Post-grounding analysis retained the deterministic TCP
reuse finding independently of the AI narrative.

The AI recognized repeated communication but omitted
important quantitative details.

The report incorrectly claimed that there was no evidence
of completed connections or data transfer despite
supporting SF states and positive observed byte counts.

It also associated source port 51834 with TCP/80 traffic,
although the corresponding original evidence record
E013 has destination port 23.

Scanning or probing was suggested without adequate
scan-specific evidence.

Required report sections remained incomplete.

---

## 9. Semantic Validation V2

Semantic Validation V2 was installed after the
post-grounding human review.

Full regression result:

**293 -> 317 tests PASS**

Twenty-four additional regression tests were introduced.

A read-only replay of the saved post-grounding analysis
identified three review requests:

| Severity | Review Check |
|---|---|
| High | network_observed_tcp_data_contradiction |
| Medium | network_source_port_group_mismatch |
| Medium | network_tcp_retry_missing_quantification |

The replay also recognized the alternate heading
`SUSPICIOUS ACTIVITY`.

The three semantic findings represent evidence-based
requests for analyst review.

They are not automatic findings of compromise.

The historical AI output and saved human review
were not modified by replay.

---

## 10. Baseline vs Post-Grounding Comparison

| Criterion | Baseline | Post-Grounding |
|---|---|---|
| Focused events | 25 | 25 |
| Human review | Corrected | Corrected |
| Saved grounded TCP reuse finding | 0 | 1 |
| Saved structural flags | 7 | 7 |
| Behavioral source grounding | Not persisted | Persisted |
| Semantic V2 replay | Not part of baseline | 3 review requests detected |

The improved deterministic grounding does not imply
that the underlying Mistral report became factually correct.

AI report quality and independent evidence-grounding
capabilities must be evaluated separately.

---

## 11. Evidence Limitations

The analysis does not independently establish:

- Periodic beaconing.
- Exponential retry backoff.
- Confirmed command-and-control execution.
- Malware attribution from traffic alone.
- File contents or payload reconstruction.
- Successful compromise or data exfiltration.
- Authorization status or endpoint process attribution.

The original dataset includes source-supplied labels,
but these were excluded from blind AI evidence.

Further investigation would require endpoint telemetry,
additional network context, and corroborating evidence.

---

## 12. Final Assessment

NT-03 demonstrates that deterministic source-grounded
detection can identify and preserve a network pattern
that a smaller local language model describes incompletely.

The grounded system verified four repeated source-port
groups involving 17 original Zeek records.

Semantic Validation V2 subsequently detected three
specific AI-report quality problems during read-only replay.

The verified conclusion is the presence of repeated
same-four-tuple TCP records consistent with a
retry-like behavioral pattern.

Malicious C2 activity and periodic beaconing are
not independently proven by these observations.

The technical verification and saved human reviews
are complete.

Final documentation manifest and evidence inventory
verification remain separate closure tasks.

---

## 13. Reproduction References

Focused Evidence:
`NT-03-focused.json`

Source Manifest:
`NT-03-Source-Manifest.json`

Evidence Mapping:
`NT-03-evidence-mapping.csv`

Verified Timeline:
`NT-03-Verified-Timeline.csv`

Baseline Analysis:
`Results/AN-20261021-121055-9c32`

Post-Grounding Analysis:
`Results/AN-20261021-132533-02e7`

Semantic Replay Command:

`python -m SOC_NT03_Semantic_Validation_v2.upgrade --replay AN-20261021-132533-02e7`

---

**End of NT-03 Case Study**
