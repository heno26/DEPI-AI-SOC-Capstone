# NT-03 ? Network TCP Retry-Like Behavior Investigation

Project: DEPI P5 ? AI-Assisted SOC Log Analysis

Dataset: Stratosphere IPS IoT-23

Capture: CTU-IoT-Malware-Capture-44-1

Status: Technical Investigation and Documentation Complete

## Overview

This investigation examines repeated TCP connections from
192.168.1.199 to 46.101.251.172 on destination port 80.

Verified observations:

- 237 original Zeek connection records.
- 24 investigated TCP/80 records.
- 13 S0 and 11 SF connection states in the target flow.
- 4 repeated source-port groups.
- 17 supporting original Zeek records.
- 25 focused events, including 2 computed aggregates.
- 23 original records in the verified evidence timeline.

The observed pattern supports investigation of retry-like
communication but does not independently prove periodic
beaconing, malicious C2 activity or compromise.

## Evidence and Documentation

- NT-03-Zeek-conn-original.labeled.log
- NT-03-Source-Manifest.json
- NT-03-focused.json
- NT-03-evidence-mapping.csv
- NT-03-Selection-Manifest.json
- NT-03-Verified-Full-Source-Statistics.json
- NT-03-Verified-Timeline.csv
- NT-03-Case-Study.md
- NT-03-Final-Verification-Manifest.json

E001-E002 are computed aggregates, not raw connections.

E003-E025 represent original source-mapped Zeek records.

## AI Evaluation

Baseline Analysis: AN-20261021-121055-9c32

Post-Grounding Analysis: AN-20261021-132533-02e7

Both human reviews: Corrected

Model: mistral:7b-instruct-v0.3-q4_K_S

## Grounded Detection

Rule: NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE

Detected 4 repeated groups supported by 17 original records.

The rule identifies the observed behavior without
automatically concluding malware infection or C2 activity.

## Semantic Validation V2

Regression Testing: 317 PASS

Read-only replay identified three review requests:

1. network_observed_tcp_data_contradiction
2. network_source_port_group_mismatch
3. network_tcp_retry_missing_quantification

Historical analyses and reviews were preserved.

## Reproduction

Run from the Week-2 project root.

Semantic replay command:

    python -m SOC_NT03_Semantic_Validation_v2.upgrade --replay AN-20261021-132533-02e7

Regression command:

    python -m unittest discover -s Testing

## Integrity

The Final Verification Manifest contains SHA-256
fingerprints for the eight preceding case artifacts.

Final Manifest SHA-256:

927b1e879ee955f3303e1bc3855f62bef259ddd1a7c05a967f3ee60ea108ef37

## Documentation References

Case Study: NT-03-Case-Study.md

Timeline: NT-03-Verified-Timeline.csv

Manifest: NT-03-Final-Verification-Manifest.json

## Limitations

Original dataset labels were excluded from the blind AI
evidence and focused selection.

Repeated connection records do not independently establish
exponential backoff, periodic beaconing, successful C2,
malware execution, or system compromise.

Additional endpoint and network telemetry would be needed
for stronger attribution.

NT-03 Documentation Complete.
