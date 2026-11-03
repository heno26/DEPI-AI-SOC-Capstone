# NT-02 — DNS Anomaly

## Overview
This dataset supports the investigation of anomalous DNS activity using Zeek DNS logs.

The investigation focuses on unusual DNS query patterns, potentially suspicious domain resolution behavior, and network indicators requiring SOC analyst review.

## Dataset Information
- Case ID: NT-02
- Scenario: DNS Anomaly
- Category: Network Attack
- Log Source: Zeek dns.log
- Project: DEPI-P5
- Phase: Week 2 — AI-Assisted SOC Analysis

## Files

| File | Description |
|---|---|
| NT-02-Case-Study.md | Investigation case study and findings |
| NT-02-evidence-mapping.csv | Mapping between selected DNS events and supporting evidence |
| NT-02-final-Verification-Manifest.json | Final evidence verification metadata |
| NT-02-focused.json | Focused DNS dataset for AI-assisted analysis |
| NT-02-Selection-Manifest.json | Event selection documentation |
| NT-02-Source-Manifest.json | Original dataset source information |
| NT-02-verified-Full-Source-Statistics.json | Verified statistics from the original DNS logs |
| NT-02-Verified-Timeline.csv | Chronological timeline of investigated DNS events |
| NT-02-Zeek-dns-original.txt | Original Zeek DNS logs |

## Investigation Objectives

1. Identify anomalous DNS query patterns.
2. Examine suspicious domain resolution activity.
3. Analyze query frequency and temporal behavior.
4. Correlate selected DNS events with original evidence.
5. Reconstruct the investigation timeline.
6. Support AI-assisted SOC triage and classification.

## Evidence Integrity

Original Zeek DNS logs are preserved separately from the focused investigation dataset.

Evidence mapping, source manifests, and verification records support traceability between selected events and their original source.

Anomalous DNS behavior alone does not establish malicious activity.

## AI-Assisted SOC Integration

The focused dataset supports the DEPI-P5 AI-assisted SOC analysis pipeline.

The AI component assists with:

- DNS anomaly interpretation.
- Suspicious activity classification.
- Evidence-based investigation summaries.
- Potential false-positive identification.
- SOC report generation.

All AI-generated conclusions require evidence verification and human analyst validation.

## Project

DEPI-P5 — AI-Assisted SOC Automation & Incident Response

Week 2 — AI-Assisted Security Log Analysis
