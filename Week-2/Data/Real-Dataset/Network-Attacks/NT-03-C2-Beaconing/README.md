# NT-03 — C2 Beaconing

## Overview

This dataset supports the investigation of potential Command-and-Control (C2) beaconing activity using network security logs.

The investigation focuses on suspicious communication patterns, repeated outbound connections, timing intervals, and potential indicators of automated communication with external systems.

## Dataset Information

- Case ID: NT-03
- Scenario: Command-and-Control (C2) Beaconing
- Category: Network Attack
- Project: DEPI-P5
- Phase: Week 2 — AI-Assisted SOC Analysis
- Classification: Suspicious Network Activity
- Investigation Status: Requires Evidence-Based Validation

## Investigation Objectives

1. Identify potential C2 communication patterns.
2. Examine repeated network connections.
3. Analyze connection timing and periodicity.
4. Investigate suspicious source and destination relationships.
5. Correlate selected events with original network evidence.
6. Reconstruct the chronological activity timeline.
7. Support AI-assisted SOC triage and incident reporting.

## Evidence Structure

The investigation dataset may include:

| Evidence Component | Description |
|---|---|
| Original Network Logs | Raw network evidence retained for verification |
| Focused Dataset | Selected events prepared for AI-assisted analysis |
| Case Study | Investigation methodology and findings |
| Evidence Mapping | Relationships between selected events and original evidence |
| Source Manifest | Original dataset provenance information |
| Selection Manifest | Documentation of event selection |
| Verification Manifest | Final evidence validation metadata |
| Verified Timeline | Chronological reconstruction of network activity |
| Source Statistics | Statistical summary of original network evidence |

## Detection Considerations

Potential C2 beaconing indicators include:

- Repeated connections to the same destination.
- Regular or near-regular communication intervals.
- Unusual outbound communication patterns.
- Suspicious destination infrastructure.
- Automated communication behavior.

These indicators are not sufficient on their own to confirm malicious activity.

## Evidence Integrity

Original network evidence must remain unchanged.

Focused investigation records should be traceable to their original sources through evidence mapping and verification manifests.

Investigation conclusions must distinguish observed evidence from analytical assumptions.

## AI-Assisted SOC Integration

This dataset supports the DEPI-P5 AI-assisted SOC analysis pipeline.

The AI component assists with:

- Network behavior interpretation.
- Potential C2 activity identification.
- Evidence-based threat classification.
- False-positive assessment.
- Incident timeline reconstruction.
- SOC investigation report generation.

All AI-generated findings require evidence verification and human analyst validation.

## Project

DEPI-P5 — AI-Assisted SOC Automation & Incident Response

Week 2 — AI-Assisted Security Log Analysis
