# NT-01 — Port Scanning

## Overview
This dataset supports the investigation of suspicious network
reconnaissance and potential port-scanning activity using Zeek
network connection logs.

## Dataset Information
- Case ID: NT-01
- Scenario: Port Scanning
- Category: Network Attack
- Log Source: Zeek conn.log
- Project: DEPI-P5
- Phase: Week 2 — AI-Assisted SOC Analysis

## Files

| File | Description |
|---|---|
| NT-01-Case-Study.md | Investigation case study and findings |
| NT-01-evidence-mapping.csv | Mapping between selected events and supporting evidence |
| NT-01-final-Verification-Manifest.json | Final verification metadata |
| NT-01-focused.json | Focused dataset for AI-assisted analysis |
| NT-01-Selection-Manifest.json | Event selection documentation |
| NT-01-Source-Manifest.json | Original dataset source information |
| NT-01-verified-Full-Source-Statistics.json | Verified source statistics |
| NT-01-Verified-Timeline.csv | Chronological investigation timeline |
| NT-01-Zeek-conn-original.txt | Original Zeek network connection logs |

## Investigation Objectives

1. Identify suspicious network reconnaissance.
2. Analyze connection patterns and destination ports.
3. Correlate selected events with original evidence.
4. Reconstruct the network activity timeline.
5. Support AI-assisted SOC triage and classification.

## Evidence Integrity

Original logs are retained separately from focused evidence.

Selection manifests, evidence mapping, and verification records
support traceability between selected events and source data.

## AI-Assisted SOC Integration

The focused dataset is intended for analysis through the
DEPI-P5 AI-assisted SOC pipeline.

AI-generated findings require evidence verification and
human analyst validation.

## Project
DEPI-P5 — AI-Assisted SOC Automation & Incident Response
