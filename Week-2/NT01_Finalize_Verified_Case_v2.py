#!/usr/bin/env python3
"""NT-01 read-only source replay + conservative 3-file final documentation (v2).

Place next to NT01_Prepare_Focused_Evidence.py in Week-2 project root.
  python NT01_Finalize_Verified_Case.py --check
  python NT01_Finalize_Verified_Case.py --finalize

Does not modify the source, focused artifacts, Core, Results, or human reviews.
This tool does NOT independently verify the review application's internal schema.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True  # Preserve existing project directories during import checks.

ROOT = Path.cwd()
BASE = ROOT / 'Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning'
OUT_TIMELINE = BASE / 'NT-01-Verified-Timeline.csv'
OUT_STUDY = BASE / 'NT-01-Case-Study.md'
OUT_MANIFEST = BASE / 'NT-01-Final-Verification-Manifest.json'
OUTPUTS = (OUT_TIMELINE, OUT_STUDY, OUT_MANIFEST)
BASELINE_ID = 'AN-20261020-011716-3d22'
POST_ID = 'AN-20261020-013537-8c86'
EXPECTED_SOURCE_SHA = 'f9282d987047ef37a807a575a353ff601ddbb1b389aa76e92214c302de2fbda9'
EXPECTED_FOCUSED_SHA = 'dcaa4d0f7dadf730d5880755db24b98e8fe5689b2af57e95631f8589135beae7'
EXPECTED_RULE = 'NETWORK_VERTICAL_PORT_SCAN'


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def need(cond: bool, msg: str):
    if not cond:
        raise RuntimeError('STOP: ' + msg)


def load_prep():
    f = ROOT / 'NT01_Prepare_Focused_Evidence.py'
    need(f.is_file(), 'Original evidence preparation script missing; run from Week-2 root')
    spec = importlib.util.spec_from_file_location('nt01_original_derivation', f)
    need(spec is not None and spec.loader is not None, 'Cannot import evidence preparation script')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def produce():
    need((ROOT / 'app.py').is_file() and (ROOT / 'Core').is_dir(), 'Run from Week-2 project root')
    need(not any(p.exists() for p in OUTPUTS),
         'One or more final documentation files already exist; no overwrites allowed')
    prep = load_prep()
    derived, events, mapping, stats = prep.create_payloads()
    need(len(events) == 31 and len(mapping) == 31, 'Expected E001 aggregate + 30 Zeek rows')
    for path, expected_bytes in derived:
        need(path.is_file(), f'Missing source-derived artifact {path}')
        need(path.read_bytes() == expected_bytes, f'Derivation or SHA256 mismatch: {path.name}')
    need(digest(prep.SOURCE.read_bytes()) == EXPECTED_SOURCE_SHA, 'Original source hash changed')
    need(digest(prep.FOCUSED.read_bytes()) == EXPECTED_FOCUSED_SHA, 'Focused source hash changed')

    _, _, all_rows = prep.source_rows()
    src_lines = prep.SOURCE.read_bytes().splitlines()
    line_index = {r['line']: r for r in all_rows}
    need(len(all_rows) == 65895 and len(src_lines) == 65904, 'Full source count mismatch')
    need(stats['scan_pair_tcp_records'] == 65747, 'Full source TCP count mismatch')
    need(stats['scan_pair_distinct_destination_ports'] == 65535, 'Full source target port count mismatch')
    need(stats['scan_pair_connection_states'] == {'REJ': 65620, 'RSTO': 15, 'S0': 112},
         'Unexpected scan-pair states')
    need(events[0].get('record_kind') == 'VERIFIED_FULL_SOURCE_AGGREGATE_NOT_RAW_ZEEK_EVENT',
         'E001 must be a derived aggregate')
    need(mapping[0]['focused_ref'] == 'E001' and mapping[0]['original_line_sha256'] == '',
         'E001 cannot map to a single original connection')

    timeline = []
    refs_seen = set()
    for i, (e, m) in enumerate(zip(events[1:], mapping[1:]), 2):
        ref = f'E{i:03d}'
        need(m['focused_ref'] == ref and ref not in refs_seen, f'Invalid evidence ref {ref}')
        refs_seen.add(ref)
        need(e['record_kind'] == 'ZEEK_CONN_ORIGINAL_SOURCE_ROW', f'Non-source row at {ref}')
        n = e['source_line']
        need(type(n) is int and 1 <= n <= len(src_lines), f'Invalid source line {ref}')
        need(n in line_index, f'Source line is not a Zeek connection: {ref}')
        original = line_index[n]
        row = original['row']
        need(original['raw_sha'] == digest(src_lines[n - 1]), f'Original line digest error {ref}')
        need(e['source_line_sha256'] == m['original_line_sha256'] == original['raw_sha'],
             f'Source line hash mismatch {ref}')
        need(str(m['original_source_line']) == str(n) and m['zeek_uid'] == e['zeek_uid'] == row['uid'],
             f'UID/source line mapping mismatch {ref}')
        need(m['original_epoch_ts'] == e['zeek_ts_exact'] == row['ts'],
             f'Original epoch mismatch {ref}')
        checks = {'src_ip': 'id.orig_h', 'src_port': 'id.orig_p',
                  'dst_ip': 'id.resp_h', 'dst_port': 'id.resp_p',
                  'proto': 'proto', 'conn_state': 'conn_state'}
        for field, source_field in checks.items():
            need(str(e[field]) == str(row[source_field]), f'Incorrect {field} in {ref}')
        need(e['timestamp'] == prep.iso_utc(row['ts']), f'UTC mismatch {ref}')
        timeline.append({
            'Evidence Ref': ref, 'Timestamp UTC': e['timestamp'],
            'Source IP': e['src_ip'], 'Source Port': e['src_port'],
            'Destination IP': e['dst_ip'], 'Destination Port': e['dst_port'],
            'Protocol': e['proto'], 'Zeek Service': e['service'],
            'Connection State': e['conn_state'], 'Zeek UID': e['zeek_uid'],
            'Source Line': n, 'Source Line SHA256': original['raw_sha'],
            'Selection Category': e['sampling_category'],
            'Evidence Kind': 'Original Zeek connection',
        })
    need(len(timeline) == len(refs_seen) == 30, 'Not exactly 30 original events')
    timeline.sort(key=lambda x: (x['Timestamp UTC'], int(x['Source Line'])))
    by_ref = {v['Evidence Ref']: v for v in timeline}
    expected_endpoints = {
        'E002': ('192.168.16.130', '192.168.16.1', '49949', '53', 'udp'),
        'E011': ('192.168.16.132', '192.168.16.130', '44372', '64112', 'tcp'),
        'E031': ('192.168.16.130', '192.168.16.1', '51814', '53', 'udp'),
    }
    for ref, truth in expected_endpoints.items():
        t = by_ref[ref]
        observed = (t['Source IP'], t['Destination IP'], t['Source Port'],
                    t['Destination Port'], t['Protocol'])
        need(observed == truth, f'Known original direction/port check failed: {ref}')

    from Core.log_parser import load_file
    from Core import grounded_detection, network_grounding, network_semantics
    parsed = load_file(prep.FOCUSED, source_hint='network')
    need(parsed['source_type'] == 'network' and not parsed['warnings'] and len(parsed['events']) == 31,
         'Parser compatibility check failed')
    findings = grounded_detection.detect(parsed['events'])['behavioral_findings']
    targeted = [x for x in findings if x['rule_id'] == EXPECTED_RULE]
    need(len(targeted) == 1, 'Expected a single independent grounded port scan detection')
    finding = targeted[0]
    need(finding['confidence_in_observed_pattern'] == 'high' and
         finding.get('details', {}).get('aggregate_is_raw_connection') is False,
         'Expected grounded scan confidence/aggregate boundary not met')

    analysis_paths = [ROOT / 'Results' / x / 'analysis.json' for x in (BASELINE_ID, POST_ID)]
    need(all(p.is_file() for p in analysis_paths), 'Historical and post-grounding results must exist')
    post_record = json.loads(analysis_paths[1].read_text(encoding='utf-8-sig'))
    saved_grounding = post_record.get('grounding') or {}
    saved = [x for x in saved_grounding.get('behavioral_findings', [])
             if x.get('rule_id') == EXPECTED_RULE]
    need(len(saved) == 1 and saved[0].get('confidence_in_observed_pattern') == 'high'
         and 'E001' in saved[0].get('evidence_refs', []),
         'Saved post-grounding analysis is missing the verified scan finding')

    # Recalculate v2 flags from actual saved report rather than transcribing counts.
    from SOC_Network_Semantic_v2.demo import extract_sections
    sections = extract_sections(post_record)
    need(sections is not None and len(sections) >= 3, 'Could not parse saved AI report sections')
    v1_requests = network_grounding.review_requests(sections, parsed['events'])
    v2_requests = network_semantics.review_requests(sections, parsed['events'])
    need(len(v2_requests) > 0, 'Unexpectedly empty network attribution replay')
    v2_counts = dict(Counter(x['check'] for x in v2_requests))

    csv_s = io.StringIO(newline='')
    cols = list(timeline[0])
    writer = csv.DictWriter(csv_s, fieldnames=cols, lineterminator='\n')
    writer.writeheader()
    writer.writerows(timeline)
    timeline_bytes = csv_s.getvalue().encode('utf-8')

    src_sha = digest(prep.SOURCE.read_bytes())
    first, last = stats['scan_pair_utc_start'], stats['scan_pair_utc_end']
    study = f"""# NT-01 — Source-Verified Vertical TCP Port Scanning Case Study

**Track:** DEPI P5 — AI-Assisted SOC Analysis  
**Network source:** Zeek `conn.log`, pinned Git repository `dikshitdhawan/NTA-Zeek-Threat-Detection-Lab`  
**Original SHA-256:** `{src_sha}`  
**Evidence scope:** 65,895 original Zeek connection records; 31 focused records (1 derived summary + 30 source rows).

## Evidence integrity and provenance

The original Zeek dataset and metadata were recomputed against the pinned-source evidence preparation logic. The saved focused JSON, mapping CSV, full-source statistics, and selection manifest match their source-derived bytes and SHA-256 values. All **30 selected original Zeek rows** were independently matched to the corresponding original source line, raw line SHA-256, Zeek UID, epoch timestamp, UTC rendering, source/destination IP, source/destination port, protocol and connection state. The project parser read 31 entries as network evidence with no warnings.

**Critical distinction:** `E001` is a *verified computed aggregate* of the complete source, **not a captured network connection**. `E002`–`E031` are sampled *original Zeek source records*; the source-derived timeline CSV contains those 30 connection rows, not a fictitious connection for `E001`.

## Verified network findings

| Metric | Source-derived result |
|---|---|
| Observed behavior | High-confidence **vertical TCP destination-port scan pattern** |
| Originator | `192.168.16.132` |
| Responder | `192.168.16.130` |
| Original connection records | **65,895** |
| TCP records for scan pair | **65,747** |
| Distinct destination TCP ports for scan pair | **65,535** (targeted; not necessarily open) |
| Pair states | **REJ 65,620; RSTO 15; S0 112** |
| Scan-pair time range (UTC) | `{first}` to `{last}` |
| Duration | Approximately **738.269 seconds** |
| Authorization / actor intent | **Unknown / not established** |
| Open ports / exploitation / compromise | **Not established** |

A single source targeted nearly the entire TCP destination-port range of one target over a concentrated period. This strongly supports a vertical port-scanning pattern, independent of authorization or malign intent. Zeek `REJ` indicates rejected connection attempts and by itself does not prove firewall enforcement or compromise. The source and destination are private IP addresses, which does not establish benignity.

## Context events vs. scan events

`E002` and `E031` are **UDP DNS** contextual events (`192.168.16.130` → `192.168.16.1:53`), **not** TCP port-scan flows. `E011` is a TCP scan-pair flow (`192.168.16.132:44372` → `192.168.16.130:64112`, state `REJ`). The verified timeline preserves source and destination *ports* separately; source-port numbers must never be reported as destination ports.

## AI analysis, validation and human-in-the-loop

- **Baseline analysis:** `{BASELINE_ID}` — failed to explicitly identify the high-confidence scan pattern and misinterpreted aggregate `E001` as a raw connection.
- **Post-grounding analysis:** `{POST_ID}` — recognized aggregate `E001`, but still failed to name the scan pattern and incorrectly attributed multiple connection directions/port roles.
- **Grounded detector:** Saved independent finding `{EXPECTED_RULE}`, high confidence **in the observed pattern**, not in malicious intent or compromise.
- **Semantic replay:** {len(v1_requests)} v1 network review request(s) and {len(v2_requests)} v2 review request(s), counted from the saved post-grounding report. Types: {', '.join(f'`{k}` ({n})' for k,n in sorted(v2_counts.items()))}.
- **Review scope:** CLI human reviews were reported as `Corrected` for the baseline and post-grounding analyses. This finalizer does *not* independently inspect or certify the application-specific review storage schema; it leaves both saved reviews unchanged.

**Do not interpret {len(v2_requests)} v2 flags as {len(v2_requests)} independent security incidents.** Repeated incorrect assertions in multiple report sections and separately referenced evidence events can produce multiple review requests.

## Verified source-derived timeline

See `NT-01-Verified-Timeline.csv` for all 30 selected original connection rows, sorted chronologically and carrying references, precise UTC timestamps, source-line IDs, UIDs and SHA-256 hashes. The aggregate scan period is described above, **not inserted as a fabricated packet, connection or user action**. The 30 rows are a **sample**, not an exhaustive incident timeline of all 65,895 original source records.

## Investigation constraints and follow-up

Determine scan authorization from change records/registered testing, assess endpoint and firewall telemetry, identify the scan tool if available, and compare against other network sources. This evidence does not establish open ports, successful compromise, exfiltration, or attacker identity. Keep security conclusions separated from observed network facts.

## Provenance and safety

Source logs, four derived evidence artifacts, `Core`, `Results`, and existing human reviews were read-only throughout this finalization. Generated documents were created exclusively, with no overwrite.
"""
    study_bytes = study.encode('utf-8')
    input_paths = (prep.SOURCE, prep.SOURCE_MANIFEST, prep.FOCUSED, prep.MAPPING,
                   prep.STATS, prep.SELECTION, *analysis_paths)
    document_manifest = {
        'case_id': 'NT-01', 'status': 'source_grounded_documentation',
        'verification_scope': 'source/raw selected lines/derived artifacts/parser/detector/saved grounding/semantic replay',
        'human_review_schema_checked': False,
        'cli_reported_human_review_status': 'Corrected (not independently verified by this script)',
        'original_source_line_count': len(src_lines),
        'original_connection_records': len(all_rows),
        'focused_events': len(events), 'computed_aggregates': 1,
        'original_sampled_zeek_connections': len(timeline),
        'evidence_to_raw_source_mappings_verified': '30/30',
        'network_rule': EXPECTED_RULE,
        'grounded_confidence_in_observed_pattern': finding['confidence_in_observed_pattern'],
        'v1_network_semantic_review_requests_replayed': len(v1_requests),
        'v2_network_semantic_review_requests_replayed': len(v2_requests),
        'v2_request_categories': v2_counts,
        'inputs': {str((ROOT / p).relative_to(ROOT)).replace('\\', '/'): digest(p.read_bytes()) for p in input_paths},
        'outputs': {
            OUT_TIMELINE.name: digest(timeline_bytes),
            OUT_STUDY.name: digest(study_bytes),
        },
        'limitations': [
            'E001 is an aggregate, not an individual network flow',
            '30 sampled Zeek connections are not an exhaustive source timeline',
            'Evidence establishes port scan pattern, not unauthorized intent or compromise',
            'Internal review schema not inspected',
            'The final-verification manifest omits its own SHA256 to avoid circular hashes',
        ]
    }
    manifest_bytes = (json.dumps(document_manifest, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    return [(OUT_TIMELINE, timeline_bytes), (OUT_STUDY, study_bytes), (OUT_MANIFEST, manifest_bytes)], len(v1_requests), len(v2_requests), v2_counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check', action='store_true', help='Read-only validation and output preview')
    modes.add_argument('--finalize', action='store_true', help='Require confirmation then exclusively create three documents')
    args = parser.parse_args()
    print('=== NT-01 VERIFIED FINAL DOCUMENTATION ===')
    outputs, n_v1, n_v2, groups = produce()
    print('Original source, metadata, focus, mapping, statistics, selection: SHA/derivation MATCH')
    print('Source connections: 65,895 | Scan pair: 65,747 TCP | Distinct ports: 65,535')
    print('E001 computed aggregate: VERIFIED (NOT RAW CONNECTION)')
    print('E002-E031 raw original line/UID/time/direction/port/hash mappings: 30/30 PASS')
    print('Parser: network, 31 events, no warnings')
    print('Independent detection: NETWORK_VERTICAL_PORT_SCAN / high')
    print('Saved post-grounding finding: VERIFIED')
    print('Semantic replay: v1 network requests=', n_v1, '; new v2 requests=', n_v2, '; categories=', groups)
    print('Human review: CLI-reported Corrected; internal schema NOT inspected')
    print('Core / Results / reviews / source evidence: UNCHANGED')
    print('\n=== FILES TO CREATE (NO OVERWRITES) ===')
    for p, data in outputs:
        print('CREATE:', p, '| bytes:', len(data), '| SHA256:', digest(data))
    if args.check:
        print('\nSTATUS: NT-01 READY TO FINALIZE - READ-ONLY VERIFICATION PASS')
        return
    if input('Type FINALIZE to create these 3 documents (Enter cancels): ').strip() != 'FINALIZE':
        print('CANCELLED: No files written')
        return
    created = []
    try:
        for p, data in outputs:
            with p.open('xb') as file:
                created.append(p)
                file.write(data)
                file.flush()
            need(p.read_bytes() == data, f'New file write verification failed: {p}')
    except Exception:
        for p in created:
            p.unlink(missing_ok=True)
        raise
    print('\n=== FINAL STATUS ===')
    print('Timeline: 30 genuine, chronological, source-verified Zeek connection records')
    print('Case Study: CREATED')
    print('Integrity Manifest: CREATED')
    print('New output hashes: VERIFIED')
    print('Original evidence / Core / Results / reviews: UNCHANGED')
    print('STATUS: NT-01 DOCUMENTATION COMPLETE (human review schema verification separate)')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)
