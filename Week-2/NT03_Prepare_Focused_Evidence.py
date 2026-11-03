#!/usr/bin/env python3
"""DEPI P5 / NT-03: source-verified, label-blind focused Zeek evidence.

From the Week-2 project root:
    python NT03_Prepare_Focused_Evidence.py --check
    python NT03_Prepare_Focused_Evidence.py --create

--check creates no permanent project files (temporary parser probe cleaned up).
--create asks for CREATE, then exclusively creates four new evidence artifacts.
No edits to original logs, source manifest, Core, Results or human reviews.

E001 and E002 are computed aggregates, NOT original individual Zeek flows.
E003-E025 are selected original Zeek rows. The source-supplied 'label' and
'detailed-label' values are deliberately NEVER copied into AI-visible evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import statistics
import sys
import tempfile

ROOT = Path.cwd().resolve()
BASE = ROOT / 'Data' / 'Real-Datasets' / 'Network-Attacks' / 'NT-03-C2-Beaconing'
SOURCE = BASE / 'NT-03-Zeek-conn-original.labeled.log'
SOURCE_MANIFEST = BASE / 'NT-03-Source-Manifest.json'
FOCUSED = BASE / 'NT-03-focused.json'
MAPPING = BASE / 'NT-03-evidence-mapping.csv'
STATS = BASE / 'NT-03-Verified-Full-Source-Statistics.json'
SELECTION = BASE / 'NT-03-Selection-Manifest.json'
EXPECTED_SHA = '12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f'
EXPECTED_SOURCE_BYTES = 31179
EXPECTED_SOURCE_LINES = 246
EXPECTED_CONNECTIONS = 237
EXPECTED_FIELDS = 23
EXPECTED_TARGET_COUNT = 24
TARGET = ('192.168.1.199', '46.101.251.172', '80', 'tcp')
PORT_GROUPS = {'59224': 4, '59228': 4, '59236': 5, '59240': 4}
UTC_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
INPUT_VISIBLE_FIELDS = (
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto',
    'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig',
    'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes',
    'resp_pkts', 'resp_ip_bytes', 'tunnel_parents',
)


def require(condition, message):
    if not condition:
        raise RuntimeError('STOP: ' + message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canon_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False) + '\n').encode('utf-8')


def timestamp(ts: str) -> str:
    """Preserve original Zeek microsecond precision without float rounding."""
    try:
        value = Decimal(ts)
        require(value.is_finite() and value >= 0, 'Invalid epoch timestamp')
        whole = int(value)
        microseconds = (value - whole) * 1_000_000
        require(microseconds == microseconds.to_integral_value(), 'Timestamp finer than microseconds; do not truncate')
        dt = UTC_EPOCH + timedelta(seconds=whole, microseconds=int(microseconds))
        return dt.isoformat(timespec='microseconds').replace('+00:00', 'Z')
    except (ValueError, InvalidOperation, OverflowError) as exc:
        raise RuntimeError('STOP: Invalid Zeek timestamp ' + repr(ts)) from exc


def parse_original(source_bytes: bytes) -> tuple[list[dict], list[str], dict]:
    text = source_bytes.decode('utf-8-sig')
    physical_lines = text.splitlines()
    require(len(physical_lines) == EXPECTED_SOURCE_LINES, 'Source physical-line count mismatch')
    headers = {}
    records = []
    fields = None
    for number, raw_line in enumerate(physical_lines, 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('#'):
            head, *tail = line.split()
            if head in ('#path', '#fields', '#open'):
                require(head not in headers, 'Duplicate Zeek header ' + head)
                headers[head] = tail
            if head == '#fields':
                fields = tail
            continue
        require(fields is not None, 'Record before #fields header')
        # Pinned original has whitespace-separated columns, not reliable TSV-only.
        columns = line.split()
        require(len(columns) == len(fields), f'Malformed source line {number}: {len(columns)} != {len(fields)}')
        row = dict(zip(fields, columns))
        try:
            epoch = Decimal(row['ts'])
        except InvalidOperation as exc:
            raise RuntimeError(f'STOP: Invalid Zeek ts at line {number}') from exc
        require(epoch.is_finite(), f'Non-finite timestamp on source line {number}')
        records.append({
            'line': number,
            'ts': epoch,
            'timestamp': timestamp(row['ts']),
            'line_sha256': sha(raw_line.encode('utf-8')),
            'row': row,  # only held in memory; labels never serialized to model files
        })
    require(headers.get('#path') == ['conn'], 'Not Zeek conn.log')
    require(fields is not None and len(fields) == EXPECTED_FIELDS, 'Unexpected Zeek schema field count')
    require(fields[-2:] == ['label', 'detailed-label'], 'Unexpected source classification column names')
    require(set(INPUT_VISIBLE_FIELDS) == set(fields) - {'label', 'detailed-label'},
            'Unexpected source schema fields')
    require(len(records) == EXPECTED_CONNECTIONS, 'Connection record count mismatch')
    require(len({r['line'] for r in records}) == EXPECTED_CONNECTIONS, 'Duplicate source-line mappings')
    return records, fields, headers


def load_original():
    require((ROOT / 'app.py').is_file(), 'Run from D:\\Desktop\\w\\Week-2 (app.py missing)')
    require(SOURCE.is_file(), 'Original Zeek source file missing: ' + str(SOURCE))
    require(SOURCE_MANIFEST.is_file(), 'Original source manifest missing: ' + str(SOURCE_MANIFEST))
    data = SOURCE.read_bytes()
    require(len(data) == EXPECTED_SOURCE_BYTES, 'Original byte count mismatch')
    require(sha(data) == EXPECTED_SHA, 'Original source SHA256 mismatch')
    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding='utf-8-sig'))
    require(manifest.get('saved_sha256', '').lower() == EXPECTED_SHA, 'Source manifest saved SHA256 mismatch')
    require(manifest.get('discovery_sha256', '').lower() == EXPECTED_SHA, 'Source manifest discovery SHA256 mismatch')
    require(manifest.get('byte_count') == EXPECTED_SOURCE_BYTES, 'Manifest source size mismatch')
    require(manifest.get('connection_records') == EXPECTED_CONNECTIONS, 'Manifest record count mismatch')
    require(manifest.get('physical_line_count') == EXPECTED_SOURCE_LINES, 'Manifest line count mismatch')
    require(manifest.get('zeek_field_count') == EXPECTED_FIELDS, 'Manifest Zeek field count mismatch')
    require(manifest.get('labels_must_be_withheld_from_blind_ai_analysis') is True,
            'Source manifest label separation requirement missing')
    records, fields, headers = parse_original(data)
    require(manifest.get('zeek_fields') == fields, 'Manifest field order mismatch')
    return records, manifest, headers


def net_key(record: dict) -> tuple[str, str, str, str]:
    r = record['row']
    return (r['id.orig_h'], r['id.resp_h'], r['id.resp_p'], r['proto'])


def intervals_for(items: list[dict]):
    ordered = sorted(items, key=lambda x: (x['ts'], x['line']))
    return [ordered[i + 1]['ts'] - ordered[i]['ts'] for i in range(len(ordered)-1)]


def stats_float(data: list[Decimal]) -> dict:
    if not data:
        return {'interval_count': 0, 'mean_seconds': None, 'median_seconds': None,
                'stddev_seconds': None, 'cv': None}
    nums = [float(x) for x in data]
    avg = statistics.mean(nums)
    std = statistics.pstdev(nums)
    return {'interval_count': len(data), 'mean_seconds': round(avg, 6),
            'median_seconds': round(statistics.median(nums), 6),
            'stddev_seconds': round(std, 6),
            'cv': round(std / avg, 6) if avg > 0 else None}


def choose_records(records: list[dict]):
    """Selection criteria use ONLY network fields and timestamps, NOT labels."""
    target = sorted([r for r in records if net_key(r) == TARGET], key=lambda r: (r['ts'], r['line']))
    require(len(target) == EXPECTED_TARGET_COUNT, 'Unexpected target flow count')
    require(Counter(r['row']['conn_state'] for r in target) == {'S0': 13, 'SF': 11},
            'Unexpected target flow Zeek states')
    groups = defaultdict(list)
    for r in target:
        groups[r['row']['id.orig_p']].append(r)
    repeated = {p: v for p, v in groups.items() if len(v) >= 3}
    require({p: len(v) for p, v in repeated.items()} == PORT_GROUPS,
            'Repeated source-port cluster mismatch')
    singles = sorted((v[0] for v in groups.values() if len(v) == 1),
                     key=lambda r: (r['ts'], r['line']))
    require(len(singles) == 7, 'Unexpected singleton context count')
    singleton_context = [singles[0], singles[len(singles) // 2], singles[-1]]
    tcp23 = [r for r in records if net_key(r) == (TARGET[0], TARGET[1], '23', 'tcp')]
    require(len(tcp23) == 1, 'Unexpected TCP/23 context count')
    udp = sorted((r for r in records if r['row']['id.orig_h'] == TARGET[0]
                  and r['row']['id.resp_p'] == '123' and r['row']['proto'] == 'udp'),
                 key=lambda r: (r['ts'], r['line']))
    require(len(udp) >= 2, 'Insufficient UDP/123 comparison context')
    entries = []
    for port in sorted(repeated, key=int):
        entries += [(r, 'repeated_tcp_source_port') for r in repeated[port]]
    entries += [(r, 'tcp_singleton_context') for r in singleton_context]
    entries += [(tcp23[0], 'tcp_other_port_context')]
    entries += [(udp[0], 'udp_service_comparison'), (udp[-1], 'udp_service_comparison')]
    entries.sort(key=lambda item: (item[0]['ts'], item[0]['line']))
    source_lines = [r['line'] for r, _ in entries]
    require(len(entries) == 23 and len(set(source_lines)) == 23, 'Expected exactly 23 unique selected rows')
    require(Counter(cat for _, cat in entries) == {
        'repeated_tcp_source_port': 17, 'tcp_singleton_context': 3,
        'tcp_other_port_context': 1, 'udp_service_comparison': 2,
    }, 'Selected evidence category mismatch')
    return entries, target, repeated


def produce():
    records, manifest, headers = load_original()
    entries, target, repeated = choose_records(records)
    start = min(r['ts'] for r in records)
    end = max(r['ts'] for r in records)
    target_interval = intervals_for(target)
    per_port = {}
    for port in sorted(repeated, key=int):
        sub = sorted(repeated[port], key=lambda r: (r['ts'], r['line']))
        gaps = intervals_for(sub)
        per_port[port] = {
            'connection_records': len(sub),
            'source_line_numbers': [r['line'] for r in sub],
            'connection_states': [r['row']['conn_state'] for r in sub],
            'zeek_histories': [r['row']['history'] for r in sub],
            'intervals_seconds': [float(x) for x in gaps],
            **stats_float(gaps),
        }
    original_states = dict(sorted(Counter(r['row']['conn_state'] for r in records).items()))
    original_protocols = dict(sorted(Counter(r['row']['proto'] for r in records).items()))
    target_states = dict(sorted(Counter(r['row']['conn_state'] for r in target).items()))
    source_time = {r['ts']: r['timestamp'] for r in records}
    require(original_protocols == {'tcp': 27, 'udp': 210}, 'Full-source protocol distribution mismatch')
    require(target_states == {'S0': 13, 'SF': 11}, 'Target connection-state counts mismatch')
    summary = {
        'source_sha256': EXPECTED_SHA,
        'source_format': 'Zeek conn.log (source supplied labeled version; classification stripped from AI evidence)',
        'total_original_connection_records': len(records),
        'total_original_physical_lines': EXPECTED_SOURCE_LINES,
        'source_protocol_counts': original_protocols,
        'source_conn_state_counts': original_states,
        'first_observed_utc': source_time[start],
        'last_observed_utc': source_time[end],
        'target_src_ip': TARGET[0], 'target_dst_ip': TARGET[1],
        'target_dst_port': int(TARGET[2]), 'target_protocol': TARGET[3],
        'target_connection_records': len(target),
        'target_conn_state_counts': target_states,
        'target_source_port_reuse_group_count': len(repeated),
        'target_source_port_reuse_record_count': sum(len(x) for x in repeated.values()),
        'target_source_port_group_statistics': per_port,
        'target_first_utc': target[0]['timestamp'],
        'target_last_utc': target[-1]['timestamp'],
        'target_coverage_seconds': float(target[-1]['ts'] - target[0]['ts']),
        'target_overall_interval_stats': stats_float(target_interval),
        'target_periodic_beaconing_confirmed': False,
        'source_file_lineage_note': 'Original SHA256 and source manifest independently verified before computing statistics.',
        'interpretation_limit': 'Observed repeated-connection and same-source-port timing patterns are NOT proof of C2, periodic beaconing, TCP retransmission, unauthorized access or transfer of specific file content.',
    }
    agg_source = {
        'record_kind': 'VERIFIED_FULL_SOURCE_CONN_AGGREGATE_NOT_RAW_ZEEK_EVENT',
        'timestamp': source_time[start],
        'log_source': 'Zeek conn.log', 'source_sha256': EXPECTED_SHA,
        'total_connection_records': len(records), 'protocol_counts': original_protocols,
        'conn_state_counts': original_states,
        'first_observed_utc': source_time[start], 'last_observed_utc': source_time[end],
        'interpretation_limit': 'Calculated whole-source connection summary. NOT an individual Zeek connection. No malicious intent or periodic beaconing established.',
    }
    agg_cluster = {
        'record_kind': 'VERIFIED_TCP_CONNECTION_RETRY_CLUSTER_AGGREGATE_NOT_RAW_ZEEK_EVENT',
        'timestamp': target[0]['timestamp'],
        'log_source': 'Zeek conn.log', 'source_sha256': EXPECTED_SHA,
        'src_ip': TARGET[0], 'dst_ip': TARGET[1], 'dst_port': int(TARGET[2]), 'proto': TARGET[3],
        'target_connection_records': len(target), 'target_conn_state_counts': target_states,
        'reused_source_port_groups': len(repeated),
        'reused_source_port_records': sum(map(len, repeated.values())),
        'source_port_groups': per_port,
        'first_observed_utc': target[0]['timestamp'], 'last_observed_utc': target[-1]['timestamp'],
        'overall_interval_statistics': stats_float(target_interval),
        'interpretation_limit': 'Source-computed timing cluster: possible retry/backoff, NOT a captured connection or confirmed retransmission, periodic beaconing, or C2 activity.',
    }
    events = [agg_source, agg_cluster]
    mapping = []
    mapping.append({'focused_ref': 'E001', 'record_kind': agg_source['record_kind'],
                    'original_source_line': 'AGGREGATE_NOT_A_SOURCE_ROW',
                    'original_line_sha256': '', 'zeek_uid': '', 'selection_category': 'computed_full_source'})
    mapping.append({'focused_ref': 'E002', 'record_kind': agg_cluster['record_kind'],
                    'original_source_line': 'AGGREGATE_NOT_A_SOURCE_ROW',
                    'original_line_sha256': '', 'zeek_uid': '', 'selection_category': 'computed_target_cluster'})
    for idx, (rec, category) in enumerate(entries, 3):
        r = rec['row']
        # Strict allowlist: do NOT serialize label or detailed-label, including under raw/meta.
        ev = {
            'record_kind': 'ZEEK_CONN_ORIGINAL_SOURCE_ROW',
            'timestamp': rec['timestamp'], 'log_source': 'Zeek conn.log',
            'source_sha256': EXPECTED_SHA,
            'zeek_ts_exact': r['ts'], 'zeek_uid': r['uid'],
            'src_ip': r['id.orig_h'], 'src_port': r['id.orig_p'],
            'dst_ip': r['id.resp_h'], 'dst_port': r['id.resp_p'],
            'proto': r['proto'], 'service': r['service'],
            'duration': r['duration'], 'orig_bytes': r['orig_bytes'],
            'resp_bytes': r['resp_bytes'], 'conn_state': r['conn_state'],
            'history': r['history'], 'orig_pkts': r['orig_pkts'],
            'resp_pkts': r['resp_pkts'], 'orig_ip_bytes': r['orig_ip_bytes'],
            'resp_ip_bytes': r['resp_ip_bytes'],
            'source_line': rec['line'], 'source_line_sha256': rec['line_sha256'],
            'selection_category': category,
        }
        events.append(ev)
        mapping.append({
            'focused_ref': f'E{idx:03d}', 'record_kind': ev['record_kind'],
            'original_source_line': rec['line'], 'original_line_sha256': rec['line_sha256'],
            'zeek_uid': r['uid'], 'original_epoch_ts': r['ts'],
            'timestamp_utc': rec['timestamp'], 'selection_category': category,
        })
    require(len(events) == 25 and len(mapping) == 25, 'Focused evidence count mismatch')
    focused = {
        'dataset': 'NT-03 Source-Verified Zeek Connection Timing',
        'evidence_scope': ('E001-E002 are verified COMPUTED summaries, NOT individual Zeek rows; '
                           'E003-E025 are 23 original Zeek connection records with exact source mapping. '
                           'Suspicious retry/backoff is a hypothesis, not established beaconing or compromise.'),
        'events': events,
    }
    focused_bytes = canon_json(focused)
    # The focused JSON must have NO source-supplied classification *values*.
    # The check does not reference any label-value text; labels are absent by strict field allowlist.
    for event in events:
        require('label' not in event and 'detailed-label' not in event,
                'Source classification fields leaked into AI evidence')
    require(b'detailed-label' not in focused_bytes and b'"label"' not in focused_bytes,
            'Source classification column leakage in focused bytes')
    mapout = io.StringIO(newline='')
    writer = csv.DictWriter(mapout, fieldnames=['focused_ref', 'record_kind', 'original_source_line', 'original_line_sha256', 'zeek_uid', 'original_epoch_ts', 'timestamp_utc', 'selection_category'], lineterminator='\n')
    # The raw entries also contain epoch and time, blank for computed records.
    writer.writeheader()
    for item in mapping:
        writer.writerow(item)
    mapping_bytes = mapout.getvalue().encode('utf-8')
    stats_bytes = canon_json(summary)
    selection = {
        'case_id': 'NT-03', 'source_sha256': EXPECTED_SHA,
        'original_source_manifest_sha256': sha(SOURCE_MANIFEST.read_bytes()),
        'source_record_count': len(records),
        'focused_event_count': len(events),
        'computed_aggregate_refs': ['E001', 'E002'],
        'original_zeek_record_ref_range': 'E003-E025',
        'selected_original_record_count': len(entries),
        'selected_source_lines': [r['line'] for r, _ in entries],
        'selected_category_counts': dict(sorted(Counter(c for _, c in entries).items())),
        'focused_sha256': sha(focused_bytes), 'mapping_sha256': sha(mapping_bytes),
        'statistics_sha256': sha(stats_bytes),
        'ground_truth_separation': 'Source-supplied class annotations omitted from the focused JSON; all 23 source rows selected only by observable connection fields.',
        'interpretation_limit': 'Timing patterns are NOT confirmed periodic beaconing, command/control success, or malicious actor attribution.',
    }
    selection_bytes = canon_json(selection)
    artifacts = ((FOCUSED, focused_bytes), (MAPPING, mapping_bytes),
                 (STATS, stats_bytes), (SELECTION, selection_bytes))
    return artifacts, events, mapping, summary


def parser_probe(focused_content: bytes, expected_events: list[dict]):
    # Never import a project module merely to cause a hidden write; parser is
    # imported only during validation and a temporary file is removed promptly.
    from Core.log_parser import load_file
    with tempfile.TemporaryDirectory(prefix='NT03-parser-probe-') as directory:
        path = Path(directory) / 'NT-03-focused.json'
        path.write_bytes(focused_content)
        parsed = load_file(path, source_hint='network')
        require(parsed.get('source_type') == 'network',
                'Parser classified focused data as ' + repr(parsed.get('source_type')))
        require(not parsed.get('warnings'), 'Parser warnings: ' + repr(parsed.get('warnings')))
        events = parsed.get('events')
        require(isinstance(events, list) and len(events) == 25,
                'Parser did not preserve 25 focused evidence records')
        require([ev.get('ref') for ev in events] == [f'E{i:03d}' for i in range(1, 26)],
                'Parser evidence references E001-E025 missing/out of sequence')
        for parsed_ev, original in zip(events, expected_events):
            visible = json.dumps(parsed_ev, ensure_ascii=False, default=str)
            require(original['record_kind'] in visible, 'Parser lost record kind')
            if original['record_kind'] == 'ZEEK_CONN_ORIGINAL_SOURCE_ROW':
                for key in ('zeek_uid', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                            'conn_state', 'history', 'timestamp'):
                    require(str(original[key]) in visible,
                            'Parser did not expose original field ' + key)
        require('C&C-FileDownload' not in str(parsed) and 'Malicious' not in str(parsed),
                'Class labels exposed to model-visible parser output')
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='Verify source/selection/parser without saving permanent files')
    mode.add_argument('--create', action='store_true', help='Create four new files with explicit confirmation')
    args = parser.parse_args()
    print('=== NT-03 VERIFIED FOCUSED EVIDENCE PREPARATION ===', flush=True)
    require(not any(p.exists() for p in (FOCUSED, MAPPING, STATS, SELECTION)),
            'One or more target evidence files already exist; no overwrite permitted')
    artifacts, events, mapping, summary = produce()
    print('\n=== ORIGINAL SOURCE & SELECTION ===')
    print('Source SHA256: MATCH | Manifest: MATCH | Source Bytes:', EXPECTED_SOURCE_BYTES)
    print('Original connection records:', EXPECTED_CONNECTIONS)
    print('Source protocols:', summary['source_protocol_counts'])
    print('Target TCP flow:', f"{TARGET[0]} -> {TARGET[1]}:{TARGET[2]}")
    print('Target connection records:', summary['target_connection_records'])
    print('Connection states:', summary['target_conn_state_counts'])
    print('Repeated source-port groups:', summary['target_source_port_reuse_group_count'])
    print('Repeated-port source rows:', summary['target_source_port_reuse_record_count'])
    print('Observed timing summary:', summary['target_overall_interval_stats'])
    print('Selected original source rows:', len(events)-2)
    print('Selected categories:', dict(sorted(Counter(e.get('selection_category') for e in events[2:]).items())))
    print('\n=== MODEL-SAFE EVIDENCE BOUNDARY ===')
    print('E001-E002: COMPUTED AGGREGATES (NOT original conn.log rows)')
    print('E003-E025: 23 ORIGINAL conn.log source rows with SHA256/UID/UTC mapping')
    print('Original source classification values: WITHHELD FROM AI')
    print('Periodic Beaconing: NOT ESTABLISHED')
    print('Retry/Backoff: PATTERN REQUIRES HUMAN REVIEW')
    parsed = parser_probe(artifacts[0][1], events)
    print('\n=== CURRENT PROJECT PARSER ===')
    print('Format:', parsed.get('format'), '| Source Type:', parsed.get('source_type'))
    print('Focused events:', len(parsed['events']), '| Warnings:', parsed.get('warnings'))
    print('Source timestamps, UIDs, direction, states, history in parsed evidence: PASS')
    print('\n=== FILES TO CREATE (EXCLUSIVE / NO OVERWRITES) ===')
    for path, content in artifacts:
        print(f'CREATE: {path.relative_to(ROOT)} | bytes={len(content)} | SHA256={sha(content)}')
    if args.check:
        print('\nOriginal Logs / Core / Results / Human Reviews: UNCHANGED')
        print('STATUS: NT-03 FOCUSED EVIDENCE READY TO CREATE - READ-ONLY PASS')
        return
    if input('\nType CREATE to save the four evidence files (Enter cancels): ').strip() != 'CREATE':
        print('CANCELLED: no new project files written')
        return
    require(not any(p.exists() for p, _ in artifacts), 'One or more output files now exist; no overwrite')
    # Check source integrity again before write (we refuse an altered source).
    require(sha(SOURCE.read_bytes()) == EXPECTED_SHA, 'Original source changed during confirmation')
    created = []
    try:
        for path, content in artifacts:
            # exclusive create, never overwrite (including after race conditions).
            with path.open('xb') as fp:
                created.append(path)
                fp.write(content)
                fp.flush()
                os.fsync(fp.fileno())
            require(sha(path.read_bytes()) == sha(content), 'New output SHA256 mismatch: ' + str(path))
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    print('\nSource, focused, mapping, stats, selection: SHA-256 VERIFIED')
    print('Original Dataset / Core / Historical Results / Human Reviews: UNCHANGED')
    print('STATUS: NT-03 FOCUSED CONNECTION EVIDENCE READY FOR AI TRIAGE')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)
