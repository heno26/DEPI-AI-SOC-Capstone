#!/usr/bin/env python3
"""DEPI P5 NT-01: source-grounded Zeek evidence selection, parser smoke test.

Usage from Week-2 root:
  python NT01_Prepare_Focused_Evidence.py --check
  python NT01_Prepare_Focused_Evidence.py --create

Does not alter Core, prior results, original evidence, or prior manifests.
E001 is EXPLICITLY a computed aggregate from the entire verified source, NOT a raw Zeek event.
E002+ are actual, individual Zeek source records with source-line SHA256 mapping.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import csv
import io
import json
import sys
import tempfile
from pathlib import Path

BASE = Path('Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning')
SOURCE = BASE / 'NT-01-Zeek-conn-original.log'
SOURCE_MANIFEST = BASE / 'NT-01-Source-Manifest.json'
FOCUSED = BASE / 'NT-01-focused.json'
MAPPING = BASE / 'NT-01-evidence-mapping.csv'
STATS = BASE / 'NT-01-Verified-Full-Source-Statistics.json'
SELECTION = BASE / 'NT-01-Selection-Manifest.json'
OUTPUTS = (FOCUSED, MAPPING, STATS, SELECTION)
SRC, DST = '192.168.16.132', '192.168.16.130'
SOURCE_SHA = 'f9282d987047ef37a807a575a353ff601ddbb1b389aa76e92214c302de2fbda9'
REQUIRED = ('ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'conn_state')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    h = hashlib.sha1()
    h.update(f'blob {len(data)}\0'.encode('ascii'))
    h.update(data)
    return h.hexdigest()


def iso_utc(epoch_text):
    """Reproduce source epoch fractional precision without assuming local timezone."""
    e = Decimal(epoch_text)
    if not e.is_finite() or e < 0:
        raise ValueError('Invalid epoch timestamp')
    seconds = int(e)
    date = datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    fraction = epoch_text.partition('.')[2]
    if fraction and not fraction.isdigit():
        raise ValueError('Unexpected fractional timestamp')
    return date + ('.' + fraction if fraction else '') + 'Z'


def source_rows():
    if not SOURCE.is_file() or not SOURCE_MANIFEST.is_file():
        raise RuntimeError('Source or source manifest missing')
    data = SOURCE.read_bytes()
    meta = json.loads(SOURCE_MANIFEST.read_text(encoding='utf-8-sig'))
    if sha(data).lower() != str(meta.get('sha256', '')).lower() or sha(data).lower() != SOURCE_SHA:
        raise RuntimeError('STOP: Source SHA-256 mismatch')
    if len(data) != int(meta.get('file_size_bytes', -1)) or len(data) != 8200705:
        raise RuntimeError('STOP: Source byte count mismatch')
    if git_blob(data).lower() != str(meta.get('git_blob_sha1','')).lower():
        raise RuntimeError('STOP: Original Git Blob SHA1 mismatch')
    lines = data.splitlines()
    if len(lines) != int(meta.get('source_line_count', -1)) or len(lines) != 65904:
        raise RuntimeError('STOP: Source line count mismatch')
    fields = None
    records = []
    for number, raw in enumerate(lines, 1):
        if raw.startswith(b'#fields\t'):
            if fields is not None:
                raise RuntimeError('Multiple unexpected #fields headers')
            fields = raw.decode('utf-8').split('\t')[1:]
            if len(fields) != len(set(fields)) or not set(REQUIRED).issubset(fields):
                raise RuntimeError('Unexpected Zeek fields')
            continue
        if raw.startswith(b'#') or not raw.strip():
            continue
        if not fields:
            raise RuntimeError('Record before #fields')
        parts = raw.decode('utf-8').split('\t')
        if len(parts) != len(fields):
            raise RuntimeError(f'Malformed source row at {number}')
        row = dict(zip(fields, parts))
        try:
            timestamp = Decimal(row['ts'])
            port = int(row['id.resp_p'])
            if not timestamp.is_finite() or not 0 <= port <= 65535:
                raise ValueError('bad ts or destination port')
        except (InvalidOperation, ValueError) as exc:
            raise RuntimeError(f'Invalid source timestamp/port at line {number}: {exc}') from exc
        records.append({'line': number, 'raw_sha': sha(raw), 'row': row, 't': timestamp,
                        'minute': int(timestamp // 60), 'port': port})
    if len(records) != 65895:
        raise RuntimeError(f'Expected 65,895 records; got {len(records)}')
    return data, meta, records


def sample_even(records, limit):
    if len(records) <= limit:
        return records
    return [records[round(i*(len(records)-1)/(limit-1))] for i in range(limit)]


def create_payloads():
    raw, meta, all_rows = source_rows()
    src_pair = [r for r in all_rows if r['row']['id.orig_h'] == SRC
                and r['row']['id.resp_h'] == DST and r['row']['proto'] == 'tcp']
    distinct = len({r['port'] for r in src_pair})
    if len(src_pair) != 65747 or distinct != 65535:
        raise RuntimeError(f'Scan pair counts mismatch; flows={len(src_pair)} unique ports={distinct}')
    minutes = defaultdict(list)
    for r in src_pair:
        minutes[r['minute']].append(r)
    if len(minutes) != 13:
        raise RuntimeError(f'Unexpected number of scan minutes: {len(minutes)}')
    # Two from each occupied UTC minute; additional source-row anchors and
    # two outside-pair records for explicit context, NEVER pre-labelled benign.
    selected = {}
    for minute in sorted(minutes):
        group = sorted(minutes[minute], key=lambda r: (r['t'], r['line']))
        for rec in sample_even(group, 2):
            selected[rec['line']] = (rec, 'scan_minute_stratified')
    for port in (80, 1, 65535):
        potential = [r for r in src_pair if r['port'] == port]
        if potential:
            r = sorted(potential, key=lambda x: x['line'])[0]
            selected.setdefault(r['line'], (r, 'scan_port_anchor'))
    context = [r for r in all_rows if r['row']['id.orig_h'] != SRC and r['row']['proto'] == 'udp']
    if len(context) < 2:
        raise RuntimeError('Expected 2 non-scan UDP context records')
    for r in sample_even(context, 2):
        selected.setdefault(r['line'], (r, 'unlabelled_udp_context'))
    chosen = sorted(selected.values(), key=lambda pair: (pair[0]['t'], pair[0]['line']))
    states = Counter(r['row']['conn_state'] for r in src_pair)
    global_states = Counter(r['row']['conn_state'] for r in all_rows)
    proto_counts = Counter(r['row']['proto'] for r in all_rows)
    start, end = min(src_pair, key=lambda r: r['t']), max(src_pair, key=lambda r: r['t'])
    timestamps = [r['t'] for r in all_rows]
    aggregate = {
        'record_kind': 'VERIFIED_FULL_SOURCE_AGGREGATE_NOT_RAW_ZEEK_EVENT',
        'timestamp': iso_utc(start['row']['ts']),
        'log_source': 'Zeek conn.log',
        'src_ip': SRC, 'dst_ip': DST,
        'source_sha256': sha(raw),
        'source_connection_record_count': len(all_rows),
        'source_tcp_records': proto_counts.get('tcp', 0),
        'source_udp_records': proto_counts.get('udp', 0),
        'scan_pair_tcp_records': len(src_pair),
        'scan_pair_distinct_destination_ports': distinct,
        'scan_pair_conn_states': dict(states),
        'scan_pair_first_utc': iso_utc(start['row']['ts']),
        'scan_pair_last_utc': iso_utc(end['row']['ts']),
        'interpretation_limit': 'Strong vertical port-scan pattern; authorization, actor intent, and compromise NOT established. Aggregate is computed, not a raw log event.',
    }
    events = [aggregate]
    mapping_records = [{
        'focused_ref': 'E001', 'record_kind': 'verified_full_source_aggregate',
        'original_source_line': 'FULL_SOURCE_1_TO_65904', 'original_line_sha256': '',
        'source_sha256': sha(raw), 'zeek_uid': '', 'original_epoch_ts': '',
        'selection_reason': 'computed_summary_not_independent_connection'}]
    for idx, (rec, reason) in enumerate(chosen, 2):
        row = rec['row']
        event = {
            'record_kind': 'ZEEK_CONN_ORIGINAL_SOURCE_ROW',
            'timestamp': iso_utc(row['ts']),
            'zeek_ts_exact': row['ts'], 'zeek_uid': row['uid'],
            'src_ip': row['id.orig_h'], 'src_port': row['id.orig_p'],
            'dst_ip': row['id.resp_h'], 'dst_port': row['id.resp_p'],
            'proto': row['proto'], 'service': row.get('service', '-'),
            'conn_state': row['conn_state'], 'history': row.get('history','-'),
            'source_line': rec['line'], 'source_line_sha256': rec['raw_sha'],
            'sampling_category': reason,
        }
        events.append(event)
        mapping_records.append({
            'focused_ref': f'E{idx:03d}', 'record_kind': 'original_zeek_connection',
            'original_source_line': rec['line'], 'original_line_sha256': rec['raw_sha'],
            'source_sha256': sha(raw), 'zeek_uid': row['uid'],
            'original_epoch_ts': row['ts'], 'selection_reason': reason})
    focused_data = {
        'dataset': 'NT-01 Network Port Scanning',
        'provenance': 'Derived from pinned source; E001 is a computed whole-file aggregate, E002+ are original source records.',
        'events': events,
    }
    focused_bytes = (json.dumps(focused_data, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(mapping_records[0].keys()), lineterminator='\n')
    writer.writeheader(); writer.writerows(mapping_records)
    mapping_bytes = stream.getvalue().encode('utf-8')
    summary = {
        'test_id': 'NT-01', 'derived_not_raw': True,
        'source_sha256': sha(raw), 'source_physical_lines': 65904,
        'source_connections': len(all_rows), 'source_protocols': dict(proto_counts),
        'global_connection_states': dict(global_states),
        'scan_src_ip': SRC, 'scan_dst_ip': DST,
        'scan_pair_tcp_records': len(src_pair), 'scan_pair_distinct_destination_ports': distinct,
        'scan_pair_connection_states': dict(states),
        'scan_pair_utc_start': iso_utc(start['row']['ts']),
        'scan_pair_utc_end': iso_utc(end['row']['ts']),
        'scan_utc_minute_count': len(minutes),
        'source_first_utc': iso_utc(min(all_rows, key=lambda x: x['t'])['row']['ts']),
        'source_last_utc': iso_utc(max(all_rows, key=lambda x: x['t'])['row']['ts']),
        'labels': {'observed_pattern': 'strong_vertical_port_scan',
                   'authorization': 'unknown', 'compromise': 'not_established',
                   'actor_intent': 'not_established'},
    }
    stats_bytes = (json.dumps(summary, indent=2) + '\n').encode('utf-8')
    selection_manifest = {
        'test_id': 'NT-01', 'source_sha256': sha(raw), 'source_git_blob_sha1': git_blob(raw),
        'sampled_original_connection_count': len(chosen),
        'total_focused_events_including_aggregate': len(events),
        'aggregate_reference': 'E001',
        'original_connection_references': f'E002-E{len(events):03d}',
        'selection_method': 'first and last per occupied scan UTC minute, port anchors 80/1/65535 when present, two UDP context records; source-time ordered',
        'sampling_is_not_prevalence_estimate': True,
        'focused_sha256': sha(focused_bytes), 'mapping_sha256': sha(mapping_bytes),
        'statistics_sha256': sha(stats_bytes),
        'warnings': [
            'E001 is a computed aggregate over the full verified source, not a captured connection record.',
            'Do not treat the focused sample size as the total scan flows.',
            'Zeek connection states do not prove malicious intent, exploitation, successful login, or host compromise.',
            'Outside-pair UDP context rows are not automatically benign.',
        ],
    }
    selection_bytes = (json.dumps(selection_manifest, indent=2) + '\n').encode('utf-8')
    return [(FOCUSED, focused_bytes), (MAPPING, mapping_bytes),
            (STATS, stats_bytes), (SELECTION, selection_bytes)], events, mapping_records, summary


def verify_parser(focused_bytes, events, mapping_records):
    try:
        from Core.log_parser import load_file, render_event
    except ImportError as exc:
        raise RuntimeError(f'Run from Week-2 root: parser unavailable: {exc}') from exc
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / 'NT01-parser-test.json'
        p.write_bytes(focused_bytes)
        result = load_file(p, source_hint='network')
        parsed = result['events']
        if result['source_type'] != 'network' or result['warnings'] or len(parsed) != len(events):
            raise RuntimeError(f'Parser check failed: {result["source_type"]}, {len(parsed)} events, warnings={result["warnings"]}')
        for i, (event, parsed_event, mp) in enumerate(zip(events, parsed, mapping_records), 1):
            expected_ref = f'E{i:03d}'
            rendered = render_event(parsed_event, 12000)
            if parsed_event['ref'] != expected_ref or mp['focused_ref'] != expected_ref:
                raise RuntimeError(f'Evidence reference mismatch: {expected_ref}')
            for required in ('record_kind', 'timestamp', 'src_ip', 'dst_ip'):
                if str(event[required]) not in rendered:
                    raise RuntimeError(f'Model-visible value missing at {expected_ref}: {required}')
            if event['record_kind'] == 'ZEEK_CONN_ORIGINAL_SOURCE_ROW':
                for required in ('zeek_uid','dst_port','conn_state','source_line_sha256'):
                    if str(event[required]) not in rendered:
                        raise RuntimeError(f'Model-visible source evidence missing at {expected_ref}: {required}')
            if not parsed_event['timestamp_utc']:
                raise RuntimeError(f'Timestamp not parsed: {expected_ref}')
        return result['source_type'], len(parsed)


def main():
    arg = argparse.ArgumentParser(description=__doc__)
    group = arg.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='Source & parser verification, no writes to project')
    group.add_argument('--create', action='store_true', help='Verify and create files exclusively after confirmation')
    args = arg.parse_args()
    print('=== NT-01 GROUNDED FOCUSED EVIDENCE PREPARATION ===')
    if not Path('Core').is_dir() or not Path('app.py').is_file():
        raise RuntimeError('Run from Week-2 project root')
    if any(p.exists() for p in OUTPUTS):
        raise RuntimeError('STOP: One or more target files already exist; refusing overwrite')
    payloads, events, mapping_records, summary = create_payloads()
    print('\n=== SOURCE / FULL-DATASET VERIFICATION ===')
    print('Original SHA256: MATCH | Git Blob SHA1: MATCH')
    print('Source connections:', summary['source_connections'])
    print('Scan-pair TCP records:', summary['scan_pair_tcp_records'])
    print('Scan-pair distinct destination ports:', summary['scan_pair_distinct_destination_ports'])
    print('Scan-pair states:', summary['scan_pair_connection_states'])
    print('UTC scan minutes:', summary['scan_utc_minute_count'])
    source_type, count = verify_parser(payloads[0][1], events, mapping_records)
    print('\n=== PARSER / EVIDENCE CHECK ===')
    print('Parser source_type:', source_type, '| parsed focused events:', count)
    print('E001: VERIFIED COMPUTED SUMMARY (NOT RAW CAPTURE)')
    print(f'E002-E{count:03d}: ORIGINAL ZEEK CONNECTIONS (SOURCE-LINE HASHES PRESERVED)')
    print('Model-visible references, endpoints, source line hashes and timestamps: PASS')
    print('Parser warnings: []')
    print('\n=== OUTPUT FILES (NO OVERWRITES) ===')
    for path, content in payloads:
        print(f'CREATE: {path} | {len(content)} bytes | SHA256={sha(content)[:20]}...')
    if args.check:
        print('\nSTATUS: NT-01 READY TO CREATE; READ-ONLY CHECK PASS (NO CHANGES MADE)')
        return
    confirm = input('\nType CREATE to save these 4 verified files (Enter cancels): ').strip()
    if confirm != 'CREATE':
        print('CANCELLED: No files created')
        return
    created = []
    try:
        for path, content in payloads:
            with path.open('xb') as f:
                created.append(path)
                f.write(content)
            if sha(path.read_bytes()) != sha(content):
                raise RuntimeError('Post-write SHA mismatch: ' + str(path))
    except Exception:
        for p in reversed(created):
            p.unlink(missing_ok=True)
        raise
    print('\nOriginal evidence, Core, historical Results/reviews: UNCHANGED')
    print('Source/Focused/Mapping/Statistics/Selection integrity: PASS')
    print('STATUS: NT-01 FOCUSED EVIDENCE READY FOR AI TRIAGE')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print('\nSTOP:', exc, file=sys.stderr)
        sys.exit(1)
