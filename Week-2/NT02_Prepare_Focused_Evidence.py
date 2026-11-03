#!/usr/bin/env python3
"""NT-02: verified DNS cluster-focused evidence preparation (stdlib-only).

From the Week-2 project root:
  python NT02_Prepare_Focused_Evidence.py --check
  python NT02_Prepare_Focused_Evidence.py --create

E001 = verified aggregate over ALL 581 Zeek DNS source rows (NOT a DNS packet/event).
E002 = verified aggregate over an identified burst subset (NOT a DNS packet/event).
E003+ = original Zeek DNS rows mapped to physical source line and SHA-256.

Only four new files are created after explicit CREATE confirmation. No Core,
Results, reviews, source logs, or original manifest are modified.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import sys
import tempfile

BASE = Path('Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly')
SOURCE = BASE / 'NT-02-Zeek-dns-original.log'
SOURCE_MANIFEST = BASE / 'NT-02-Source-Manifest.json'
FOCUSED = BASE / 'NT-02-focused.json'
MAPPING = BASE / 'NT-02-evidence-mapping.csv'
STATS = BASE / 'NT-02-Verified-Full-Source-Statistics.json'
SELECTION = BASE / 'NT-02-Selection-Manifest.json'
OUTPUTS = (FOCUSED, MAPPING, STATS, SELECTION)
EXPECTED_SOURCE_SHA = 'a5a31f5be2a6bfdcce1ab1f2d43e34a2b1ff49bee4d3737560c8b9b6e6775942'
EXPECTED_BLOB = '752daa17b27eb584d8fbedd2da4322c661c30e30'
EXPECTED_COMMIT = 'bb2817e4a783dd2578383aa6e3f0adab12052904'
EXPECTED_SIZE = 104260
REQUIRED = {'ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto',
            'query','qtype_name','rcode_name'}
BURST_NAME = re.compile(r'^chunk[0-9]{3,6}-[a-f0-9]{16,64}\.lab\.test\.?$', re.I)
CLIENT = '192.168.16.132'
RESOLVER = '192.168.16.131'


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f'blob {len(data)}\0'.encode('ascii') + data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def utc_exact(text: str) -> str:
    epoch = Decimal(text)
    if not epoch.is_finite() or epoch < 0:
        raise ValueError('bad epoch: ' + repr(text))
    whole, dot, fraction = text.partition('.')
    if dot and (not fraction.isdigit() or len(fraction) > 6):
        raise ValueError('unexpected epoch fractional precision: ' + repr(text))
    dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S') + ('.' + fraction if dot else '') + 'Z'


def even_sample(rows: list, n: int) -> list:
    if n <= 0: return []
    if len(rows) <= n: return rows[:]
    if n == 1: return [rows[len(rows)//2]]
    return [rows[(i * (len(rows)-1)) // (n-1)] for i in range(n)]


def load_original():
    if not SOURCE.is_file() or not SOURCE_MANIFEST.is_file():
        raise RuntimeError('Verified NT-02 original or Source Manifest is missing')
    payload = SOURCE.read_bytes()
    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding='utf-8-sig'))
    provenance = manifest.get('provenance', {})
    checks = {
        'size pinned and manifest': len(payload) == EXPECTED_SIZE == manifest.get('file_size_bytes'),
        'SHA-256 pinned and manifest': sha256(payload) == EXPECTED_SOURCE_SHA == manifest.get('sha256'),
        'Git blob pinned and manifest': git_blob_sha1(payload) == EXPECTED_BLOB == manifest.get('git_blob_sha1'),
        'commit pinned': provenance.get('commit') == EXPECTED_COMMIT,
        'source file pinned': provenance.get('path_in_repository') == 'Zeek-Logs/dns_anomaly/dns.log',
    }
    if not all(checks.values()):
        raise RuntimeError('STOP: original provenance/integrity mismatch: ' + repr(checks))
    raw_lines = payload.decode('utf-8', errors='strict').splitlines()
    if len(raw_lines) != 590:
        raise RuntimeError(f'Expected 590 physical source lines, found {len(raw_lines)}')
    header = {}; fields = None; events = []
    for number, line in enumerate(raw_lines, 1):
        if line.startswith('#'):
            key, sep, value = line.partition('\t')
            if key == '#fields':
                if fields is not None: raise RuntimeError('Unexpected repeated #fields')
                fields = value.split('\t')
                if len(fields) != len(set(fields)) or not REQUIRED.issubset(fields):
                    raise RuntimeError('Invalid field names in Zeek header')
            elif key in ('#path','#open','#separator','#unset_field','#empty_field'):
                header[key] = value
            continue
        if not line or fields is None:
            raise RuntimeError(f'Empty line or data before header at original line {number}')
        parts = line.split('\t')
        if len(parts) != len(fields):
            raise RuntimeError(f'Malformed Zeek data at source line {number}: {len(parts)} columns')
        row = dict(zip(fields, parts))
        try:
            epoch = Decimal(row['ts'])
            iso = utc_exact(row['ts'])
            ipaddress.ip_address(row['id.orig_h'])
            ipaddress.ip_address(row['id.resp_h'])
            for key in ('id.orig_p','id.resp_p'):
                port = int(row[key]); assert 0 <= port <= 65535
            query = row['query'].rstrip('.').lower()
            if not query or query == '-':
                raise ValueError('Empty DNS query')
        except (KeyError, ValueError, InvalidOperation, AssertionError, OverflowError) as exc:
            raise RuntimeError(f'Invalid DNS row {number}: {exc}') from exc
        events.append({'source_line': number, 'raw': line, 'raw_sha': sha256(line.encode('utf-8')),
                       'row':row, 'epoch':epoch, 'timestamp':iso, 'query':query})
    if header.get('#path') != 'dns' or len(fields or []) != 26 or len(events) != 581:
        raise RuntimeError('Source DNS format/count mismatch; cannot continue')
    return payload, manifest, events


def produce():
    payload, manifest, records = load_original()
    query_count = Counter(r['query'] for r in records)
    clients = Counter(r['row']['id.orig_h'] for r in records)
    resolvers = Counter(r['row']['id.resp_h'] for r in records)
    pairs = Counter((r['row']['id.orig_h'], r['row']['id.resp_h']) for r in records)
    qtypes = Counter(r['row']['qtype_name'] for r in records)
    rcodes = Counter(r['row']['rcode_name'] for r in records)
    proto = Counter(r['row']['proto'] for r in records)
    nx = sum(r['row']['rcode_name'].upper() == 'NXDOMAIN' or r['row'].get('rcode') == '3' for r in records)
    # Independent consistency checks from user's read-only inspection.
    baseline = (len(query_count)==258 and clients[CLIENT]==255 and clients[RESOLVER]==326
                and pairs[(CLIENT,RESOLVER)]==255 and pairs[(RESOLVER,'192.168.16.1')]==326
                and qtypes['A']==401 and qtypes['AAAA']==180 and
                rcodes['NOERROR']==255 and rcodes['-']==326 and nx==0 and proto['udp']==581)
    if not baseline:
        raise RuntimeError('STOP: Independently recomputed DNS inventory differs from inspected source')

    burst = sorted((r for r in records if r['row']['id.orig_h']==CLIENT
                    and r['row']['id.resp_h']==RESOLVER and BURST_NAME.fullmatch(r['query'])),
                   key=lambda r:(r['epoch'],r['source_line']))
    if len(burst) < 20 or len({r['query'] for r in burst}) < 20:
        raise RuntimeError('STOP: Insufficient verified chunk-pattern DNS cluster; manual inspection needed')
    burst_qtypes = Counter(r['row']['qtype_name'] for r in burst)
    burst_rcodes = Counter(r['row']['rcode_name'] for r in burst)
    start, finish = burst[0], burst[-1]
    cluster_seconds = float(finish['epoch'] - start['epoch'])
    # Focus selection: 16 time-spaced burst records, 4 other same-endpoint
    # records when available, 4 surrounding resolver/background records.
    # Context rows are NOT asserted to be benign.
    outside = sorted((r for r in records if r['row']['id.orig_h']==CLIENT and
                      r['row']['id.resp_h']==RESOLVER and not BURST_NAME.fullmatch(r['query'])),
                     key=lambda r:(r['epoch'],r['source_line']))
    background = sorted((r for r in records if r['row']['id.orig_h']==RESOLVER and
                         r['row']['id.resp_h']=='192.168.16.1'),
                        key=lambda r:(r['epoch'],r['source_line']))
    picked = {}
    for category, rows, max_n in [('chunk_pattern_time_stratified',burst,16),
                                  ('same_pair_unlabelled_context',outside,4),
                                  ('other_pair_unlabelled_context',background,4)]:
        for rec in even_sample(rows,max_n):
            picked[rec['source_line']] = (rec, category)
    if len(picked) != 24:
        raise RuntimeError(f'Unexpected selected original source rows ({len(picked)}); expected 24')
    chosen = sorted(picked.values(), key=lambda item:(item[0]['epoch'],item[0]['source_line']))
    earliest = min(records, key=lambda r:r['epoch'])
    latest = max(records, key=lambda r:r['epoch'])
    full_aggregate = {
        'record_kind':'VERIFIED_FULL_SOURCE_DNS_AGGREGATE_NOT_RAW_ZEEK_EVENT',
        'timestamp': earliest['timestamp'], 'log_source':'Zeek dns.log',
        'source_sha256':sha256(payload), 'total_dns_records':len(records),
        'distinct_exact_queries':len(query_count), 'dns_client_counts':dict(clients),
        'resolver_destination_counts':dict(resolvers),
        'query_type_counts':dict(qtypes), 'response_code_counts':dict(rcodes),
        'nxdomain_count':nx, 'total_udp_records':proto.get('udp',0),
        'first_observed_utc':earliest['timestamp'], 'last_observed_utc':latest['timestamp'],
        'interpretation_limit':'Verified whole-source statistics, NOT individual DNS query. No exfiltration or attacker intent established.',
    }
    burst_aggregate = {
        'record_kind':'VERIFIED_DNS_QUERY_CLUSTER_AGGREGATE_NOT_RAW_ZEEK_EVENT',
        'timestamp':start['timestamp'], 'log_source':'Zeek dns.log',
        'source_sha256':sha256(payload), 'src_ip':CLIENT, 'dst_ip':RESOLVER,
        'query_pattern':'chunkNNN-hex.lab.test', 'approximate_domain_group':'lab.test',
        'matching_dns_records':len(burst), 'matching_distinct_exact_queries':len({r['query'] for r in burst}),
        'matching_query_type_counts':dict(burst_qtypes), 'matching_response_code_counts':dict(burst_rcodes),
        'first_observed_utc':start['timestamp'], 'last_observed_utc':finish['timestamp'],
        'duration_seconds':round(cluster_seconds,6),
        'interpretation_limit':'Distinct chunk-like DNS labels in a concentrated time interval support review for possible DNS tunneling-like behavior. They do NOT prove payload encoding, DNS tunneling, or exfiltration.',
    }
    evidence_events = [full_aggregate, burst_aggregate]
    mappings = []
    for ix,label,reason in ((1,'verified_full_source_aggregate','computed_full_source_summary_not_raw_event'),
                            (2,'verified_dns_cluster_aggregate','computed_cluster_summary_not_raw_event')):
        mappings.append({'focused_ref':f'E{ix:03d}','record_kind':label,
                         'original_source_line':'AGGREGATE_NOT_A_SOURCE_ROW',
                         'original_line_sha256':'','source_sha256':sha256(payload),
                         'zeek_uid':'','original_epoch_ts':'','selection_reason':reason})
    for num,(item,why) in enumerate(chosen,3):
        row=item['row']
        event = {
            'record_kind':'ZEEK_DNS_ORIGINAL_SOURCE_ROW',
            'timestamp':item['timestamp'], 'zeek_ts_exact':row['ts'],
            'zeek_uid':row['uid'], 'src_ip':row['id.orig_h'],
            'src_port':row['id.orig_p'], 'dst_ip':row['id.resp_h'],
            'dst_port':row['id.resp_p'], 'proto':row['proto'],
            'query':row['query'], 'qtype_name':row['qtype_name'],
            'rcode_name':row['rcode_name'], 'answers':row.get('answers','-'),
            'source_line':item['source_line'], 'source_line_sha256':item['raw_sha'],
            'selection_category':why,
            'interpretation_limit':'One original Zeek DNS record; rcode - means unrecorded, not NXDOMAIN; NOERROR alone does not prove successful exfiltration.',
        }
        evidence_events.append(event)
        mappings.append({'focused_ref':f'E{num:03d}', 'record_kind':'original_zeek_dns_row',
                         'original_source_line':item['source_line'],
                         'original_line_sha256':item['raw_sha'],
                         'source_sha256':sha256(payload), 'zeek_uid':row['uid'],
                         'original_epoch_ts':row['ts'],'selection_reason':why})
    assert len(evidence_events)==len(mappings)==26
    focused_struct={'dataset':'NT-02 Suspicious DNS Activity - Candidate Investigation',
      'evidence_scope':'E001/E002 computed aggregates from verified source, E003-E026 exact sampled Zeek DNS source rows',
      'events':evidence_events}
    focused_bytes=json_bytes(focused_struct)
    fh=io.StringIO(newline='')
    writer=csv.DictWriter(fh,fieldnames=list(mappings[0]),lineterminator='\n')
    writer.writeheader();writer.writerows(mappings)
    mapping_bytes=fh.getvalue().encode('utf-8')
    stats={
        'test_id':'NT-02','source_sha256':sha256(payload),
        'source_total_dns_records':len(records),'source_distinct_exact_queries':len(query_count),
        'source_clients':dict(clients), 'source_client_resolver_pairs':
            {f'{a} -> {b}':n for (a,b),n in sorted(pairs.items())},
        'source_qtypes':dict(qtypes), 'source_rcodes':dict(rcodes),
        'source_nxdomain_count':nx, 'source_first_utc':earliest['timestamp'],
        'source_last_utc':latest['timestamp'],
        'cluster_src':CLIENT,'cluster_dst':RESOLVER,'cluster_query_pattern':'chunkNNN-hex.lab.test',
        'cluster_record_count':len(burst),'cluster_distinct_queries':len({r['query'] for r in burst}),
        'cluster_start_utc':start['timestamp'],'cluster_end_utc':finish['timestamp'],
        'cluster_duration_seconds':round(cluster_seconds,6),
        'cluster_qtypes':dict(burst_qtypes), 'cluster_rcodes':dict(burst_rcodes),
        'interpretation':'DNS query burst with diverse chunk-style labels. Potential DNS tunneling-like indicator, NOT proof of exfiltration or confirmed malware.',
        'uncertainties':['authorized lab/test activity unknown','DNS payload meaning unknown',
                         'NOERROR is not evidence of exfiltration','Zeek rcode - is not NXDOMAIN',
                         'lab.test is a test-style domain, not confirmed attacker infrastructure'],
    }
    stats_bytes=json_bytes(stats)
    manifest={
        'test_id':'NT-02','original_source_sha256':sha256(payload),
        'original_git_blob_sha1':git_blob_sha1(payload),
        'original_record_count':len(records),
        'computed_aggregates':['E001','E002'],
        'original_sample_reference_range':'E003-E026',
        'original_sample_count':len(chosen),
        'source_line_reference_count':len(mappings)-2,
        'selection_method':'16 evenly spaced matching chunk-style DNS queries, 4 nonmatching same-pair records, 4 other-pair context records; selected source rows sorted chronologically',
        'sampling_is_not_prevalence_estimate':True,
        'focused_sha256':sha256(focused_bytes),'mapping_sha256':sha256(mapping_bytes),
        'statistics_sha256':sha256(stats_bytes),
        'model_input_event_count':len(evidence_events),
        'limitations':['E001/E002 are computed evidence, not captured DNS query events.',
                       'Context rows are unlabelled and NOT confirmed benign.',
                       'High query diversity and speed do not establish tunneling or exfiltration.',
                       'A query response code is not a substitute for payload/network egress investigation.',
                       'Log source may reflect a lab scenario and .test suffix is reserved for testing.',
                       'Per-line SHA256 hashes are provenance hashes, NOT threat/malware IOCs.'],
    }
    manifest_bytes=json_bytes(manifest)
    return [(FOCUSED,focused_bytes),(MAPPING,mapping_bytes),(STATS,stats_bytes),(SELECTION,manifest_bytes)], evidence_events, mappings, stats


def parser_smoke(focused_bytes:bytes, events:list, mappings:list):
    from Core.log_parser import load_file, render_event
    with tempfile.TemporaryDirectory(prefix='NT02-dns-smoke-') as tmp:
        path=Path(tmp)/'nt02-dns-smoke.json'
        path.write_bytes(focused_bytes)
        parsed=load_file(path, source_hint='network')
        if parsed['source_type']!='network' or parsed['warnings'] or len(parsed['events'])!=len(events):
            raise RuntimeError(f'Parser source/count/warnings mismatch: {parsed["source_type"]}, {len(parsed["events"])} events, {parsed["warnings"]}')
        for i,(original,ev,mp) in enumerate(zip(events,parsed['events'],mappings),1):
            ref=f'E{i:03d}'
            if ev.get('ref')!=ref or mp['focused_ref']!=ref:
                raise RuntimeError('Evidence reference mismatch at '+ref)
            text=render_event(ev,14000)
            keys=('record_kind','timestamp','source_sha256') if i<=2 else (
                  'record_kind','timestamp','src_ip','dst_ip','query','qtype_name','rcode_name','source_line_sha256')
            for key in keys:
                if str(original[key]) not in text:
                    raise RuntimeError(f'Model-visible {key} missing at {ref}')
            if not ev.get('timestamp_utc'):
                raise RuntimeError('Parser failed to normalize timestamp '+ref)
        return parsed['source_type'],len(parsed['events'])


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    mode=cli.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check',action='store_true')
    mode.add_argument('--create',action='store_true')
    args=cli.parse_args()
    print('=== NT-02 VERIFIED DNS FOCUSED EVIDENCE PREPARATION ===')
    if not Path('app.py').is_file() or not Path('Core/log_parser.py').is_file():
        raise RuntimeError('Run from Week-2 project root with app.py and Core/')
    if any(p.exists() for p in OUTPUTS):
        raise RuntimeError('STOP: An output file already exists; no overwrite allowed')
    payloads,events,mappings,stats=produce()
    print('\n=== FULL-SOURCE INTEGRITY & DNS CLUSTER ===')
    print('Original SHA256: MATCH | Git blob SHA1: MATCH | Pinned commit: MATCH')
    print('Total DNS records:',stats['source_total_dns_records'])
    print('Exact distinct queries:',stats['source_distinct_exact_queries'])
    print('DNS query types:',stats['source_qtypes'])
    print('DNS response codes:',stats['source_rcodes'])
    print('Pattern:',stats['cluster_query_pattern'])
    print('Client -> resolver:',stats['cluster_src'],'->',stats['cluster_dst'])
    print('Matching chunk-pattern rows:',stats['cluster_record_count'])
    print('Matching unique exact queries:',stats['cluster_distinct_queries'])
    print('First/last UTC:',stats['cluster_start_utc'],'->',stats['cluster_end_utc'])
    print('Cluster duration (s):',stats['cluster_duration_seconds'])
    print('Cluster query types:',stats['cluster_qtypes'])
    print('Cluster rcode names:',stats['cluster_rcodes'])
    srctype,n=parser_smoke(payloads[0][1],events,mappings)
    print('\n=== PARSER & SOURCE MAPPING ===')
    print('Source Type:',srctype,'| Focused Events:',n,'| Warnings: []')
    print('E001-E002: COMPUTED AGGREGATES (NOT RAW DNS RECORDS)')
    print('E003-E026: ORIGINAL ZEEK DNS RECORDS (24/24 SOURCE-LINE + HASH MAPPED)')
    print('Model-visible source content / original UTC timestamps: PASS')
    print('\n=== FILES TO CREATE (EXCLUSIVE / NO OVERWRITES) ===')
    for path,data in payloads:
        print('CREATE:',path,'| bytes:',len(data),'| SHA256:',sha256(data))
    print('\nSAFETY: Potential suspicious DNS cluster, NOT confirmed DNS tunneling or exfiltration.')
    if args.check:
        print('STATUS: NT-02 READY TO CREATE - READ-ONLY CHECK PASS (NO CHANGES MADE)')
        return
    if input('\nType CREATE to save the four files (Enter cancels): ').strip()!='CREATE':
        print('CANCELLED: No project files created')
        return
    created=[]
    try:
        for path,data in payloads:
            with path.open('xb') as stream:
                created.append(path)
                stream.write(data)
            if sha256(path.read_bytes())!=sha256(data):
                raise RuntimeError('Saved hash mismatch: '+str(path))
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    print('\nSource / Core / Results / reviews: UNCHANGED')
    print('Source / focused / mapping / statistics / selection: SHA-256 VERIFIED')
    print('STATUS: NT-02 FOCUSED DNS EVIDENCE READY FOR AI TRIAGE')


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,ValueError,KeyError,UnicodeError,ImportError,json.JSONDecodeError,InvalidOperation) as exc:
        print('STOP:',type(exc).__name__,str(exc),file=sys.stderr)
        sys.exit(1)
