#!/usr/bin/env python3
"""NT-02: read-only, evidence-preserving inspection of pinned original Zeek dns.log.

Run from Week-2 root: python NT02_Inspect_Zeek_DNS.py
Does not write any project files, call the model, or label activity malicious.
Python standard library only.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import sys

BASE = Path('Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly')
SRC = BASE / 'NT-02-Zeek-dns-original.log'
MAN = BASE / 'NT-02-Source-Manifest.json'
EXPECTED_SIZE = 104260
EXPECTED_BLOB = '752daa17b27eb584d8fbedd2da4322c661c30e30'
EXPECTED_COMMIT = 'bb2817e4a783dd2578383aa6e3f0adab12052904'
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def stop(message):
    raise RuntimeError(message)


def blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def utc_from_zeek(value):
    try:
        t = Decimal(value)
        if not t.is_finite() or t < 0:
            stop('Invalid Zeek epoch timestamp: ' + repr(value))
        us = int((t * 1000000).to_integral_value())
        return EPOCH + timedelta(microseconds=us), us // 60000000
    except (InvalidOperation, OverflowError, ValueError) as exc:
        stop('Invalid Zeek epoch timestamp: ' + repr(value) + ' ' + str(exc))


def shannon(value):
    if not value:
        return 0.0
    freqs = Counter(value.lower())
    n = len(value)
    return -sum((v / n) * math.log2(v / n) for v in freqs.values())


def compact(text, n=120):
    return text if len(text) <= n else text[:n - 3] + '...'


def main():
    root = Path.cwd()
    if not (root / 'app.py').is_file() or not (root / 'Core').is_dir():
        stop('Run from D:\\Desktop\\w\\Week-2 (project root with Core/ and app.py).')
    if not SRC.is_file() or not MAN.is_file():
        stop('Required verified source or manifest missing: ' + str(SRC))
    payload = SRC.read_bytes()
    meta = json.loads(MAN.read_text(encoding='utf-8-sig'))
    actual_sha = hashlib.sha256(payload).hexdigest()
    actual_blob = blob_sha(payload)
    actual_size = len(payload)
    prov = meta.get('provenance', {})
    checks = {
        'bytes vs pinned GitHub object': actual_size == EXPECTED_SIZE,
        'bytes vs saved manifest': actual_size == meta.get('file_size_bytes'),
        'SHA-256 vs saved manifest': actual_sha == meta.get('sha256'),
        'Git blob SHA-1 vs pinned object': actual_blob == EXPECTED_BLOB,
        'Git blob SHA-1 vs saved manifest': actual_blob == meta.get('git_blob_sha1'),
        'pinned commit vs manifest': prov.get('commit') == EXPECTED_COMMIT,
        'source path vs manifest': prov.get('path_in_repository') == 'Zeek-Logs/dns_anomaly/dns.log',
    }
    print('=== NT-02 VERIFIED ZEEK DNS SOURCE INSPECTION (READ-ONLY) ===')
    print('\n=== SOURCE INTEGRITY ===')
    for name, passed in checks.items():
        print(('PASS' if passed else 'FAIL') + ': ' + name)
    print('Source bytes:', actual_size)
    print('Source SHA-256:', actual_sha)
    print('Git Blob SHA-1:', actual_blob)
    if not all(checks.values()):
        stop('Integrity/provenance check failed. Stop before interpretation.')

    lines = payload.decode('utf-8', errors='strict').splitlines()
    metadata = {}
    fields = None
    rows = []
    bad = []
    for num, line in enumerate(lines, 1):
        if line.startswith('#'):
            key, sep, val = line.partition('\t')
            if key == '#fields':
                if fields is not None:
                    stop('More than one #fields header; this inspector expects one Zeek section')
                fields = val.split('\t')
            elif key in ('#path', '#open', '#close', '#separator', '#unset_field', '#empty_field'):
                metadata[key] = val
            continue
        if not line:
            bad.append((num, 'blank nonheader line'))
            continue
        if not fields:
            stop('Encountered data before #fields')
        parts = line.split('\t')
        if len(parts) != len(fields):
            bad.append((num, 'column count ' + str(len(parts))))
            continue
        event = dict(zip(fields, parts))
        try:
            when, minute = utc_from_zeek(event['ts'])
            ipaddress.ip_address(event['id.orig_h'])
            ipaddress.ip_address(event['id.resp_h'])
            q = event['query'].rstrip('.')
            if not q or q == '-':
                q = ''
        except (KeyError, ValueError, RuntimeError) as exc:
            bad.append((num, compact(str(exc))))
            continue
        labs = [label for label in q.split('.') if label]
        max_label = max((len(x) for x in labs), default=0)
        candidate_label = max(labs, key=len, default='')
        rows.append({'n':num,'data':event,'when':when,'minute':minute,'query':q,
                     'length':len(q),'max_label':max_label,'entropy':shannon(candidate_label),
                     'raw_sha256':hashlib.sha256(line.encode('utf-8')).hexdigest()})

    print('\n=== ZEEK FORMAT & PARSER VALIDATION ===')
    print('#path:', metadata.get('#path', '<missing>'))
    print('#open:', metadata.get('#open', '<missing>'))
    print('Physical lines:',len(lines))
    print('Number of fields:',len(fields or []))
    print('Parsed DNS records:',len(rows))
    print('Malformed records:',len(bad))
    for n, msg in bad[:5]:
        print('  Malformed source line', n, ':', msg)
    required = {'ts','uid','id.orig_h','id.resp_h','query','qtype_name','rcode_name','proto'}
    if metadata.get('#path') != 'dns' or not fields or not required.issubset(fields):
        stop('Zeek header/required columns invalid; present fields: ' + repr(fields))
    if bad or not rows:
        stop('Malformed/empty DNS data; no classification until source inspection corrected.')

    source_ctr = Counter(r['data']['id.orig_h'] for r in rows)
    resolver_ctr = Counter(r['data']['id.resp_h'] for r in rows)
    pairs = Counter((r['data']['id.orig_h'],r['data']['id.resp_h']) for r in rows)
    proto = Counter(r['data']['proto'] for r in rows)
    qtypes = Counter(r['data']['qtype_name'] for r in rows)
    rcodes = Counter(r['data']['rcode_name'] for r in rows)
    queries = Counter(r['query'] for r in rows)
    # Last-two-label grouping is approximate and is NOT a registrable domain calculation.
    approx_suffix = defaultdict(set)
    for r in rows:
        labs = r['query'].lower().split('.')
        if len(labs) >= 3:
            approx_suffix['.'.join(labs[-2:])].add(r['query'].lower())
    windows = Counter((r['data']['id.orig_h'],r['minute']) for r in rows)
    first = min(r['when'] for r in rows)
    last = max(r['when'] for r in rows)
    longq = [r for r in rows if r['length'] >= 100 or r['max_label'] >= 40]
    entropy_q = [r for r in rows if r['max_label'] >= 20 and r['entropy'] >= 3.5]
    nx = [r for r in rows if r['data']['rcode_name'].upper() == 'NXDOMAIN'
          or r['data'].get('rcode') == '3']
    
    print('\n=== DNS TRAFFIC INVENTORY ===')
    print('Earliest UTC:',first.isoformat())
    print('Latest UTC:  ',last.isoformat())
    print('Coverage seconds:',round((last-first).total_seconds(),3))
    print('Total DNS records:',len(rows))
    print('Distinct exact queries:',len(queries))
    print('NXDOMAIN count:',len(nx))
    print('NXDOMAIN percentage:',round(100*len(nx)/len(rows),2))
    print('Query length >=100 OR a label >=40:',len(longq))
    print('High-entropy-long-label screening candidates:',len(entropy_q))
    print('Max query length:',max(r['length'] for r in rows))
    print('Max DNS label length:',max(r['max_label'] for r in rows))
    for label, counter in (
        ('CLIENTS',source_ctr),('RESOLVERS',resolver_ctr),('CLIENT/RESOLVER PAIRS',pairs),
        ('PROTOCOLS',proto),('QUERY TYPES',qtypes),('RESPONSE CODES',rcodes),
        ('EXACT QUERY REPEATS',queries)):
        print('\n=== TOP '+label+' ===')
        for key, val in counter.most_common(8):
            print(f'{str(key):<68} {val}')
    print('\n=== MOST DIVERSE APPROXIMATE DOMAIN-SUFFIX GROUPS ===')
    for domain, names in sorted(approx_suffix.items(), key=lambda pair:(-len(pair[1]),pair[0]))[:10]:
        print(f'{domain:<48} distinct_exact_queries={len(names)}')
    print('NOTE: Last two labels are a screening approximation, NOT eTLD+1.')
    print('\n=== PEAK 60-SECOND CLIENT WINDOWS (UTC, FIXED EPOCH MINUTES) ===')
    for (host, minute), num in windows.most_common(10):
        since = EPOCH + timedelta(minutes=minute)
        print(f'{since.isoformat()} | client={host} | DNS records={num}')

    def show_sample(label, items, key=None, count=8):
        print('\n=== '+label+' ===')
        if key is not None:
            items = sorted(items, key=key, reverse=True)
        for r in items[:count]:
            e = r['data']
            print(f"Source line {r['n']} | {r['when'].isoformat()} | {e['id.orig_h']} -> {e['id.resp_h']} "
                  f"| qtype={e['qtype_name']} | rcode={e['rcode_name']} | length={r['length']} "
                  f"| max_label={r['max_label']} | entropy={r['entropy']:.2f}")
            print('  Query:',compact(r['query'],140))
            print('  Source logical-line SHA-256:',r['raw_sha256'])
        if not items:
            print('None under this screening condition.')

    show_sample('LONGEST DNS QUERY SAMPLES',rows,key=lambda x:(x['length'],x['max_label']))
    show_sample('HIGH-ENTROPY/LONG-LABEL CANDIDATES',entropy_q,key=lambda x:(x['entropy'],x['max_label']))
    show_sample('NXDOMAIN ORIGINAL-EVIDENCE SAMPLES',nx)
    print('\n=== EVIDENCE LIMITATIONS ===')
    print('- This is a read-only source inventory, NOT a DNS tunneling detection verdict.')
    print('- High entropy, many distinct labels, NXDOMAIN, and query bursts may be legitimate.')
    print('- Missing response data and explicit negative outcomes must not be inferred as successful exfiltration.')
    print('- Approximate suffix grouping does not identify registrable domains without a Public Suffix List.')
    print('- Timestamps are converted directly from Zeek ts (UTC); #open is log-writer metadata.')
    print('- Source line numbers and SHA-256 refer to logical Zeek lines, not invented evidence refs.')
    print('\nCore / Results / existing evidence: UNCHANGED')
    print('Permanent project files created: 0')
    print('STATUS: NT-02 SOURCE DNS INSPECTION COMPLETE - CANDIDATE REVIEW NEXT')

if __name__ == '__main__':
    try:
        main()
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print('STOP:',type(exc).__name__+':',str(exc))
        sys.exit(1)
