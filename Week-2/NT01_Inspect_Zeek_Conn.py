#!/usr/bin/env python3
"""NT-01: read-only, source-verified Zeek conn.log inventory and scan screening.

Run from Week-2 root: python NT01_Inspect_Zeek_Conn.py
Does not write project files, change Core, call Ollama, or declare attacks confirmed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import sys

BASE = Path('Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning')
SOURCE = BASE / 'NT-01-Zeek-conn-original.log'
MANIFEST = BASE / 'NT-01-Source-Manifest.json'
REQUIRED = ('ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'conn_state')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    h = hashlib.sha1()
    h.update(f'blob {len(data)}\0'.encode('ascii'))
    h.update(data)
    return h.hexdigest()


def utc(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec='milliseconds')
    except (OverflowError, OSError, ValueError):
        return '<timestamp outside displayable range>'


def spaced_sample(items: list, limit: int = 9) -> list:
    if len(items) <= limit:
        return items
    return [items[round(i * (len(items) - 1) / (limit - 1))] for i in range(limit)]


def run() -> None:
    print('=== NT-01 ZEEK CONN.LOG FORMAT & SCAN PATTERN INSPECTION ===')
    if not SOURCE.is_file() or not MANIFEST.is_file():
        raise RuntimeError('Original source or source manifest missing; no changes made.')
    data = SOURCE.read_bytes()
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8-sig'))
    if digest(data).lower() != str(manifest.get('sha256', '')).lower():
        raise RuntimeError('Original SHA-256 does not match saved manifest.')
    if len(data) != int(manifest.get('file_size_bytes', -1)):
        raise RuntimeError('Original byte size does not match saved manifest.')
    if git_blob(data).lower() != str(manifest.get('git_blob_sha1', '')).lower():
        raise RuntimeError('Git Blob SHA-1 mismatch.')

    raw_lines = data.splitlines()
    if len(raw_lines) != int(manifest.get('source_line_count', -1)):
        raise RuntimeError('Original line count mismatch.')
    print('\n=== SOURCE INTEGRITY ===')
    print('SHA256: MATCH | Git Blob SHA-1: MATCH | File Size: MATCH')
    print(f'Bytes: {len(data):,} | Total physical lines: {len(raw_lines):,}')
    print('Pinned commit:', manifest.get('repository_commit', '<missing>'))

    fields = None
    zeek_path = None
    zeek_open = None
    sep_marker = None
    rows = []
    comments = Counter()
    malformed = []
    invalid_ts = []
    invalid_port = []
    protos = Counter()
    states = Counter()
    service = Counter()
    sources = Counter()
    destinations = Counter()
    ports = Counter()
    per_pair = defaultdict(lambda: {'n': 0, 'ports': set(), 'states': Counter(),
                                   'first': math.inf, 'last': -math.inf, 'rows': []})
    by_minute = defaultdict(lambda: {'n': 0, 'ports': set(), 'states': Counter()})
    horizontal = defaultdict(lambda: {'n': 0, 'targets': set()})
    earliest = math.inf
    latest = -math.inf

    for line_no, line in enumerate(raw_lines, 1):
        if line.startswith(b'#'):
            key = line.partition(b' ')[0].decode('ascii', 'replace')
            comments[key] += 1
            if line.startswith(b'#separator '):
                sep_marker = line.split(b' ', 1)[1]
            elif line.startswith(b'#path\t'):
                zeek_path = line.partition(b'\t')[2].decode('utf-8', 'replace')
            elif line.startswith(b'#open\t'):
                zeek_open = line.partition(b'\t')[2].decode('utf-8', 'replace')
            elif line.startswith(b'#fields\t'):
                fields = line.split(b'\t')[1:]
                fields = [f.decode('utf-8', 'replace') for f in fields]
                if len(fields) != len(set(fields)):
                    raise RuntimeError('Duplicate Zeek field names in header.')
                missing = set(REQUIRED) - set(fields)
                if missing:
                    raise RuntimeError('Required conn fields missing: ' + ', '.join(sorted(missing)))
            continue
        if not line.strip():
            continue
        if fields is None:
            raise RuntimeError(f'Data line {line_no} arrived before #fields header.')
        parts = line.split(b'\t')
        if len(parts) != len(fields):
            malformed.append((line_no, len(parts), len(fields)))
            continue
        row = dict(zip(fields, (p.decode('utf-8', 'replace') for p in parts)))
        try:
            ts = float(row['ts'])
            if not math.isfinite(ts):
                raise ValueError('nonfinite timestamp')
        except ValueError:
            invalid_ts.append(line_no)
            continue
        try:
            port = int(row['id.resp_p'])
            if not 0 <= port <= 65535:
                raise ValueError('port out of range')
        except ValueError:
            invalid_port.append(line_no)
            continue
        source = row['id.orig_h']
        dest = row['id.resp_h']
        state = row['conn_state']
        proto = row['proto']
        rec = {'source_line': line_no, 'ts': ts, 'uid': row['uid'],
               'src': source, 'dst': dest, 'dst_port': port,
               'state': state, 'proto': proto, 'service': row.get('service', '-'),
               'history': row.get('history', '-'), 'line_sha256': digest(line)}
        rows.append(rec)
        protos[proto] += 1
        states[state] += 1
        service[row.get('service', '-')] += 1
        sources[source] += 1
        destinations[dest] += 1
        ports[port] += 1
        earliest = min(earliest, ts)
        latest = max(latest, ts)
        pair = per_pair[(source, dest)]
        pair['n'] += 1
        pair['ports'].add(port)
        pair['states'][state] += 1
        pair['first'] = min(pair['first'], ts)
        pair['last'] = max(pair['last'], ts)
        pair['rows'].append(rec)
        minute = int(ts // 60)
        bucket = by_minute[(source, dest, minute)]
        bucket['n'] += 1
        bucket['ports'].add(port)
        bucket['states'][state] += 1
        hp = horizontal[(source, port)]
        hp['n'] += 1
        hp['targets'].add(dest)

    if sep_marker != b'\\x09':
        raise RuntimeError(f'Unexpected Zeek separator metadata: {sep_marker!r}')
    if zeek_path != 'conn':
        raise RuntimeError(f'Zeek #path is {zeek_path!r}, expected conn')
    if not rows:
        raise RuntimeError('No valid Zeek conn records available.')

    print('\n=== ZEEK FILE FORMAT ===')
    print('Header #path:', zeek_path, '| Header #open:', zeek_open)
    print('Columns:', len(fields), '| Relevant:', ', '.join(REQUIRED))
    print('Parsed connection records:', f'{len(rows):,}')
    print('Malformed rows:', len(malformed), '| Invalid timestamps:', len(invalid_ts),
          '| Invalid destination ports:', len(invalid_port))
    print('Earliest event (from ts):', utc(earliest))
    print('Latest event (from ts):  ', utc(latest))
    print('Coverage duration (s):', round(latest - earliest, 3))
    if malformed:
        print('Malformed row examples:', malformed[:5])
    if invalid_ts:
        print('Invalid ts line numbers:', invalid_ts[:10])
    if invalid_port:
        print('Invalid port line numbers:', invalid_port[:10])

    print('\n=== NETWORK TRAFFIC INVENTORY ===')
    for label, counter, limit in (
        ('Protocols', protos, 8), ('Connection states', states, 12),
        ('Top sources', sources, 8), ('Top destinations', destinations, 8),
        ('Top destination ports', ports, 12), ('Services (unconfirmed/- included)', service, 8)):
        print('\n' + label + ':')
        for value, count in counter.most_common(limit):
            print(f'  {value}: {count:,}')

    print('\n=== VERTICAL SCAN SCREENING (SOURCE -> TARGET; DISTINCT PORTS) ===')
    ranked = sorted(per_pair.items(), key=lambda kv: (-len(kv[1]['ports']), -kv[1]['n']))
    for (src, dst), v in ranked[:10]:
        interesting = v['states'].get('S0', 0) + v['states'].get('REJ', 0)
        print(f'{src} -> {dst} | flows={v["n"]:,} | distinct_ports={len(v["ports"]):,} '
              f'| S0+REJ={interesting:,} | UTC {utc(v["first"])} -> {utc(v["last"])}')

    print('\n=== 60-SECOND SCREENING WINDOWS (UTC EPOCH MINUTES) ===')
    ranked_minutes = sorted(by_minute.items(), key=lambda kv: (-len(kv[1]['ports']), -kv[1]['n']))
    threshold = 20  # Inspection heuristic only; NOT a validated IDS rule or true-positive label.
    count_windows = sum(len(v['ports']) >= threshold for v in by_minute.values())
    print(f'Windows with >= {threshold} distinct target ports: {count_windows} '
          '(screening heuristic; NOT proof of malicious activity)')
    for (src, dst, minute), v in ranked_minutes[:10]:
        print(f'{utc(minute * 60)} | {src} -> {dst} | flows={v["n"]:,} '
              f'| ports={len(v["ports"]):,} | states={dict(v["states"].most_common(4))}')

    print('\n=== HORIZONTAL SCAN SCREENING (SOURCE + TARGET PORT -> DISTINCT TARGETS) ===')
    ranked_horizontal = sorted(horizontal.items(), key=lambda kv: (-len(kv[1]['targets']), -kv[1]['n']))
    for (src, port), v in ranked_horizontal[:8]:
        print(f'{src} -> port {port} | targets={len(v["targets"]):,} | flows={v["n"]:,}')

    (chosen_src, chosen_dst), top = ranked[0]
    print('\n=== ORIGINAL-EVIDENCE SAMPLES FROM TOP VERTICAL PAIR ===')
    print(f'Pair: {chosen_src} -> {chosen_dst} | total_records={top["n"]:,} '
          f'| distinct_ports={len(top["ports"]):,}')
    print('These are SOURCE LINE refs, NOT yet assigned E001/E002 identifiers.')
    for rec in spaced_sample(top['rows'], 9):
        print(f'Line {rec["source_line"]} | {utc(rec["ts"])} | '
              f'uid={rec["uid"]} | port={rec["dst_port"]} | '
              f'proto={rec["proto"]} | state={rec["state"]} | '
              f'history={rec["history"]} | sha256={rec["line_sha256"][:16]}...')

    print('\n=== EVIDENCE LIMITATIONS ===')
    print('- Zeek conn.log summarizes observed traffic; connection state is not proof of attacker intent.')
    print('- A high distinct-port count is a scan candidate, not a confirmed malicious label.')
    print('- No port-scan conclusion, successful compromise, or attribution is assumed from repository name.')
    print('- Original evidence, manifests, Core, Results, and historical reviews remain unchanged.')
    print('\nSTATUS: NT-01 FORMAT INSPECTION COMPLETE - SCAN CANDIDATE REVIEW NEXT')


if __name__ == '__main__':
    try:
        run()
    except (RuntimeError, ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print('\nSTOP:', exc, file=sys.stderr)
        sys.exit(1)
