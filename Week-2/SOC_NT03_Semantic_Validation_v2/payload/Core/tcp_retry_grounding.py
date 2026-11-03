"""Conservative TCP same-four-tuple sequence grounding from supplied Zeek rows.

Detection is evidence pattern recognition, never a C2 or malware verdict.
No network, model, filesystem, or original source manifest is consulted here.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
import re
import statistics

RAW_KIND = 'ZEEK_CONN_ORIGINAL_SOURCE_ROW'
RULE = 'NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE'
_REF = re.compile(r'E\d{3,5}\Z')
_BH = re.compile(r'\b(?:retry|retries|retransmi\w*|back[ -]?off|source[ -]?port reuse|reused source[ -]?ports?|'
                 r'repeated (?:tcp )?(?:four[ -]?tuple|source[ -]?port)|S0\s*(?:to|->|→)\s*SF)\b', re.I)
_NEGATION = re.compile(r'\b(?:no|not|without|absent|unlikely)\b.{0,45}?\b(?:retry|retries|back[ -]?off|retransmi\w*|source[ -]?port reuse)\b', re.I)


def _value(ev, key):
    fields = ev.get('fields')
    return fields.get(key) if isinstance(fields, dict) else ev.get(key)


def _ip(v):
    try:
        return str(ip_address(v)) if isinstance(v, str) else None
    except ValueError:
        return None


def _port(v):
    if isinstance(v, bool):
        return None
    try:
        num = int(v)
        return num if 0 <= num <= 65535 and str(v).strip() == str(num) else None
    except (ValueError, TypeError, OverflowError):
        return None


def _time(ev):
    for candidate in (ev.get('timestamp_utc'), _value(ev, 'timestamp'), ev.get('timestamp_raw')):
        if not isinstance(candidate, str):
            continue
        try:
            dt = datetime.fromisoformat(candidate.replace('Z', '+00:00'))
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).timestamp()
        except (ValueError, OverflowError):
            pass
    return None


def _flag(check, severity, section, value, message):
    return {'check': check, 'severity': severity, 'section': section,
            'value': value[:160], 'message': message, 'analyst_disposition': 'Unreviewed'}


def detect_tcp_retry_sequences(events):
    """Evidence-gated patterns from distinct raw Zeek TCP rows only.

    Require >=2 source ports each having >=3 same-tuple rows, >=2 S0
    and a later SF. Thus single S0/SF, UDP/NTP, DNS, and aggregates do
    not trigger. Same four-tuple can represent retransmission/capture
    artefact; it is NOT proof of distinct sessions or a backoff algorithm.
    """
    grouped, refs = defaultdict(list), set()
    for ev in events:
        ref = ev.get('ref')
        if not isinstance(ref, str) or not _REF.fullmatch(ref) or ref in refs:
            continue
        refs.add(ref)
        if _value(ev, 'record_kind') != RAW_KIND or str(_value(ev, 'proto')).lower() != 'tcp':
            continue
        src, dst = _ip(_value(ev, 'src_ip')), _ip(_value(ev, 'dst_ip'))
        sp, dp = _port(_value(ev, 'src_port')), _port(_value(ev, 'dst_port'))
        state = str(_value(ev, 'conn_state') or '').upper()
        ts = _time(ev)
        if not src or not dst or src == dst or sp is None or dp is None or ts is None:
            continue
        if state not in ('S0', 'SF'):
            continue
        grouped[(src, dst, dp, sp)].append((ts, ref, state))

    pairs = defaultdict(list)
    for key, items in grouped.items():
        items = sorted(items)
        states = [row[2] for row in items]
        if len(items) < 3 or states.count('S0') < 2 or 'SF' not in states:
            continue
        sf_index = states.index('SF')
        if states[:sf_index].count('S0') < 2:
            continue
        deltas = [b[0] - a[0] for a, b in zip(items, items[1:])]
        if not all(0 < d <= 86400 for d in deltas):
            continue
        pairs[key[:3]].append((key[3], items, deltas))

    findings = []
    for (src, dst, dst_port), groups in sorted(pairs.items()):
        if len(groups) < 2:
            continue
        groups.sort(key=lambda g: g[0])
        all_refs = sorted({item[1] for _, records, _ in groups for item in records})
        intervals = [round(v, 3) for _, _, values in groups for v in values]
        detail_groups = [
            {'source_port': source_port,
             'connection_record_count': len(records),
             'sequence': [r[2] for r in records],
             'inter_arrival_seconds': [round(d, 3) for d in values],
             'evidence_refs': [r[1] for r in records]}
            for source_port, records, values in groups
        ]
        findings.append({
            'rule_id': RULE,
            'label': 'Repeated Zeek TCP four-tuple rows with S0-before-SF sequences',
            'confidence_in_observed_pattern': 'high' if len(groups) >= 3 else 'medium',
            'evidence_refs': all_refs,
            'observation': (
                f'{len(groups)} repeated TCP source-port groups ({sum(len(g[1]) for g in groups)} '
                f'original conn.log rows) from {src} to {dst}:{dst_port} show '
                f'at least two S0 rows preceding an SF row per group; observed inter-arrival '
                f'intervals vary, potentially consistent with retry/retransmission/backoff-like activity.'),
            'outcome': ('Repeated same-four-tuple records do NOT prove independent connection attempts, '
                        'exponential backoff, periodic beaconing, C2, malware, authorization, '
                        'file-download contents or compromise.'),
            'details': {
                'src_ip': src, 'dst_ip': dst, 'dst_port': dst_port, 'proto': 'tcp',
                'repeated_source_port_groups': len(groups),
                'repeated_source_port_rows': sum(len(g[1]) for g in groups),
                'all_intervals_median_seconds': round(statistics.median(intervals), 3),
                'groups': detail_groups, 'raw_zeek_row_refs_only': True,
                'full_source_integrity_checked_in_this_function': False,
            },
            'status': 'investigation_indicator_not_incident_verdict',
        })
    return {'behavioral_findings': findings, 'context_observations': []}


def prompt_notes(events):
    if not detect_tcp_retry_sequences(events)['behavioral_findings']:
        return []
    return [
        'TCP GROUNDING: Verify repeated same-four-tuple/source-port TCP rows and their S0-before-SF '
        'patterns using [E###]. Report counts and timing intervals when available. Same-tuple Zeek '
        'rows can reflect retransmission, not necessarily separate TCP sessions.',
        'TCP INTERPRETATION: Consider retries or backoff-like behavior as hypotheses only. '
        'Do not infer periodic beaconing, confirmed C2, successful attack, file downloads or '
        'authorization from conn.log connection state or original dataset labels.'
    ]


def review_requests(sections, events):
    if not isinstance(sections, dict):
        return []
    findings = detect_tcp_retry_sequences(events)['behavioral_findings']
    if not findings:
        return []
    relevant = '\n'.join(str(sections.get(k, '')) for k in (
        'EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS',
        'SUSPICIOUS ACTIVITIES', 'POTENTIAL ATTACK INDICATORS'))
    if not relevant.strip():
        return []
    if not _BH.search(relevant) or _NEGATION.search(relevant):
        return [_flag('network_tcp_retry_pattern_not_identified', 'high', 'SUSPICIOUS ACTIVITIES',
                      relevant, 'Supported repeated same-four-tuple S0-before-SF TCP sequences '
                      'were not identified in the security narrative.')]
    # Mentioning "retry" or an aggregate alone is not a quantitatively grounded
    # explanation. This check is deliberately distinct from missed detection.
    # Do not use fixed IP addresses, port numbers, record counts or durations.
    findings_text = relevant
    review = []
    for item in findings[:5]:
        details = item.get('details') or {}
        group_count = details.get('repeated_source_port_groups')
        row_count = details.get('repeated_source_port_rows')
        groups = details.get('groups') or []
        if not isinstance(group_count, int) or not isinstance(row_count, int) or not groups:
            continue
        # A count is accepted only near an appropriate noun, not anywhere in
        # the report (e.g. in an unrelated IP address, port or timestamp).
        groups_named = bool(re.search(
            rf'(?<!\d){group_count}\s+(?:(?:repeated|distinct|different)\s+)?'
            rf'(?:(?:source[ -]?port|four[ -]?tuple|tcp)\s+)?(?:groups|sequences|series)\b',
            findings_text, re.I))
        rows_named = bool(re.search(
            rf'(?<!\d){row_count}\s+(?:(?:original|raw|zeek|tcp|connection)\s+)*'
            rf'(?:rows|records|events)\b', findings_text, re.I))
        ports = [str(g.get('source_port')) for g in groups if _port(g.get('source_port')) is not None]
        # At least two of the actually observed ports must appear as numerals.
        ports_named = sum(bool(re.search(rf'(?<!\d){re.escape(pt)}(?!\d)', findings_text))
                          for pt in set(ports)) >= min(2, len(set(ports)))
        intervals = [float(x) for group in groups for x in group.get('inter_arrival_seconds', [])
                     if isinstance(x, (int, float)) and not isinstance(x, bool) and x > 0]
        reported_times = [float(m.group(1)) for m in re.finditer(
            r'(?<![\w.])(\d+(?:\.\d+)?)\s*(?:seconds?|secs?|s)\b', findings_text, re.I)]
        interval_named = bool(intervals and any(
            abs(t - actual) <= max(0.08, actual * 0.01)
            for t in reported_times for actual in intervals))
        absent = [name for name, ok in (
            ('repeated_group_count', groups_named), ('raw_row_count', rows_named),
            ('source_port_examples', ports_named), ('verified_interval_example', interval_named)) if not ok]
        if absent:
            review.append(_flag('network_tcp_retry_missing_quantification', 'medium',
                                'SUSPICIOUS ACTIVITIES', ', '.join(absent),
                                f'TCP sequence was mentioned, but grounded supporting details are absent: '
                                f'{", ".join(absent)}. Input shows {group_count} groups and {row_count} raw rows. '
                                'Review only; repeated Zeek rows are not proof of distinct retry sessions or C2.'))
    return review
