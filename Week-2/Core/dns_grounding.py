"""Evidence-grounded Zeek DNS burst detection, independent from LLM output.

Checks supplied verified-format aggregate against independent sampled Zeek DNS rows.
The aggregate is DERIVED from an original source, not a captured query. This module
cannot independently establish the provenance of the source; the NT02 preparation
script and saved SHA256 manifest perform that separate check.
"""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
import re

RULE = 'NETWORK_DNS_CHUNK_BURST'
AGG = 'VERIFIED_DNS_QUERY_CLUSTER_AGGREGATE_NOT_RAW_ZEEK_EVENT'
RAW = 'ZEEK_DNS_ORIGINAL_SOURCE_ROW'
REF = re.compile(r'E\d{3,5}\Z')
CHUNK = re.compile(r'^chunk(?P<ordinal>\d{3,6})-(?P<payload>[a-f0-9]{12,64})\.(?P<suffix>[a-z0-9.-]+)\.?$', re.I)
SHA = re.compile(r'^[a-fA-F0-9]{64}$')


def _field(ev, k):
    fs = ev.get('fields') if isinstance(ev.get('fields'), dict) else ev
    return fs.get(k)


def _integer(value):
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
        return n if str(n) == str(value).strip() else None
    except (TypeError, ValueError, OverflowError):
        return None


def _float(value):
    try:
        n = float(value)
        return n if 0 <= n <= 86400 and n == n else None
    except (TypeError, ValueError, OverflowError):
        return None


def _ip(value):
    try:
        return str(ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt if dt.tzinfo is not None else None
    except ValueError:
        return None


def _counts(ev, prefix, nested):
    # Core.log_parser JSON normalizer flattens nested dict fields with dots.
    fields = ev.get('fields') if isinstance(ev.get('fields'), dict) else ev
    out = {}
    for k, v in fields.items():
        if isinstance(k, str) and k.startswith(prefix):
            n = _integer(v)
            if n is None or n < 0:
                return None
            out[k[len(prefix):]] = n
    if not out and isinstance(fields.get(nested), dict):
        for k, v in fields[nested].items():
            n = _integer(v)
            if n is None or n < 0:
                return None
            out[str(k)] = n
    return out


def _valid_refs(events):
    refs = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        r = ev.get('ref')
        if isinstance(r, str) and REF.fullmatch(r) and r not in refs:
            refs.add(r)
            yield ev


def detect_dns(events):
    items = list(_valid_refs(events))
    aggregates = [e for e in items if _field(e, 'record_kind') == AGG]
    rows = [e for e in items if _field(e, 'record_kind') == RAW]
    findings, context = [], []
    for agg in aggregates:
        a_ref = agg['ref']
        src = _ip(_field(agg, 'src_ip'))
        dst = _ip(_field(agg, 'dst_ip'))
        count = _integer(_field(agg, 'matching_dns_records'))
        distinct = _integer(_field(agg, 'matching_distinct_exact_queries'))
        seconds = _float(_field(agg, 'duration_seconds'))
        raw_pattern = str(_field(agg, 'query_pattern') or '')
        declared = re.fullmatch(r'chunkNNN-hex\.([a-z0-9.-]+)', raw_pattern, re.I)
        src_hash = _field(agg, 'source_sha256')
        start = _parse_time(_field(agg, 'first_observed_utc'))
        end = _parse_time(_field(agg, 'last_observed_utc'))
        qtypes = _counts(agg, 'matching_query_type_counts.', 'matching_query_type_counts')
        rcodes = _counts(agg, 'matching_response_code_counts.', 'matching_response_code_counts')
        if (not src or not dst or src == dst or not isinstance(src_hash, str) or
            not SHA.fullmatch(src_hash) or count is None or distinct is None or
            seconds is None or not start or not end or not qtypes or not rcodes or
            count < 20 or distinct < 20 or distinct > count or seconds > 300 or
            declared is None or
            abs((end-start).total_seconds() - seconds) > 0.002 or
            sum(qtypes.values()) != count or sum(rcodes.values()) != count):
            continue
        witnesses, query_set, ordinals = [], set(), set()
        for row in rows:
            if _ip(_field(row, 'src_ip')) != src or _ip(_field(row, 'dst_ip')) != dst:
                continue
            query = _field(row, 'query')
            if not isinstance(query, str):
                continue
            m = CHUNK.fullmatch(query.strip().lower())
            if not m or m.group('suffix').rstrip('.').lower() != declared.group(1).lower():
                continue
            if str(_field(row, 'proto')).lower() not in ('udp', 'tcp'):
                continue
            if str(_field(row, 'qtype_name')) not in qtypes:
                continue
            if str(_field(row, 'rcode_name')) not in rcodes:
                continue
            if not SHA.fullmatch(str(_field(row, 'source_line_sha256') or '')):
                continue
            when = _parse_time(_field(row, 'timestamp'))
            if when is None or not start <= when <= end:
                continue
            witnesses.append(row['ref'])
            query_set.add(query.lower().rstrip('.'))
            ordinals.add(int(m.group('ordinal')))
        # Aggregate alone is never sufficient for a grounded finding.
        if len(witnesses) < 5 or len(query_set) < 5 or len(ordinals) < 5 or len(query_set) > distinct:
            continue
        high = count >= 100 and distinct >= 50 and seconds <= 60 and len(witnesses) >= 8
        findings.append({
            'rule_id': RULE,
            'label': 'Concentrated sequential chunk-style DNS query burst',
            'confidence_in_observed_pattern': 'high' if high else 'medium',
            'evidence_refs': [a_ref] + sorted(set(witnesses)),
            'observation': (f'Supplied computed aggregate and corroborating original Zeek DNS rows support '
                            f'{count} queries ({distinct} distinct) from {src} to DNS resolver {dst} '
                            f'in {seconds:.6f}s with sequential chunk-like names.'),
            'outcome': ('DNS tunneling-like indicator requires investigation; successful tunneling, '
                        'data exfiltration, authorization status and malicious intent NOT established.'),
            'status': 'investigation_indicator_not_incident_verdict',
            'details': {
                'source_ip': src, 'resolver_ip': dst,
                'dns_records': count, 'distinct_exact_queries': distinct,
                'duration_seconds': seconds, 'query_pattern': raw_pattern,
                'query_type_counts': qtypes, 'response_code_counts': rcodes,
                'aggregate_ref': a_ref, 'sample_source_refs': sorted(set(witnesses)),
                'aggregate_is_raw_dns_record': False,
                'full_source_integrity_checked_in_this_function': False,
                'source_sha256_claimed_by_aggregate': src_hash,
            },
        })
    if aggregates:
        context.append({
            'rule_id': 'NETWORK_DNS_AGGREGATE_CONTEXT',
            'evidence_refs': [e['ref'] for e in aggregates],
            'observation': 'A computed DNS cluster aggregate is present, not an individual DNS query.',
            'security_limit': 'The original DNS source and derivation must be independently verified.',
        })
    return {'behavioral_findings': findings, 'context_observations': context}


def prompt_notes(events):
    results = detect_dns(events)
    if not results['behavioral_findings']:
        return []
    computed_refs = [e['ref'] for e in _valid_refs(events)
                     if str(_field(e, 'record_kind') or '').endswith('_AGGREGATE_NOT_RAW_ZEEK_EVENT')]
    return [
        'DNS GROUNDING: Evidence supports a concentrated, high-diversity sequential chunk-style DNS query '
        'BURST. Name it explicitly, with aggregate DNS-record count, number of distinct queries, duration, '
        'client and resolver. This supports review for DNS tunneling-LIKE activity, not proven tunneling.',
        'DNS EVIDENCE ROLES: Computed aggregate refs ' + ', '.join(computed_refs) + ' are NOT DNS packets or single queries. '
        'Original sampled DNS rows must be distinguished from summaries. Do not confuse DNS client with resolver.',
        'DNS OUTCOME LIMITS: NOERROR does not prove data transmission/exfiltration or attacker control; "-" '
        'is unavailable rcode, not NXDOMAIN. Private or .test domains do not establish benign intent. '
        'Hex-looking labels are not necessarily cryptographic hashes. Each finding needs [E###].',
    ]


def _flag(kind, severity, section, value, message):
    return {'check': kind, 'severity': severity, 'section': section, 'value': value[:160],
            'message': message, 'analyst_disposition': 'Unreviewed'}


def review_requests(sections, events):
    if not isinstance(sections, dict):
        return []
    detections = detect_dns(events)['behavioral_findings']
    if not detections:
        return []
    relevant = '\n'.join(str(sections.get(k, '')) for k in (
        'EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS',
        'SUSPICIOUS ACTIVITIES', 'POTENTIAL ATTACK INDICATORS'))
    flags = []
    # The old phrase detector missed reports saying e.g. "a concentrated,
    # high-diversity sequential DNS query burst" (NT-02 post-grounding case).
    # Require both DNS burst semantics and chunk/sequential context; discussing
    # DNS tunneling alone is not enough to prove the observed pattern was named.
    burst_named = bool(re.search(r'\bdns\b', relevant, re.I) and
                       re.search(r'\b(?:burst|high[ -]?frequency|rapid[- ]fire|\d+\s+queries?\s+(?:within|in|over)\s+\d+)', relevant, re.I))
    chunk_named = bool(re.search(
        r'\b(?:chunk\d+|chunk[- ](?:style|like)|chunkNNN|sequential\s+(?:dns\s+)?(?:query|queries|subdomains)|'
        r'(?:query|queries|subdomains)\s+(?:with\s+)?(?:sequential|chunk[- ](?:style|like)))\b',
        relevant, re.I))
    # Negated pattern statements ("no DNS burst observed") do not count as a
    # positive finding merely because they contain keywords.
    denied = bool(re.search(r'\b(?:no|not|without)\s+(?:observed\s+|evidence\s+of\s+|confirmed\s+)?'
                            r'(?:sequential\s+)?dns\s+(?:query\s+)?burst\b', relevant, re.I))
    found = burst_named and chunk_named and not denied
    if relevant.strip() and not found:
        flags.append(_flag('network_dns_chunk_burst_not_identified', 'high', 'SUSPICIOUS ACTIVITIES',
                           relevant, 'Grounded evidence supports a concentrated chunk-style DNS query burst; AI did not identify it.'))
    if found:
        # Counts/durations are derived from the grounded input, not hard-coded
        # to the lab dataset. An LLM can identify the behavior but omit or
        # misstate its quantitative support. Report that separately.
        for detection in detections[:4]:
            details = detection.get('details') or {}
            count = _integer(details.get('dns_records'))
            distinct = _integer(details.get('distinct_exact_queries'))
            seconds = _float(details.get('duration_seconds'))
            if count is None or distinct is None or seconds is None:
                continue
            count_pattern = rf'(?<!\d){count}(?!\d)'
            distinct_pattern = rf'(?<!\d){distinct}(?!\d)'
            count_named = bool(re.search(rf'(?:{count_pattern}\s+(?:(?:distinct|unique)\s+)?(?:dns\s+)?(?:queries|query\s+records|records)|'
                                         rf'(?:dns\s+)?(?:queries|records)\s*[:=]\s*{count_pattern})', relevant, re.I))
            distinct_named = bool(re.search(rf'(?:{distinct_pattern}\s+(?:distinct|unique)\s+(?:dns\s+)?queries|'
                                            rf'(?:distinct|unique)\s+(?:dns\s+)?queries\s*[:=]\s*{distinct_pattern}|'
                                            rf'{distinct_pattern}\s+distinct\b)', relevant, re.I))
            reported_durations = [float(m.group(1)) for m in re.finditer(
                r'(?<![\w.])(\d+(?:\.\d+)?)\s*(?:seconds?|secs?|s)\b', relevant, re.I)]
            duration_named = any(abs(t - seconds) <= max(0.05, seconds * 0.01) for t in reported_durations)
            absent = [label for label, ok in (
                ('query_count', count_named), ('distinct_query_count', distinct_named),
                ('duration_seconds', duration_named)) if not ok]
            if absent:
                flags.append(_flag('network_dns_chunk_burst_missing_quantification', 'medium',
                                   'SUSPICIOUS ACTIVITIES', ', '.join(absent),
                                   f'DNS burst identified but missing verified metrics: {", ".join(absent)}. '
                                   f'Grounded input: {count} DNS records, {distinct} distinct queries, '
                                   f'{seconds:.6f} seconds. This is a review request, not a claim of malicious intent.'))
    for section, body in sections.items():
        if not isinstance(body, str) or section not in (
            'EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS', 'SUSPICIOUS ACTIVITIES',
            'POTENTIAL ATTACK INDICATORS', 'CONFIDENCE AND UNCERTAINTY'):
            continue
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            # Only decisive affirmative claims, not "no evidence" or "potential".
            if re.search(r'\b(?:confirmed|proven|definitive|successfully|verified)\s+'
                         r'(?:data\s+)?(?:exfiltrat\w*|dns\s+tunnel\w*)\b', line, re.I) and not re.search(
                         r'\b(?:not|no|without|unconfirmed|unknown)\b', line, re.I):
                flags.append(_flag('network_dns_exfiltration_outcome_unsupported', 'high', section, line,
                                   'Observed queries do not establish successful DNS tunneling or exfiltration.'))
            if re.search(r'\b(?:E001|E002)\b', line) and re.search(
                    r'\b(?:single\s+(?:query|packet)|one\s+(?:query|packet)|individual\s+dns\s+query)\b', line, re.I):
                if not re.search(r'\b(?:not|never|isn.t)\b', line, re.I):
                    flags.append(_flag('network_dns_aggregate_misread_as_query', 'high', section, line,
                                       'E001/E002 are computed statistics, not individual DNS query records.'))
    return flags[:15]
