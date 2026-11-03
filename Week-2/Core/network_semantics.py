"""Deterministic, conservative review requests for Zeek report attribution.

This code NEVER labels a packet malicious, modifies evidence, or issues actions.
It tests explicit AI-report claims against supplied structured evidence fields.
Only raw source-row records are compared; aggregate records are excluded.
"""
from __future__ import annotations

import ipaddress
import re

RAW_KIND = 'ZEEK_CONN_ORIGINAL_SOURCE_ROW'
SECTIONS = frozenset({
    'EXECUTIVE SUMMARY', 'LOG SOURCE', 'SIGNIFICANT SECURITY EVENTS',
    'SUSPICIOUS ACTIVITIES', 'EVIDENCE REFERENCES', 'INCIDENT TIMELINE',
    'POTENTIAL ATTACK INDICATORS', 'CONFIDENCE AND UNCERTAINTY',
})
BRACKET_REF = re.compile(r'\[\s*(E\d{3,5})\s*\]')
BRACKET_RANGE = re.compile(r'\[\s*E(\d{3,5})\s*\]\s*(?:-|–|—|to)\s*\[\s*E(\d{3,5})\s*\]', re.I)
PAIR = re.compile(r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})\b', re.I)
ON_PORT = re.compile(r'\b(?:on|destination|target|dst)\s+port\s+(\d{1,5})\b', re.I)
RANGE_MAX = 100


def _field(event, name):
    fields = event.get('fields')
    if isinstance(fields, dict):
        return fields.get(name)
    return event.get(name)


def _ip(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port(value):
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
        return n if 0 <= n <= 65535 and str(value).strip() == str(n) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _refs_in_line(line):
    refs = set(BRACKET_REF.findall(line))
    for range_match in BRACKET_RANGE.finditer(line):
        a, b = int(range_match.group(1)), int(range_match.group(2))
        if 0 <= b - a <= RANGE_MAX:
            width = max(len(range_match.group(1)), len(range_match.group(2)))
            refs.update(f'E{n:0{width}d}' for n in range(a, b + 1))
    return sorted(refs)


def _raw_map(events):
    by_ref = {}
    for event in events:
        ref = event.get('ref')
        if (isinstance(ref, str) and re.fullmatch(r'E\d{3,5}', ref) and
                _field(event, 'record_kind') == RAW_KIND and ref not in by_ref):
            by_ref[ref] = event
    return by_ref


def _private_as_benign(text):
    # Requires an explicit *causal* association: private/internal geography
    # cited as the reason for a safe/no-threat verdict. Neutral descriptions
    # and negated assumptions do not qualify.
    risk_verdict = re.compile(
        r'\b(?:no\s+(?:clear\s+)?(?:evidence|indication|signs?)\s+of\s+malicious\s+activity|'
        r'no\s+malicious\s+activity\s+(?:is\s+)?(?:evident|detected)|'
        r'(?:is|are|was|were)\s+(?:benign|safe|harmless)|'
        r'not\s+malicious|low[ -]risk)\b', re.I)
    network_as_reason = re.compile(
        r'\b(?:because|since|as|due\s+to|given\s+that|therefore)\b.{0,170}?'
        r'\b(?:within\s+(?:the\s+)?same\s+network|'
        r'(?:the\s+)?same\s+(?:sub)?network|'
        r'(?:internal|private|local)\s+(?:sub)?network|'
        r'(?:private|rfc\s*1918)\s+(?:ip\s+)?addresses?)\b', re.I)
    alternative = re.compile(
        r'\b(?:same\s+(?:sub)?network|(?:internal|private)\s+(?:sub)?network|private\s+ip)\b'
        r'.{0,100}?\b(?:therefore|thus|so)\b.{0,100}?'
        r'\b(?:benign|safe|harmless|not\s+malicious)\b', re.I)
    return bool((risk_verdict.search(text) and network_as_reason.search(text)) or alternative.search(text))


def _flag(check, severity, section, line, message):
    return {'check': check, 'severity': severity, 'section': section,
            'value': line[:160], 'message': message,
            'analyst_disposition': 'Unreviewed'}



def _positive_bytes(value):
    if isinstance(value, bool):
        return False
    try:
        return int(value) > 0 and str(value).strip() == str(int(value))
    except (ValueError, TypeError, OverflowError):
        return False


def _denies_any_completed_data_connection(line):
    # Deliberately narrow: never challenge "no confirmed C2", "no known
    # malicious transfer", "no exfiltration", or absence of application logs.
    # Those remain unknown even when SF traffic exists.
    return bool(re.search(
        r'\b(?:no\s+(?:clear\s+)?evidence\s+of|no|without)\s+'
        r'(?:any\s+)?(?:successful|completed|established)\s+'
        r'(?:tcp\s+)?connections?\s+(?:or|and)\s+'
        r'(?:any\s+)?(?:data\s+transfer|data\s+exchange|transferred\s+data)\b',
        line, re.I))


def _source_port_group_mismatch(line, rows):
    # A grouped port statement without an E### does not support arbitrary
    # attribution. Limit to clear "on port N ... source ports (A, B)" claims
    # with two confirming source-port values and unambiguous contradictions.
    # Suffix trailing punctuation is allowed; full source logs aren't needed.
    dst_match = ON_PORT.search(line)
    if not dst_match:
        return []
    target_port = _port(dst_match.group(1))
    if target_port is None:
        return []
    matches = list(re.finditer(r'\bsource\s+ports?\s*[:(]\s*'
                              r'((?:\d{1,5}\s*,\s*){2,}\d{1,5})\)', line, re.I))
    # Simpler "source ports: 123, 456, 789" version, where no ')' exists.
    if not matches:
        matches = list(re.finditer(r'\bsource\s+ports?\s*[:]\s*'
                                  r'((?:\d{1,5}\s*,\s*){2,}\d{1,5})', line, re.I))
    if not matches:
        return []
    ports = [int(x) for x in re.findall(r'\b\d{1,5}\b', matches[0].group(1))]
    if not ports or len(ports) < 3 or len(set(ports)) != len(ports):
        return []
    observed = {}
    for ref, event in rows.items():
        sp = _port(_field(event, 'src_port'))
        dp = _port(_field(event, 'dst_port'))
        if sp is not None and dp is not None and sp in ports:
            observed.setdefault(sp, []).append((dp, ref))
    # At least two of the enumerated ports must truly belong to the stated
    # destination port, avoiding guesses based on a lone matching number.
    if sum(any(dp == target_port for dp, _ in observed.get(sp, []))
           for sp in ports) < 2:
        return []
    wrong = []
    for sp in ports:
        candidates = observed.get(sp, [])
        if candidates and not any(dp == target_port for dp, _ in candidates):
            dsts = {dp for dp, _ in candidates}
            if len(dsts) == 1:
                wrong.append((sp, next(iter(dsts)), candidates[0][1]))
    return wrong

def review_requests(sections, events):
    """Return only supported review requests, never automatic guilt findings.

    Input report sections should be the existing project sections dict. If
    report text does not explicitly link a direction/port to a [E###] ref,
    this function does not infer a mismatch.
    """
    if not isinstance(sections, dict):
        return []
    rows = _raw_map(events)
    if not rows:
        return []
    results, seen = [], set()
    # Only statements about observable TCP connections / data are compared
    # with conn.log states and bytes. Do not confuse this with proof of C2 or
    # application-level success. State SF + bidirectional positive bytes means
    # the log did observe an established, data-bearing TCP connection.
    observed_complete_with_data = [ev for ev in rows.values()
                                   if str(_field(ev, 'proto')).lower() == 'tcp'
                                   and str(_field(ev, 'conn_state')).upper() == 'SF'
                                   and _positive_bytes(_field(ev, 'orig_bytes'))
                                   and _positive_bytes(_field(ev, 'resp_bytes'))]
    for section, text in sections.items():
        if section not in SECTIONS or not isinstance(text, str):
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if observed_complete_with_data and _denies_any_completed_data_connection(line):
                key = ('network_observed_tcp_data_contradiction', section)
                if key not in seen:
                    seen.add(key)
                    refs = ', '.join(ev.get('ref', '?') for ev in observed_complete_with_data[:3])
                    results.append(_flag('network_observed_tcp_data_contradiction', 'high',
                                         section, line,
                                         'Report categorically denies completed connections / observed '
                                         f'data, but raw TCP SF rows with positive bidirectional bytes '
                                         f'exist (examples: {refs}). This does not establish C2 success.'))
            # An explicitly enumerated "source ports" list can be checked in
            # the same sentence against the asserted destination port. Require
            # at least two listed ports actually known for that destination;
            # do not guess from uncited generic prose or aggregate-only inputs.
            context_ports = _source_port_group_mismatch(line, rows)
            if context_ports:
                key = ('network_source_port_group_mismatch', section)
                if key not in seen:
                    seen.add(key)
                    examples = '; '.join(f'{port} maps to dst {dst}, {ref}'
                                         for port, dst, ref in context_ports[:4])
                    results.append(_flag('network_source_port_group_mismatch', 'medium',
                                         section, line,
                                         f'Source port(s) grouped under a different asserted destination port: '
                                         f'{examples}. Requires analyst review; no malicious verdict.'))
            if _private_as_benign(line):
                key = ('private_network_not_benign', section)
                if key not in seen:
                    seen.add(key)
                    results.append(_flag('private_network_not_benign', 'medium', section, line,
                        'The fact that endpoints are on the same/private network does not establish benign intent or lack of a scan.'))
            refs = _refs_in_line(line)
            if not refs:
                continue
            pair = PAIR.search(line)
            line_src = _ip(pair.group(1)) if pair else None
            line_dst = _ip(pair.group(2)) if pair else None
            # Ignore expressly conditional/negated flow direction claims.
            negated = bool(re.search(r'\b(?:not|incorrect(?:ly)?|wrong(?:ly)?)\s+(?:a\s+)?(?:flow\s+)?from\b', line, re.I))
            claimed_ports = [int(m.group(1)) for m in ON_PORT.finditer(line)]
            for ref in refs:
                event = rows.get(ref)
                if not event:
                    continue  # In particular, NEVER treat E001 aggregate as a raw connection.
                src, dst = _ip(_field(event, 'src_ip')), _ip(_field(event, 'dst_ip'))
                if pair and line_src and line_dst and src and dst and not negated and (line_src, line_dst) != (src, dst):
                    key = ('network_direction_mismatch', section, ref)
                    if key not in seen:
                        seen.add(key)
                        results.append(_flag('network_direction_mismatch', 'high', section, line,
                            f'{ref}: reported {line_src} -> {line_dst}; source record shows {src} -> {dst}.'))
                src_port, dst_port = _port(_field(event, 'src_port')), _port(_field(event, 'dst_port'))
                if dst_port is None:
                    continue
                for claimed in claimed_ports:
                    # Different (unverified) ports might be transcription mistakes,
                    # but do not call them a *source-vs-destination port* swap.
                    if claimed == src_port and claimed != dst_port:
                        key = ('network_port_role_mismatch', section, ref)
                        if key not in seen:
                            seen.add(key)
                            results.append(_flag('network_port_role_mismatch', 'medium', section, line,
                                f'{ref}: report uses source port {src_port} as destination/on-port; observed destination port is {dst_port}.'))
                    # A different port number is a factual mismatch too; the
                    # older validator only caught source/destination port swaps.
                    # Limit this check to one explicitly cited raw record so a
                    # grouped summary cannot generate misleading mismatches.
                    elif (len(refs) == 1 and pair and (line_src, line_dst) == (src, dst) and
                          claimed != dst_port and claimed != src_port):
                        key = ('network_destination_port_mismatch', section, ref)
                        if key not in seen:
                            seen.add(key)
                            results.append(_flag('network_destination_port_mismatch', 'high', section, line,
                                f'{ref}: report says destination/on-port {claimed}; original Zeek row shows destination port {dst_port}.'))
    return results[:30]  # bounded to avoid excessive flags for long report tables
