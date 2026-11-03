#!/usr/bin/env python3
"""DEPI P5 Week-2: mixed-log intake and evidence-aware local AI routing.

Optional add-on for existing Week-2 Core; never alters original input or Core.
Requires Python 3.10+, stdlib, and existing project dependencies.
Usage: python -B unified_soc.py inspect PATH
       python -B unified_soc.py analyze PATH
All generated reports require human review. No response/containment is performed.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
from unittest.mock import patch

import config
from Core import analysis, grounded_detection, log_parser, ollama_client, store

ENGINE_VERSION = 'unified-intake-0.4.0-candidate'
FAMILIES = ('windows', 'linux', 'network', 'wazuh', 'unknown')
SYSLOG_LINE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\S+\s+')
APACHE_PARSE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<method>GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(?P<target>[^\"\s]+)\s+[^\"]*\"\s+(?P<status>[1-5]\d\d)\b')
APACHE_LINE = re.compile(r'^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+[^"\r\n]*"\s+[1-5]\d\d\b')
LOG_FAMILY = {
    'windows': 'Microsoft Windows event telemetry',
    'linux': 'Linux host/audit/syslog telemetry',
    'network': 'Network/Zeek/HTTP/firewall telemetry',
    'wazuh': 'Wazuh alert with unspecified underlying telemetry',
    'unknown': 'Unrecognized or conflicting source',
}

# Redact secrets from the *copy* used for AI/report. Input evidence never changed.
PW_ARG = re.compile(r'(?i)(?<!\S)-pw(?:\s+|=)(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s,;"\x27}\]\r\n]+)')
SECRET_KV = re.compile(r'(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)\b(\s*[=:]\s*)(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s,;\r\n}\]]+)')
BEARER = re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~-]{8,}')
BASIC = re.compile(r'(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}')
PRIVATE_KEY = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S)


def redact_text(s: str) -> str:
    s = PRIVATE_KEY.sub('[REDACTED_PRIVATE_KEY]', s)
    s = PW_ARG.sub('-pw [REDACTED]', s)
    s = SECRET_KV.sub(lambda m: m.group(1) + m.group(2) + '[REDACTED]', s)
    s = BEARER.sub('Bearer [REDACTED]', s)
    return BASIC.sub('Basic [REDACTED]', s)


def redact_object(obj):
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: '[REDACTED]' if re.search(r'(?i)^(?:password|passwd|pwd|token|secret|api_?key|authorization|x-depi-webhook-key)$', str(k).split('.')[-1])
                else redact_object(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_object(v) for v in obj]
    return obj



# Parser evidence references are reassigned to E001.. within a mixed file.
# Pre-existing E### tokens in SOURCE CONTENT must never masquerade as the
# canonical references the model should cite. Strip only when the original
# field is explicitly an evidence/ref identifier. This is an AI-facing COPY:
# original bytes and the mapping remain available separately via SHA256/manifest.
LEGACY_REF_VALUE = re.compile(r'^E\d{3,5}$', re.I)
LEGACY_REF_KV = re.compile(
    r'(?i)(?<![\w.])(?P<key>(?:original_)?(?:evidence_id|evidence_ref|ref))'
    r'(?P<sep>\s*=\s*)(?P<val>E\d{3,5})(?!\w)'
)
SOURCE_REF_KEYS = frozenset(('ref', 'evidence_id', 'evidence_ref', 'original_evidence_id'))


def suppress_source_refs(raw):
    """Hide embedded *legacy IDs*, preserving the canonical event['ref'].

    No sweeping E### regex: a reference-like token in unrelated log text is
    not automatically assumed to be a source reference. We only treat named
    source reference fields as legacy identifiers.
    """
    if not isinstance(raw, str):
        return raw
    try:
        data = json.loads(raw)
    except ValueError:
        return LEGACY_REF_KV.sub(lambda m: m.group('key') + m.group('sep') +
                                'SOURCE_ID_WITHHELD', raw)

    def clean(value):
        if isinstance(value, dict):
            return {k: ('SOURCE_ID_WITHHELD' if k.lower() in SOURCE_REF_KEYS
                        and isinstance(v, str) and LEGACY_REF_VALUE.fullmatch(v)
                        else clean(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            return LEGACY_REF_KV.sub(lambda m: m.group('key') + m.group('sep') +
                                     'SOURCE_ID_WITHHELD', value)
        return value

    if not isinstance(data, (dict, list)):
        return raw
    return json.dumps(clean(data), ensure_ascii=False, separators=(',', ':'))


def model_safe_events(events):
    """Privacy/referencing-clean copies; originals are never changed.

    For structured JSON, redact parsed values and serialize them *afterwards*;
    regex-redacting the JSON source string itself can swallow closing quotes.
    """
    safe = [redact_object(ev) for ev in events]
    for original_ev, ev in zip(events, safe):
        original_raw = original_ev.get('raw', '')
        try:
            raw_object = json.loads(original_raw)
        except (ValueError, TypeError):
            ev['raw'] = suppress_source_refs(redact_text(original_raw))
        else:
            ev['raw'] = suppress_source_refs(json.dumps(
                redact_object(raw_object), ensure_ascii=False))
        for key, value in (ev.get('fields') or {}).items():
            if (str(key).lower().split('.')[-1] in SOURCE_REF_KEYS and
                    isinstance(value, str) and LEGACY_REF_VALUE.fullmatch(value)):
                ev['fields'][key] = 'SOURCE_ID_WITHHELD'
        meta = ev.get('meta')
        if isinstance(meta, dict):
            # Original source provenance remains safely available in the
            # unified manifest, not in the model-visible event copy.
            meta.pop('original_evidence_id', None)
            meta.pop('original_source', None)
    return safe


def source_evidence_timeline(events):
    """Code-created audit trail, in supplied record order, not AI chronology.

    No application success/intent is inferred. Auditd PROCTITLE rows are
    *records of arguments*, not independent process-execution proofs.
    """
    out = []
    for ev in events:
        fields = _f(ev)
        family = ((ev.get('meta') or {}).get('unified') or {}).get('family', 'unknown')
        if family == 'windows':
            provider = _val(fields, 'provider')
            eventid = ev.get('event_id')
            label = f'Windows event record (EventID {eventid})' if eventid else 'Windows event record'
            if 'sysmon' in provider.lower():
                label = 'Sysmon ' + label
        elif family == 'linux':
            label = 'Linux audit/process arguments record' if ('proctitle' in (ev.get('raw') or '').lower()) else 'Linux log record'
        elif family == 'network':
            kind = _val(fields, 'record_kind')
            if 'AGGREGATE' in kind.upper():
                label = 'Derived network aggregate (NOT an individual flow)'
            elif 'ZEEK_CONN_ORIGINAL_SOURCE_ROW' == kind.upper():
                label = 'Zeek original connection record'
            else:
                label = 'Network event record'
        elif family == 'wazuh':
            label = 'Wazuh alert envelope (underlying family not determined)'
        else:
            label = 'Unclassified event record'
        original_source = ((ev.get('meta') or {}).get('original_source') or {})
        out.append({
            'ref': ev['ref'],
            'source_timestamp': str(ev.get('timestamp_raw') or 'Not provided'),
            'family': family,
            'observation': label,
            'original_record': (
                str(original_source.get('file')) + ':' + str(original_source.get('ref'))
                if original_source.get('file') and original_source.get('ref') else 'Not recorded'
            )
        })
    return out


def _md_cell(value):
    return str(value).replace('|', '/').replace('\r', ' ').replace('\n', ' ')


def final_quality_gate(batch_records):
    """Do not self-approve. Gate just flags acceptance-blocking drafts."""
    high = sum(r.get('qa', {}).get('high_severity_flags', 0) for r in batch_records)
    incomplete = sum(bool(r.get('qa', {}).get('missing_or_truncated_output')) for r in batch_records)
    return {
        'status': 'BLOCKED_PENDING_CORRECTION' if high or incomplete else 'HUMAN_REVIEW_REQUIRED',
        'high_severity_flag_count': high,
        'incomplete_batch_count': incomplete,
        'human_approval_recorded': False,
        'note': 'Operational execution is not an approval of any AI security conclusion.',
    }

def _f(ev):
    return {str(k).lower(): v for k, v in (ev.get('fields') or {}).items()}


def _val(fields, *keys):
    for k in keys:
        v = fields.get(k.lower())
        if v is not None and v != '':
            return str(v)
    return ''


def classify_event(event):
    """Source type derived per-event; no filename-based guesses.

    Conflicting indicators abstain instead of forcing one source. `wazuh` is a
    transport; strong underlying source signatures may identify a family.
    """
    f = _f(event)
    raw = str(event.get('raw') or '')
    original = str(event.get('source_kind') or 'generic').lower()
    low = raw.lower()
    positives = defaultdict(list)

    provider = _val(f, 'provider', 'data.win.system.providername')
    if ('microsoft-windows-' in provider.lower() or 'sysmon' in provider.lower()
            or 'service control manager' in provider.lower()):
        positives['windows'].append('Windows event provider')
    if original == 'windows' or ('event_data.processguid' in f and ('event_id' in f or 'eventid' in f)):
        positives['windows'].append('Structured Windows event')
    if 'data.win.system.eventid' in f or ('event_data.commandline' in f and 'event_data.processguid' in f):
        positives['windows'].append('Windows event_data/data.win fields')
    if original != 'wazuh' and ('eventid=' in low or re.search(r'\b(?:eventid|event_id)\s*=\s*\d+\b', low)):
        positives['windows'].append('Windows text EventID')

    if original == 'linux':
        positives['linux'].append('Linux syslog normalization')
    if ('linux_process_event' in low or 'linux-sysmon' in low
            or re.search(r'\btype=(?:syscall|proctitle|execve|user_auth|avc)\b', low)):
        positives['linux'].append('Linux audit/process marker')
    if SYSLOG_LINE.match(raw) and re.search(r'\b(?:sshd|sudo|pam_unix|systemd|kernel|cron|syslogd|klogd)\b', low):
        positives['linux'].append('Linux syslog process')
    decoder = _val(f, 'decoder.name').lower()
    if decoder in ('sshd', 'sudo', 'auditd', 'pam', 'syslog', 'linux'): 
        positives['linux'].append('Linux Wazuh decoder')
    if re.search(r'\b(?:failed password for|accepted publickey for|pam_unix\(|sudo:\s)\b', low):
        positives['linux'].append('Linux authentication message')

    if ('record_kind' in f and any(x in str(f['record_kind']).upper() for x in
         ('ZEEK', 'NETWORK', 'DNS', 'TCP_RETRY', 'AGGREGATE_NOT_RAW', 'RAW_CONN'))):
        positives['network'].append('Network evidence record_kind')
    if ('id.orig_h' in f and 'id.resp_h' in f) or ('id.orig_p' in f and 'id.resp_p' in f):
        positives['network'].append('Zeek conn/dns fields')
    if ('src_ip' in f and 'dst_ip' in f and any(k in f for k in ('proto', 'dst_port', 'scan_pair_tcp_records', 'scan_pair_distinct_destination_ports', 'http_method'))):
        positives['network'].append('Network endpoint/protocol fields')
    if _val(f, 'event_type') == 'apache_access' or APACHE_LINE.match(raw):
        positives['network'].append('Apache access log')
    if ('proto=' in low and ('src=' in low or 'src_ip=' in low) and ('dst=' in low or 'dst_ip=' in low)):
        positives['network'].append('Network flow/firewall text')
    if re.search(r'\b(?:id\.orig_h|id\.resp_h|conn_state|query|qtype)\s*=', low) and ('uid=' in low or 'id.orig_h=' in low):
        positives['network'].append('Zeek text flow fields')
    if original == 'network':
        positives['network'].append('Network normalized text source')

    # An explicit Wazuh envelope can still contain Windows or Linux data.
    wazuh = (original == 'wazuh' or
             ('rule.id' in f and ('agent.id' in f or 'decoder.name' in f)))
    if wazuh and re.search(r'"data"\s*:\s*\{', raw) and 'data.win.system.eventid' in f:
        positives['windows'].append('Wazuh Windows event')

    candidates = [k for k in ('windows', 'linux', 'network') if positives[k]]
    if len(candidates) > 1:
        return {'family': 'unknown', 'confidence': 'none', 'reason': 'Conflicting independent source signatures: ' + ', '.join(candidates),
                'transport': 'wazuh' if wazuh else 'file'}
    if candidates:
        kind = candidates[0]
        certainty = 'high' if any(q in ('Structured Windows event', 'Windows event provider', 'Zeek conn/dns fields', 'Network evidence record_kind', 'Linux audit/process marker', 'Linux syslog normalization', 'Apache access log', 'Windows event_data/data.win fields') for q in positives[kind]) else 'medium'
        return {'family': kind, 'confidence': certainty, 'reason': '; '.join(dict.fromkeys(positives[kind])),
                'transport': 'wazuh' if wazuh else 'file'}
    if wazuh:
        return {'family': 'wazuh', 'confidence': 'medium', 'reason': 'Wazuh alert envelope; original OS/log family unproven', 'transport': 'wazuh'}
    return {'family': 'unknown', 'confidence': 'none', 'reason': 'No supported source signature', 'transport': 'file'}


def supplement_structured_text(parsed, path: Path):
    """Decode only supported Zeek TSV headers and Apache combined-format fields.

    The original Core parser retains raw rows. This function adds fields only
    to our in-memory copy; unsupported formats retain `unknown` attribution.
    """
    # A Zeek TSV file must explicitly name its columns, not be inferred from
    # a generic row's position alone.
    fields = None
    try:
        raw = path.read_bytes()
        if raw[:2] == b'\x1f\x8b':
            raw = gzip.decompress(raw)
        if len(raw) <= config.MAX_FILE_BYTES * 2:
            for line in raw.decode('utf-8-sig', errors='replace').splitlines():
                if line.startswith('#fields\t'):
                    fields = line.split('\t')[1:]
                    break
    except OSError:
        pass
    if fields and 2 <= len(fields) <= 128 and len(set(fields)) == len(fields):
        for event in parsed['events']:
            row = event.get('raw', '').split('\t')
            if len(row) != len(fields):
                continue
            event['fields'].update({k: v for k, v in zip(fields, row) if v != '-'})
            event['src_ip'] = event.get('src_ip') or event['fields'].get('id.orig_h')
            event['dst_ip'] = event.get('dst_ip') or event['fields'].get('id.resp_h')
            # Original Zeek epoch value is kept exactly; no inferred timezone.
            event['timestamp_raw'] = event['fields'].get('ts') or event.get('timestamp_raw')
    for event in parsed['events']:
        if event.get('fields', {}).get('http_method'):
            continue
        m = APACHE_PARSE.match(event.get('raw') or '')
        if not m:
            continue
        event['fields'].update({'event_type': 'apache_access', 'src_ip': m['ip'],
                                'http_method': m['method'], 'http_status': int(m['status']),
                                'http_path': m['target'].split('?', 1)[0]})
        event['src_ip'] = m['ip']
        event['timestamp_raw'] = m['time']
        try:
            event['timestamp_utc'] = datetime.strptime(m['time'], '%d/%b/%Y:%H:%M:%S %z').astimezone(timezone.utc).isoformat()
        except ValueError:
            # Keep source text. Never invent date/timezone values.
            pass


def load_and_route(path: Path):
    """Keep original file and original evidence IDs; enrich only in memory."""
    parsed = log_parser.load_file(path, source_hint='auto')
    routed = deepcopy(parsed)
    supplement_structured_text(routed, Path(path))
    # Classify from fields enriched within the copied representation.
    provenance = []
    if parsed['format'] == 'json':
        try:
            wrapper = json.loads(Path(path).read_text(encoding='utf-8-sig'))
            if isinstance(wrapper, dict) and wrapper.get('schema_version') == 'depi-p5-mixed-v1':
                candidate_map = wrapper.get('source_map')
                if isinstance(candidate_map, list) and len(candidate_map) == len(routed['events']):
                    provenance = candidate_map
        except (OSError, UnicodeError, ValueError):
            pass
    counts = Counter()
    classification = []
    for idx, (original_ev, ev) in enumerate(zip(parsed['events'], routed['events'])):
        result = classify_event(ev)
        family = result['family']
        counts[family] += 1
        ev['meta'] = dict(ev.get('meta') or {})
        ev['meta']['unified'] = result
        ev['meta']['original_source_kind'] = ev.get('source_kind')
        # Remember the source evidence ID before the existing parser numbers it.
        if provenance and isinstance(provenance[idx], dict):
            ev['meta']['original_source'] = {k: provenance[idx].get(k) for k in ('file','sha256','ref','line_no')}
        original_id = (original_ev.get('fields') or {}).get('evidence_id')
        if original_id:
            ev['meta']['original_evidence_id'] = str(original_id)
        if family in ('windows', 'linux', 'network') and ev.get('source_kind') != 'wazuh':
            ev['source_kind'] = family
        classification.append({'ref': ev['ref'], 'line_no': ev.get('line_no'), 'family': family,
                               'confidence': result['confidence'], 'reason': result['reason'],
                               'transport': result['transport'], 'original_evidence_id': ev['meta'].get('original_evidence_id'),
                               'original_source': ev['meta'].get('original_source')})
    routed['source_type'] = 'mixed' if sum(x > 0 for x in counts.values()) > 1 else next(iter(counts))
    return routed, classification, counts


def _field(ev, key):
    fields = _f(ev)
    for k, val in fields.items():
        if k.split('.')[-1] == key.lower() and val is not None:
            return str(val)
    return ''


def plink_evidence(events):
    """Conservative Plink facts. Never infer tunnel success or C2 attribution."""
    processes = defaultdict(lambda: {'creation_refs': [], 'connection_refs': [], 'targets_rdp': False,
                                     'ssh_port_80': False, 'password_arg': False})
    for ev in events:
        if ev.get('meta', {}).get('unified', {}).get('family') != 'windows':
            continue
        if _field(ev, 'Image').replace('\\', '/').split('/')[-1].lower() != 'plink.exe':
            continue
        guid = _field(ev, 'ProcessGuid')
        if not guid:
            continue
        command = _field(ev, 'CommandLine')
        event_id = str(ev.get('event_id') or '')
        rec = processes[guid]
        # Count process creations ONLY when Sysmon Event 1 is present.
        if event_id == '1' and re.search(r'(?<!\S)-R(?=\s|$)', command, re.I):
            rec['creation_refs'].append(ev['ref'])
            rec['ssh_port_80'] |= bool(re.search(r'(?<!\S)-P\s+80(?=\s|$)', command, re.I))
            rec['targets_rdp'] |= bool(re.search(r'(?<!\S)-R\s+\S*:3389(?=\s|$)', command, re.I))
            rec['password_arg'] |= bool(PW_ARG.search(command))
        elif event_id == '3' and _field(ev, 'DestinationIp') and _field(ev, 'Initiated').lower() == 'true':
            rec['connection_refs'].append(ev['ref'])
    findings = []
    for rec in processes.values():
        if not rec['creation_refs']:
            continue
        findings.append({'rule_id': 'WINDOWS_PLINK_REVERSE_FORWARD',
                         'evidence_refs': sorted(set(rec['creation_refs'] + rec['connection_refs'])),
                         'process_creation_records': len(set(rec['creation_refs'])),
                         'tcp_connection_records': len(set(rec['connection_refs'])),
                         'ssh_port_80_in_command': rec['ssh_port_80'],
                         'rdp_target_in_command': rec['targets_rdp'],
                         'command_line_password_present': rec['password_arg'],
                         'assessment': 'Suspicious reverse-forwarding command pattern; authorization, SSH success, RDP access and C2 not confirmed.'})
    return findings


def pre_ai_notes(events):
    """Bounded, deterministic instructions/facts, never untrusted raw text."""
    notes = [f'UNIFIED ROUTING: {len(events)} event(s) assigned to this source family using per-event signatures. '
             'Do not infer that unknown or omitted records were analyzed.']
    for fact in plink_evidence(events):
        notes.append('WINDOWS GROUNDED FACT: Sysmon evidence shows '
                     f"{fact['process_creation_records']} observed plink.exe process creation record(s) and "
                     f"{fact['tcp_connection_records']} TCP connection event(s) sharing the process identity. "
                     'Command includes -R reverse SSH forwarding'
                     + (', SSH target port 80' if fact['ssh_port_80_in_command'] else '')
                     + (', RDP port 3389' if fact['rdp_target_in_command'] else '')
                     + (', a password argument (secret withheld)' if fact['command_line_password_present'] else '')
                     + '. Do not infer repeated process launches from connection events; '
                     'do not claim the SSH tunnel or RDP session succeeded or activity is authorized.')
    return notes[:8]


def check_ai_claims(sections, events):
    """Review requests, not proof of hallucination; bounded and secret-free."""
    facts = plink_evidence(events)
    if not facts:
        return []
    flags = []
    # Check only security-interpretation sections, not hypothetical advice.
    txt = '\n'.join(str(sections.get(k, '')) for k in
                    ('EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS', 'SUSPICIOUS ACTIVITIES', 'POTENTIAL ATTACK INDICATORS'))
    patterns = [
        ('plink_process_vs_connections', r'(?:plink(?:\.exe)?\s+(?:multiple|several|repeated)\s+(?:times|executions?|launches?)|(?:multiple|several|repeated)\s+(?:instances?\s+of\s+)?plink(?:\.exe)?\s+(?:executions?|launches?|runs?)|(?:running|executing|launching)\s+plink(?:\.exe)?.{0,70}(?:multiple|several|repeated)\s+times)', 'Multiple Plink executions are not proven by one process record and multiple TCP records.'),
        ('plink_unproven_tunnel_success', r'\b(?:reverse\s+ssh\s+)?tunnels?\s+(?:was\s+|were\s+)?(?:successfully\s+)?(?:established|used\s+again|operational)\b|\bestablished\s+(?:a\s+)?reverse\s+ssh\s+tunnel\b', 'Success of SSH authentication, tunnel operation or RDP usage is not demonstrated.'),
        ('plink_unverified_benign_reassurance', r'\b(?:does\s+not\s+appear\s+malicious|appears?\s+(?:to\s+be\s+)?benign|nothing\s+suspicious)\b', 'Do not dismiss reverse SSH forwarding as benign without authorization evidence.'),
    ]
    for name, regex, msg in patterns:
        if name == 'plink_process_vs_connections' and (len(facts) != 1 or facts[0]['process_creation_records'] != 1):
            continue
        for line in txt.splitlines():
            if not re.search(regex, line, re.I):
                continue
            # Avoid flagging a correctly negated tunnel success statement.
            if name == 'plink_unproven_tunnel_success' and re.search(r'\b(?:not|never|unconfirmed|without evidence of|no evidence (?:of|that))\b', line, re.I):
                continue
            flags.append({'check': name, 'severity': 'medium', 'section': 'UNIFIED SEMANTIC REVIEW',
                          'value': redact_text(line)[:120], 'message': msg, 'analyst_disposition': 'Unreviewed'})
            break  # one flag per distinct issue, not one per repeated phrasing
    return flags




def report_safety_review(sections, raw_text, events, family):
    """Conservative, evidence-based report QA; warnings, never automatic verdicts.

    Review *all* AI draft text for unfinished placeholder output and compare
    narrow network assertions to the raw Zeek rows actually sent to this batch.
    This function never turns an unfired indicator into a malicious verdict.
    """
    issues = []

    def add(check, severity, snippet, message, section='UNIFIED REPORT QA'):
        if check not in {f['check'] for f in issues}:
            issues.append({'check': check, 'severity': severity,
                           'section': section, 'value': redact_text(str(snippet))[:160],
                           'message': message, 'analyst_disposition': 'Unreviewed'})

    # Placeholder prose in an otherwise full-length response is still incomplete.
    for line in raw_text.splitlines():
        if (re.search(r'\.\.\.\s*\(\s*(?:continue|fill|add|etc\b)', line, re.I)
                or re.search(r'^\s*(?:[-*]\s*|\|\s*)?\.\.\.\s*(?:\||$)', line)
                or re.search(r'\b(?:continue for (?:all|remaining)|same as above)\b', line, re.I)):
            add('ai_unfinished_placeholder', 'high', line,
                'The AI draft contains unfinished placeholder text; complete the report before acceptance.')
            break

    conf = str(sections.get('CONFIDENCE AND UNCERTAINTY', '') or '')
    labels = set(x.lower() for x in re.findall(r'\b(?:Low|Medium|High)\s*:', conf, re.I))
    if len(labels) >= 2:
        add('multiple_confidence_levels', 'low', conf[:160],
            'Several conflicting report-level confidence headings appear; choose one justified level.')

    if family != 'network':
        return issues

    zeek = {}
    for ev in events:
        f = _f(ev)
        if str(f.get('record_kind', '')).upper() == 'ZEEK_CONN_ORIGINAL_SOURCE_ROW':
            zeek[ev.get('ref')] = ev

    if not zeek:
        return issues
    relevant = ('SIGNIFICANT SECURITY EVENTS', 'SUSPICIOUS ACTIVITIES',
                'EVIDENCE REFERENCES', 'INCIDENT TIMELINE')
    for name in relevant:
        for line in str(sections.get(name, '') or '').splitlines():
            refs = set(re.findall(r'\bE\d{3,5}\b', line))
            if (refs and refs <= set(zeek) and
                    re.search(r'\b(?:scan(?:ning|ned)?\s+(?:of\s+)?all\s+ports|all\s+\d{1,5}\s+ports|scan\s+of\s+all\s+ports|entire\s+port\s+range)\b', line, re.I)):
                add('raw_row_claims_full_port_scan', 'high', line,
                    'Cited Zeek source row(s) represent individual flow records; only a corroborated aggregate '
                    'can support a claim about scanning the full destination-port range.', name)

    ports = {_field(ev, 'src_port') or _field(ev, 'id.orig_p') for ev in zeek.values()}
    ports.discard('')
    # Only contradict a universal same-source-port claim if sampled rows *prove* otherwise.
    if len(ports) > 1:
        for name in ('EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS',
                     'SUSPICIOUS ACTIVITIES', 'POTENTIAL ATTACK INDICATORS'):
            for line in str(sections.get(name, '') or '').splitlines():
                if re.search(r'\b(?:single|same|one)\b.{0,80}\bsource\s+port\b.{0,110}\b(?:all|every|entire)\b|'
                             r'\b(?:all|every)\b.{0,80}\b(?:same|single|one)\b.{0,70}\bsource\s+port\b', line, re.I):
                    add('source_port_uniformity_contradicted', 'medium', line,
                        'Provided raw Zeek rows include more than one source port; blanket single-port attribution requires review.', name)
                    break
    return issues

def create_mixed_file(files, output: Path):
    """Build one sanitised mixed JSON file without overwriting any source.

    Each source row retains its original input-file hash and reference in the
    wrapper source_map. The engine never treats it as a production SIEM event.
    """
    if len(files) < 2:
        raise ValueError('mix requires at least two input files')
    if output.exists():
        raise FileExistsError(f'Output exists; refusing overwrite: {output}')
    if not output.parent.is_dir():
        raise FileNotFoundError(f'Output folder does not exist: {output.parent}')
    events, source_map, sources = [], [], []
    for file in files:
        parsed = log_parser.load_file(file, source_hint='auto')
        if Path(file).resolve() == output.resolve():
            raise ValueError('Output must not be an input file')
        for ev in parsed['events']:
            # Preserve original JSON row structure or source log string. No
            # untrusted code execution or model calls here.
            if parsed['format'] in ('json', 'ndjson'):
                try:
                    original_row = json.loads(ev['raw'])
                except ValueError:
                    # A JSON list is permitted to contain plain-text log rows;
                    # Core parses those strings via _event_from_line.
                    original_row = ev['raw']
            else:
                original_row = ev['raw']
            events.append(redact_object(original_row))
            source_map.append({'file': parsed['name'], 'sha256': parsed['sha256'],
                               'ref': ev['ref'], 'line_no': ev.get('line_no')})
        sources.append({'file': parsed['name'], 'sha256': parsed['sha256'],
                        'events': len(parsed['events']), 'evidence_class': parsed['evidence_class']})
    if len(events) > config.MAX_EVENTS:
        raise ValueError('Mixed event count exceeds the Core input limit; no output created')
    document = {'schema_version': 'depi-p5-mixed-v1',
                'notice': 'Sanitized replay / mixed-file QA only. Not a live incident.',
                'sources': sources, 'source_map': source_map, 'events': events}
    blob = json.dumps(document, indent=2, ensure_ascii=False).encode('utf-8')
    if len(blob) > config.MAX_FILE_BYTES:
        raise ValueError('Mixed file exceeds Core input byte limit; no output created')
    with output.open('xb') as handle:
        handle.write(blob)
    print(f'STATUS: MIXED QA FILE CREATED: {output} | records={len(events)} (original files unchanged)')
    return output


def inspect(path: Path):
    parsed, classifications, counts = load_and_route(path)
    print(f'FILE: {parsed["name"]} | SHA256: {parsed["sha256"]} | parsed={len(classifications)}')
    print('Evidence class:', parsed['evidence_class'])
    for family in FAMILIES:
        if counts[family]:
            print(f'  {family:8s}: {counts[family]}')
    for item in classifications:
        print(f"{item['ref']} -> {item['family']} ({item['confidence']}); {item['reason']}")
    groups = defaultdict(list)
    for e in parsed['events']:
        groups[e['meta']['unified']['family']].append(e)
    for kind in FAMILIES:
        evs = groups.get(kind, [])
        if evs and kind != 'unknown':
            try:
                base = grounded_detection.detect(evs)
                ids = [x.get('rule_id') for x in base.get('behavioral_findings', [])]
                ids.extend(x['rule_id'] for x in plink_evidence(evs))
                print(f'PRE-AI [{kind}]: {len(ids)} grounding finding(s) {ids}')
            except Exception as exc:
                print('PRE-AI ERROR:', kind, type(exc).__name__)
                raise
    print('STATUS: READ-ONLY INSPECTION COMPLETE (NOT AN AI TEST)')
    return parsed, classifications, counts


@contextmanager
def _extra_notes(notes, valid_ref=None):
    """Scoped Core hooks; no file modifications and no leaked cross-run patches.

    The upstream `log_analysis.txt` contains a literal citation example [E003].
    That example is out-of-batch for Linux E021+, which may confuse small
    local models. In each call replace only the example with an in-batch
    canonical reference. Record a hash of the *effective* virtual template.
    """
    original_notes = log_parser.reference_notes
    original_template = analysis.load_prompt

    def scoped_template(task):
        body, version, digest, filename = original_template(task)
        if task == 'log_analysis' and valid_ref:
            body = body.replace('such as [E003]', 'such as [' + valid_ref + ']')
            digest = hashlib.sha256(body.encode('utf-8')).hexdigest()
            version += '+unified-v04-canonical-ref'
        return body, version, digest, filename

    with patch.object(log_parser, 'reference_notes',
                      side_effect=lambda events: original_notes(events) + notes), \
         patch.object(analysis, 'load_prompt', side_effect=scoped_template):
        yield



def evidence_baseline(events):
    """Whole-family code-only baseline, independent of any model batching.

    Preserve observation vs verdict, including aggregate provenance limitations.
    Use only redacted in-memory event copies; source files remain unchanged.
    """
    safe = [redact_object(ev) for ev in events]
    grounded = grounded_detection.detect(safe)
    plink = plink_evidence(safe)
    return {
        'event_count': len(safe),
        'refs': [ev['ref'] for ev in safe],
        'findings': grounded.get('behavioral_findings', []),
        'context': grounded.get('context_observations', []),
        'windows_plink': plink,
        'interpretation': 'Observed indicators only; authorization, attack success and compromise require external verification.',
    }


def whole_family_guidance(family, baseline, current_refs):
    """Bounded context outside the untrusted data zone, no uncited invented claims."""
    findings = baseline['findings'] + baseline['windows_plink']
    if not findings:
        return []
    ids = sorted({str(f['rule_id']) for f in findings})
    extra = set(baseline['refs']) - set(current_refs)
    note = ('WHOLE-FILE PYTHON GROUNDING CONTEXT: ' + family +
            ' has evidence-dependent finding type(s): ' + ', '.join(ids[:8]) +
            '. Evidence counts reflect the FULL family subset, not necessarily this AI batch. '
            'Do not cite references absent from the current LOG DATA; do not invent events to bridge batches. '
            'Use only per-event evidence shown in this call for individual chronology and endpoint attribution. '
            'An aggregate is not an individual Zeek flow. This observation is not proof of attacker intent or intrusion.')
    if extra:
        note += ' Other source records exist outside this batch and are independently summarized in the unified Python baseline.'
    return [note]


def output_quality(rec):
    """Descriptive QA for report presentation; cannot approve an AI conclusion."""
    flags = rec['validation']['flags']
    kinds = sorted({str(x.get('check', '')) for x in flags})
    return {
        'needs_human_review': True,
        'missing_or_truncated_output': bool(rec['ai_output']['truncated'] or any(
            x in kinds for x in ('missing_section', 'output_truncated', 'input_truncated', 'ai_unfinished_placeholder'))),
        'flag_count': len(flags),
        'high_severity_flags': sum(str(f.get('severity', '')).lower() == 'high' for f in flags),
        'review_checks': kinds,
        'status': 'REVIEW_REQUIRED',
    }



def run_ai(path: Path, *, model=None, max_events_per_call=16, max_calls=12, num_ctx=8192, num_predict=2500):
    parsed, classifications, counts = load_and_route(path)
    groups = defaultdict(list)
    for ev in parsed['events']:
        groups[ev['meta']['unified']['family']].append(ev)
    # Critical: aggregate-level scan detection often needs E001 plus supporting
    # rows across an entire network case. A 16-row model batch must NOT erase
    # those whole-file deterministic observations.
    family_baselines = {family: evidence_baseline(evs)
                        for family, evs in groups.items() if family != 'unknown'}
    calls = [(k, evs[i:i + max_events_per_call])
             for k in ('windows', 'linux', 'network', 'wazuh')
             for evs in [groups.get(k, [])] for i in range(0, len(evs), max_events_per_call)]
    if not calls:
        raise ValueError('No supported classified events; abstaining. Inspect file first.')
    if len(calls) > max_calls:
        raise ValueError(f'{len(calls)} model calls required, exceeding --max-calls={max_calls}; no model calls made.')
    if not (config.PROMPTS_DIR / 'log_analysis.txt').is_file():
        raise FileNotFoundError('Prompts/log_analysis.txt missing; no AI call')
    # Fail early for model availability; avoids claiming successful analysis after an
    # environment check alone. The primary model is not silently replaced.
    st = ollama_client.check_environment()
    selected_model = model or config.PRIMARY_MODEL
    if not st['server_up'] or not ollama_client.resolve_model(selected_model, st['installed']):
        raise RuntimeError(f'Local Ollama or requested model {selected_model} is unavailable; no calls made')

    batch_records = []
    detailed_runs = []
    for family, evs in calls:
        # Strip potential credentials from *copies* before sending to Ollama and
        # before saving via Core/store. Original on disk stays unchanged.
        safe = model_safe_events(evs)
        scoped = dict(parsed)
        scoped['events'] = safe
        scoped['source_type'] = family
        scoped['warnings'] = list(parsed.get('warnings') or [])
        scoped['warnings'].append('Input is a subset of the classified file; unknown/conflicting events were withheld from AI.')
        # Explicit pre-AI evidence extraction. The native Core.run_task also
        # computes its pre-model grounding notes from this same routed subset.
        pre_ai = grounded_detection.detect(safe)
        extra_plink = plink_evidence(safe)
        notes = (pre_ai_notes(safe) +
                 whole_family_guidance(family, family_baselines[family],
                                       [x['ref'] for x in safe]))
        notes.append('CITATION POLICY: Cite ONLY the canonical [E###] tag immediately preceding each input record. '
                     'Source-origin E### IDs are withheld from the model and remain in the analyst manifest. '
                     'Never invent an E### reference or use internal/source-level IDs as citation labels.')
        notes.append('DRAFT COMPLETENESS: Include all required ## headings, one clearly scoped report confidence level. '
                     'Give at most THREE representative evidence-linked bullets per narrative section, '
                     'no more than THREE real source-timestamp timeline rows, and at most FOUR evidence explanations. '
                     'The program adds the COMPLETE evidence timeline independently. '
                     'Never use "...", "continue for all events", filler rows or implied missing content. '
                     'Unknown details must be explicitly called unknown, not guessed.')
        if family == 'network':
            notes.append('ZEEK FACT BOUNDARIES: A raw conn.log row represents an individual flow '
                         'record; one dst_port=65535 row is NOT evidence that all ports were '
                         'scanned. Use full-source counts ONLY from the verified-in-input aggregate '
                         'and distinguish that derived count from sample rows. '
                         'Zeek REJ is a connection state, not proof of firewall blocking. '
                         'Never assert all sampled rows use one source port unless verified.')
        print(f'AI ROUTE: {family} | refs={safe[0]["ref"]}..{safe[-1]["ref"]} | events={len(safe)}')
        with _extra_notes(notes, valid_ref=safe[0]['ref']):
            rec = analysis.run_task('log_analysis', scoped, model=selected_model,
                                    options={'num_ctx': num_ctx, 'num_predict': num_predict},
                                    progress=print)
        # Explicitly record the classifier and the pre-AI facts sent in this run.
        rec['unified'] = {'engine_version': ENGINE_VERSION, 'family': family,
                          'pre_ai_notes': notes, 'baseline_grounding': pre_ai,
                          'windows_plink': extra_plink,
                          'input_original_sha256': parsed['sha256'],
                          'prompt_source_file_sha256': log_parser.sha256_file(config.PROMPTS_DIR / 'log_analysis.txt')}
        new_flags = (check_ai_claims(rec['ai_output']['sections'], safe) +
                     report_safety_review(rec['ai_output']['sections'],
                                          rec['ai_output']['raw_text'], safe, family))
        next_index = len(rec['validation']['flags'])
        for idx, flag in enumerate(new_flags, 1):
            flag['id'] = f'F{next_index + idx:03d}'
            rec['validation']['flags'].append(flag)
        if new_flags:
            rec['validation']['severity_counts'] = __import__('Core.validator', fromlist=['summarize_flags']).summarize_flags(rec['validation']['flags'])
        rec['unified']['whole_family_rules'] = sorted({
            f['rule_id'] for f in family_baselines[family]['findings']
            + family_baselines[family]['windows_plink']})
        rec['unified']['qa'] = output_quality(rec)
        saved = store.save_result(rec)
        detailed_runs.append(rec)
        batch_records.append({'family': family, 'refs': [e['ref'] for e in safe],
                              'analysis_id': rec['analysis_id'], 'saved': str(saved),
                              'model': rec['model']['name'], 'validation_flags': len(rec['validation']['flags']),
                              'review_status': rec['review']['status'],
                              'qa': rec['unified']['qa'],
                              'events_sent_to_ai': rec['input']['events_analysed']})
        print(f'AI RESULT: {rec["analysis_id"]} | review={rec["review"]["status"]} | flags={len(rec["validation"]["flags"])}')

    # Single manifest for full file and classified outputs; no raw tokens/commands.
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder = config.RESULTS_DIR / f'UNIFIED-{stamp}-{uuid.uuid4().hex[:4]}'
    folder.mkdir(parents=True, exist_ok=False)
    manifest = {'engine_version': ENGINE_VERSION, 'source_file': parsed['name'],
                'source_sha256': parsed['sha256'], 'evidence_class': parsed['evidence_class'],
                'input_event_count': len(classifications), 'counts_by_family': dict(counts),
                'classification': classifications, 'analysis_runs': batch_records,
                'whole_family_python_baseline': family_baselines,
                'source_evidence_timeline': source_evidence_timeline(parsed['events']),
                'acceptance_gate': final_quality_gate(batch_records),
                'unknown_refs_not_sent_to_ai': [x['ref'] for x in classifications if x['family'] == 'unknown'],
                'notes': ['AI outputs are drafts requiring human review.',
                          'Mixed sources were grouped; this run does not prove cross-source correlation.',
                          'Source evidence references are mapped in classification; secrets are redacted in analysis copies.',
                          'Context limits may truncate events within an AI call; check events_sent_to_ai vs refs.']}
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = ['# DEPI P5 — Unified Log Triage (AI draft)', '',
             '**Human validation required — not an incident verdict.**', '',
             f'Input: `{parsed["name"]}`', f'SHA256: `{parsed["sha256"]}`', '',
             '## Source attribution']
    lines.extend(f'- {kind}: {counts[kind]} event(s)' for kind in FAMILIES if counts[kind])
    lines.extend(['', '**Canonical citation rule:** report `[E###]` IDs refer to this unified input; original per-file IDs are provenance metadata only.',
                  '', f'**QA acceptance gate:** {manifest["acceptance_gate"]["status"]} (human review still required).',
                  '', '## Whole-family Python baseline (NOT an AI verdict)'])
    for family in FAMILIES:
        baseline = family_baselines.get(family)
        if not baseline:
            continue
        lines.append(f'### {family.upper()} — {baseline["event_count"]} input event(s)')
        for finding in baseline['findings']:
            obs = redact_text(str(finding.get('observation', ''))).replace('|', '/')
            status = str(finding.get('outcome', ''))
            refs = ', '.join(finding.get('evidence_refs', [])[:24])
            lines.append(f'- **{finding["rule_id"]}**: {obs} (refs: {refs}).')
            if status:
                lines.append('  - Boundary: ' + redact_text(status))
        for finding in baseline['windows_plink']:
            lines.append(f'- **{finding["rule_id"]}**: {finding["process_creation_records"]} process-creation and '
                         f'{finding["tcp_connection_records"]} TCP record(s) observed (refs: '
                         f'{", ".join(finding["evidence_refs"])}). SSH/RDP success not established.')
        if not baseline['findings'] and not baseline['windows_plink']:
            lines.append('- No deterministic behavioral rule fired; this is not evidence of benignity.')
        if len(baseline['refs']) > max_events_per_call:
            lines.append('- **Batching limitation:** AI summaries analyze portions of this family; '
                         'the Python baseline above uses all its supplied events.')
    lines.extend(['', '## Local Mistral analysis runs'])
    for run in batch_records:
        excluded = sorted(set(run['refs']) - set(run['events_sent_to_ai']))
        lines.append(f"- {run['family']}: `{run['analysis_id']}` | events {len(run['events_sent_to_ai'])}/{len(run['refs'])} | flags {run['validation_flags']} | {run['review_status']}")
        if run['qa']['missing_or_truncated_output']:
            lines.append('  - **WARNING:** incomplete or truncated AI output; not a complete SOC report.')
        if run['qa']['flag_count']:
            lines.append('  - QA checks: ' + ', '.join(run['qa']['review_checks']))
        if excluded:
            lines.append(f"  - **CAUTION:** context-truncated evidence excluded: {', '.join(excluded[:30])}")
    if manifest['unknown_refs_not_sent_to_ai']:
        lines.extend(['', '## Not classified / not sent to AI', ', '.join(manifest['unknown_refs_not_sent_to_ai'])])
    lines.extend(['', '## Source-derived evidence timeline (Python, not AI)',
                  'Input record order is retained; times from unrelated hosts or years are not assumed to form one incident.',
                  'A record is not proof of successful execution, access, or compromise.',
                  '', '| Unified ref | Source timestamp (verbatim) | Family | Record type | Original source record |',
                  '|---|---|---|---|---|'])
    for entry in manifest['source_evidence_timeline']:
        lines.append('| ' + ' | '.join(_md_cell(entry[key]) for key in (
            'ref', 'source_timestamp', 'family', 'observation', 'original_record')) + ' |')
    lines.extend(['', '## Per-family AI drafts (verbatim, not verified)'])
    for rec in detailed_runs:
        kind = rec['unified']['family']
        lines.extend(['', f"### {kind.upper()} — {rec['analysis_id']}",
                      f"Evidence refs sent: {', '.join(rec['input']['events_analysed'])}",
                      f"Human review: {rec['review']['status']}",
                      f"Automated validation flags: {len(rec['validation']['flags'])}",
                      '', rec['ai_output']['raw_text'], ''])
        rules = [str(f.get('rule_id')) for f in rec['unified']['baseline_grounding']['behavioral_findings']]
        rules.extend(f['rule_id'] for f in rec['unified']['windows_plink'])
        lines.append('Deterministic indicators: ' + (', '.join(rules) if rules else 'None detected by implemented rules'))
        issues = sorted({str(f['check']) for f in rec['validation']['flags']})
        lines.append('Review checks: ' + (', '.join(issues) if issues else 'None raised (not proof of correctness)'))
    lines.extend(['', '## Evidence and limitations',
                  '- Exact per-event classifier decisions: `manifest.json`.',
                  '- Detailed AI outputs / deterministic findings / validation flags: respective `Results/AN-*` folders.',
                  '- No verification of successful compromise, authorization, or provenance is implied.',
                  '- This mixed QA fixture combines independent datasets; it is NOT evidence of a single correlated incident.',
                  '- Group analyses are not equivalent to end-to-end SIEM or cross-source correlation acceptance.',
                  '- No SOAR action was taken.'])
    (folder / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('STATUS: UNIFIED AI DRAFT SAVED:', folder)
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description='Safe source-aware log intake / local AI triage add-on')
    commands = ap.add_subparsers(dest='cmd', required=True)
    for cmd in ('inspect', 'analyze'):
        p = commands.add_parser(cmd)
        p.add_argument('input', type=Path)
        if cmd == 'analyze':
            p.add_argument('--model', default=None, help='Never silently switch models')
            p.add_argument('--max-events-per-call', type=int, default=16)
            p.add_argument('--max-calls', type=int, default=12)
            p.add_argument('--num-ctx', type=int, default=8192)
            p.add_argument('--num-predict', type=int, default=2500)
    p = commands.add_parser('mix', help='Build a sanitized mixed-file QA fixture; never overwrite output')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('files', nargs='+', type=Path)
    args = ap.parse_args(argv)
    try:
        if args.cmd == 'inspect':
            inspect(args.input)
        elif args.cmd == 'mix':
            create_mixed_file(args.files, args.output)
        else:
            if not 1 <= args.max_events_per_call <= 40 or not 1 <= args.max_calls <= 50:
                raise ValueError('--max-events-per-call must be 1..40 and --max-calls 1..50')
            if not (6144 <= args.num_ctx <= 16384 and 1500 <= args.num_predict <= 4096
                    and args.num_ctx - args.num_predict >= 3000):
                raise ValueError('Context/predict limits invalid: ctx 6144..16384, predict 1500..4096, at least 3000 tokens input room')
            run_ai(args.input, model=args.model, max_events_per_call=args.max_events_per_call,
                   max_calls=args.max_calls, num_ctx=args.num_ctx, num_predict=args.num_predict)
    except (log_parser.InputError, ValueError, RuntimeError, OSError, ollama_client.OllamaError) as exc:
        print(f'STOP: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
