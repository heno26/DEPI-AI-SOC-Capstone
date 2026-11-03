"""Read-only, source-grounded SOC behavioral observations and review requests.

Grounded observations are not incident verdicts, proof of attack success, or
authorization assessments. This module never invokes models, network or SOAR.
Only supplied event fields/raw are considered; all raw input is untrusted.
"""
from Core import network_grounding
import ipaddress
import json
import re
from collections import defaultdict

VERSION = 'grounded-detection-1.0'
_SSH_FAIL = re.compile(r'\bFailed password for (?:invalid user )?\S+ from ((?:\d{1,3}\.){3}\d{1,3})\b', re.I)
_TCP = re.compile(r'/dev/tcp/((?:\d{1,3}\.){3}\d{1,3})/(\d{1,5})\b')
_CHMOD = re.compile(r'\bchmod\s+u\+s\s+\S+', re.I)
_SETCAP = re.compile(r'\bsetcap\s+cap_setuid\+ep\s+\S+', re.I)
_SHELL_REDIRECT = re.compile(r'\b(?:sh|bash)\s+<&\d+\s+>&\d+', re.I)
_EVIDENCE_REF = re.compile(r'^E\d{3,5}$')
_NEGATIVE_CLAIM = re.compile(r'\b(?:no evidence|not observed|not established|unconfirmed|unsupported|did not|not a|is not|not an|never|without|cannot)\b', re.I)


def _val(event, *names):
    fields = event.get('fields') or {}
    for name in names:
        for k, v in fields.items():
            if str(k).lower().split('.')[-1] == name.lower() and isinstance(v, (str, int)) and str(v):
                return str(v)
    return ''


def _raw(event):
    return str(event.get('raw') or '')


def _is_linux(event):
    raw = _raw(event)
    return (event.get('source_kind') == 'linux' or
            'Linux-Sysmon' in raw or 'linux_process_event' in raw or
            bool(re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\S+\s+', raw)))


def _command(event):
    command = _val(event, 'CommandLine', 'command_line')
    if command:
        return command
    raw = _raw(event)
    # Prefer explicit normalized command token; don't treat commentary as commands.
    match = re.search(r'\bcommand_line\s*=\s*(.+?)\s+command_target_ip\s*=', raw, re.I)
    return match.group(1) if match else ''


def _observations(events):
    refs = set()
    valid = []
    for e in events:
        ref = e.get('ref')
        if not isinstance(ref, str) or not _EVIDENCE_REF.fullmatch(ref) or ref in refs:
            continue
        refs.add(ref)
        valid.append(e)
    return valid


def _finding(rule, label, confidence, refs, observation, outcome, **details):
    return {
        'rule_id': rule, 'label': label,
        'confidence_in_observed_pattern': confidence,
        'evidence_refs': sorted(set(refs)),
        'observation': observation, 'outcome': outcome,
        'details': details,
        'status': 'investigation_indicator_not_incident_verdict',
    }


def detect(events):
    """Deterministic source observations; never mark a system safe or compromised."""
    items = _observations(events)
    findings, context = [], []
    ssh_by_ip = defaultdict(list)
    setcap, chmod = [], []
    reverse = []
    boot_evidence = []
    for e in items:
        ref, raw = e['ref'], _raw(e)
        if not _is_linux(e):
            continue
        for m in _SSH_FAIL.finditer(raw):
            try:
                ipaddress.IPv4Address(m.group(1))
            except ValueError:
                continue
            ssh_by_ip[m.group(1)].append(ref)
        cmd = _command(e)
        # For auditd-normalized records, argv is explicit JSON in the line.
        # For structured Sysmon events, the explicit CommandLine is used.
        source_cmd = cmd
        if not source_cmd and 'argv=' in raw:
            # LT-02 normalization records exact argv JSON from auditd PROCTITLE.
            argv_match = re.search(r'\bargv=(\[[^\]\n]+\])', raw)
            if argv_match:
                try:
                    args = json.loads(argv_match.group(1))
                    if isinstance(args, list) and all(isinstance(arg, str) for arg in args):
                        source_cmd = ' '.join(args)
                except (ValueError, TypeError):
                    pass
        if not source_cmd:
            source_cmd = _val(e, 'argv')
        if _CHMOD.search(source_cmd):
            chmod.append(ref)
        if _SETCAP.search(source_cmd):
            setcap.append(ref)
        if '/dev/tcp/' in cmd and _SHELL_REDIRECT.search(cmd):
            m = _TCP.search(cmd)
            if m:
                try:
                    ip = ipaddress.IPv4Address(m.group(1))
                    port = int(m.group(2))
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    reverse.append((ref, str(ip), port, 'private' if ip.is_private else 'not_private'))
        if re.search(r'(?:\bBIOS-e820:|\bmachine check reporting enabled\b|\bsyslogd startup succeeded\b|\bklogd startup succeeded\b|\bBringing up loopback interface:)', raw, re.I):
            boot_evidence.append(ref)
    for ip, refs in sorted(ssh_by_ip.items()):
        unique = sorted(set(refs))
        if len(unique) >= 5:
            findings.append(_finding(
                'LINUX_SSH_REPEAT_FAILURE', 'Repeated failed SSH authentication', 'high', unique,
                f'{len(unique)} records with Failed password from {ip}',
                'Successful login and unauthorized access NOT established', source_ip=ip,
                failed_password_records=len(unique), threshold=5))
    if setcap or chmod:
        findings.append(_finding(
            'LINUX_PRIVILEGE_SENSITIVE_COMMAND', 'Privilege-sensitive setcap/SUID arguments', 'high', setcap + chmod,
            'Recorded setcap cap_setuid+ep and/or chmod u+s command arguments',
            'Execution success, operator identity, authorization, privilege attainment NOT established',
            setcap_records=len(setcap), chmod_records=len(chmod)))
    for ref, ip, port, ip_scope in reverse:
        findings.append(_finding(
            'LINUX_BASH_REVERSE_SHELL_PATTERN', 'Bash /dev/tcp reverse-shell command pattern', 'high', [ref],
            f'Process command contains /dev/tcp/{ip}/{port} and shell I/O redirection',
            'Network connection success and interactive shell NOT established',
            command_target_ip=ip, command_target_port=port,
            command_target_ip_scope=ip_scope))
    if boot_evidence:
        context.append({
            'rule_id': 'LINUX_ROUTINE_BOOT_CONTEXT',
            'evidence_refs': sorted(set(boot_evidence)),
            'observation': 'Boot/service initialization markers observed',
            'security_limit': 'These records alone do not prove whole-host benignity or authorization.',
        })
    network = network_grounding.detect_network(items)
    findings.extend(network['behavioral_findings'])
    context.extend(network['context_observations'])
    return {'version': VERSION, 'scope': 'observed_input_events_only',
            'events_inspected': len(items), 'behavioral_findings': findings,
            'context_observations': context,
            'final_incident_verdict': 'human_review_required',
            'guarantees': ['No LLM inference', 'No proof of attack success', 'No SOAR actions']}


def prompt_notes(events):
    """Bounded source facts included *outside* model-visible raw log region.

    Rules never contain raw command lines or attacker-controlled log text;
    this prevents prompt injection through a fact string.
    """
    result = detect(events)
    notes = []
    ids = {f['rule_id'] for f in result['behavioral_findings']}
    if 'LINUX_SSH_REPEAT_FAILURE' in ids:
        notes.append('GROUNDED OBSERVATION: Repeated SSH failed-password records observed. Identify failure pattern; never invent a successful login or a year/timezone.')
    if 'LINUX_PRIVILEGE_SENSITIVE_COMMAND' in ids:
        notes.append('GROUNDED OBSERVATION: setcap/SUID command arguments recorded. Explain sensitivity; do not claim execution success, authorization, or privilege attainment from PROCTITLE alone.')
    if 'LINUX_BASH_REVERSE_SHELL_PATTERN' in ids:
        notes.append('GROUNDED OBSERVATION: Linux Bash /dev/tcp shell-redirection reverse-shell COMMAND PATTERN is strongly supported. Explicitly name the pattern. A TCP connection or interactive shell is NOT established. Do not invent netcat or a second execution.')
    if result['context_observations']:
        notes.append('GROUNDED BOOT CONTEXT: Linux startup, BIOS-e820 memory-map enumeration and machine-check REPORTING ENABLED are not evidence of BIOS modification, machine-check error or privilege escalation. Do not list these hypothetical attacks as detected indicators.')
    if any(_is_linux(e) and re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d', _raw(e)) for e in events):
        notes.append('TIMELINE: Syslog month/day/time has no source-proven year/timezone. For each timeline row use the original timestamp, process/provider, actual hostname and a valid event ref; never output ellipsis placeholder rows.')
    notes.extend(network_grounding.prompt_notes(events))
    if notes:
        notes.append('REPORT WRITING: Do not expose internal rule or feedback lesson IDs. Separate observed behavior, possible intent, and unconfirmed results.')
    return notes[:6]


def review_requests(sections, events):
    """Additional review flags. Each return value is one Core-style unnumbered flag."""
    info = detect(events)
    rules = {f['rule_id'] for f in info['behavioral_findings']}
    boot = bool(info['context_observations'])
    flags = []

    def flag(check, severity, section, value, message):
        flags.append({'check': check, 'severity': severity, 'section': section,
                      'value': value[:160], 'message': message,
                      'analyst_disposition': 'Unreviewed'})

    if 'LINUX_BASH_REVERSE_SHELL_PATTERN' in rules:
        relevant = ' '.join(sections.get(k, '') for k in (
            'EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS', 'SUSPICIOUS ACTIVITIES', 'POTENTIAL ATTACK INDICATORS'))
        # Missing explicit pattern: review request, not a guaranteed model error.
        if relevant.strip() and not re.search(r'\breverse[ -]?shell\b|\b/dev/tcp\b', relevant, re.I):
            flag('missed_explicit_reverse_shell_pattern', 'medium', 'SUSPICIOUS ACTIVITIES',
                 relevant[:160], 'Input CommandLine explicitly contains Bash /dev/tcp with shell I/O redirection. The report did not name that pattern in security findings.')

    if boot:
        indicators = (sections.get('POTENTIAL ATTACK INDICATORS', '') + '\n' +
                      sections.get('SUSPICIOUS ACTIVITIES', ''))
        for ln in indicators.splitlines():
            line = ln.strip()
            if re.search(r'\bBIOS\b|\bmemory map\b', line, re.I) and re.search(r'\b(?:unauthoriz\w*|tamper\w*|privilege escalation|modif\w*)\b', line, re.I):
                if not _NEGATIVE_CLAIM.search(line):
                    flag('unsupported_boot_security_speculation', 'medium', 'POTENTIAL ATTACK INDICATORS', line,
                         'Only BIOS-e820 enumeration appears in this boot sample; even a speculative attack claim needs separate supporting evidence.')
                    break
        for key, body in sections.items():
            if key not in ('EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS', 'POTENTIAL ATTACK INDICATORS', 'SUSPICIOUS ACTIVITIES'):
                continue
            for line in body.splitlines():
                if re.search(r'\b(?:possible|potential|observed|detected|occurred)\s+(?:CPU\s+)?machine[ -]check\s+(?:event|error|exception)\b', line, re.I):
                    if not _NEGATIVE_CLAIM.search(line):
                        flag('machine_check_reporting_not_error', 'medium', key, line.strip(),
                             'Source states machine check REPORTING ENABLED, not that a CPU machine-check error occurred.')
                        break
            if any(f['check'] == 'machine_check_reporting_not_error' for f in flags):
                break
    flags.extend(network_grounding.review_requests(sections, events))
    return flags
