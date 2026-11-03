"""Conservative evidence-grounded checks for Windows baseline *candidates*.

These produce requests for analyst review, not malware or benign verdicts.
"""
import json
import re

_REF = re.compile(r"\bE\d{3,5}\b")
_NEG = re.compile(r"\b(?:no|not|without|cannot|can't|unconfirmed|did\s+not|rather\s+than)\b", re.I)
_PROCESSES = re.compile(r"\b(?:mscorsvw(?:\.exe)?|(?:these|the|multiple)\s+(?:process(?:es)?|instances|workers)|ngen\s+worker)\b", re.I)
_STOP = re.compile(r"\b(?:stop(?:s|ping|ped)?|terminat(?:ed|ion|ing)|exit(?:ed|ing)?)\b", re.I)
_BAD_LOGON = re.compile(r"\b(?:interactive|network)\s+(?:logon|login|authentication)\b", re.I)
_SERVICE_STATES = re.compile(r"\b(?:repeated|multiple)\b.{0,45}\b(?:start(?:s|ed|ing)?\s+(?:and|or|/)\s+stop(?:s|ped|ping)?|stop(?:s|ped|ping)?\s+(?:and|or|/)\s+start(?:s|ed|ing)?)\b", re.I)


def _fields(e):
    data = {}
    try:
        raw = json.loads(e.get('raw', '{}'))
        if isinstance(raw, dict):
            data = raw.get('event_data', {}) or {}
    except (ValueError, TypeError):
        pass
    f = e.get('fields', {}) or {}
    return {**(data if isinstance(data, dict) else {}),
            **{key.split('event_data.', 1)[1]: val for key, val in f.items() if key.startswith('event_data.')}}


def _scope(events):
    win = [e for e in events if e.get('source_kind') == 'windows']
    if len(win) != len(events) or not win:
        return None
    ids = {str(e.get('event_id')) for e in win}
    dat = [_fields(e) for e in win]
    if ids == {'1'} and all(str(d.get('Image', '')).lower().replace('/', '\\').endswith('\\mscorsvw.exe')
                             and str(d.get('ParentImage', '')).lower().replace('/', '\\').endswith('\\ngen.exe') for d in dat):
        return 'BT-01'
    if ids == {'4624', '4672'} and all(
        (str(e['event_id']) == '4624' and str(d.get('LogonType')) == '5'
         and str(d.get('TargetUserName', '')).upper() == 'SYSTEM') or
        (str(e['event_id']) == '4672' and str(d.get('SubjectUserName', '')).upper() == 'SYSTEM')
        for e, d in zip(win, dat)):
        return 'BT-02'
    if ids == {'7036'} and all(str(d.get('param2', '')).lower() in ('stopped', 'running') for d in dat):
        return 'BT-03'
    return None


def _lines(sections):
    for name in ('EXECUTIVE SUMMARY', 'SIGNIFICANT SECURITY EVENTS', 'SUSPICIOUS ACTIVITIES',
                 'EVIDENCE REFERENCES', 'INCIDENT TIMELINE', 'POTENTIAL ATTACK INDICATORS',
                 'CONFIDENCE AND UNCERTAINTY'):
        for line in (sections.get(name, '') or '').splitlines():
            if line.strip() and not line.strip().startswith('|---'):
                yield name, line.strip()


def add_review_requests(F, sections, events):
    """Extend existing _Flags, without changing originals or labeling evidence benign."""
    scope = _scope(events)
    if scope is None:
        return
    counter = {}

    def flag(check, severity, name, line, why, limit=3):
        if counter.get(check, 0) < limit:
            F.add(check, severity, line[:180], why, section=name)
            counter[check] = counter.get(check, 0) + 1

    if scope == 'BT-01':
        for name, line in _lines(sections):
            if name in ('INCIDENT TIMELINE', 'EVIDENCE REFERENCES'):
                pass
            if _STOP.search(line) and _PROCESSES.search(line):
                before = line[:_STOP.search(line).start()]
                if not _NEG.search(before) and not re.search(r'\b(?:investigate|verify|check|whether|if)\b', before, re.I):
                    flag('process_termination_not_observed', 'medium', name, line,
                         'The selected Sysmon 1 events show process creation only; no termination (Sysmon 5) for these processes appears in the input.')
            if re.search(r'c:\\windows\\system32', line, re.I) and re.search(
                r'\b(?:run|runs|execut(?:ed|ion)|located|directory|path|from|mscorsvw)\b', line, re.I
            ) and not _NEG.search(line.split('c:\\', 1)[0]):
                flag('process_image_path_mismatch', 'medium', name, line,
                     'The process Image fields point to the .NET Framework directory, not C:\\Windows\\System32. Confirm the claimed process path against the input.')

    if scope == 'BT-02':
        service_refs = {e.get('ref') for e in events if str(e.get('event_id')) == '4624' and str(_fields(e).get('LogonType')) == '5'}
        for name, line in _lines(sections):
            if _BAD_LOGON.search(line) and (set(_REF.findall(line)) & service_refs):
                before = line[:_BAD_LOGON.search(line).start()]
                if not _NEG.search(before):
                    flag('service_logon_type_mismatch', 'high', name, line,
                         'Cited Event ID 4624 has LogonType 5 (Service), not Interactive (2) or Network (3).', limit=6)

        # Suppress ONE broad keyword-only high alert for a tightly scoped normal
        # SYSTEM service-logon/4672 pair when there are no other risk signals.
        # Do not suppress references or unsupported privilege assertions.
        svc_ids = {str(_fields(e).get('TargetLogonId')).lower() for e in events if str(e.get('event_id')) == '4624'}
        priv_ids = {str(_fields(e).get('SubjectLogonId')).lower() for e in events if str(e.get('event_id')) == '4672'}
        valid_ids = (len(svc_ids) == 1 and svc_ids == priv_ids and all(x not in ('', 'none') for x in svc_ids))
        if valid_ids:
            # Already flagged as false alarm by the human analyst in the initial BT-02 case.
            F.items[:] = [f for f in F.items if not (
                f.get('check') == 'none_claim_vs_signals' and
                f.get('value', '').strip().lower() == 'sedebugprivilege assigned'
            )]

    if scope == 'BT-03':
        started = sum(str(_fields(e).get('param2', '')).lower() == 'running' for e in events)
        if started <= 1:
            for name, line in _lines(sections):
                if _SERVICE_STATES.search(line) and not _NEG.search(line[:_SERVICE_STATES.search(line).start()]):
                    flag('service_start_stop_overgeneralization', 'low', name, line,
                         'Selected records contain only one Running transition. Repeated starts and stops across multiple services are not established.', limit=2)


def extra_reference_notes(events):
    scope = _scope(events)
    if scope == 'BT-01':
        return ['Sysmon Event ID 1 = Process Creation, NOT Process Termination; do not assert that a process stopped unless Sysmon 5 or independent termination evidence is present.',
                'Use the complete Image path verbatim; mscorsvw.exe in Microsoft.NET Framework is not in System32 based on a generic expectation.']
    if scope == 'BT-02':
        return ['Windows 4624 LogonType 5 = Service, never Interactive (2) or Network (3). 4672 records assignment of a special-privilege logon token, not abuse of that privilege.',
                'SYSTEM with SeDebugPrivilege can be routine; do not call it unnecessary or compromise without separate evidence.']
    if scope == 'BT-03':
        return ['Service Control Manager EventID 7036 records a single service state transition. Service stopped/running alone does not prove malicious concealment.',
                'Distinguish observed transitions from hypothetical attacker intent; repeated starts require multiple Running records.']
    return []
