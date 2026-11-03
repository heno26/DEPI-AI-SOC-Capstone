"""Evidence-grounded SOC semantic review checks (no verdicts or automatic containment).

Designed for Week-2 validator's `_Flags` interface. Each check requests analyst
verification. Never treats missing telemetry as proof that an event did not occur.
"""
import ipaddress
import re

# Narrow rules with explicit positive/negative guardrails, rather than keyword=attack.
_NETCAT = re.compile(r'\b(?:netcat|ncat|nc)\b', re.I)
# Per-mention negation matters: "does not show ... execution of netcat" is a
# denial, not a positive claim. Bound the window and don't cross adversative
# clause separators, otherwise a real positive claim could be hidden.
_NETCAT_DENIAL_BEFORE = re.compile(
    r'\b(?:no|not|never|without|absence of|lack of|instead of|rather than|'
    r'does not|did not|isn.t|wasn.t|cannot)\b[\w\s/-]{0,105}$', re.I)
_NETCAT_DENIAL_AFTER = re.compile(
    r'^\s*(?:(?:execution|use|usage|invocation)\s+)?'
    r'(?:(?:was|were|is|has been|had been)\s+)?'
    r'(?:not|never|absent|unobserved)\b', re.I)
_NETCAT_CLAUSE_SPLIT = re.compile(r'\s*(?:[,;]|\bbut\b|\bhowever\b|\byet\b)\s*', re.I)


def _has_unnegated_netcat_mention(text):
    """Flag a possible tool attribution only when a mention is NOT denied.

    Conservative language heuristic: clauses such as 'no ... execution of
    netcat' and 'netcat was not observed' are denials. Mixed texts that later
    claim the tool was used are still reviewable. This is NOT an NLP verifier.
    """
    for clause in _NETCAT_CLAUSE_SPLIT.split(text):
        for occurrence in _NETCAT.finditer(clause):
            left = clause[max(0, occurrence.start() - 120):occurrence.start()]
            right = clause[occurrence.end():]
            if _NETCAT_DENIAL_BEFORE.search(left) or _NETCAT_DENIAL_AFTER.match(right):
                continue
            return True
    return False
_IP = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_NEGATED = re.compile(r'\b(?:no|not|without|never|unknown|unconfirmed|cannot|did not|does not|is not|was not|'
                      r'could|would|might|may|possible|potential|whether|if|needs|requires)\b', re.I)
_UNAUTHORIZED = re.compile(r'\b(?:successful(?:ly)?|confirmed|established|opened|connected|gained|obtained)\b', re.I)
_DOMAIN = re.compile(r'^[\w-]+\.service$', re.I)
_SERVICE_CONTEXT = re.compile(r'\b(?:systemctl|systemd|service\s+unit|(?:auditd|splunkforwarder)\.service)\b', re.I)
_SENSITIVE_COMMANDS = re.compile(r'(?:\bsetcap\b.{0,35}\bcap_setuid\b|\bchmod\b.{0,12}\bu\+s\b|'
                                  r'cap_setuid\+ep|\bchmod\s+u\+s\b)', re.I)


def _command_lines(events):
    result = []
    for e in events:
        fields = e.get('fields') or {}
        for key, value in fields.items():
            if str(key).lower().split('.')[-1] in ('commandline', 'command_line') and isinstance(value, str):
                result.append(value)
        raw = e.get('raw') or ''
        if not any(x in raw.lower() for x in ('commandline', 'command_line')):
            continue
        # Raw key/value logs may not have been parsed into fields.
        if not result or not any(s in raw for s in result):
            result.append(raw)
    return '\n'.join(result)


def _sentences(text):
    # Sentence + bullet/row boundaries. Do not split on IPv4 dots.
    return [s.strip() for s in re.split(r'(?<=[.!?])\s+|\n+', text) if s.strip()]


def _linux_reverse_shell(events):
    return bool(events and any('/dev/tcp/' in _command_lines([e]) and
        (e.get('source_kind') == 'linux' or 'Linux-Sysmon' in (e.get('raw') or ''))
        for e in events))


def _auditd_proctitle_only(events):
    if not events:
        return False
    texts = [e.get('raw') or '' for e in events]
    return (all('proctitle' in raw.lower() for raw in texts) and
            not any(re.search(r'\b(?:SYSCALL|USER_AUTH|EXECVE)\b', raw, re.I) for raw in texts))


def is_service_unit_domain(value, raw):
    """Conservatively disambiguate `systemctl ... xxx.service` from DNS names.

    A real .service URL/domain in another context is *not* automatically removed.
    """
    if not _DOMAIN.fullmatch(value) or not _SERVICE_CONTEXT.search(raw):
        return False
    if re.search(r'https?://(?:[\w.-]+\.)?' + re.escape(value) + r'(?:[/\s]|$)', raw, re.I):
        return False
    # A systemd unit token near a systemctl invocation or command-line argv.
    return bool(re.search(r'\bsystemctl\b[^\n]{0,180}' + re.escape(value), raw, re.I) or
                re.search(r'(?:argv|command|systemd)[^\n]{0,180}' + re.escape(value), raw, re.I))


def additional_risk_signals(events):
    """Code-detected *indicators for investigation*, not attack confirmations."""
    out = []
    for e in events:
        raw = e.get('raw') or ''
        cmd = _command_lines([e])
        if '/dev/tcp/' in cmd and re.search(r'(?:<>/dev/tcp/|sh\s+<&|bash\s+-c)', cmd):
            out.append({'ref': e['ref'], 'label': 'reverse-shell command pattern in process-creation evidence; network outcome unknown'})
        elif _SENSITIVE_COMMANDS.search(raw):
            out.append({'ref': e['ref'], 'label': 'privilege-sensitive setcap/SUID command recorded; execution outcome unknown'})
    return out


def _flag(F, check, severity, snippet, message):
    F.add(check, severity, snippet[:160], message)



def _lt04_startup_candidate(events):
    """Only source-verified Linux boot telemetry, not all generic kernel logs."""
    raw = '\n'.join(e.get('raw') or '' for e in events).lower()
    linux = all(e.get('source_kind') == 'linux' for e in events)
    return (linux and 'bios-e820:' in raw and 'kernel:' in raw and
            ('syslogd startup succeeded' in raw or 'klogd startup succeeded' in raw) and
            not re.search(r'\b(?:tampering|unauthorized firmware modification|firmware exploit)\b', raw))


def _add_lt04_review_requests(F, sections, events):
    """Human-review requests for narrowly scoped LT-04 failure modes.

    An E820 memory-map entry is an observation, not a change event. A claim
    about a possible *consequence* can be legitimate in general, but is an
    unsupported threat inference when falsely attached to these boot records.
    """
    if not _lt04_startup_candidate(events):
        return
    indicators = sections.get('POTENTIAL ATTACK INDICATORS', '') + '\n' + sections.get('SUSPICIOUS ACTIVITIES', '')
    for sentence in _sentences(indicators):
        if re.search(r'\bunauthorized\b.{0,100}\bBIOS\b.{0,30}\bmemory\s+map\b', sentence, re.I):
            if re.search(r'\b(?:no|not|without|lack of|absence of|no evidence of)\b.{0,40}\bunauthorized\b', sentence, re.I):
                continue
            F.add('bios_boot_threat_inference_review', 'medium', sentence[:160],
                  'BIOS-e820 in selected kernel boot logs reports a memory map; no recorded unauthorized change or privilege escalation. Treat speculative BIOS-tampering claims as unsupported by E003.',
                  section='POTENTIAL ATTACK INDICATORS')
            break

    hosts = {str(e.get('host')).strip().lower() for e in events if e.get('host')}
    if len(hosts) != 1:
        return
    observed = next(iter(hosts))
    log_source = sections.get('LOG SOURCE', '')
    host_match = re.search(r'\bhosts?\s*:\s*([a-zA-Z0-9_.-]+)', log_source, re.I)
    if host_match and host_match.group(1).lower() != observed:
        F.add('linux_syslog_host_mismatch_review', 'medium', host_match.group(0),
              f'The recorded host is {observed!r}; do not substitute {host_match.group(1)!r} without evidence.',
              section='LOG SOURCE')
    source_match = re.search(r'\bsource\s+type\s*:\s*([a-zA-Z0-9_.-]+)', log_source, re.I)
    if source_match and source_match.group(1).lower() == observed:
        F.add('linux_syslog_source_host_confusion_review', 'low', source_match.group(0),
              f'{observed!r} is the recorded hostname, not a log source type; source is Linux syslog.',
              section='LOG SOURCE')

def add_review_requests(F, sections, events):
    """Append conservative flags for claims inconsistent with provided records."""
    if not events:
        return
    text = '\n'.join(sections.values())
    if not text.strip():
        return
    sentences = _sentences(text)
    commands = _command_lines(events)
    source = '\n'.join(e.get('raw') or '' for e in events)

    if _linux_reverse_shell(events):
        # Unsupported netcat may occur in more than one report section: one flag per section.
        netcat_sections_flagged = 0
        for section, body in sections.items():
            matches = [s for s in _sentences(body) if _has_unnegated_netcat_mention(s)]
            if matches and not _NETCAT.search(commands):
                F.add('unsupported_command_tool', 'high', matches[0][:160],
                      'Report attributes netcat/nc to the event, but the supplied Linux process command contains '
                      'a Bash /dev/tcp pattern and no netcat execution. Verify against the original command line.', section=section)
                netcat_sections_flagged += 1
                if netcat_sections_flagged >= 2:
                    break
        for s in sentences:
            # Distinguish *public Internet address* from "external to this host".
            if not re.search(r'\b(?:external|public|internet[- ]routable)\s+(?:ipv4\s+)?(?:ip\s+)?address\b', s, re.I):
                continue
            if re.search(r'\b(?:not|never|no|isn.t|cannot|without)\b.{0,26}\b(?:external|public)\b', s, re.I):
                continue
            for token in set(_IP.findall(s)):
                try:
                    ip = ipaddress.ip_address(token)
                except ValueError:
                    continue
                if ip.version == 4 and ip.is_private:
                    _flag(F, 'private_ip_scope_review', 'medium', s,
                          f'{token} is private/non-public (RFC 1918 when in private ranges). '
                          '“External” could mean external to the host, but must not imply a public Internet-routable address.')
                    break
        strong_network = re.compile(
            r'(?:\b(?:connection|tcp session|reverse.shell|c2 channel)\b.{0,45}\b(?:was|is|has been)\s+(?:successfully\s+)?(?:established|opened|connected)\b|'
            r'\b(?:successfully\s+connected|established\s+(?:a\s+)?(?:tcp|network|reverse.shell)\s+connection)\b)', re.I)
        for s in sentences:
            if strong_network.search(s) and not _NEGATED.search(s):
                _flag(F, 'network_success_not_established', 'high', s,
                      'Only a process-creation command is supplied. No corroborating successful TCP connection '
                      'or interactive reverse-shell session was supplied.')
                break
        if re.search(r'(?:DuplicateRawRecords|duplicate_raw_records|duplicate_source_lines|OriginalSourceLines)', source, re.I):
            overcount = re.compile(r'\b(?:two|2|multiple)\s+(?:independent\s+)?(?:reverse.shell\s+)?(?:process\s+creations?|executions?|attacks?|attempts?)\b', re.I)
            for s in sentences:
                if overcount.search(s) and not _NEGATED.search(s) and not re.search(r'\bduplicate\b', s, re.I):
                    _flag(F, 'duplicate_event_overcount_review', 'medium', s,
                          'The focused input is one unique deduplicated event; multiple raw source lines do not '
                          'prove independent process executions.')
                    break

    if _auditd_proctitle_only(events) and _SENSITIVE_COMMANDS.search(source):
        for s in sentences:
            if re.search(r'\b(?:system administrators?|sysadmins?|administrators?)\s+(?:executed|performed|ran|used|issued)\b', s, re.I) and not _NEGATED.search(s):
                _flag(F, 'unverified_administrator_attribution', 'medium', s,
                      'PROCTITLE-only evidence does not identify the authorized operator, UID/EUID or approval context.')
                break
        for s in sentences:
            if re.search(r'\b(?:successfully\s+(?:escalat\w*|gained)|(?:gained|obtained)\s+root|privilege escalation succeeded)\b', s, re.I) and not _NEGATED.search(s):
                _flag(F, 'privilege_escalation_outcome_unsupported', 'high', s,
                      'PROCTITLE alone does not prove command success, UID change, or attained root privileges.')
                break
        exec_summary = sections.get('EXECUTIVE SUMMARY', '')
        if re.search(r'\b(?:appear(?:s)?\s+to\s+be\s+|(?:are|is|was)\s+)(?:entirely\s+|clearly\s+)?(?:benign|legitimate)\b', exec_summary, re.I):
            _flag(F, 'unsupported_benign_assessment_review', 'medium', exec_summary,
                  'Privilege-sensitive command records lack authorization and execution-result evidence; '
                  'benign intent is not established.')

    _add_lt04_review_requests(F, sections, events)

