"""Human-gated, deterministic retrieval of curated SOC feedback for local prompts.

No model fine-tuning. Analyst freeform fields are NEVER inserted into prompts.
Only fixed reviewed lessons (IDs matched against a local allowlist) are used.
"""
import hashlib
import json
import re
from pathlib import Path

import config

KB_PATH = config.PROMPTS_DIR / 'Validated-SOC-Lessons.json'
CATALOG = {
    'LT01_SSH_TIME': ('LT-01', 'SSH logs may omit year/timezone. Preserve recorded month/day/time; do not invent UTC year. Repeated failures do not prove access.'),
    'LT02_AUDITD_OUTCOME': ('LT-02', 'Auditd PROCTITLE records capture command arguments, not execution results, authorization, UID changes or independently confirmed attempts.'),
    'LT03_REVERSE_SHELL': ('LT-03', 'For Linux Sysmon /dev/tcp shell-redirection commands: do not invent netcat/nc; treat target IP/port as command-derived, not an observed successful connection; do not double-count identical source records.'),
}


def _context(events):
    raw = '\n'.join(e.get('raw', '') for e in events)
    # Explicit CLI --source-type linux may update dataset metadata without
    # changing per-event source_kind on JSON records; trust verified provider.
    linux = any(e.get('source_kind') == 'linux' or
                re.search(r'Linux-Sysmon', e.get('raw') or '', re.I)
                for e in events)
    return linux, raw.lower()


def _relevant(lesson_id, events):
    linux, raw = _context(events)
    if not linux:
        return False
    if lesson_id == 'LT01_SSH_TIME':
        return bool(re.search(r'\b(?:sshd|failed password|accepted password)\b', raw))
    if lesson_id == 'LT02_AUDITD_OUTCOME':
        return 'proctitle' in raw
    if lesson_id == 'LT03_REVERSE_SHELL':
        return '/dev/tcp/' in raw
    return False


def _read_approved():
    if not KB_PATH.is_file():
        return [], 'not_present'
    data = KB_PATH.read_bytes()
    try:
        payload = json.loads(data)
        if payload.get('schema_version') != 'soc-feedback-1' or not isinstance(payload.get('validated_lesson_ids'), list):
            return [], 'invalid_schema'
        allowed = sorted(set(str(x) for x in payload['validated_lesson_ids']) & CATALOG.keys())
        return allowed, hashlib.sha256(data).hexdigest()
    except (ValueError, TypeError):
        return [], 'invalid_json'


def prompt_guidance(events):
    """Bounded factual guardrails + case-matched analyst-validated lessons.

    Appended to reference notes, outside the nonce-bounded *untrusted* input.
    """
    if not events:
        return []
    linux, raw = _context(events)
    notes = []
    if linux and '/dev/tcp/' in raw:
        notes.append('LOCAL SAFETY RULE: Linux /dev/tcp in a shell command is not proof of netcat execution or a successful TCP connection. Private IPv4 is not public Internet routing. A deduplicated event must not be counted twice.')
    if linux and 'proctitle' in raw:
        notes.append('LOCAL SAFETY RULE: Auditd PROCTITLE proves recorded command arguments only, not sudo success, authorization, setuid success, or independent command invocation count.')
    if linux and re.search(r'\bsshd\b', raw):
        notes.append('LOCAL SAFETY RULE: Month/day/time without year/timezone is not a UTC timestamp. Multiple failed SSH logons alone do not prove compromise.')
    approved, _ = _read_approved()
    for key in approved:
        if _relevant(key, events):
            notes.append('ANALYST-VALIDATED LESSON ' + key + ': ' + CATALOG[key][1])
    # Bound context cost on low-resource local models.
    return notes[:6]


def feedback_audit(events):
    approved, kb_sha = _read_approved()
    relevant = [key for key in approved if _relevant(key, events)]
    return {
        'knowledge_base': str(KB_PATH.name),
        'knowledge_base_sha256': kb_sha,
        'applied_reviewed_lesson_ids': relevant,
        'general_guardrails_applied': bool(prompt_guidance(events)),
        'method': 'curated case-matched prompt guidance; not model fine-tuning',
    }
