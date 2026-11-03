r"""Refresh local feedback lessons from SAVED analyst reviews; no LLM inference.

Run from Week-2 root:
    python .\\SOC_Feedback_Upgrade\\sync_feedback.py
Only curated lesson IDs can be activated. Free-form review text is never loaded as instructions.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

CASES = {
    'LT01_SSH_TIME': 'AN-20261018-183730-901f',
    'LT02_AUDITD_OUTCOME': 'AN-20261018-221905-552c',
    'LT03_REVERSE_SHELL': 'AN-20261018-231218-e901',
    'LT04_BOOT_BASELINE': 'AN-20261019-003000-126d',
}


def refresh(root, dry_run=False):
    root = Path(root)
    output = root / 'Prompts' / 'Validated-SOC-Lessons.json'
    existing = None
    if output.exists():
        try:
            existing = json.loads(output.read_text(encoding='utf-8-sig'))
        except ValueError:
            raise RuntimeError('Existing feedback knowledge base is invalid; refusing overwrite.')
        if existing.get('schema_version') != 'soc-feedback-1':
            raise RuntimeError('Unexpected knowledge-base schema; refusing overwrite.')
        if existing.get('manual_lock') is True:
            raise RuntimeError('Knowledge base is locked (manual_lock=true).')
    approved, pending, provenance = [], [], {}
    for lesson_id, analysis_id in CASES.items():
        p = root / 'Results' / analysis_id / 'analysis.json'
        if not p.is_file():
            pending.append(lesson_id)
            provenance[lesson_id] = {'analysis_id': analysis_id, 'review_status': 'MISSING'}
            continue
        raw = p.read_bytes()
        data = json.loads(raw.decode('utf-8-sig'))
        if data.get('analysis_id') != analysis_id:
            raise RuntimeError(f'Record ID mismatch: {p}')
        rv = data.get('review') or {}
        status = rv.get('status') or 'Pending Review'
        has_human_review = bool(rv.get('analyst')) and (
            bool(rv.get('incorrect_findings')) or bool(rv.get('notes')))
        provenance[lesson_id] = {
            'analysis_id': analysis_id, 'review_status': status,
            'analysis_json_sha256': hashlib.sha256(raw).hexdigest(),
            'reviewed_utc': rv.get('reviewed_utc'),
            'human_review_fields_present': has_human_review,
        }
        if status in ('Corrected', 'Approved') and has_human_review:
            approved.append(lesson_id)
        else:
            pending.append(lesson_id)
    payload = {
        'schema_version': 'soc-feedback-1',
        'description': 'Only hardcoded curated lessons are eligible. Human review text is never injected.',
        'validated_lesson_ids': sorted(approved),
        'pending_lesson_ids': sorted(pending),
        'review_provenance': provenance,
    }
    print('=== HUMAN-GATED FEEDBACK SYNC ===')
    print('Validated lessons:', ', '.join(sorted(approved)) or 'none')
    print('Pending lessons:', ', '.join(sorted(pending)) or 'none')
    if dry_run:
        print('DRY RUN: knowledge-base file unchanged')
        return payload
    output.parent.mkdir(parents=True, exist_ok=True)
    if existing == payload:
        print('UNCHANGED: Knowledge base already current')
        return payload
    if output.exists():
        archive = root / 'Feedback-Backups' / ('KB-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ%f') + '.json')
        archive.parent.mkdir(parents=True, exist_ok=True)
        # Backup without replacement.
        archive.write_bytes(output.read_bytes())
        print('Previous KB backup:', archive)
    text = json.dumps(payload, indent=2, ensure_ascii=False) + '\n'
    fd, tmp = tempfile.mkstemp(dir=output.parent, prefix='.feedback-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(tmp, output)
    finally:
        Path(tmp).unlink(missing_ok=True)
    print('Knowledge base saved:', output)
    print('SHA-256:', hashlib.sha256(output.read_bytes()).hexdigest())
    return payload


if __name__ == '__main__':
    a = argparse.ArgumentParser()
    a.add_argument('--dry-run', action='store_true')
    ns = a.parse_args()
    try:
        refresh(Path.cwd(), dry_run=ns.dry_run)
    except Exception as e:
        print('STOP:', e, file=sys.stderr)
        sys.exit(1)
