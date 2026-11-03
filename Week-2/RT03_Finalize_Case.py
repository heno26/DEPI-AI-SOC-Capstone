#!/usr/bin/env python3
"""Verify and document RT-03 using immutable saved SOC runs.

Usage: copy into Week-2 root; python RT03_Finalize_Case.py
This does NOT re-run Mistral, modify any result, or patch project code.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

CASE_REL = Path('Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement')
OLD_ID = 'AN-20261018-004828-3c5c'
NEW_ID = 'AN-20261018-010933-ca14'
EXPECTED_IMAGES = ('winrshost.exe', 'cmd.exe', 'ipconfig.exe')


def load_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_valid(cond: bool, explanation: str):
    if not cond:
        raise ValueError('STOP: ' + explanation)


def md_safe(value: object):
    return str(value or '').replace('|', '/').replace('\n', ' ').replace('\r', ' ')


def as_md_list(values):
    return '\n'.join(f'- {md_safe(v)}' for v in values) if values else '- None recorded.'


def main():
    root = Path.cwd().resolve()
    assert_valid((root / 'app.py').is_file(), 'Run from Week-2 project root (app.py not found).')
    case = root / CASE_REL
    old_path = root / 'Results' / OLD_ID / 'analysis.json'
    new_path = root / 'Results' / NEW_ID / 'analysis.json'
    data_path = case / 'RT-03-focused.json'
    evtx_path = case / 'LM_winrm_exec_sysmon_1_winrshost.evtx'
    manifest_path = case / 'RT-03-Source-Manifest.json'
    replay_path = case / 'RT-03-postfix-validator-replay.json'
    for path in (old_path, new_path, data_path, evtx_path, manifest_path, replay_path):
        assert_valid(path.is_file(), f'Missing required evidence file: {path}')

    csv_path = case / 'RT-03-Verified-Timeline.csv'
    md_path = case / 'RT-03-Case-Study.md'
    assert_valid(not csv_path.exists() and not md_path.exists(), 'Output exists; no overwriting evidence documentation.')

    old, new = load_json(old_path), load_json(new_path)
    src, manifest, replay = load_json(data_path), load_json(manifest_path), load_json(replay_path)

    assert_valid(old['analysis_id'] == OLD_ID and new['analysis_id'] == NEW_ID, 'Analysis ID mismatch.')
    assert_valid(old['review']['status'] == 'Corrected' and new['review']['status'] == 'Corrected', 'Human Review not saved as Corrected.')
    assert_valid(isinstance(src, list) and len(src) == 3, 'Expected exactly three recorded events.')
    assert_valid(sha256(data_path) == old['input']['sha256'] == new['input']['sha256'], 'Input SHA256 mismatch; saved runs do not match current dataset.')
    assert_valid(sha256(evtx_path).lower() == str(manifest['local_sha256']).lower(), 'Original EVTX SHA256 no longer matches recorded provenance.')
    assert_valid(len(old['events']) == len(new['events']) == 3, 'Stored analyzed-event count mismatch.')
    assert_valid(len(new['evidence_timeline']) == 3, 'Evidence-derived timeline incomplete.')

    mapping = []
    for n, (raw, old_ev, new_ev, tl) in enumerate(zip(src, old['events'], new['events'], new['evidence_timeline']), 1):
        ref = f'E{n:03d}'
        assert_valid(raw['evidence_id'] == ref and old_ev['ref'] == ref and new_ev['ref'] == ref, f'Evidence mapping mismatch: {ref}')
        assert_valid(str(raw['event_id']) == str(old_ev['event_id']) == str(new_ev['event_id']) == '1', f'Event ID mismatch: {ref}')
        assert_valid(raw['timestamp'] == old_ev['timestamp_raw'] == new_ev['timestamp_raw'] == tl['timestamp'], f'Source timestamp mismatch: {ref}')
        assert_valid(raw['computer'] == new_ev['host'] and raw['computer'] == old_ev['host'], f'Host mismatch: {ref}')
        image = str(raw['event_data'].get('Image', '')).replace('/', '\\').rsplit('\\', 1)[-1].lower()
        assert_valid(image == EXPECTED_IMAGES[n - 1], f'Unexpected process image: {ref}: {image}')
        assert_valid(tl['evidence_ref'] == ref, f'Canonical timeline evidence mismatch: {ref}')
        mapping.append({'Evidence': ref, 'Timestamp (original UTC)': raw['timestamp'], 'Event ID': raw['event_id'],
                        'Host': raw['computer'], 'Image': image, 'Record ID': raw['record_id']})

    correlations = []
    for idx in (1, 2):
        p = src[idx - 1]['event_data']
        ch = src[idx]['event_data']
        parent_guid = str(p.get('ProcessGuid', '')).strip().lower()
        observed_parent_guid = str(ch.get('ParentProcessGuid', '')).strip().lower()
        assert_valid(parent_guid and observed_parent_guid and parent_guid == observed_parent_guid,
                     f'ProcessGuid parent chain does not match {src[idx-1]["evidence_id"]} -> {src[idx]["evidence_id"]}.')
        correlations.append(f'{EXPECTED_IMAGES[idx-1]} -> {EXPECTED_IMAGES[idx]}: ProcessGuid MATCH')

    old_flags = old['validation']['flags']
    new_flags = new['validation']['flags']
    timeline_flags = [f for f in new_flags if f.get('check') == 'timeline_timestamp_mismatch']
    assert_valid(len(timeline_flags) == 3, f'Expected three invalid-model-timestamp flags; found {len(timeline_flags)}.')
    assert_valid(all(f['severity'] == 'high' for f in timeline_flags), 'Invalid AI timestamps were not marked high severity.')
    assert_valid(all('XX' in str(f['value']).upper() for f in timeline_flags), 'Review required: timestamp flags did not contain expected XX placeholders.')

    # Saved analyses provide the canonical flags. Replay JSON is preserved separately.
    old_count = len(old_flags)
    new_count = len(new_flags)
    assert_valid(old_count == 2 and new_count == 5, f'Unexpected saved validation flag counts: old={old_count}, new={new_count}.')

    lines = [
        '# RT-03 — WinRM-Related Remote Command Execution | Case Study',
        '',
        '> Source-derived timeline is authoritative. AI timeline is an unverified draft. Human review was required.',
        '',
        '## Case metadata',
        f'- Original EVTX: `{evtx_path.name}` (recorded lab sample, not production telemetry)',
        f'- EVTX SHA-256: `{sha256(evtx_path)}`',
        f'- Focused input SHA-256: `{sha256(data_path)}`',
        f'- Source host: `{md_safe(src[0]["computer"])}`',
        f'- Events: {len(src)} Sysmon Event ID 1 records; all three included (full sample).',
        f'- Model: `{md_safe(new["model"]["name"])}` (local inference)',
        f'- Original analysis: `{OLD_ID}` — analyst status: {old["review"]["status"]}.',
        f'- Post-fix analysis: `{NEW_ID}` — analyst status: {new["review"]["status"]}.',
        '',
        '## Verified timeline — derived from ORIGINAL log events, not generated by the AI',
        '| Source UTC timestamp | Evidence | Event ID | Process | Record ID |',
        '|---|---|---:|---|---:|',
    ]
    for m in mapping:
        lines.append(f'| `{m["Timestamp (original UTC)"]}` | `{m["Evidence"]}` | {m["Event ID"]} | `{m["Image"]}` | {m["Record ID"]} |')
    lines += [
        '',
        '## Process chain verification',
        *[f'- {c}' for c in correlations],
        '',
        '## Observations vs hypotheses',
        '- Observed: process execution chain `winrshost.exe -> cmd.exe -> ipconfig.exe` on the specified host, with valid ProcessGuid correlations.',
        '- Interpretation: consistent with WinRM-related command execution; `ipconfig.exe` can be a discovery command.',
        '- Unverified: remote client identity, session authentication, approved change, attacker intent, or confirmed malicious lateral movement.',
        '',
        '## Validation before and after semantic improvements',
        f'- Original analysis: {old_count} automated flags (both missing-reference warnings).',
        '- Validator replay on the original report after semantic fix: 5 flags (2 original missing-reference + 3 added authorization/scope warnings).',
        f'- Post-fix AI analysis: {new_count} flags, including {len(timeline_flags)} high-severity invalid-timestamp flags.',
        '- RT-03 semantic patch: 76 unit tests passed on the user machine as previously recorded.',
        '- The three `XX`-containing timestamps generated by the AI must NOT be used as evidence timestamps.',
        '- Deterministic `evidence_timeline` is already present in stored analysis data and in `report.md`; this CSV is a separate verified extract.',
        '',
        '## Human analyst decisions (post-fix)',
        f'- Analyst: {md_safe(new["review"].get("analyst"))}.',
        f'- Review status: **{new["review"]["status"]}**.',
        '',
        '**Correct findings:**',
        as_md_list(new['review'].get('correct_findings', [])),
        '',
        '**Incorrect findings:**',
        as_md_list(new['review'].get('incorrect_findings', [])),
        '',
        '**Missing evidence:**',
        as_md_list(new['review'].get('missing_evidence', [])),
        '',
        '**Hallucinations / unsupported claims identified by analyst:**',
        as_md_list(new['review'].get('hallucinations', [])),
        '',
        '**Review notes:**',
        md_safe(new['review'].get('notes', '')),
        '',
        '## Resolution and scope',
        '- The original Mistral output, analyst decisions, EVTX, and JSON are preserved without rewriting.',
        '- For reporting, use the source-derived canonical timeline above; do not substitute the AI placeholder values.',
        '- Semantic validation was improved and regression-tested, but the model remains fallible.',
        '- Case status: **Completed — Corrected**. This does not confirm malicious lateral movement.',
        '',
        '## Evidence files',
        f'- Original result: `Results/{OLD_ID}/analysis.json` and `report.md`.',
        f'- Post-fix result: `Results/{NEW_ID}/analysis.json` and `report.md`.',
        '- `RT-03-postfix-validator-replay.json` (post-fix replay, unchanged).',
        '- `RT-03-Verified-Timeline.csv` (generated canonical timestamp table).',
    ]

    # Only write outputs after all verification passes.
    with csv_path.open('x', encoding='utf-8-sig', newline='') as fp:
        writer = csv.DictWriter(fp, fieldnames=list(mapping[0].keys()))
        writer.writeheader()
        writer.writerows(mapping)
    with md_path.open('x', encoding='utf-8') as fp:
        fp.write('\n'.join(lines) + '\n')

    print('=== RT-03 FINAL EVIDENCE VERIFICATION ===')
    print('Original EVTX hash: PASS')
    print('Recorded input hash: PASS')
    print('Evidence IDs and full-precision timestamps: PASS')
    print('ProcessGuid parent-child chain: PASS')
    print('AI placeholder timestamps: 3 HIGH flags (preserved, not rewritten)')
    print('Human review: Corrected (saved)')
    print('Verified timeline saved:', csv_path)
    print('Final case study saved:', md_path)
    print('STATUS: RT-03 DOCUMENTATION COMPLETE')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as err:
        raise SystemExit(str(err))
