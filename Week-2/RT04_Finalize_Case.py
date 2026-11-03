#!/usr/bin/env python3
"""RT-04 final forensic verification and case study, run from Week-2 root.

No LLM calls. Does not alter the EVTX, input JSON, stored AI analyses,
reviews, source manifests, replay output, or application code.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

BASE = Path('Data/Real-Datasets/Windows-Attacks/RT-04-Persistence')
FIRST_ID = 'AN-20261018-014225-d45b'  # output truncated
BASELINE_ID = 'AN-20261018-015226-37b2'  # complete, before semantic patch
FINAL_ID = 'AN-20261018-022126-c65b'  # complete, after semantic patch
ORIGINAL_REFS = ('E001', 'E002', 'E003', 'E017', 'E018', 'E019', 'E021')
EVENT_IDS = (1, 11, 13, 1, 1, 1, 1)
PROCESS_IMAGES = ('a.exe', '', 'a.exe', 'userinit.exe',
                  'bre6bge2jubb.exe', 'explorer.exe', 'bre6bge2jubb.exe')


def require(test: bool, message: str):
    if not test:
        raise ValueError('STOP: ' + message)


def get_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def digest(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha(data: bytes):
    return hashlib.sha1(f'blob {len(data)}\0'.encode('ascii') + data).hexdigest()


def display_path(value):
    return str(value or '').replace('|', '/').replace('\r', ' ').replace('\n', ' ')


def base_name(value):
    return str(value or '').replace('/', '\\').rsplit('\\', 1)[-1].lower()


def md_list(value):
    if isinstance(value, str):
        value = [value] if value.strip() else []
    return '\n'.join('- ' + display_path(v) for v in (value or [])) or '- Nothing recorded.'


def main():
    root = Path.cwd().resolve()
    require((root / 'app.py').is_file(), 'Start PowerShell in Week-2 (app.py not found).')
    case = root / BASE
    evtx = case / 'sysmon_13_1_persistence_via_winlogon_shell.evtx'
    raw_path = case / 'RT-04-converted.json'
    focused_path = case / 'RT-04-focused.json'
    manifest_path = case / 'RT-04-Source-Manifest.json'
    mapping_path = case / 'RT-04-evidence-mapping.csv'
    replay_path = case / 'RT-04-postfix-validator-replay.json'
    run_paths = {run_id: root / 'Results' / run_id / 'analysis.json'
                 for run_id in (FIRST_ID, BASELINE_ID, FINAL_ID)}
    verified_csv = case / 'RT-04-Verified-Timeline.csv'
    case_study = case / 'RT-04-Case-Study.md'

    inputs = [evtx, raw_path, focused_path, manifest_path, mapping_path, replay_path,
              *run_paths.values()]
    for path in inputs:
        require(path.is_file(), f'Missing required input: {path}')
    require(not verified_csv.exists() and not case_study.exists(),
            'One or both final output files exist; refusing to overwrite them.')

    manifest, original, focused, replay = (
        get_json(manifest_path), get_json(raw_path), get_json(focused_path),
        get_json(replay_path))
    runs = {i: get_json(p) for i, p in run_paths.items()}
    original_hash, focused_hash = digest(evtx), digest(focused_path)
    require(original_hash.lower() == str(manifest.get('local_sha256', '')).lower(),
            'Original EVTX hash differs from provenance manifest.')
    require(git_blob_sha(evtx.read_bytes()).lower() == str(manifest.get('github_blob_sha', '')).lower(),
            'EVTX GitHub blob hash differs from recorded source manifest.')
    require(isinstance(original, list) and len(original) == 25, 'Original dataset must contain 25 events.')
    require(isinstance(focused, list) and len(focused) == 7, 'Focused dataset must contain 7 events.')

    for run_id, rec in runs.items():
        require(rec.get('analysis_id') == run_id, f'Wrong stored analysis ID: {run_id}')
        require(rec.get('task') == 'log_analysis', f'Wrong task: {run_id}')
        require(rec['input']['sha256'] == focused_hash,
                f'Input SHA-256 differs from saved analysis: {run_id}')
        require(len(rec['events']) == 7, f'Wrong event count in saved analysis: {run_id}')
    require(runs[BASELINE_ID]['review']['status'] == 'Corrected',
            'Baseline human review is not saved as Corrected.')
    require(runs[FINAL_ID]['review']['status'] == 'Corrected',
            'Final human review is not saved as Corrected.')
    require(len(runs[FIRST_ID]['validation']['flags']) == 9,
            'Unexpected first-run flag count (expected 9).')
    require(len(runs[BASELINE_ID]['validation']['flags']) == 2,
            'Unexpected complete pre-patch flag count (expected 2).')
    require(len(runs[FINAL_ID]['validation']['flags']) == 1,
            'Unexpected post-patch flag count (expected 1).')
    require(runs[FIRST_ID]['ai_output'].get('truncated') is True,
            'Initial AI output was expected to be truncated.')
    require(runs[BASELINE_ID]['ai_output'].get('truncated') is False and
            runs[FINAL_ID]['ai_output'].get('truncated') is False,
            'A complete analysis is marked truncated.')
    require(runs[FINAL_ID]['validation']['flags'][0].get('check') == 'unsupported_download_origin',
            'Final flag does not match expected unsupported download-origin claim.')
    require(replay.get('source_analysis_id') == BASELINE_ID and
            replay.get('before_flag_count') == 2 and replay.get('after_flag_count') == 10,
            'Semantic validator replay counts/analysis ID do not match recorded output.')

    source_lookup = {}
    for event in original:
        ref = event.get('evidence_id')
        require(ref not in source_lookup, 'Duplicate reference in original event file: ' + str(ref))
        source_lookup[ref] = event

    with mapping_path.open('r', encoding='utf-8-sig', newline='') as f:
        mappings = list(csv.DictReader(f))
    require(len(mappings) == 7, 'Evidence mapping CSV must contain seven rows.')

    timeline = runs[FINAL_ID].get('evidence_timeline', [])
    require(len(timeline) == 7, 'Evidence-derived canonical timeline missing or incomplete.')
    verified_rows = []

    for ix, (event, mapping_row, canonical) in enumerate(zip(focused, mappings, timeline)):
        orig_ref = ORIGINAL_REFS[ix]
        new_ref = f'E{ix+1:03d}'
        true_event = source_lookup.get(orig_ref)
        require(true_event is not None and event == true_event,
                f'Focused event is not an unchanged original event: {orig_ref}')
        require(mapping_row.get('original_ref') == orig_ref and
                mapping_row.get('parsed_ref') == new_ref,
                f'Evidence mapping CSV mismatch: {orig_ref} -> {new_ref}')
        require(int(event['event_id']) == EVENT_IDS[ix], f'Unexpected Sysmon ID at {orig_ref}.')
        require(str(mapping_row.get('record_id')) == str(event['record_id']),
                f'Record ID differs in mapping for {orig_ref}')
        require(mapping_row.get('timestamp') == event['timestamp'],
                f'Timestamp differs in mapping for {orig_ref}')
        require(canonical['evidence_ref'] == new_ref and
                canonical['timestamp'] == event['timestamp'],
                f'Canonical timeline mismatch at {new_ref}')
        for run_id, stored in runs.items():
            ev = stored['events'][ix]
            require(ev['ref'] == new_ref and
                    str(ev['event_id']) == str(event['event_id']) and
                    ev['timestamp_raw'] == event['timestamp'] and
                    ev['host'] == event['computer'],
                    f'Event/ref/timestamp mismatch in {run_id} at {new_ref}')
        data = event['event_data']
        image = base_name(data.get('Image'))
        if PROCESS_IMAGES[ix]:
            require(image == PROCESS_IMAGES[ix], f'Unexpected image for {new_ref}: {image}')
        verified_rows.append({
            'Parsed Evidence': new_ref,
            'Original Evidence': orig_ref,
            'Timestamp (original UTC)': event['timestamp'],
            'Sysmon Event ID': event['event_id'],
            'Record ID': event['record_id'],
            'Host': event['computer'],
            'Image': data.get('Image', ''),
            'ParentImage': data.get('ParentImage', ''),
            'TargetFilename': data.get('TargetFilename', ''),
            'TargetObject': data.get('TargetObject', ''),
            'Details': data.get('Details', ''),
        })

    # Concrete source-evidence checks for creation -> registry value -> later logon execution.
    created_file = str(focused[1]['event_data'].get('TargetFilename', ''))
    reg = focused[2]['event_data']
    require(created_file and 'winlogon\\shell' in str(reg.get('TargetObject', '')).lower(),
            'Winlogon Shell registry-change evidence missing.')
    require(created_file.lower() in str(reg.get('Details', '')).lower(),
            'Registry Shell value does not include the created file.')
    require(created_file.lower() == str(focused[4]['event_data'].get('Image', '')).lower(),
            'Subsequent payload image does not match the created file.')

    guid_status = []
    for parent_idx, child_idx in ((3, 4), (3, 5), (4, 6)):
        parent = focused[parent_idx]['event_data']
        child = focused[child_idx]['event_data']
        p_guid = str(parent.get('ProcessGuid') or '').strip().lower()
        c_parent_guid = str(child.get('ParentProcessGuid') or '').strip().lower()
        require(not(p_guid and c_parent_guid and p_guid != c_parent_guid),
                f'Conflicting ProcessGuid chain for E{parent_idx+1:03d} -> E{child_idx+1:03d}.')
        label = 'GUID MATCH' if p_guid and c_parent_guid else 'GUID NOT AVAILABLE; do not assert direct GUID verification'
        guid_status.append(f'E{parent_idx+1:03d} -> E{child_idx+1:03d}: {label}')

    final_review = runs[FINAL_ID]['review']
    report_lines = [
        '# RT-04 — Winlogon Shell Persistence | Final Case Study',
        '',
        '> Recorded laboratory telemetry. Source-derived evidence is authoritative; AI analysis is reviewed, not treated as proof.',
        '',
        '## Case information',
        f'- Original EVTX: `{evtx.name}` (25 recorded Sysmon events).',
        f'- Original EVTX SHA-256: `{original_hash}` (matches provenance manifest).',
        f'- Original EVTX Git blob hash: `{git_blob_sha(evtx.read_bytes())}` (matches provenance manifest).',
        f'- Focused input: `RT-04-focused.json` — 7 selected events; SHA-256 `{focused_hash}`.',
        '- Evidence crosswalk: `RT-04-evidence-mapping.csv` (original references preserved).',
        f'- Original truncated report: `{FIRST_ID}` — 9 flags, output truncated at generation limit.',
        f'- Complete pre-patch report: `{BASELINE_ID}` — 2 flags, human review Corrected.',
        f'- Post-patch report: `{FINAL_ID}` — 1 flag, human review Corrected.',
        '- Local model: `mistral:7b-instruct-v0.3-q4_K_S`.',
        '',
        '## Verified evidence timeline (NOT the generated AI timeline)',
        '| Original UTC timestamp | Model evidence | Original evidence | Sysmon ID | Observed record |',
        '|---|---|---|---:|---|',
    ]
    labels = [
        'a.exe process creation', 'BRE6BgE2JubB.exe file creation',
        'Winlogon\\Shell registry value set', 'userinit.exe process creation',
        'BRE6BgE2JubB.exe started by userinit.exe',
        'explorer.exe started by userinit.exe',
        'additional BRE6BgE2JubB.exe process creation',
    ]
    for row, label in zip(verified_rows, labels):
        report_lines.append(
            f'| `{row["Timestamp (original UTC)"]}` | `{row["Parsed Evidence"]}` | '
            f'`{row["Original Evidence"]}` | {row["Sysmon Event ID"]} | {label} |')
    report_lines += [
        '',
        '## Process relationship verification',
        *[f'- {text}' for text in guid_status],
        '',
        '## Evidence-backed security interpretation',
        '- [E001] Sysmon ID 1 documents execution of `a.exe` from a local `Downloads` path, not where it came from.',
        '- [E002] Sysmon ID 11 documents creation of the executable subsequently configured in `Winlogon\\Shell`.',
        '- [E003] Sysmon ID 13 documents modification of the user-level Winlogon Shell registry value, including the created executable and `explorer.exe`.',
        '- [E004–E006] The later logon sequence includes `userinit.exe`, the configured payload, and `explorer.exe`.',
        '- [E007] A further process creation for the payload was observed; this does not alone establish a separate logon session.',
        '- **Supported finding:** the observed sequence is consistent with activation of Winlogon Shell persistence during a later logon.',
        '- **Unverified:** malicious intent, confirmed malware identity, download origin, repeated persistence across several reboots, and distinct user sessions.',
        '',
        '## AI performance, validator improvement, and regression',
        '- First analysis: 9 flags and incomplete/truncated output with 1500-token generation limit.',
        '- Complete pre-patch analysis: 2 flags after using `--num-ctx 8192 --num-predict 3000`.',
        '- Deterministic post-patch replay of that saved pre-patch report: 10 flags (not necessarily 10 unique semantic errors).',
        '- Post-patch live analysis: 1 medium flag for unsupported inference that `a.exe` had been downloaded.',
        '- Previous 1 high-severity timeline mismatch was absent in the post-patch output; all seven source timestamps remain available in the canonical timeline.',
        '- Semantic patch: 92/92 unit tests passed on the analyst machine (as recorded in the terminal output).',
        '- A reduced validation-flag count is not a guarantee of correctness; human review remains mandatory.',
        '',
        '## Human review of post-patch report',
        f'- Analyst: {display_path(final_review.get("analyst"))}.',
        f'- Status: **{final_review["status"]}**.',
        '- F001 (`unsupported_download_origin`): analyst classified the unsupported download claim as a hallucination.',
        '',
        '**Correct findings**',
        md_list(final_review.get('correct_findings', [])),
        '',
        '**Incorrect findings**',
        md_list(final_review.get('incorrect_findings', [])),
        '',
        '**Missing evidence**',
        md_list(final_review.get('missing_evidence', [])),
        '',
        '**Hallucinations and unsupported statements**',
        md_list(final_review.get('hallucinations', [])),
        '',
        '**Analyst notes**',
        display_path(final_review.get('notes', '')),
        '',
        '## Final disposition',
        '**Completed — Corrected.** The reported Winlogon Shell modification and subsequent payload execution are evidenced by the recorded events. This case does not independently prove malicious intent or persistence across multiple reboots. Stored AI output and human review are retained without editing.',
        '',
        '## Retained evidence',
        f'- `Results/{FIRST_ID}/analysis.json`',
        f'- `Results/{BASELINE_ID}/analysis.json`',
        f'- `Results/{FINAL_ID}/analysis.json`',
        '- `RT-04-postfix-validator-replay.json`',
        '- `RT-04-evidence-mapping.csv`',
        '- `RT-04-Verified-Timeline.csv`',
        '- `RT-04-Source-Manifest.json`',
    ]

    # All checks happen before any outputs are created. Exclusive creation prevents overwriting.
    try:
        with verified_csv.open('x', encoding='utf-8-sig', newline='') as fp:
            writer = csv.DictWriter(fp, fieldnames=list(verified_rows[0]))
            writer.writeheader()
            writer.writerows(verified_rows)
        with case_study.open('x', encoding='utf-8') as fp:
            fp.write('\n'.join(report_lines) + '\n')
    except Exception:
        # Roll back only the files this run created; never touch inputs.
        if verified_csv.exists() and not case_study.exists():
            verified_csv.unlink()
        raise

    print('=== RT-04 FINAL EVIDENCE VERIFICATION ===')
    print('Original EVTX SHA-256 + GitHub blob hash: PASS')
    print('Recorded input SHA-256 (all three analyses): PASS')
    print('Original 25 events + focused 7 event mapping: PASS')
    print('Sysmon semantics + Winlogon Shell file linkage: PASS')
    print('Evidence-derived full-precision timeline: PASS')
    print('Process chain:', '; '.join(guid_status))
    print('Stored analyses: truncated 9 flags; complete 2 flags; post-fix 1 flag')
    print('Semantic replay: 2 -> 10 flags (PASS)')
    print('Final human review: Corrected (saved)')
    print('Verified timeline:', verified_csv)
    print('Case study:', case_study)
    print('STATUS: RT-04 DOCUMENTATION COMPLETE')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc))
