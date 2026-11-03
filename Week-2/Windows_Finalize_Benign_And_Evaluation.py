"""Finish Windows benign case studies and consolidated evaluation, without Ollama.

Run from D:\\Desktop\\w\\Week-2:
    python .\\Windows_Finalize_Benign_And_Evaluation.py

Creates ONLY new Markdown / JSON documentation. No original data, code, reviews,
prior reports, or installer folders are rewritten. Existing output -> STOP.
"""
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('Data/Real-Datasets')
BENIGN = ROOT / 'Windows-Benign'
ATTACK = ROOT / 'Windows-Attacks'
RESULTS = Path('Results')
DOC = Path('Documentation/Windows')

BT = {
    'BT-01': dict(name='.NET Runtime Optimization / process creation',
                  analysis='AN-20261018-160709-eabf', event_count=6, flag_count=2,
                  ids={1: 6},
                  observations=[
                      'Six Sysmon Event ID 1 records establish **process creation**, not termination.',
                      '`mscorsvw.exe` ran under `NT AUTHORITY\\SYSTEM`, with `ngen.exe` as the parent process.',
                      'The recorded image path is under `C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319`, not `C:\\Windows\\System32`.',
                  ],
                  interpretation='The activity is compatible with .NET native-image optimization, but approved/benign operation is not independently proven.',
                  errors='The post-fix report twice claimed that the executable ran under System32; both path assertions contradict the Image fields.',
                  flags='Both medium process_image_path_mismatch flags were confirmed by the analyst. A prior report also inferred process stops from Event ID 1 alone.',
                  missing='Signed-binary / hash verification, process termination data, host baseline and maintenance records.'),
    'BT-02': dict(name='SYSTEM service logons / special privileges',
                  analysis='AN-20261018-160835-f96a', event_count=4, flag_count=1,
                  ids={4624: 2, 4672: 2},
                  observations=[
                      'Two Security Event ID 4624 records are **Logon Type 5 (service)** for `SYSTEM`.',
                      'Two Event ID 4672 records enumerate special privileges for `SYSTEM`, including `SeDebugPrivilege`.',
                      'The selected records share logon identifier `0x3e7`, which provides context, not proof of abuse.',
                  ],
                  interpretation='Service logons and privileges are compatible with routine SYSTEM service execution. Abnormality or unauthorized use is not established by these records.',
                  errors='The new analysis correctly identifies service logons, but calls SYSTEM privilege assignment unusual without a historical baseline.',
                  flags='One medium finding_without_evidence_ref flag was reviewed as Needs Follow-up; the unsupported abnormality assessment remains unverified.',
                  missing='Service identity, detailed authorization context, long-term baseline, and evidence of actual privileged misuse.'),
    'BT-03': dict(name='Windows service state transitions',
                  analysis='AN-20261018-160932-6d1c', event_count=6, flag_count=2,
                  ids={7036: 6},
                  observations=[
                      'Six System Event ID 7036 records describe service state transitions.',
                      'Software Protection is observed **running once and stopped once** in this selected window.',
                      'Windows Biometric Service, BITS, Microsoft Passport and AppX Deployment Service have recorded **stop** events; no start event is present for those services in this selection.',
                  ],
                  interpretation='The selection is consistent with ordinary service state changes; intent, authorization, and full lifecycle are not proven by this small window.',
                  errors='The post-fix report generalized single transitions to repeated start/stop cycles and speculated about malicious concealment without independent support.',
                  flags='Both low service_start_stop_overgeneralization flags were confirmed by the analyst for the unsupported repetition claims; conditional hypotheses alone are not fabricated events.',
                  missing='Surrounding service history, SCM process/actor evidence, approved maintenance context and security correlation.'),
}

RT = {
    'RT-01': dict(folder='RT-01-C2', study='RT-01-Case-Study.md', timeline='RT-01-Verified-Timeline.csv',
                  summary='Plink process and network connection telemetry; configuration and observed connections do not by themselves prove fully established remote access or malicious intent.',
                  review='Corrected'),
    'RT-02': dict(folder='RT-02-Discovery', study='RT-02-Case-Study.md', timeline='RT-02-Verified-Timeline.csv',
                  summary='Security Event ID 1102 records audit-log clearing, followed by IPC$ named-pipe access checks (Event ID 5145); success, authorization and causal linkage remain unproven.',
                  review='Approved'),
    'RT-03': dict(folder='RT-03-Lateral-Movement', study='RT-03-Case-Study.md', timeline='RT-03-Verified-Timeline.csv',
                  summary='WinRM-related winrshost.exe → cmd.exe → ipconfig.exe process chain; alone it does not establish attacker lateral movement.',
                  review='Corrected'),
    'RT-04': dict(folder='RT-04-Persistence', study='RT-04-Case-Study.md', timeline='RT-04-Verified-Timeline.csv',
                  summary='Executable creation, Winlogon Shell registry modification and subsequent payload execution support a persistence mechanism, not independently malware attribution.',
                  review='Corrected'),
}


def ensure(condition, msg):
    if not condition:
        raise RuntimeError(msg)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def jsonfile(path):
    ensure(path.is_file(), f'Missing file: {path}')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def readcsv(path):
    ensure(path.is_file(), f'Missing file: {path}')
    with path.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        ensure(reader.fieldnames is not None, f'Missing CSV header: {path}')
        return list(reader), set(reader.fieldnames)


def md(s):
    return str(s).replace('\\', '\\').replace('|', r'\|').replace('\n', ' ').replace('\r', ' ')


def utc(s):
    dt = datetime.fromisoformat(str(s).strip().replace('Z', '+00:00'))
    ensure(dt.tzinfo is not None, 'Timestamp has no timezone: ' + str(s))
    return dt.astimezone(timezone.utc)


def inspect_benign(case, cfg):
    folder = BENIGN / case
    dataset = folder / f'{case}-focused.json'
    mapping = folder / f'{case}-evidence-mapping.csv'
    source_manifest = folder / f'{case}-source-manifest.json'
    result = RESULTS / cfg['analysis'] / 'analysis.json'
    inputs = [dataset, mapping, source_manifest, result]
    events = jsonfile(dataset)
    man = jsonfile(source_manifest)
    analysis = jsonfile(result)
    mappings, fields = readcsv(mapping)

    ensure(isinstance(events, list) and len(events) == cfg['event_count'], f'{case}: event count mismatch')
    ensure(isinstance(man, dict), f'{case}: source manifest is invalid')
    ensure(isinstance(analysis, dict), f'{case}: analysis is invalid')
    ensure({'source_channel', 'source_record_id', 'evidence_ref', 'event_id', 'timestamp_utc', 'computer'} <= fields,
           f'{case}: evidence mapping schema mismatch')
    ensure(len(mappings) == len(events), f'{case}: evidence mapping row count mismatch')
    by_ref = {e.get('evidence_id'): e for e in events}
    ensure(len(by_ref) == len(events), f'{case}: duplicate/missing evidence IDs')
    ensure(set(by_ref) == {r['evidence_ref'] for r in mappings}, f'{case}: evidence ref mapping mismatch')
    for m in mappings:
        e = by_ref[m['evidence_ref']]
        ensure(int(e['record_id']) == int(m['source_record_id']), f'{case} {m["evidence_ref"]}: Record ID mismatch')
        ensure(int(e['event_id']) == int(m['event_id']), f'{case} {m["evidence_ref"]}: Event ID mismatch')
        ensure(str(e['computer']).lower() == str(m['computer']).lower(), f'{case}: Host mismatch')
        ensure(abs((utc(e['timestamp'])-utc(m['timestamp_utc'])).total_seconds()) < 0.001,
               f'{case}: Timestamp mismatch')
        ensure(bool(e.get('provider')) and isinstance(e.get('event_data'), dict), f'{case}: incomplete event')
    counts = Counter(int(e['event_id']) for e in events)
    ensure(counts == cfg['ids'], f'{case}: Event IDs mismatch: {dict(counts)}')

    if case == 'BT-01':
        for e in events:
            d = e['event_data']
            ensure(str(d.get('Image', '')).lower().endswith('\\microsoft.net\\framework\\v4.0.30319\\mscorsvw.exe'),
                   'BT-01: image path mismatch')
            ensure(str(d.get('ParentImage', '')).lower().endswith('\\ngen.exe'), 'BT-01: parent mismatch')
            ensure(str(d.get('User', '')).upper() == 'NT AUTHORITY\\SYSTEM', 'BT-01: user mismatch')
    if case == 'BT-02':
        for e in events:
            d = e['event_data']
            if int(e['event_id']) == 4624:
                ensure(str(d.get('LogonType')) == '5' and str(d.get('TargetUserName')).upper() == 'SYSTEM',
                       'BT-02: unsupported logon interpretation')
            else:
                ensure(str(d.get('SubjectUserName')).upper() == 'SYSTEM', 'BT-02: privilege account mismatch')
                ensure('SeDebugPrivilege' in str(d.get('PrivilegeList', '')), 'BT-02: privilege evidence missing')
    if case == 'BT-03':
        state_by_service = {}
        for e in events:
            d = e['event_data']
            state_by_service.setdefault(d.get('param1'), []).append(d.get('param2'))
        ensure(state_by_service.get('Software Protection') == ['running', 'stopped'],
               f'BT-03: service state order mismatch: {state_by_service.get("Software Protection")}')
        ensure(sum(len(v) for v in state_by_service.values()) == 6, 'BT-03: service count mismatch')

    ensure(str(man.get('focused_json_sha256', '')).lower() == sha(dataset), f'{case}: focused file SHA mismatch')
    sources = man.get('source_evtx_files')
    ensure(isinstance(sources, dict) and sources, f'{case}: no original EVTX provenance')
    for source in sources.values():
        src = Path(source['relative_path'])
        ensure(src.is_file(), f'{case}: missing source EVTX: {src}')
        ensure(sha(src).lower() == source['sha256'].lower(), f'{case}: source EVTX changed: {src}')
        inputs.append(src)
    archive = BENIGN / 'win2022-evtx.tgz'
    if man.get('source_archive_sha256_local'):
        ensure(archive.is_file() and sha(archive).lower() == str(man['source_archive_sha256_local']).lower(),
               f'{case}: original archive SHA mismatch')
        inputs.append(archive)
    if isinstance(analysis.get('input'), dict) and analysis['input'].get('sha256'):
        ensure(analysis['input']['sha256'].lower() == sha(dataset).lower(), f'{case}: analysis input SHA mismatch')
    review = analysis.get('review', {})
    ensure(isinstance(review, dict) and str(review.get('status', '')).lower() == 'corrected',
           f'{case}: post-fix human review must be Corrected')
    flags = analysis.get('validation', {}).get('flags', [])
    ensure(isinstance(flags, list) and len(flags) == cfg['flag_count'],
           f'{case}: expected {cfg["flag_count"]} saved post-fix validation flags, got {len(flags) if isinstance(flags,list) else "invalid"}')
    return dict(case=case, cfg=cfg, events=events, mapping=mappings,
                source_hashes={str(p): sha(p) for p in inputs}, review=review,
                flags=flags)


def benign_study(obj):
    case = obj['case']; cfg = obj['cfg']
    rows = []
    for r in obj['mapping']:
        e = next(e for e in obj['events'] if e['evidence_id'] == r['evidence_ref'])
        d = e['event_data']
        if case == 'BT-01':
            observation = 'Process creation: ' + str(d.get('Image',''))
        elif case == 'BT-02':
            observation = ('Logon Type 5 for SYSTEM' if int(e['event_id']) == 4624 else
                           'Special privileges assigned to SYSTEM')
        else:
            observation = f"{d.get('param1', 'Service')} → {d.get('param2', 'state unknown')}"
        rows.append((str(e['timestamp']), int(e['event_id']), int(e['record_id']),
                     r['evidence_ref'], observation))
    rows.sort(key=lambda x: (utc(x[0]), x[2]))
    table = '\n'.join(f'| `{md(t)}` | {eid} | {rid} | {ref} | {md(obs)} |'
                      for t, eid, rid, ref, obs in rows)
    notes = '\n'.join(f'- {s}' for s in cfg['observations'])
    return f'''# {case} — {cfg['name']}

**Scope:** Windows baseline *candidate*, not ground-truth-confirmed benign behavior.  
**Model:** local Mistral 7B Instruct.  
**Post-fix analysis:** `{cfg['analysis']}`.  
**Analyst review:** **Corrected**.  
**Saved validator flags:** {cfg['flag_count']} (review requests, not proven incidents).

## Evidence sources and verification

- `{case}-focused.json`: {len(rows)} selected Windows events.
- `{case}-evidence-mapping.csv`: verified evidence references, record IDs, hosts and timestamps against focused JSON (<1 ms).
- `{case}-source-manifest.json`: verified SHA-256 of focused JSON, original EVTX sources and original archive (when recorded).
- The manifest and event mapping provide provenance, but this script **does not independently reparse each source EVTX event**.
- Original AI output, review, project source code and evidence were not modified.

## Selected evidence timeline (UTC)

| Timestamp | Event ID | Source Record ID | Evidence Ref | Observed event |
|---|---:|---:|---|---|
{table}

## Evidence-supported findings

{notes}

**Interpretation boundary:** {cfg['interpretation']}

## AI quality and validation

- **Incorrect or unsupported claims:** {cfg['errors']}
- **Validator results and analyst adjudication:** {cfg['flags']}
- **Missing information:** {cfg['missing']}
- **Final analyst disposition:** Corrected (approval of a corrected report does not prove the events benign).

## False-positive assessment limitations

The sample is intentionally small and hand-selected, without independently established ground-truth benign labels. It can demonstrate specific false-positive *risks* and unsupported model inferences, **not an operational false-positive rate** or general detection accuracy.
'''


def inspect_attack(case, cfg):
    folder = ATTACK / cfg['folder']
    study = folder / cfg['study']
    timeline = folder / cfg['timeline']
    ensure(study.is_file() and study.stat().st_size > 50, f'{case}: missing/empty case study: {study}')
    records, fields = readcsv(timeline)
    preferred = ('timestamp_utc', 'original_timestamp_utc', 'utc_timestamp',
                 'timestamp', 'time_utc', 'timestamp_raw', 'timecreatedutc',
                 'timestamp_(utc)', 'timecreated', 'time_created')
    normal_fields = {k.strip().lower().replace(' ', '_'): k for k in fields if k}
    ts_col = next((normal_fields[k] for k in preferred if k in normal_fields), None)
    if ts_col is None:
        candidates = [k for k in fields if k and ('timestamp' in k.lower() or 'timecreated' in k.lower())]
        if len(candidates) == 1:
            ts_col = candidates[0]
    ensure(len(records) > 0 and ts_col is not None,
           f'{case}: verified timeline needs a recognizable timestamp column; columns={sorted(fields)}')
    for row in records:
        utc(row[ts_col])
    mapping = list(folder.glob('*evidence-mapping.csv'))
    ensure(len(mapping) == 1, f'{case}: expected one evidence mapping, got {len(mapping)}')
    mapped, _ = readcsv(mapping[0])
    ensure(len(mapped) >= len(records), f'{case}: mapping shorter than verified timeline')
    return {'case': case, 'cfg': cfg, 'timeline_rows': len(records),
            'paths': [study, timeline, mapping[0]],
            'hashes': {str(p):sha(p) for p in (study,timeline,mapping[0])}}


def attack_eval(attacks):
    lines = ['# Windows Attack Evaluation — RT-01 through RT-04', '',
             '**Scope:** Four focused recorded-lab Windows cases. This is a qualitative case-study review, not a population-level detection-rate experiment.', '',
             '| Test | Focus | Verified timeline rows | Human-review status |', '|---|---|---:|---|']
    for a in attacks:
        c = a['case']; cfg = a['cfg']
        lines.append(f'| {c} | {cfg["folder"]} | {a["timeline_rows"]} | {cfg["review"]} |')
    lines += ['', '## Evidence-supported observations', '']
    for a in attacks:
        lines.append(f'- **{a["case"]}:** {a["cfg"]["summary"]}')
    lines += ['', '## Method and limitations', '',
              '- Reviewed reports and source-linked timelines are preserved as separate case artifacts.',
              '- AI hallucinations and uncertainty were addressed via analyst review and semantic validation enhancements.',
              '- A reviewed security finding is not an independent proof of unauthorized activity, attack success or attacker identity.',
              '- Four selected cases cannot support a generalized true-positive rate.', '']
    return '\n'.join(lines)


def benign_eval(objs):
    lines = ['# Windows Benign Candidate Evaluation — BT-01 through BT-03', '',
             '**Design:** Three intentionally selected Windows baseline candidates, each analyzed with local Mistral and reviewed by a human analyst.', '',
             '| Test | Events | Initial flags | Post-fix live flags | Human review |',
             '|---|---:|---:|---:|---|']
    initial = {'BT-01': 0, 'BT-02': 3, 'BT-03': 0}
    for o in objs:
        c = o['case']; cfg = o['cfg']
        lines.append(f'| {c} | {len(o["events"])} | {initial[c]} | {len(o["flags"])} | Corrected |')
    lines += ['', '## Review findings', '']
    for o in objs:
        cfg = o['cfg']
        lines.append(f'- **{o["case"]}:** {cfg["errors"]} **Analyst finding:** {cfg["flags"]}')
    lines += ['', '## Validity constraints', '',
              '- **Zero validator flags does not prove model correctness.** Initial BT-01 and BT-03 generated no flags while human review found unsupported assertions.',
              '- Flag counts represent candidate review signals. A larger count does not imply better precision without adjudication.',
              '- The three Windows baseline samples are *benign candidates*, not an independently labelled ground-truth set.',
              '- **Do not report a numerical false-positive rate, precision, recall, specificity or accuracy** from these three cases.',
              '- Human-reviewed corrected outputs support targeted validator evaluation and regression tests.', '']
    return '\n'.join(lines)


def summary(attacks, benign):
    return f'''# Windows Testing Summary — DEPI Week 2 (Windows scope)

**Current scope:** Windows only; **Linux logs and Wazuh alert triage are still outstanding**.  
**Completed Windows cases:** {len(attacks)} focused attack scenarios + {len(benign)} benign candidates = {len(attacks)+len(benign)}.  
**Latest documented regression:** 113 tests passed (observed in saved PowerShell output; not rerun by this documentation tool).  
**Local AI:** Mistral 7B Instruct; human analyst remains the final arbiter.

## Deliverables

- `Windows-Attack-Evaluation.md`: qualitative findings from RT-01–RT-04.
- `Windows-Benign-Evaluation.md`: comparison and review findings for BT-01–BT-03.
- Case-specific evidence-linked documents and verified timelines for the four attack cases.
- Three separate post-fix benign case studies, referencing focused logs and recorded human reviews.
- `Windows-Finalization-Manifest.json`: hashes of inspected inputs and generated outputs.

## Key technical learning

1. Evidence IDs can differ between full original logs and focused input; preserve the explicit mapping.
2. Validate event semantics: process creation is not termination, `4624` Logon Type 5 is service logon, `4672` privileges alone are not exploitation, and `7036` state changes alone do not prove concealment.
3. Guard timestamp parsing and cite original event timestamps, not generated model values.
4. Automated validation is a review aid, not an incident-confirmation engine. All seven cases require interpretable human adjudication.
5. Source hashes and unchanged original analyses/reviews preserve provenance and auditability.

## Next phases

- **Linux:** focused attack/benign log analysis using the existing parser + analyst review flow.
- **Wazuh:** alert triage and source-evidence correlation.
- **Week 2 integrated report:** finish only after Linux and Wazuh testing. This document is **not** the final Week 2 report.

## Evaluation caution

These seven selected case studies and three unverified-benign baseline candidates do not yield a statistically meaningful operational detection or false-positive rate.
'''


def main():
    ensure(Path('app.py').is_file() and Path('Core').is_dir() and Path('Results').is_dir(),
           'Run from the Week-2 project root (app.py / Core / Results).')
    attacks = [inspect_attack(c, cfg) for c, cfg in RT.items()]
    benign = [inspect_benign(c, cfg) for c, cfg in BT.items()]
    manifest = DOC / 'Windows-Finalization-Manifest.json'
    planned = {}
    for b in benign:
        c = b['case']
        planned[BENIGN / c / f'{c}-Case-Study.md'] = benign_study(b)
    planned[DOC / 'Windows-Attack-Evaluation.md'] = attack_eval(attacks)
    planned[DOC / 'Windows-Benign-Evaluation.md'] = benign_eval(benign)
    planned[DOC / 'Windows-Testing-Summary.md'] = summary(attacks, benign)
    ensure(all(not p.exists() for p in [*planned, manifest]),
           'STOP: One or more final documentation outputs already exist. No files overwritten: ' +
           ', '.join(str(p) for p in [*planned, manifest] if p.exists()))

    original_hashes = {}
    for a in attacks:
        original_hashes.update(a['hashes'])
    for b in benign:
        original_hashes.update(b['source_hashes'])
    manifest_data = {
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Windows selected attack and benign candidate cases only',
        'attack_cases': list(RT),
        'benign_candidates': {b['case']:{'analysis_id':b['cfg']['analysis'],
                                       'review':'Corrected',
                                       'postfix_flag_count':len(b['flags'])} for b in benign},
        'source_sha256': original_hashes,
        'generated_sha256': {str(p): hashlib.sha256(text.encode('utf-8')).hexdigest() for p,text in planned.items()},
        'original_sources_or_ai_reviews_changed': False,
        'limitations': ['Existing original EVTX SHA-256 hashes verified for benign files, but each benign source EVTX record was not independently re-extracted by this tool.',
                        'Three benign candidates do not establish false-positive rates or absolute benign ground truth.',
                        'Linux and Wazuh are outside the scope of this Windows report.'],
    }
    planned[manifest] = json.dumps(manifest_data, ensure_ascii=False, indent=2) + '\n'
    created = []
    try:
        for p, contents in planned.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open('x', encoding='utf-8', newline='') as f:
                f.write(contents)
            created.append(p)
            print('CREATED:', p, flush=True)
    except BaseException:
        for p in created:
            p.unlink(missing_ok=True)
        raise
    # Recheck the produced docs and the source hashes after writing.
    for p, h in manifest_data['generated_sha256'].items():
        ensure(sha(Path(p)) == h, f'Generated doc SHA mismatch: {p}')
    for p, h in original_hashes.items():
        ensure(sha(Path(p)) == h, f'Source changed during documentation: {p}')
    print('\n=== WINDOWS FINAL EVALUATION ===')
    print('Attack case studies + verified timelines: 4/4 PRESENT')
    print('Benign case studies: 3/3 CREATED')
    print('Windows evaluations + summary: 3 CREATED')
    print('Windows finalization manifest: CREATED')
    print('Focused dataset / original source checksums: PASS')
    print('Human reviews: 3 BENIGN CORRECTED; attack studies PRESERVED')
    print('Original Data, Results, code and analyst reviews: UNCHANGED')
    print('STATUS: WINDOWS DOCUMENTATION COMPLETE — LINUX/WAZUH PENDING')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('FAIL:', str(e), file=sys.stderr)
        sys.exit(1)
