"""Prepare three candidate Windows baseline cases; no Ollama or project code changes.

Run from D:\\Desktop\\w\\Week-2 on Windows:
    python .\\BT_Prepare_3_Cases.py

Safety: source EVTX files stay unchanged; no existing case output is overwritten.
"""
import base64
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from collections import Counter

ROOT = Path('Data/Real-Datasets/Windows-Benign')
CHANNELS = ROOT / 'Selected-Channels' / 'win2022-evtx'

CASES = [
    {
        'id': 'BT-01',
        'scenario': 'Candidate normal .NET native-image optimization process execution',
        'selections': [
            ('Microsoft-Windows-Sysmon%4Operational.evtx', 1, [512678, 512613, 512513, 512447, 512366, 512304]),
        ],
    },
    {
        'id': 'BT-02',
        'scenario': 'Candidate SYSTEM service logons and special-privilege audit events (NOT interactive user login)',
        'selections': [
            ('Security.evtx', 4624, [33813, 33788]),
            ('Security.evtx', 4672, [33815, 33790]),
        ],
    },
    {
        'id': 'BT-03',
        'scenario': 'Candidate routine Windows service state changes',
        'selections': [
            ('System.evtx', 7036, [1864, 1863, 1862, 1861, 1860, 1858]),
        ],
    },
]

PS_EXTRACT = r'''param([string]$LogPath, [int]$EventId, [int]$Limit)
$ErrorActionPreference = 'Stop'
$items = @(Get-WinEvent -FilterHashtable @{Path=$LogPath; Id=$EventId} -MaxEvents $Limit -ErrorAction Stop)
if ($items.Count -ne $Limit) { throw "Expected $Limit events; got $($items.Count) for $EventId" }
$result = [System.Collections.Generic.List[object]]::new()
foreach ($event in $items) {
    [xml]$x = $event.ToXml()
    $data = [ordered]@{}
    $unnamed = 0
    foreach ($node in $x.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if (-not $name) { $unnamed++; $name = "param$unnamed" }
        if ($data.Contains($name)) { throw "Duplicate EventData field $name" }
        $data[$name] = $node.InnerText
    }
    foreach ($node in $x.SelectNodes("//*[local-name()='UserData']//*[not(*)]")) {
        $name = $node.LocalName
        if ($data.Contains($name) -and [string]$data[$name] -ne [string]$node.InnerText) {
            throw "Conflicting UserData field $name"
        }
        $data[$name] = $node.InnerText
    }
    $result.Add([ordered]@{
        timestamp=[string]$x.Event.System.TimeCreated.SystemTime
        event_id=[int]$event.Id
        record_id=[long]$event.RecordId
        provider=[string]$x.Event.System.Provider.Name
        computer=[string]$x.Event.System.Computer
        event_data=$data
    })
}
$json = ConvertTo-Json -InputObject @($result.ToArray()) -Depth 40 -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
'''


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def extract(log_path, event_id, record_ids, ps_script):
    cp = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(ps_script),
         "-LogPath", str(log_path.resolve()), "-EventId", str(event_id),
         "-Limit", str(len(record_ids))],
        capture_output=True, text=True, errors='replace', timeout=180,
    )
    if cp.returncode:
        raise RuntimeError('Windows event extraction failed:\n' + cp.stderr.strip())
    lines = [line.strip() for line in cp.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError('Expected one encoded JSON result, got: ' + repr(lines[:3]))
    try:
        result = json.loads(base64.b64decode(lines[0], validate=True).decode('utf-8'))
    except Exception as e:
        raise RuntimeError('Invalid PowerShell extraction result') from e
    if not isinstance(result, list) or len(result) != len(record_ids):
        raise RuntimeError(f'Event count mismatch for {log_path.name}: expected {len(record_ids)}')
    actual = [int(r['record_id']) for r in result]
    if set(actual) != set(record_ids) or len(set(actual)) != len(record_ids):
        raise RuntimeError(f'Selected Record IDs changed for {log_path.name}, ID={event_id}: {actual}')
    for r in result:
        if int(r['event_id']) != event_id:
            raise RuntimeError('Event ID mismatch')
        if not r['timestamp'] or not r['computer'] or not r['provider']:
            raise RuntimeError('Missing event metadata')
        t = datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00'))
        if t.tzinfo is None:
            raise RuntimeError('Timestamp without timezone')
        if not isinstance(r['event_data'], dict):
            raise RuntimeError('Invalid event_data object')
    return result


def make_case(case, ps_script, load_file):
    cid = case['id']
    case_dir = ROOT / cid
    json_path = case_dir / f'{cid}-focused.json'
    mapping_path = case_dir / f'{cid}-evidence-mapping.csv'
    manifest_path = case_dir / f'{cid}-source-manifest.json'

    for path in (json_path, mapping_path, manifest_path):
        if path.exists():
            raise RuntimeError(f'STOP: Existing file preserved: {path}')

    events, files = [], {}
    for filename, event_id, record_ids in case['selections']:
        evtx = CHANNELS / filename
        if not evtx.is_file():
            raise FileNotFoundError(evtx)
        if filename not in files:
            files[filename] = {'relative_path': str(evtx), 'sha256': digest(evtx)}
        for r in extract(evtx, event_id, record_ids, ps_script):
            r['_source_channel'] = filename
            events.append(r)

    events.sort(key=lambda r: (r['timestamp'], r['record_id'], r['_source_channel']))
    if len({(e['_source_channel'], e['record_id']) for e in events}) != len(events):
        raise RuntimeError(f'{cid}: Duplicate source channel and record ID')

    # Keep the same JSON schema the Week-2 Windows parser accepts.
    sources = [e.pop('_source_channel') for e in events]
    for i, e in enumerate(events, 1):
        e['evidence_id'] = f'E{i:03d}'

    if cid == 'BT-01':
        for e in events:
            d = e['event_data']
            if not (d.get('Image', '').lower().endswith('\\mscorsvw.exe') and
                    d.get('ParentImage', '').lower().endswith('\\ngen.exe')):
                raise RuntimeError('BT-01 unexpected process/parent image')
    if cid == 'BT-02':
        for e in events:
            d = e['event_data']
            if e['event_id'] == 4624 and not (
                str(d.get('LogonType')) == '5' and d.get('TargetUserName', '').upper() == 'SYSTEM'
            ):
                raise RuntimeError('BT-02 unexpected service logon attributes')
            if e['event_id'] == 4672 and d.get('SubjectUserName', '').upper() != 'SYSTEM':
                raise RuntimeError('BT-02 unexpected special-privileges account')
    if cid == 'BT-03':
        for e in events:
            d = e['event_data']
            if not d.get('param1') or d.get('param2', '').lower() not in ('stopped', 'running'):
                raise RuntimeError('BT-03 unexpected service state fields')

    case_dir.mkdir(parents=True, exist_ok=True)
    # Temporary write; verify the real parser BEFORE installing final output.
    with tempfile.NamedTemporaryFile(
        'w', encoding='utf-8', suffix='.json', prefix=f'{cid}-verify-',
        dir=case_dir, delete=False
    ) as f:
        tmp_path = Path(f.name)
        json.dump(events, f, ensure_ascii=False, indent=2)

    try:
        parsed = load_file(str(tmp_path))
        if len(parsed['events']) != len(events) or parsed['source_type'] != 'windows' or parsed['warnings']:
            raise RuntimeError(f'{cid}: Parser mismatch: ' + repr(
                (len(parsed['events']), parsed['source_type'], parsed['warnings'])))
        mapping = []
        for e, pe, channel in zip(events, parsed['events'], sources):
            if (str(e['event_id']) != str(pe['event_id']) or
                    e['computer'] != pe['host'] or not pe['ref']):
                raise RuntimeError(f'{cid}: Parser event identity mismatch')
            for key, value in e['event_data'].items():
                if pe['fields'].get('event_data.' + key) != value:
                    raise RuntimeError(f'{cid}: Parser lost field {key}')
            mapping.append({
                'source_channel': channel, 'source_record_id': e['record_id'],
                'evidence_ref': pe['ref'], 'event_id': e['event_id'],
                'timestamp_utc': e['timestamp'], 'computer': e['computer'],
            })
        tmp_path.replace(json_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    with mapping_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(mapping[0]))
        writer.writeheader()
        writer.writerows(mapping)

    manifest = {
        'test_id': cid,
        'classification': 'BENIGN CANDIDATE — analyst review needed; not confirmed clean',
        'scenario': case['scenario'],
        'dataset_repository': 'NextronSystems/evtx-baseline',
        'dataset_release': 'v0.8.5',
        'source_archive': 'win2022-evtx.tgz',
        'source_archive_sha256_local': digest(ROOT / 'win2022-evtx.tgz'),
        'source_evtx_files': files,
        'focused_json_sha256': digest(json_path),
        'events': len(events),
        'event_id_distribution': dict(Counter(str(e['event_id']) for e in events)),
        'parser_check': 'PASS',
        'mapping_file': mapping_path.name,
        'limitations': [
            'Baseline source does not prove each event is benign.',
            'This is a small hand-selected candidate test, not a measured population-level false-positive rate.',
            'Do not infer authorized activity or absence of malicious behavior without supporting context.'
        ],
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')

    print(f'\n=== {cid} / {case["scenario"]} ===')
    print(f'Events: {len(events)} | Event IDs: {dict(Counter(e["event_id"] for e in events))}')
    print('Parser: PASS | Evidence mapping: PASS')
    for m in mapping:
        print(f'  {m["evidence_ref"]} <- Record {m["source_record_id"]} (Event {m["event_id"]})')
    print('Focused JSON:', json_path)
    print('Mapping CSV:', mapping_path)
    print('Manifest:', manifest_path)


def main():
    if os.name != 'nt':
        raise RuntimeError('This script must run on the Windows machine with Get-WinEvent.')
    try:
        from Core.log_parser import load_file
    except ImportError as e:
        raise RuntimeError('Run from the Week-2 project directory.') from e
    archive = ROOT / 'win2022-evtx.tgz'
    if not archive.is_file():
        raise FileNotFoundError(f'Expected downloaded baseline archive: {archive}')
    # Check all outputs beforehand: existing files are never overwritten.
    for case in CASES:
        cid = case['id']
        for name in (f'{cid}-focused.json', f'{cid}-evidence-mapping.csv', f'{cid}-source-manifest.json'):
            output = ROOT / cid / name
            if output.exists():
                raise RuntimeError(f'STOP: Existing file not overwritten: {output}')
    with tempfile.TemporaryDirectory(prefix='bt-prepare-') as d:
        ps_script = Path(d) / 'extract_by_event.ps1'
        ps_script.write_text(PS_EXTRACT, encoding='utf-8-sig')
        print('=== BENIGN CANDIDATE PREPARATION ===')
        for case in CASES:
            make_case(case, ps_script, load_file)
    print('\nSTATUS: THREE CANDIDATE DATASETS READY FOR ANALYST REVIEW')
    print('No model inference performed; no application code or prior results modified.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAIL:', exc, file=sys.stderr)
        sys.exit(1)
