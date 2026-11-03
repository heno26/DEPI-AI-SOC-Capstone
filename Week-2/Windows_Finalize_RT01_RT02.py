"""Close missing RT-01 and RT-02 Windows attack documentation.

Run from D:\\Desktop\\w\\Week-2 with Python on Windows:
    python .\\Windows_Finalize_RT01_RT02.py

Creates only missing verified timelines, RT-02 case study, and a provenance manifest.
Original EVTX, mappings, focused JSON, saved AI analyses/reviews and project code
are read-only. Uses Get-WinEvent to verify events against the original EVTX.
"""
import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ATTACK_ROOT = Path('Data/Real-Datasets/Windows-Attacks')
RESULTS = Path('Results')
DOCUMENTATION = Path('Documentation/Windows')

CASES = {
    'RT-01': {
        'folder': ATTACK_ROOT / 'RT-01-C2',
        'evtx': 'DE_sysmon-3-rdp-tun.evtx',
        'dataset': 'RT-01-C2-plink-focused.json',
        'mapping': 'RT-01-C2-evidence-mapping.csv',
        'analysis_id': 'AN-20261017-222659-f35b',
        'review_status': 'corrected',
        'pairs': [('E003', 'E001', 1940899, 1),
                  ('E004', 'E002', 1940900, 3),
                  ('E005', 'E003', 1940901, 3),
                  ('E023', 'E004', 1940919, 3)],
        'timeline': 'RT-01-Verified-Timeline.csv',
    },
    'RT-02': {
        'folder': ATTACK_ROOT / 'RT-02-Discovery',
        'evtx': 'discovery_psloggedon.evtx',
        'dataset': 'RT-02-Discovery-focused-v2.json',
        'mapping': 'RT-02-evidence-mapping.csv',
        'analysis_id': 'AN-20261018-002643-c097',
        'review_status': 'approved',
        'pairs': [('E001', 'E001', 32950, 1102),
                  ('E002', 'E002', 32951, 5145),
                  ('E003', 'E003', 32952, 5145),
                  ('E004', 'E004', 32953, 5145)],
        'timeline': 'RT-02-Verified-Timeline.csv',
        'study': 'RT-02-Case-Study.md',
    },
}

# PowerShell emits ONLY a single base64 JSON line so messages / Unicode cannot
# interfere with Python parsing. XML TimeCreated.SystemTime retains full precision.
PS_VERIFY = r'''param([string]$EvtxPath, [string]$RecordIdsCsv)
$ErrorActionPreference = 'Stop'
$requested = @{}
foreach ($part in ($RecordIdsCsv -split ',')) { $requested[[long]$part] = $true }
$found = [System.Collections.Generic.List[object]]::new()
Get-WinEvent -Path $EvtxPath -Oldest -ErrorAction Stop | ForEach-Object {
    if ($requested.ContainsKey([long]$_.RecordId)) {
        $e = $_
        [xml]$x = $e.ToXml()
        $fields = [ordered]@{}
        $index = 0
        foreach ($n in $x.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
            $index++
            $key = $n.GetAttribute('Name')
            if (-not $key) { $key = "param$index" }
            $fields[$key] = $n.InnerText
        }
        foreach ($n in $x.SelectNodes("//*[local-name()='UserData']//*[not(*)]")) {
            $fields[$n.LocalName] = $n.InnerText
        }
        $found.Add([ordered]@{
            record_id = [long]$e.RecordId
            event_id = [int]$e.Id
            timestamp = [string]$x.Event.System.TimeCreated.SystemTime
            computer = [string]$x.Event.System.Computer
            provider = [string]$x.Event.System.Provider.Name
            event_data = $fields
        })
    }
}
$json = ConvertTo-Json -InputObject @($found.ToArray()) -Depth 35 -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
'''


def require(ok, error):
    if not ok:
        raise RuntimeError(error)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def time_value(raw):
    # Python accepts seven-digit .NET fractions, discarding only the 7th digit.
    return datetime.fromisoformat(str(raw).strip().replace('Z', '+00:00'))


def timestamp_matches(left, right):
    a, b = time_value(left), time_value(right)
    require(a.tzinfo is not None and b.tzinfo is not None, 'Timestamp missing timezone')
    return abs((a - b).total_seconds()) < 0.001


def check_event_against(ev, ref, record_id, event_id, host, time):
    require(int(ev['record_id']) == record_id, f'{ref}: RecordId mismatch')
    require(int(ev['event_id']) == event_id, f'{ref}: Event ID mismatch')
    require(str(ev['computer']).lower() == str(host).lower(), f'{ref}: Host mismatch')
    require(timestamp_matches(ev['timestamp'], time), f'{ref}: Timestamp mismatch')


def read_evtx(path, record_ids, ps_path):
    cmd = ['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
           str(ps_path.resolve()), '-EvtxPath', str(path.resolve()),
           '-RecordIdsCsv', ','.join(map(str, record_ids))]
    proc = subprocess.run(cmd, text=True, capture_output=True, errors='replace', timeout=180)
    require(proc.returncode == 0, 'Get-WinEvent verification failed:\n' + proc.stderr[-1400:])
    lines = [s.strip() for s in proc.stdout.splitlines() if s.strip()]
    require(len(lines) == 1, 'Unexpected Get-WinEvent output; aborting')
    try:
        events = json.loads(base64.b64decode(lines[0], validate=True).decode('utf-8'))
    except Exception as e:
        raise RuntimeError('Could not decode original EVTX events') from e
    require(isinstance(events, list) and len(events) == len(record_ids),
            'Original EVTX did not return expected number of events')
    require({int(e['record_id']) for e in events} == set(record_ids),
            'Original EVTX Record IDs do not match focused input')
    return {int(e['record_id']): e for e in events}


def describe(event):
    eid, data = int(event['event_id']), event.get('event_data') or {}
    if eid == 1:
        return 'Sysmon process creation: ' + str(data.get('Image', 'image not supplied'))
    if eid == 3:
        ip = data.get('DestinationIp', 'unknown IP')
        port = data.get('DestinationPort', 'unknown port')
        return f'Sysmon network connection event: destination {ip}:{port}'
    if eid == 1102:
        user = data.get('SubjectUserName', 'unspecified account')
        return f'Windows Security audit log cleared (Event 1102); account: {user}'
    if eid == 5145:
        target = data.get('RelativeTargetName', 'unknown target')
        origin = data.get('IpAddress', 'unknown address')
        return f'Network share access check (Event 5145): {target}, source {origin}'
    return f'Windows Event ID {eid}'


def csv_content(rows):
    buf = io.StringIO(newline='')
    headers = ['timestamp_utc', 'event_id', 'record_id', 'host', 'source_provider',
               'event_summary', 'original_ref', 'parsed_ref', 'timestamp_validation']
    w = csv.DictWriter(buf, fieldnames=headers, lineterminator='\n')
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def md_value(s):
    return str(s).replace('|', r'\|').replace('\n', ' ').replace('\r', ' ')


def rt02_case_study(cfg, records, hashes):
    refmap = {r['original_ref']: r for r in records}
    audit = refmap['E001']
    rows = [f"| {md_value(r['timestamp_utc'])} | {r['event_id']} | {r['record_id']} | "
            f"{md_value(r['event_summary'])} | {r['original_ref']} / {r['parsed_ref']} |"
            for r in records]
    return ('# RT-02 — Windows Discovery / IPC$ Access Checks\n\n'
            '**Status:** Evidence-verified case documentation; human review **Approved**.  '
            '**Dataset type:** Recorded lab Windows events, not production telemetry.\n\n'
            '## Scope and source\n\n'
            f'- Original EVTX: `{cfg["evtx"]}` (SHA-256: `{hashes["evtx_sha256"]}`).\n'
            f'- Corrected focused JSON: `{cfg["dataset"]}` (SHA-256: `{hashes["focused_sha256"]}`).\n'
            f'- Original-to-parsed evidence mapping: `{cfg["mapping"]}`.\n'
            f'- Saved AI analysis: `{cfg["analysis_id"]}`; original analysis and human review unchanged.\n'
            '- Four selected events were independently matched back to the original EVTX by '
            'Record ID, Event ID, host and original XML timestamp (< 1 ms tolerance).\n\n'
            '## Verified evidence timeline (UTC)\n\n'
            '| Original XML timestamp | Event ID | Record ID | Observation | Original / parsed evidence |\n'
            '|---|---:|---:|---|---|\n' + '\n'.join(rows) + '\n\n'
            '## Evidence-supported findings\n\n'
            f'- [{audit["original_ref"]}] Event ID **1102** records that the Windows Security audit log was cleared. '
            'This is **not** an administrator logon event.\n'
            '- [E002–E004] Event ID **5145** records network share access **checks** for IPC$ named-pipe paths '
            'including `winreg`, `lsarpc`, and `srvsvc` from an internal address, as present in the source events.\n'
            '- Event ID 5145 does not, by itself, prove successful remote execution, reading/modification of '
            'system files, unauthorized access or lateral movement.\n'
            '- This small window does not establish a causal relationship between the log-clear event and the '
            'subsequent access checks.\n\n'
            '## Analyst disposition and limitations\n\n'
            '- Human review of the saved AI report: **Approved**. This approves the reviewed interpretation, '
            '**not** the activity as proven benign.\n'
            '- **Intent/authorization:** Undetermined from four selected events.\n'
            '- **Recommended follow-up:** Correlate authentication/session logs and IPC$ access checks, '
            'verify the source host/account and authorized maintenance, and investigate the audit-log-clear event.\n'
            '- **Reputation:** No external IP or file reputation lookup established by this case.\n\n'
            '## Integrity notes\n\n'
            'Original files and saved AI/human-review artifacts were read-only. '
            'The verified timeline was produced from original EVTX XML timestamps, not AI-generated timestamps.\n')


def prepare_case(cid, cfg, ps_path):
    folder = cfg['folder']
    files = {k: folder / cfg[k] for k in ['evtx', 'dataset', 'mapping']}
    result = RESULTS / cfg['analysis_id'] / 'analysis.json'
    for path in [*files.values(), result]:
        require(path.is_file(), f'{cid}: Missing source {path}')
    data = read_json(files['dataset'])
    require(isinstance(data, list) and len(data) == 4,
            f'{cid}: Expected exactly 4 focused JSON events')
    with files['mapping'].open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        require({'original_ref', 'parsed_ref', 'record_id', 'event_id', 'timestamp'} <=
                set(reader.fieldnames or ()), f'{cid}: Evidence mapping columns mismatch')
        mappings = list(reader)
    require(len(mappings) == 4, f'{cid}: Expected 4 evidence mapping rows')
    analysis = read_json(result)
    review = analysis.get('review', {})
    require(isinstance(review, dict), f'{cid}: No saved review object')
    status = str(review.get('status', '')).lower().strip()
    require(status == cfg['review_status'],
            f'{cid}: Expected review {cfg["review_status"]!r}, got {status!r}')
    expected = {(o, p, rec, eid) for o, p, rec, eid in cfg['pairs']}
    actual = {(r['original_ref'].strip(), r['parsed_ref'].strip(),
               int(r['record_id']), int(r['event_id'])) for r in mappings}
    require(actual == expected, f'{cid}: Mapping original/parsed refs or record IDs changed')
    by_ref = {e.get('evidence_id'): e for e in data}
    require(len(by_ref) == 4 and set(by_ref) == {a for a, _, _, _ in cfg['pairs']},
            f'{cid}: Focused JSON original evidence refs mismatch')
    from_evtx = read_evtx(files['evtx'], [r[2] for r in cfg['pairs']], ps_path)
    rows = []
    for mapping in mappings:
        original_ref = mapping['original_ref']
        event = by_ref[original_ref]
        raw = from_evtx[int(mapping['record_id'])]
        for item in (event, raw):
            check_event_against(item, original_ref, int(mapping['record_id']),
                                int(mapping['event_id']), event['computer'], mapping['timestamp'])
        require(timestamp_matches(event['timestamp'], raw['timestamp']),
                f'{cid}: JSON timestamp does not match source XML')
        # Named-pipe targets and recovered log-clear user need to be identical.
        for key in ('RelativeTargetName', 'IpAddress', 'SubjectUserName'):
            if key in event.get('event_data', {}) and key in raw.get('event_data', {}):
                require(str(event['event_data'][key]) == str(raw['event_data'][key]),
                        f'{cid} {original_ref}: Field {key} mismatch with original EVTX')
        rows.append({
            'timestamp_utc': raw['timestamp'], 'event_id': int(raw['event_id']),
            'record_id': int(raw['record_id']), 'host': raw['computer'],
            'source_provider': raw['provider'], 'event_summary': describe(raw),
            'original_ref': original_ref, 'parsed_ref': mapping['parsed_ref'],
            'timestamp_validation': 'MATCH (<1ms)',
        })
    rows.sort(key=lambda r: (time_value(r['timestamp_utc']), r['record_id']))
    hashes = {key + '_sha256': digest(path) for key, path in files.items()}
    hashes['analysis_json_sha256'] = digest(result)
    # If the stored analysis exposes a direct input SHA-256, require it to match.
    inp = analysis.get('input', {})
    claimed = inp.get('sha256') if isinstance(inp, dict) else None
    if claimed:
        require(str(claimed).lower() == hashes['dataset_sha256'],
                f'{cid}: Saved analysis input hash does not match focused dataset')
    hashes['focused_sha256'] = hashes['dataset_sha256']
    timeline = folder / cfg['timeline']
    outputs = {timeline: csv_content(rows)}
    if cid == 'RT-02':
        outputs[folder / cfg['study']] = rt02_case_study(cfg, rows, hashes)
    return outputs, {
        'case': cid, 'source_files': {str(path): digest(path) for path in [*files.values(), result]},
        'analysis_id': cfg['analysis_id'], 'review_status': status,
        'evidence_count': len(rows), 'xml_verification': 'PASS: Record ID, Event ID, host, UTC timestamp',
        'ref_mapping': [{'original': r['original_ref'], 'parsed': r['parsed_ref']} for r in rows],
        'note': 'Evidence refs can differ between the original and focused data. '
                'RT-01 uses original E003/E004/E005/E023 mapped to E001/E002/E003/E004.',
    }


def main():
    require(os.name == 'nt', 'Run this finalization script on Windows with Get-WinEvent')
    require(Path('app.py').is_file() and Path('Core').is_dir(),
            'Run from the Week-2 project root')
    manifest = DOCUMENTATION / 'RT01-RT02-Finalization-Manifest.json'
    destinations = [cfg['folder'] / cfg['timeline'] for cfg in CASES.values()]
    destinations.append(CASES['RT-02']['folder'] / CASES['RT-02']['study'])
    destinations.append(manifest)
    for p in destinations:
        require(not p.exists(), f'STOP: Destination already exists; no overwrite: {p}')

    with tempfile.TemporaryDirectory(prefix='rt01-rt02-evtx-') as tmp:
        ps = Path(tmp) / 'verify_xml.ps1'
        ps.write_text(PS_VERIFY, encoding='utf-8-sig')
        planned = {}
        provenance = []
        print('=== RT-01 / RT-02 ORIGINAL EVTX VERIFICATION ===', flush=True)
        for cid, cfg in CASES.items():
            files, info = prepare_case(cid, cfg, ps)
            planned.update(files)
            provenance.append(info)
            print(f'{cid}: EVTX Record ID/Event ID/Host/Timestamp PASS; mapping PASS; '
                  f'review {info["review_status"].upper()}', flush=True)

    manifest_body = {
        'purpose': 'Generate only RT-01 and RT-02 missing documentation',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'cases': provenance,
        'outputs': {str(path): hashlib.sha256(data.encode('utf-8')).hexdigest()
                    for path, data in planned.items()},
        'sources_or_prior_results_modified': False,
        'timestamp_tolerance': '< 1 millisecond',
    }
    planned[manifest] = json.dumps(manifest_body, indent=2, ensure_ascii=False) + '\n'
    written = []
    try:
        for path, data in planned.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            # Exclusive create; existing user work will never be replaced.
            with path.open('x', encoding='utf-8', newline='') as f:
                f.write(data)
            written.append(path)
            print('CREATED:', path, flush=True)
    except BaseException:
        # Rollback only NEW files created during this attempt.
        for path in written:
            path.unlink(missing_ok=True)
        raise
    print('\nSTATUS: RT-01 / RT-02 MISSING DOCUMENTATION COMPLETED', flush=True)
    print('Original EVTX, focused JSON, mappings, saved analyses/reviews: UNCHANGED', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAIL:', exc, file=sys.stderr, flush=True)
        sys.exit(1)
