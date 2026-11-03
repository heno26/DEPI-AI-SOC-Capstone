"""Safely extend Windows Event Log recognition to Service Control Manager,
then finish only BT-03. Requires BT_Prepare_3_Cases.py in Week-2 root.

Never modifies BT-01 / BT-02, original EVTX, baseline archive or AI results.
"""
import ast
import importlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import BT_Prepare_3_Cases as prep
from Core import log_parser

CORE = Path('Core/log_parser.py')
TEST = Path('Testing/test_bt03_service_control_manager.py')
CASE = next(c for c in prep.CASES if c['id'] == 'BT-03')
EXACT_OLD = 'and ("microsoft-windows-" in provider or "sysmon" in provider)'
EXACT_NEW = 'and ("microsoft-windows-" in provider or "sysmon" in provider or provider == "service control manager")'
BACKUPS = Path('BT-Backups')

TEST_CODE = '''"""Regression: Windows Service Control Manager EVTX conversion."""
import unittest
from Core import log_parser


class TestBT03SystemProvider(unittest.TestCase):
    def example(self, provider='Service Control Manager'):
        return {
            'timestamp': '2022-04-04T14:11:47.8527230Z',
            'event_id': 7036, 'record_id': 1862,
            'provider': provider, 'computer': 'WIN-TKC15D7KHUR',
            'event_data': {'param1': 'Software Protection', 'param2': 'running'},
        }

    def test_service_control_manager_is_windows(self):
        e = log_parser._event_from_json(self.example(), 'E001', 1)
        self.assertEqual(e['source_kind'], 'windows')
        self.assertEqual(str(e['event_id']), '7036')
        self.assertEqual(e['host'], 'WIN-TKC15D7KHUR')
        self.assertEqual(e['fields']['event_data.param1'], 'Software Protection')

    def test_unrelated_generic_provider_stays_generic(self):
        e = log_parser._event_from_json(self.example('Unrelated Provider'), 'E001', 1)
        self.assertEqual(e['source_kind'], 'generic')

    def test_wazuh_precedence_preserved(self):
        data = self.example()
        data['rule'] = {'id': '100001', 'level': 3}
        e = log_parser._event_from_json(data, 'E001', 1)
        self.assertEqual(e['source_kind'], 'wazuh')


if __name__ == '__main__':
    unittest.main()
'''


def stop(msg):
    raise RuntimeError(msg)


def main():
    print('=== BT-03 SAFE PARSER FIX + CASE PREPARATION ===', flush=True)
    if not CORE.is_file() or not Path('Testing').is_dir():
        stop('Run from D:\\Desktop\\w\\Week-2; project files not found.')
    if not Path('BT_Prepare_3_Cases.py').is_file():
        stop('Missing original BT_Prepare_3_Cases.py in Week-2 root.')
    if TEST.exists():
        stop('Permanent BT-03 regression test already exists; no overwrite.')
    for cid, count in (('BT-01', 6), ('BT-02', 4)):
        p = prep.ROOT / cid / f'{cid}-focused.json'
        if not p.is_file():
            stop(f'Missing previously prepared {cid} dataset: {p}')
        result = log_parser.load_file(str(p))
        if len(result['events']) != count or result['source_type'] != 'windows' or result['warnings']:
            stop(f'Previously prepared {cid} dataset failed verification.')
    target = prep.ROOT / 'BT-03' / 'BT-03-focused.json'
    if target.exists() or any((prep.ROOT / 'BT-03' / name).exists() for name in (
        'BT-03-evidence-mapping.csv', 'BT-03-source-manifest.json')):
        stop('Existing BT-03 output detected; no files overwritten.')

    with tempfile.TemporaryDirectory(prefix='bt03-verify-') as d:
        script = Path(d) / 'extract.ps1'
        script.write_text(prep.PS_EXTRACT, encoding='utf-8-sig')
        filename, event_id, record_ids = CASE['selections'][0]
        records = prep.extract(prep.CHANNELS / filename, event_id, record_ids, script)
        providers = {str(e['provider']).lower() for e in records}
        print('Original providers:', ', '.join(sorted(providers)), flush=True)
        if providers != {'service control manager'}:
            stop('Unexpected original provider; stop and inspect instead of guessing.')
        kinds = {log_parser._event_from_json(e, '', 1)['source_kind'] for e in records}
        print('Before fix: event source kinds =', kinds, flush=True)
        if kinds != {'generic'}:
            stop('Unexpected parser behavior; manual review needed.')

    before = CORE.read_text(encoding='utf-8-sig')
    if before.count(EXACT_OLD) != 1:
        stop('Parser logic differs from expected; no file changed.')
    updated = before.replace(EXACT_OLD, EXACT_NEW, 1)
    ast.parse(updated)
    ast.parse(TEST_CODE)
    BACKUPS.mkdir(exist_ok=True)
    backup = BACKUPS / ('log_parser-before-BT03-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.py')
    if backup.exists():
        stop('Backup collision; no file changed.')
    shutil.copy2(CORE, backup)
    print('Backup:', backup, flush=True)

    installed = False
    try:
        CORE.write_text(updated, encoding='utf-8')
        installed = True
        TEST.write_text(TEST_CODE, encoding='utf-8')
        importlib.invalidate_caches()
        importlib.reload(log_parser)

        # Verify the six *actual* extracted records via the project's parser.
        with tempfile.TemporaryDirectory(prefix='bt03-parser-') as d:
            sample = Path(d) / 'service_control_manager.json'
            sample.write_text(json.dumps(records, indent=2), encoding='utf-8')
            parsed = log_parser.load_file(str(sample))
            assert len(parsed['events']) == 6
            assert parsed['source_type'] == 'windows' and not parsed['warnings']
            for rec, ev in zip(records, parsed['events']):
                assert ev['source_kind'] == 'windows'
                assert str(rec['event_id']) == str(ev['event_id'])
                assert rec['computer'] == ev['host']
                for key, value in rec['event_data'].items():
                    assert ev['fields'].get('event_data.' + key) == value
        print('BT-03 real-record parser verification: PASS', flush=True)
        for cid, count in (('BT-01', 6), ('BT-02', 4)):
            p = prep.ROOT / cid / f'{cid}-focused.json'
            result = log_parser.load_file(str(p))
            assert len(result['events']) == count and result['source_type'] == 'windows'
        print('BT-01 and BT-02 unaffected: PASS', flush=True)

        print('Running full permanent regression suite...', flush=True)
        result = subprocess.run(
            [sys.executable, '-m', 'unittest', 'discover', '-s', 'Testing', '-p', 'test*.py', '-q'],
            capture_output=True, text=True, errors='replace', timeout=180,
        )
        report = (result.stdout + '\n' + result.stderr).strip()
        print('\n'.join(report.splitlines()[-14:]), flush=True)
        if result.returncode != 0 or 'FAILED' in report:
            stop('Full regression suite failed; rolling back parser and new test.')
        print('Full regression: PASS', flush=True)
    except BaseException:
        if installed:
            shutil.copy2(backup, CORE)
            if TEST.exists():
                TEST.unlink()
            print('ROLLBACK: Parser restored and new test removed. Original datasets unchanged.', flush=True)
        raise

    # Run ONLY BT-03; do not rerun prep.main() because BT-01/BT-02 exist.
    with tempfile.TemporaryDirectory(prefix='bt03-prepare-') as d:
        ps_script = Path(d) / 'extract.ps1'
        ps_script.write_text(prep.PS_EXTRACT, encoding='utf-8-sig')
        prep.make_case(CASE, ps_script, log_parser.load_file)

    final = log_parser.load_file(str(target))
    if final['source_type'] != 'windows' or len(final['events']) != 6 or final['warnings']:
        stop('BT-03 output verification failed; do not analyze.')
    print('\nBT-01: READY | BT-02: READY | BT-03: READY', flush=True)
    print('STATUS: THREE CANDIDATE DATASETS READY FOR ANALYST REVIEW', flush=True)
    print('Original EVTX and BT-01/BT-02 outputs preserved.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('FAIL:', repr(exc), file=sys.stderr, flush=True)
        sys.exit(1)
