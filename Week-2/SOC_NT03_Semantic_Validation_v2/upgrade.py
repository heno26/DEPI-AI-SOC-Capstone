"""Guarded NT-03 semantic validator v2 installation / read-only replay.

Run from Week-2 root with `python -m SOC_NT03_Semantic_Validation_v2.upgrade --check`
or --install, then --replay AN-20261021-132533-02e7.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
BASELINE = {
    # Exact Core files from reviewed ZIP / guarded NT-03 v1 payload.
    'Core/analysis.py': '6cba1149ae87696f01c2ffa6d3d33bb5dbfe9d379a4e9bc9bd30d4ae2c19adb0',
    'Core/tcp_retry_grounding.py': '81893653999884e021e05a6f865f50aaeda5ed5dbd0e8a437c2e75cac8f09d7d',
    'Core/network_semantics.py': '61dd8e957b05f66984ff0e9c542d4f08e8db4dc20352ef7548de7e86cc25de3d',
    # Not changed but required for integrated review function routing.
    'Core/network_grounding.py': 'af3d62587e29128dca2c8de30c8dc8c92dc235513aac57423aad0e674802f046',
}
PATCH = ('Core/analysis.py', 'Core/tcp_retry_grounding.py', 'Core/network_semantics.py')
TEST = 'Testing/test_nt03_semantic_validation_v2.py'
BASELINE_TESTS = 293
NEW_TESTS = 24
RULE = 'NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE'


def sha256(blob):
    return hashlib.sha256(blob).hexdigest()


def check_compatibility():
    if not (ROOT / 'app.py').is_file() or not (ROOT / 'Testing').is_dir():
        raise RuntimeError('Run commands from Week-2 root (app.py and Testing/ required).')
    unexpected = []
    for rel, expected in BASELINE.items():
        p = ROOT / rel
        if not p.is_file():
            unexpected.append(f'{rel} MISSING')
        elif sha256(p.read_bytes()) != expected:
            unexpected.append(f'{rel} SHA256 MISMATCH')
    if unexpected:
        raise RuntimeError('STOP: Reviewed v1 source differs: ' + '; '.join(unexpected) + '. Do not force patch.')
    if (ROOT / TEST).exists():
        raise RuntimeError(f'STOP: New test file already exists: {TEST}. No overwrite.')
    patches = {}
    for rel in (*PATCH, TEST):
        path = HERE / 'payload' / rel
        if not path.is_file():
            raise RuntimeError('STOP: Patch file missing: ' + str(path))
        data = path.read_bytes()
        import ast
        ast.parse(data.decode('utf-8'), filename=rel)
        patches[rel] = data
    count = len(re.findall(rb'(?m)^    def test_\d+_', patches[TEST]))
    if count != NEW_TESTS:
        raise RuntimeError(f'Unexpected test count {count}; expected {NEW_TESTS}')
    return patches


def regression():
    process = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                              '-s', 'Testing', '-p', 'test*.py', '-q'],
                             cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             timeout=300, text=True, errors='replace')
    matches = re.findall(r'Ran\s+(\d+)\s+tests?', process.stdout)
    count = int(matches[-1]) if matches else -1
    print('\n'.join(process.stdout.strip().splitlines()[-12:]), flush=True)
    return process.returncode, count


def write_atomic(path, blob):
    fd, tmp = tempfile.mkstemp(prefix='.nt03-v2-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(blob)
            target.flush()
            os.fsync(target.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def install(patches):
    print('\n=== PRE-INSTALL REGRESSION ===', flush=True)
    rc, count = regression()
    if rc != 0 or count != BASELINE_TESTS:
        raise RuntimeError(f'STOP: Expected {BASELINE_TESTS} passing tests; got rc={rc}, count={count}. No changes made.')
    # Guard against changes during slow regression.
    check_compatibility()
    backup = ROOT / 'Feedback-Backups' / ('NT03-Semantic-v2-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
    backup.mkdir(parents=True, exist_ok=False)
    for rel in PATCH:
        dst = backup / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)
        if sha256(dst.read_bytes()) != BASELINE[rel]:
            raise RuntimeError('STOP: Backup hash mismatch before patch: ' + rel)
    (backup / 'MANIFEST.json').write_text(json.dumps({
        'sha256_original': {rel: BASELINE[rel] for rel in PATCH},
        'new_test_file': TEST, 'note': 'Rollback of 3 Core files; no original Data/Results/Reviews affected',
    }, indent=2) + '\n', encoding='utf-8')
    print('Verified rollback backup:', backup, flush=True)
    touched, added = [], False
    try:
        check_compatibility()
        for rel in PATCH:
            p = ROOT / rel
            if sha256(p.read_bytes()) != BASELINE[rel]:
                raise RuntimeError('Concurrent modification detected: ' + rel)
            write_atomic(p, patches[rel])
            touched.append(rel)
        with (ROOT / TEST).open('xb') as f:
            added = True
            f.write(patches[TEST])
        for rel, blob in patches.items():
            if sha256((ROOT / rel).read_bytes()) != sha256(blob):
                raise RuntimeError('Installed bytes changed: ' + rel)
        print('\n=== POST-INSTALL REGRESSION ===', flush=True)
        rc, after = regression()
        if rc != 0 or after != BASELINE_TESTS + NEW_TESTS:
            raise RuntimeError(f'Post-install regression failed: rc={rc}, count={after}.')
    except BaseException:
        print('STOP: Install failed; rolling back 3 Core files + new test.', flush=True)
        for rel in reversed(touched):
            write_atomic(ROOT / rel, (backup / rel).read_bytes())
        if added:
            (ROOT / TEST).unlink(missing_ok=True)
        print('Rollback attempted. Backup retained:', backup, flush=True)
        raise
    print(f'REGRESSION: PASS {BASELINE_TESTS} -> {after}', flush=True)
    print('Original logs / Results / Human Reviews: UNCHANGED', flush=True)
    print('STATUS: NT-03 SEMANTIC VALIDATION V2 INSTALLED', flush=True)


def replay(identifier):
    if Path(identifier).name != identifier or not re.fullmatch(r'AN-[\w-]{4,80}', identifier):
        raise RuntimeError('Invalid analysis ID')
    file = ROOT / 'Results' / identifier / 'analysis.json'
    if not file.is_file():
        raise RuntimeError('Saved analysis missing: ' + str(file))
    record = json.loads(file.read_text(encoding='utf-8-sig'))
    if record.get('analysis_id') != identifier:
        raise RuntimeError('Saved analysis ID mismatch')
    src = Path(record['input']['path'])
    if not src.is_absolute():
        src = ROOT / src
    if not src.is_file():
        raise RuntimeError('Original analyzed evidence file missing: ' + str(src))
    if sha256(src.read_bytes()) != record['input']['sha256']:
        raise RuntimeError('Source integrity mismatch: saved input SHA-256')
    from Core import analysis, grounded_detection
    events = record.get('events') or []
    if not events:
        raise RuntimeError('No saved event inputs in analysis')
    raw = (record.get('ai_output') or {}).get('raw_text', '')
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError('No saved model text')
    sections = analysis.parse_sections(raw, analysis.HEADINGS['log_analysis'])
    findings = grounded_detection.detect(events).get('behavioral_findings', [])
    checks = grounded_detection.review_requests(sections, events)
    print('=== NT-03 POST-FIX SEMANTIC REPLAY — READ-ONLY ===')
    print('Analysis:', identifier, '| Source SHA-256: MATCH')
    print('Saved human review:', (record.get('review') or {}).get('status'))
    print('Parsed section count:', len(sections))
    print('Suspicious activities alias:', 'RECOGNIZED' if 'SUSPICIOUS ACTIVITIES' in sections else 'ABSENT')
    print('Grounded retry rule:', 'FOUND' if any(f.get('rule_id') == RULE for f in findings) else 'NOT FOUND')
    print('Network review requests:', len(checks))
    for f in checks:
        print(f"[{f.get('severity')}] {f.get('check')}: {f.get('value')}")
    if any(f.get('rule_id') == RULE for f in findings):
        expected = ('network_tcp_retry_missing_quantification',
                    'network_observed_tcp_data_contradiction',
                    'network_source_port_group_mismatch')
        found = {f.get('check') for f in checks}
        for check in expected:
            print('Target check:', check, 'FOUND' if check in found else 'NOT TRIGGERED')
    print('Saved Results / Human Reviews / Original Evidence / Core: UNCHANGED')
    print('STATUS: NT-03 SEMANTIC REPLAY COMPLETE (READ-ONLY)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--install', action='store_true')
    group.add_argument('--replay', metavar='ANALYSIS_ID')
    opts = parser.parse_args()
    if opts.replay:
        replay(opts.replay)
        return
    print('=== NT-03 SEMANTIC VALIDATION V2 — GUARDED UPGRADE ===', flush=True)
    patches = check_compatibility()
    print('Verified reviewed baseline SHA-256: MATCH (4/4)', flush=True)
    print('WOULD PATCH:', ', '.join(PATCH), flush=True)
    print('WOULD CREATE:', TEST, flush=True)
    print('New regression tests:', NEW_TESTS, flush=True)
    if opts.check:
        print('Core / Data / Results / Human Reviews: UNCHANGED', flush=True)
        print('STATUS: READY FOR GUARDED NT-03 SEMANTIC V2 INSTALL (READ-ONLY PASS)', flush=True)
        return
    install(patches)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('STOP:', exc, file=sys.stderr)
        sys.exit(1)
