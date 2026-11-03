r"""Guarded patch: add Zeek source/destination attribution review requests.

Run from the Week-2 root:
 python .\SOC_Network_Semantic_v2\upgrade.py --check
 python .\SOC_Network_Semantic_v2\upgrade.py --install
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
MODULE = ROOT / 'Core' / 'network_grounding.py'
NEW_MODULE = ROOT / 'Core' / 'network_semantics.py'
NEW_TESTS = ROOT / 'Testing' / 'test_network_semantics.py'
EXPECTED_BASE = '05a516c0d87d3f0558baea4c5f4e38e1b8a785a90c142b3134c2c175ad587e6e'
TESTS_ADDED = 27


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes):
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix='.netsem-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def run_tests():
    cmd = [sys.executable, '-m', 'unittest', 'discover', '-s', 'Testing', '-p', 'test*.py', '-q']
    process = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True,
                             errors='replace', timeout=240)
    logs = (process.stdout + '\n' + process.stderr).strip()
    matches = re.findall(r'Ran\s+(\d+)\s+tests?', logs)
    count = int(matches[-1]) if matches else -1
    return process.returncode, count, '\n'.join(logs.splitlines()[-14:])


def preflight():
    if not (ROOT / 'app.py').is_file() or not MODULE.is_file():
        raise RuntimeError('Run from the Week-2 project root with Network Grounding v1 installed')
    if NEW_MODULE.exists() or NEW_TESTS.exists():
        raise RuntimeError('STOP: Network Semantic v2 module or tests already exist: no overwrite')
    old = MODULE.read_bytes()
    digest = sha(old)
    if digest != EXPECTED_BASE:
        raise RuntimeError('STOP: Unknown/customized Core/network_grounding.py SHA256 ' + digest +
                           '; do not force this patch; send its content for compatibility review')
    text = old.decode('utf-8-sig')
    first, second = 'import re\n', '    return flags\n'
    if text.count(first) != 1 or text.count(second) != 1:
        raise RuntimeError('STOP: Expected exact patch anchors missing or ambiguous')
    text = text.replace(first, 'from Core import network_semantics\nimport re\n', 1)
    text = text.replace(second, '    flags.extend(network_semantics.review_requests(sections, events))\n    return flags\n', 1)
    ast.parse(text, str(MODULE))
    for rel in ('Core/network_semantics.py', 'Testing/test_network_semantics.py'):
        payload = HERE / 'payload' / rel
        if not payload.is_file():
            raise RuntimeError('Package incomplete: ' + str(payload))
        ast.parse(payload.read_text(encoding='utf-8'), str(payload))
    return old, digest, text.encode('utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    x = p.add_mutually_exclusive_group(required=True)
    x.add_argument('--check', action='store_true')
    x.add_argument('--install', action='store_true')
    args = p.parse_args()
    print('=== NT-01 NETWORK SEMANTIC ATTRIBUTION V2 ===', flush=True)
    old, original_digest, patch = preflight()
    print('Baseline SHA256:', original_digest, flush=True)
    print('Patch compatibility: PASS', flush=True)
    print('WOULD PATCH: Core/network_grounding.py', flush=True)
    print('WOULD CREATE: Core/network_semantics.py; Testing/test_network_semantics.py', flush=True)
    print(f'Additional isolated regression tests: {TESTS_ADDED}', flush=True)
    print('Data / original logs / Results / saved reviews: UNCHANGED', flush=True)
    if args.check:
        print('STATUS: READY FOR GUARDED NETWORK SEMANTIC PATCH (NO CHANGES MADE)', flush=True)
        return
    print('\n=== PRE-INSTALL REGRESSION ===', flush=True)
    rc, before, tail = run_tests()
    print(tail, flush=True)
    if rc != 0 or before < 196:
        raise RuntimeError(f'Existing regression failure or unexpected count: rc={rc} tests={before}')
    if sha(MODULE.read_bytes()) != original_digest or NEW_MODULE.exists() or NEW_TESTS.exists():
        raise RuntimeError('Files changed during preflight; refusing install')
    backup = ROOT / 'Feedback-Backups' / ('Network-Semantic-v2-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')) / 'Core' / 'network_grounding.py'
    backup.parent.mkdir(parents=True, exist_ok=False)
    shutil.copy2(MODULE, backup)
    print('Backup:', backup, flush=True)
    created = []
    patched = False
    try:
        for rel, dest in (('Core/network_semantics.py', NEW_MODULE), ('Testing/test_network_semantics.py', NEW_TESTS)):
            with dest.open('xb') as output:
                created.append(dest)
                output.write((HERE / 'payload' / rel).read_bytes())
        atomic_write(MODULE, patch)
        patched = True
        print('\n=== POST-INSTALL REGRESSION ===', flush=True)
        rc, after, tail = run_tests()
        print(tail, flush=True)
        if rc != 0 or after != before + TESTS_ADDED:
            raise RuntimeError(f'Post-install regression not clean: before={before}, after={after}, rc={rc}')
    except BaseException:
        print('INSTALL ERROR: restoring code and removing created files', flush=True)
        if patched:
            atomic_write(MODULE, backup.read_bytes())
        for path in created:
            path.unlink(missing_ok=True)
        raise
    print(f'Full regression: PASS {before} -> {after}', flush=True)
    print('Original evidence / Results / human reviews: UNCHANGED', flush=True)
    print('STATUS: NETWORK SEMANTIC V2 INSTALLED', flush=True)
    print('NEXT: python -m SOC_Network_Semantic_v2.demo --replay AN-20261020-013537-8c86', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('STOP:', str(exc), file=sys.stderr)
        sys.exit(1)
