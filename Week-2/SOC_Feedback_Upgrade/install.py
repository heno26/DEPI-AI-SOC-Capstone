r"""Guarded installation of human-feedback prompts and semantic-review checks.

Run from Week-2 project ROOT:
  python .\SOC_Feedback_Upgrade\install.py --check
  python .\SOC_Feedback_Upgrade\install.py --install

--check is non-mutating. --install backs up code, adds only bounded hooks, runs
full regression, then creates a human-gated knowledge base. No data or saved
analyses/reviews are modified.
"""
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

from sync_feedback import refresh

ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / 'payload'
ANALYSIS = ROOT / 'Core' / 'analysis.py'
VALIDATOR = ROOT / 'Core' / 'validator.py'
CREATED = [
    ROOT / 'Core' / 'feedback_semantics.py',
    ROOT / 'Core' / 'feedback_learning.py',
    ROOT / 'Testing' / 'test_feedback_semantics.py',
    ROOT / 'Prompts' / 'Validated-SOC-Lessons.json',
]
ANALYSIS_ANCHOR = '    reference = log_parser.reference_notes(events)\n'
ANALYSIS_HOOK = (
    '    # Curated, case-matched rules; never raw analyst feedback.\n'
    '    from Core import feedback_learning\n'
    '    if task in ("log_analysis", "alert_triage"):\n'
    '        reference.extend(feedback_learning.prompt_guidance(events))\n'
)
ANALYSIS_AUDIT = (
    '    # Prompt provenance records the reviewed feedback KB fingerprint.\n'
    '    record["prompt"]["feedback"] = feedback_learning.feedback_audit(events)\n'
)
VAL_ANCHOR = '    for i, f in enumerate(F.items, 1):\n'
VAL_HOOK = (
    '    # Human-review requests for Linux command/IP/outcome contradictions.\n'
    '    from Core import feedback_semantics\n'
    '    feedback_semantics.add_review_requests(F, sections, events)\n'
)
DOMAIN_ANCHOR = '                vals = [v for v in vals if not any(v in u for u in found["url"])]\n'
DOMAIN_HOOK = (
    '                from Core import feedback_semantics\n'
    '                vals = [v for v in vals if not feedback_semantics.is_service_unit_domain(v, ev["raw"])]\n'
)
RISK_ANCHOR = '    return out\n\n\ndef benign_context(events):'
RISK_HOOK = (
    '    # Source-derived investigation signals; not evidence of proven attack success.\n'
    '    from Core import feedback_semantics\n'
    '    out.extend(feedback_semantics.additional_risk_signals(events))\n'
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_one(text, anchor, insert, *, before=False):
    if text.count(anchor) != 1:
        raise RuntimeError(f'Expected one patch anchor, got {text.count(anchor)}: {anchor[:65]!r}')
    return text.replace(anchor, (insert + anchor) if before else (anchor + insert), 1)


def patch_plan():
    for required in (ROOT/'app.py', ROOT/'Testing'/'test_week2.py', ANALYSIS, VALIDATOR,
                     ROOT/'Core'/'log_parser.py', ROOT/'Prompts'/'log_analysis.txt'):
        if not required.is_file():
            raise RuntimeError(f'Missing required project file: {required}')
    for p in CREATED:
        if p.exists():
            raise RuntimeError(f'STOP: Existing installation/customization would be overwritten: {p}')
    for relative in ('Core/feedback_semantics.py','Core/feedback_learning.py','Testing/test_feedback_semantics.py'):
        p = PAYLOAD / relative
        if not p.is_file():
            raise RuntimeError(f'Upgrade payload missing: {p}')
        ast.parse(p.read_text(encoding='utf-8'), str(p))
    a = ANALYSIS.read_text(encoding='utf-8-sig')
    v = VALIDATOR.read_text(encoding='utf-8-sig')
    if 'feedback_semantics.add_review_requests' in v or 'feedback_learning.prompt_guidance' in a:
        raise RuntimeError('Feedback hooks are already installed; refusing duplicate patch.')
    a = replace_one(a, ANALYSIS_ANCHOR, ANALYSIS_HOOK)
    a = replace_one(a, '    flags = list(extra_flags)\n', ANALYSIS_AUDIT, before=True)
    v = replace_one(v, VAL_ANCHOR, VAL_HOOK, before=True)
    v = replace_one(v, DOMAIN_ANCHOR, DOMAIN_HOOK)
    v = replace_one(v, RISK_ANCHOR, RISK_HOOK, before=True)
    ast.parse(a, str(ANALYSIS)); ast.parse(v, str(VALIDATOR))
    return {ANALYSIS:a.encode('utf-8'), VALIDATOR:v.encode('utf-8')}


def atomic_bytes(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.soc-fix-')
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(contents)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def suite():
    proc = subprocess.run([sys.executable,'-m','unittest','discover', '-s','Testing',
                           '-p','test*.py','-q'], cwd=ROOT, capture_output=True,
                          text=True, errors='replace', timeout=240)
    output = (proc.stdout + '\n' + proc.stderr).strip()
    m = re.search(r'Ran\s+(\d+)\s+tests?', output)
    count = int(m.group(1)) if m else 0
    return count, proc.returncode, '\n'.join(output.splitlines()[-16:])


def install(minimum):
    print('=== SOC FEEDBACK UPGRADE SAFE INSTALLER ===', flush=True)
    patch = patch_plan()  # Fail closed before making *any* changes.
    print('Patch compatibility: PASS; original files:', flush=True)
    for p in patch:
        print(' ',p.relative_to(ROOT), 'sha256=', digest(p), flush=True)
    print('Running pre-install regression...',flush=True)
    before, code, summary = suite()
    print(summary, flush=True)
    if code != 0 or before < minimum:
        raise RuntimeError(f'Baseline tests failed or fewer than {minimum} tests ({before}). No files changed.')

    backup = ROOT/'Feedback-Backups'/('install-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
    if backup.exists():
        raise RuntimeError('Backup destination collision')
    for p in patch:
        target = backup / p.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, target)
    print('Backup:',backup,flush=True)
    made = []
    changed = []
    try:
        for p, new in patch.items():
            atomic_bytes(p, new)
            changed.append(p)
        for relative in ('Core/feedback_semantics.py','Core/feedback_learning.py','Testing/test_feedback_semantics.py'):
            src = PAYLOAD / relative
            dest = ROOT / relative
            with dest.open('xb') as f:
                made.append(dest)
                f.write(src.read_bytes())
        print('Running entire regression suite with new tests...',flush=True)
        after, returncode, summary = suite()
        print(summary,flush=True)
        if returncode != 0 or after < before + 24 or after < minimum + 24:
            raise RuntimeError(f'Regression failed or new tests missing: before {before}, after {after}, rc={returncode}')
        # Curated review feedback is refreshed only after *successful* regression.
        from sync_feedback import refresh
        refresh(ROOT)
    except BaseException:
        print('INSTALL FAILED: restoring original Core files...',flush=True)
        for p in changed:
            atomic_bytes(p, (backup/p.relative_to(ROOT)).read_bytes())
        for p in made:
            p.unlink(missing_ok=True)
        # Do not remove an existing KB the user may have created independently.
        print('ROLLBACK: original Core restored; generated module/test removed.',flush=True)
        raise
    print('Full regression: PASS', before, '->', after,flush=True)
    print('Core code backups: PRESERVED',flush=True)
    print('Data, Results, saved AI analyses/reviews: UNCHANGED',flush=True)
    print('STATUS: SOC FEEDBACK UPGRADE INSTALLED',flush=True)
    print('Next: python .\\SOC_Feedback_Upgrade\\replay_validation.py AN-20261018-231218-e901',flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--check', action='store_true', help='Read-only compatibility and file collision check')
    p.add_argument('--install', action='store_true', help='Back up, install, run regression, sync reviewed lessons')
    p.add_argument('--minimum-existing-tests', type=int, default=113,
                   help='Require >= this many passing tests before install (default 113)')
    args = p.parse_args()
    if args.install == args.check:
        p.error('Choose exactly one of --check or --install')
    if args.check:
        patch = patch_plan()
        print('=== READ-ONLY UPGRADE PREFLIGHT ===')
        print('Project:',ROOT)
        print('Core patch anchors: PASS')
        for file in patch:
            print('WOULD PATCH:',file.relative_to(ROOT))
        for file in CREATED:
            print('WOULD CREATE:',file.relative_to(ROOT))
        refresh(ROOT, dry_run=True)
        print('STATUS: READY FOR GUARDED INSTALL (NO CHANGES MADE)')
    else:
        install(args.minimum_existing_tests)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('STOP:',repr(exc),file=sys.stderr)
        sys.exit(1)
