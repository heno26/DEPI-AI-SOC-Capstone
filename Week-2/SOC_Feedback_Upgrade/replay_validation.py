r"""Replay NEW semantic checks against a stored analysis without Ollama or writes.

Example from Week-2 root:
  python .\SOC_Feedback_Upgrade\replay_validation.py AN-20261018-231218-e901
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


def main(analysis_id):
    if not analysis_id.startswith('AN-') or '/' in analysis_id or '\\' in analysis_id:
        raise RuntimeError('Invalid analysis ID')
    path = Path('Results') / analysis_id / 'analysis.json'
    if not path.is_file():
        raise FileNotFoundError(path)
    record = json.loads(path.read_text(encoding='utf-8-sig'))
    if record.get('analysis_id') != analysis_id:
        raise RuntimeError('Analysis ID does not match record content')
    project_root = Path.cwd().resolve()
    if not (project_root / 'app.py').is_file() or not (project_root / 'Core').is_dir():
        raise RuntimeError('Run from Week-2 project root')
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from Core import feedback_semantics
    class Flags:
        def __init__(self): self.items = []
        def add(self, check, severity, value, message, section=None):
            self.items.append({'check':check,'severity':severity,'section':section or '(whole output)',
                              'value': value,'message':message})
    f = Flags()
    events = record.get('events', [])
    sections = (record.get('ai_output') or {}).get('sections') or {}
    feedback_semantics.add_review_requests(f, sections, events)
    input_info = record.get('input', {})
    original = Path(input_info.get('path',''))
    print('=== SOC FEEDBACK SEMANTIC REPLAY (READ-ONLY) ===')
    print('Analysis:', analysis_id)
    print('Saved status:', record.get('review',{}).get('status'))
    print('Original automated flags:',len((record.get('validation') or {}).get('flags') or []))
    print('New candidate flags:',len(f.items))
    if original.is_file():
        actual = hashlib.sha256(original.read_bytes()).hexdigest()
        print('Input integrity:', 'MATCH' if actual == input_info.get('sha256') else 'MISMATCH — REVIEW REQUIRED')
    else:
        print('Input integrity: ORIGINAL NOT ACCESSIBLE (cannot certify)')
    for i,item in enumerate(f.items,1):
        print(f"  R{i:03d} [{item['severity']}] {item['check']} | section={item['section']}")
        print('    ',item['value'][:160])
        print('    ',item['message'])
    print('Saved Results: UNCHANGED; no model inference used')
    print('STATUS: REPLAY COMPLETE — FLAGS REQUIRE ANALYST REVIEW')

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('analysis_id')
    a = ap.parse_args()
    try:
        main(a.analysis_id)
    except Exception as ex:
        print('STOP:',ex,file=sys.stderr)
        sys.exit(1)
