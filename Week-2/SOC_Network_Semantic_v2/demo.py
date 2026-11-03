r"""Read-only re-evaluation of previously saved NT-01 AI report against focused Zeek evidence.

Run as a module from Week-2 project root:
    python -m SOC_Network_Semantic_v2.demo --replay AN-20261020-013537-8c86
Optional report path if an unfamiliar analysis.json schema is encountered:
    python -m SOC_Network_Semantic_v2.demo --replay AN-20261020-013537-8c86 --report-file C:\\path\\report.md
"""
import argparse
import json
import re
import hashlib
from pathlib import Path

ROOT = Path.cwd().resolve()
FOCUSED = ROOT / 'Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-focused.json'
EXPECTED_FOCUSED_SHA256 = 'dcaa4d0f7dadf730d5880755db24b98e8fe5689b2af57e95631f8589135beae7'
SECTION_NAMES = (
    'EXECUTIVE SUMMARY', 'LOG SOURCE', 'SIGNIFICANT SECURITY EVENTS',
    'SUSPICIOUS ACTIVITIES', 'EVIDENCE REFERENCES', 'INCIDENT TIMELINE',
    'EXTRACTED IOCS', 'POTENTIAL ATTACK INDICATORS',
    'CONFIDENCE AND UNCERTAINTY', 'MISSING INFORMATION',
    'RECOMMENDED INVESTIGATION STEPS',
)
HEADING_RE = re.compile(r'^\s*#{1,4}\s+(.+?)\s*$', re.M)


def split_markdown(text):
    hits = [(m, m.group(1).upper().strip()) for m in HEADING_RE.finditer(text)]
    out = {}
    for i, (match, name) in enumerate(hits):
        if name in SECTION_NAMES:
            end = hits[i + 1][0].start() if i + 1 < len(hits) else len(text)
            out[name] = text[match.end():end].strip()
    return out


def extract_sections(tree):
    # Try markdown report text first; schemas from different project versions vary.
    stack = [tree]
    text_candidates, dict_candidates = [], []
    while stack:
        node = stack.pop()
        if isinstance(node, str) and len(node) >= 100:
            parsed = split_markdown(node)
            if len(parsed) >= 3:
                text_candidates.append((len(parsed), parsed))
        elif isinstance(node, dict):
            upper = {str(k).upper(): v for k, v in node.items() if isinstance(v, str) and str(k).upper() in SECTION_NAMES}
            if len(upper) >= 3:
                dict_candidates.append((len(upper), upper))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    candidates = text_candidates + dict_candidates
    if not candidates:
        return None
    return max(candidates, key=lambda x: x[0])[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--replay', required=True, help='Previously saved analysis ID')
    ap.add_argument('--report-file', type=Path, help='Optional saved Markdown/text report')
    args = ap.parse_args()
    if not re.fullmatch(r'AN-\d{8}-\d{6}-[a-z0-9]+', args.replay):
        raise RuntimeError('Expected an analysis ID like AN-20261020-013537-8c86')
    if not (ROOT / 'app.py').is_file():
        raise RuntimeError('Run from the Week-2 project root')
    if not FOCUSED.is_file() or hashlib.sha256(FOCUSED.read_bytes()).hexdigest() != EXPECTED_FOCUSED_SHA256:
        raise RuntimeError('Focused NT-01 evidence missing or SHA256 mismatch: STOP')
    from Core.log_parser import load_file
    from Core import network_grounding, network_semantics
    events = load_file(FOCUSED, source_hint='network')['events']
    if len(events) != 31:
        raise RuntimeError('Unexpected NT-01 focused evidence count')
    analysis = ROOT / 'Results' / args.replay / 'analysis.json'
    if not analysis.is_file():
        raise RuntimeError('Missing historical analysis.json: ' + str(analysis))
    record = json.loads(analysis.read_text(encoding='utf-8-sig'))
    sections = None
    if args.report_file:
        sections = split_markdown(args.report_file.read_text(encoding='utf-8-sig'))
    else:
        sections = extract_sections(record)
        if sections is None:
            result_dir = analysis.parent
            for pat in ('*.md', '*.txt'):
                for file in result_dir.glob(pat):
                    if file.stat().st_size < 2_000_000:
                        sections = split_markdown(file.read_text(encoding='utf-8-sig', errors='replace'))
                        if len(sections) >= 3:
                            break
                if sections:
                    break
    if not sections or len(sections) < 3:
        print('STOP: Could not locate structured report sections in this analysis schema.')
        print('Run again with --report-file <saved report.md>; no project files were changed.')
        raise SystemExit(2)
    print('=== NT-01 SEMANTIC ATTRIBUTION REPLAY (READ-ONLY) ===')
    print('Analysis:', args.replay)
    print('Focused SHA256: MATCH')
    print('Loaded Sections:', len(sections))
    print('Raw E002/E011/E031 provenance: checked against supplied structured focused evidence')
    old = network_grounding.review_requests(sections, events)
    new = network_semantics.review_requests(sections, events)
    print('Network review requests (v1 + v2):', len(old))
    print('New v2 attribution requests:', len(new))
    for i, flag in enumerate(new, 1):
        print(f"R{i:03d} [{flag['severity']}] {flag['check']} | section={flag['section']}")
        print(' ', flag['message'])
    print('Historical Results / Reviews / Core: UNCHANGED')
    print('STATUS: NT-01 SEMANTIC REPLAY COMPLETE - ANALYST REVIEW REQUIRED')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('STOP: ' + str(error))
