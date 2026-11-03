"""LT-04: prepare a source-provenance-preserving Linux benign *candidate*.

Run from the DEPI Week-2 project root:
    python LT04_Prepare_Benign_Case_v2.py

Creates exactly three new files and never overwrites existing files.
Uses only the standard library and the project's read-only Core.log_parser API.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import tempfile
from collections import Counter
from pathlib import Path

from Core.log_parser import load_file, render_event

ROOT = Path('Data/Real-Datasets/Linux-Benign/LT-04-Normal-Operations')
ORIGINAL = ROOT / 'LT-04-Linux-original.log'
ORIGINAL_MANIFEST = ROOT / 'LT-04-Source-Manifest.json'
FOCUSED = ROOT / 'LT-04-focused.log'
MAPPING = ROOT / 'LT-04-evidence-mapping.csv'
SELECTION = ROOT / 'LT-04-Selection-Manifest.json'
OUTPUTS = (FOCUSED, MAPPING, SELECTION)

# A single Jul 27 system-startup-like cluster. All line numbers come from
# the source sample displayed by the analyst. Not a global benign label.
SELECTED = {
    1909: 'syslog',
    1910: 'kernel',
    1917: 'kernel',
    1921: 'syslog',
    1924: 'kernel',
    1932: 'kernel',
    1942: 'kernel',
    1950: 'kernel',
    1958: 'kernel',
    1965: 'kernel',
    1973: 'kernel',
    1980: 'kernel',
    1985: 'bluetooth',
    1987: 'network',
    1988: 'bluetooth',
    1991: 'network',
    1993: 'kernel',
    2000: 'kernel',
}

SYSLOG_RE = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+'
    r'(?P<clock>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<program>[^:]+):\s*(?P<message>.*)$'
)
RISK_RE = re.compile(
    r'\b(?:ALERT|error|failed|failure|warning|denied|unauthorized|'
    r'critical|panic|segfault|intrusion|attack|unable|cannot)\b',
    re.IGNORECASE,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SystemExit('STOP: ' + reason)


print('=== LT-04 SOURCE-VERIFIED BENIGN CANDIDATE PREPARATION ===')
require(ORIGINAL.is_file(), f'Missing source: {ORIGINAL}')
require(ORIGINAL_MANIFEST.is_file(), f'Missing source manifest: {ORIGINAL_MANIFEST}')
for output in OUTPUTS:
    require(not output.exists(), f'Output exists; refusing overwrite: {output}')

source_bytes = ORIGINAL.read_bytes()
source_manifest = json.loads(ORIGINAL_MANIFEST.read_text(encoding='utf-8-sig'))
require(
    sha256(source_bytes).lower() == str(source_manifest['sha256']).lower(),
    'Original SHA-256 mismatch',
)
require(
    len(source_bytes) == int(source_manifest['file_size_bytes']),
    'Original source byte-size mismatch',
)
raw_line_bytes = source_bytes.splitlines()
require(len(raw_line_bytes) == 2000, 'Expected 2,000 source lines')
source_lines = [item.decode('utf-8', errors='strict') for item in raw_line_bytes]

print('\n=== SOURCE VERIFICATION ===')
print('SHA256: MATCH')
print(f'Source Bytes: {len(source_bytes)}')
print(f'Source Lines: {len(source_lines)}')
print(f'Selected Source Lines: {len(SELECTED)}')

mapping_rows = []
focused_lines = []
kind_counts = Counter()
print('\n=== FOCUSED EVIDENCE (ORIGINAL SYSLOG TEXT) ===')
for number, (source_line, expected_program) in enumerate(SELECTED.items(), 1):
    original = source_lines[source_line - 1]
    match = SYSLOG_RE.fullmatch(original)
    require(match is not None, f'Unparseable selected source line {source_line}')
    require(match.group('month') == 'Jul' and match.group('day') == '27',
            f'Unexpected day at line {source_line}')
    require(match.group('host') == 'combo', f'Unexpected host at line {source_line}')
    actual_program = re.sub(r'\[\d+\]', '', match.group('program')).strip().lower()
    require(actual_program == expected_program,
            f'Program changed at source line {source_line}: {actual_program}')
    require(not RISK_RE.search(match.group('message')),
            f'Risk-language found on selected line {source_line}; review selection')
    ref = f'E{number:03d}'
    mapping_rows.append({
        'focused_ref': ref,
        'focused_line': number,
        'original_source_line': source_line,
        'source_line_sha256_excluding_newline': sha256(raw_line_bytes[source_line - 1]),
        'original_syslog_timestamp_yearless': (
            f"{match.group('month')} {int(match.group('day'))} {match.group('clock')}"
        ),
        'original_host': match.group('host'),
        'original_program': actual_program,
    })
    focused_lines.append(original)
    kind_counts[actual_program] += 1
    print(f'{ref} <- source line {source_line} [{actual_program}] {original}')

# Direct originals, not artificial syslog wrappers or fabricated timestamps.
focused_data = ('\n'.join(focused_lines) + '\n').encode('utf-8')
buf = io.StringIO(newline='')
writer = csv.DictWriter(buf, fieldnames=list(mapping_rows[0]))
writer.writeheader()
writer.writerows(mapping_rows)
mapping_data = buf.getvalue().encode('utf-8')

# Prove the real project parser and model renderer preserve evidence before
# writing permanent outputs. Year/timezone are not assigned to these logs.
print('\n=== PROJECT PARSER / MODEL-VISIBILITY SMOKE TEST ===')
with tempfile.TemporaryDirectory() as tmpdir:
    temp_log = Path(tmpdir) / 'LT04-parser-smoke.log'
    temp_log.write_bytes(focused_data)
    parsed = load_file(temp_log)
    events = parsed.get('events', [])
    warnings = parsed.get('warnings', [])
    source_type = parsed.get('source_type')
    print(f'Source Type: {source_type}')
    print(f'Parsed Events: {len(events)}')
    print(f'Warnings: {warnings}')
    require(source_type == 'linux', 'Expected Linux source type, no files saved')
    require(not warnings, 'Parser emitted warnings, no files saved')
    require(len(events) == len(focused_lines),
            f'Parser event count mismatch: {len(events)}')
    # This project's current Core/log_parser.py calls ln.strip() when
    # ingesting text logs. It can remove terminal whitespace from the
    # in-memory event.raw, even while the focused file retains the exact
    # source line. Allow ONLY this known, reversible presentation change.
    # Any actual content modification (including internal spaces) is fatal.
    parser_trim_notes = []
    for idx, (event, original) in enumerate(zip(events, focused_lines), 1):
        ref = f'E{idx:03d}'
        source_line = list(SELECTED)[idx - 1]
        require(event.get('ref') == ref,
                f'Parser evidence reference mismatch {ref}')
        parsed_raw = event.get('raw', '')
        # All selected syslog records must begin at column 1; even leading
        # whitespace normalization is not silently accepted by this verifier.
        require(original == original.lstrip(),
                f'Unexpected source leading whitespace {ref}')
        expected_parser_raw = original.rstrip()
        require(parsed_raw == expected_parser_raw,
                f'Parser changed NON-WHITESPACE evidence at {ref}; STOP')
        if parsed_raw != original:
            trimmed = len(original) - len(expected_parser_raw)
            parser_trim_notes.append({
                'focused_ref': ref,
                'original_source_line': source_line,
                'trailing_whitespace_chars_trimmed_by_parser': trimmed,
                'source_line_sha256_excluding_newline': sha256(raw_line_bytes[source_line - 1]),
            })
            print(f'NOTE: {ref} parser view trims {trimmed} terminal whitespace char(s); '
                  'the source and focused file retain them')
        rendered = render_event(event, 16000)
        require(expected_parser_raw in rendered,
                f'Actual source content not fully model-visible {ref}')
    print('Evidence Refs: 18/18 PASS')
    print('Focused Syslog Source Text: 18/18 PRESERVED (line endings normalized)')
    print(f'Parser Boundary Whitespace Differences: {len(parser_trim_notes)} DOCUMENTED')
    print('Model-visible Event Content: 18/18 PASS')

# Adjacent records may have other risks; this sample is never labeled as
# proof of a clean system or as a verified benign ground-truth dataset.
nearby_risk_lines = []
for source_line in range(1909, 2001):
    if RISK_RE.search(source_lines[source_line - 1]):
        nearby_risk_lines.append(source_line)

selection_manifest = {
    'test_id': 'LT-04',
    'scenario': 'Linux low-risk system startup and initialization events',
    'classification': 'benign_candidate_not_ground_truth',
    'source_verified': True,
    'source_sha256': sha256(source_bytes),
    'source_bytes': len(source_bytes),
    'source_line_count': len(source_lines),
    'focused_line_count': len(focused_lines),
    'original_source_lines': list(SELECTED),
    'evidence_refs': [row['focused_ref'] for row in mapping_rows],
    'selection_program_counts': dict(kind_counts),
    'focused_sha256': sha256(focused_data),
    'mapping_sha256': sha256(mapping_data),
    'parser_source_type': source_type,
    'parser_boundary_whitespace_normalization': parser_trim_notes,
    'source_context_window': {'first_line': 1909, 'last_line': 2000},
    'risk_keyword_lines_in_context_window': nearby_risk_lines,
    'limitations': [
        'Source syslog timestamps contain no year or timezone; do not fabricate either.',
        'The project parser strips boundary whitespace when rendering raw text; original/focused source content remains preserved and any trailing-trim is recorded.',
        'Focused logs preserve source order; that order is not necessarily timestamp order.',
        'Benign candidate is a local activity assessment, not proof the host is clean.',
        'Original source contains authentication failures and other potentially risky events that are excluded from this focused sample.',
        'Absence of attack indicators in the selected sample is not proof of authorization.',
        'System service startup does not establish why it occurred.',
        'This single curated sample cannot establish a statistically valid false-positive rate.',
    ],
}
selection_data = (json.dumps(selection_manifest, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
print('\n=== CONTEXT SAFETY NOTES ===')
print('Nearby risk-keyword source lines (1909..2000):', nearby_risk_lines)
print('Year / timezone of source syslog: NOT SPECIFIED')
print('Candidate Label: LOW-RISK, NOT VERIFIED BENIGN')
print('Original / Core / Results: UNCHANGED')
print('\n=== FILES TO CREATE (NO OVERWRITES) ===')
for output in OUTPUTS:
    print('CREATE:', output)
answer = input('\nType CREATE to save these three files (Enter cancels): ').strip()
if answer != 'CREATE':
    raise SystemExit('CANCELLED: No files created')

created = []
try:
    for path, payload in (
        (FOCUSED, focused_data),
        (MAPPING, mapping_data),
        (SELECTION, selection_data),
    ):
        with path.open('xb') as handle:
            created.append(path)
            handle.write(payload)
    for path, payload in (
        (FOCUSED, focused_data),
        (MAPPING, mapping_data),
        (SELECTION, selection_data),
    ):
        require(path.read_bytes() == payload, f'Write verification failed for {path}')
except BaseException:
    for path in created:
        path.unlink(missing_ok=True)
    raise

print('\n=== LT-04 FINAL PREPARATION STATUS ===')
print('Original SHA256: MATCH')
print(f'Original Records: {len(source_lines)}')
print(f'Focused Candidate Events: {len(focused_lines)}')
print(f'Evidence Mapping: {len(mapping_rows)}/{len(focused_lines)} PASS')
print('Source Type: linux')
print('Source and Focused Evidence: PRESERVED (focused line endings normalized)')
print(f'Parser-only Trailing Whitespace Notes: {len(parser_trim_notes)}')
print('Core / Results / Reviews: UNCHANGED')
print('STATUS: LT-04 FOCUSED BENIGN CANDIDATE READY FOR AI REVIEW')
