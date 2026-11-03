#!/usr/bin/env python3
"""NT-02 final source-verified DNS documentation (stdlib + existing project).

From D:\\Desktop\\w\\Week-2 with NT02_Prepare_Focused_Evidence.py present:
  python NT02_Finalize_Verified_Case.py --check
  python NT02_Finalize_Verified_Case.py --finalize

--check: reads original source, derivations, analyses, and current Core only.
--finalize: repeats the checks, asks FINALIZE, then exclusively writes three
new documents. Source evidence, Core, prior Results and reviews are NEVER edited.

The application-specific human-review schema is NOT certified by this tool;
review status is the CLI-reported status furnished by the analyst.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
DATA = ROOT / 'Data' / 'Real-Datasets' / 'Network-Attacks' / 'NT-02-DNS-Anomaly'
TIMELINE = DATA / 'NT-02-Verified-Timeline.csv'
CASE_STUDY = DATA / 'NT-02-Case-Study.md'
FINAL_MANIFEST = DATA / 'NT-02-Final-Verification-Manifest.json'
OUTPUTS = (TIMELINE, CASE_STUDY, FINAL_MANIFEST)
BASELINE_ID = 'AN-20261020-024440-4bee'
POST_ID = 'AN-20261020-033312-7c54'
RULE = 'NETWORK_DNS_CHUNK_BURST'
SOURCE_SHA = 'a5a31f5be2a6bfdcce1ab1f2d43e34a2b1ff49bee4d3737560c8b9b6e6775942'
FOCUSED_SHA = '15d82bea320702cc5f00c304618019c043305f749bb732a48cdeda7863ffc466'


def require(ok, why):
    if not ok:
        raise RuntimeError('STOP: ' + why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rel(path):
    # Accept either source relative paths or absolute paths: no mixed-path bug.
    return str(path.resolve().relative_to(ROOT)).replace('\\', '/')


def import_preparer():
    p = ROOT / 'NT02_Prepare_Focused_Evidence.py'
    require(p.is_file(), 'NT02_Prepare_Focused_Evidence.py missing from project root')
    spec = importlib.util.spec_from_file_location('nt02_source_derivation', p)
    require(spec is not None and spec.loader is not None, 'Source derivation import unavailable')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_analysis(analysis_id):
    p = ROOT / 'Results' / analysis_id / 'analysis.json'
    require(p.is_file(), f'Saved AI analysis missing: {analysis_id}')
    data = json.loads(p.read_text(encoding='utf-8-sig'))
    require(data.get('analysis_id') == analysis_id, f'Analysis ID mismatch: {analysis_id}')
    inp = data.get('input') or {}
    require(inp.get('sha256') == FOCUSED_SHA, f'Analysis input hash mismatch: {analysis_id}')
    # Do not confuse a saved model report with ground-truth evidence.
    require(isinstance((data.get('ai_output') or {}).get('raw_text'), str),
            f'Saved model raw text missing: {analysis_id}')
    return p, data


def make_outputs():
    require((ROOT / 'app.py').is_file() and (ROOT / 'Core' / 'log_parser.py').is_file(),
            'Run from Week-2 root (app.py and Core/log_parser.py required)')
    require(not any(p.exists() for p in OUTPUTS),
            'At least one final output already exists; refusing to overwrite')
    prep = import_preparer()

    # Re-derive ALL four focused evidence files from the source, byte for byte.
    artifacts, source_events, mappings, stats = prep.produce()
    require(len(source_events) == 26 and len(mappings) == 26 and len(artifacts) == 4,
            'Unexpected focused evidence structure')
    for file_path, expected_bytes in artifacts:
        actual = Path(file_path)
        require(actual.is_file(), f'Derived artifact missing: {actual}')
        require(actual.read_bytes() == expected_bytes,
                f'Original source derivation/hash mismatch: {actual.name}')
    require(sha(prep.SOURCE.read_bytes()) == SOURCE_SHA, 'Original source SHA-256 changed')
    require(sha(prep.FOCUSED.read_bytes()) == FOCUSED_SHA, 'Focused SHA-256 changed')

    # Independently cross-check saved, selected raw Zeek rows with exact source.
    _original, _original_manifest, all_source_rows = prep.load_original()
    index = {r['source_line']: r for r in all_source_rows}
    require(len(all_source_rows) == 581 and len(index) == 581, 'Original DNS row count/lines mismatch')
    require(len({r['query'] for r in all_source_rows}) == 258, 'Original distinct-query count mismatch')
    require(source_events[0]['record_kind'].endswith('_AGGREGATE_NOT_RAW_ZEEK_EVENT') and
            source_events[1]['record_kind'] == 'VERIFIED_DNS_QUERY_CLUSTER_AGGREGATE_NOT_RAW_ZEEK_EVENT',
            'E001/E002 must be COMPUTED aggregates')
    require(all(mappings[i]['original_source_line'] == 'AGGREGATE_NOT_A_SOURCE_ROW'
                for i in (0, 1)), 'Aggregate mappings incorrectly pretend to be raw Zeek rows')
    require(stats['cluster_record_count'] == 250 and stats['cluster_distinct_queries'] == 250 and
            stats['cluster_duration_seconds'] == 3.552866 and
            stats['cluster_src'] == '192.168.16.132' and
            stats['cluster_dst'] == '192.168.16.131', 'Full-source verified DNS burst values changed')
    require(stats['source_nxdomain_count'] == 0, 'Unexpected source NXDOMAIN count')

    rows = []
    seen = set()
    categories = Counter()
    for i in range(2, 26):
        ref = f'E{i+1:03d}'
        ev, mp = source_events[i], mappings[i]
        require(mp['focused_ref'] == ref and ref not in seen, f'Wrong or duplicate ref: {ref}')
        seen.add(ref)
        require(ev.get('record_kind') == 'ZEEK_DNS_ORIGINAL_SOURCE_ROW', f'Not a raw row: {ref}')
        line_no = int(ev['source_line'])
        require(line_no in index and str(line_no) == str(mp['original_source_line']),
                f'Mapping line mismatch: {ref}')
        original = index[line_no]
        raw = original['row']
        require(ev['source_line_sha256'] == original['raw_sha'] == mp['original_line_sha256'],
                f'Source logical-line SHA mismatch: {ref}')
        require(original['timestamp'] == ev['timestamp'] and original['epoch'] == __import__('decimal').Decimal(ev['zeek_ts_exact']),
                f'Time mismatch: {ref}')
        checks = {
            'zeek_uid': raw['uid'], 'src_ip': raw['id.orig_h'],
            'src_port': raw['id.orig_p'], 'dst_ip': raw['id.resp_h'],
            'dst_port': raw['id.resp_p'], 'proto': raw['proto'],
            'query': raw['query'], 'qtype_name': raw['qtype_name'],
            'rcode_name': raw['rcode_name'],
        }
        for key, expected in checks.items():
            require(ev.get(key) == expected, f'Zeek {key} mismatch at {ref}')
        require(mp['zeek_uid'] == raw['uid'] and mp['original_epoch_ts'] == raw['ts'],
                f'Zeek mapping UID/epoch mismatch: {ref}')
        categories[ev['selection_category']] += 1
        rows.append({
            'Evidence Ref': ref, 'Timestamp UTC': ev['timestamp'],
            'Original Zeek Epoch': ev['zeek_ts_exact'], 'Original Line': line_no,
            'Zeek UID': raw['uid'], 'Client IP': ev['src_ip'], 'Client Port': ev['src_port'],
            'Resolver IP': ev['dst_ip'], 'Resolver Port': ev['dst_port'],
            'Protocol': ev['proto'], 'DNS Query': ev['query'],
            'Query Type': ev['qtype_name'], 'Response Code': ev['rcode_name'],
            'Selection Category': ev['selection_category'],
            'Original Source Line SHA256': ev['source_line_sha256'],
        })
    require(len(rows) == 24 and len(seen) == 24, 'Selected raw DNS rows are not 24/24')
    require(categories == {'chunk_pattern_time_stratified': 16,
                           'same_pair_unlabelled_context': 4,
                           'other_pair_unlabelled_context': 4},
            f'Unanticipated source sampling classes: {dict(categories)}')
    require(rows == sorted(rows, key=lambda x: (x['Timestamp UTC'], x['Original Line'])),
            'Evidence records are not in chronological order')
    e024 = next(x for x in rows if x['Evidence Ref'] == 'E024')
    require((e024['Client IP'], e024['Resolver IP'], e024['Original Line']) ==
            ('192.168.16.132', '192.168.16.131', 437), 'E024 client/resolver/line mismatch')

    from Core.log_parser import load_file
    from Core import grounded_detection, analysis, network_grounding
    parsed = load_file(prep.FOCUSED, source_hint='network')
    require(parsed.get('source_type') == 'network' and not parsed.get('warnings') and
            len(parsed.get('events', [])) == 26, 'Project parser did not validate 26 network records')
    findings = grounded_detection.detect(parsed['events']).get('behavioral_findings', [])
    independent = [f for f in findings if f.get('rule_id') == RULE]
    require(len(independent) == 1 and
            independent[0].get('confidence_in_observed_pattern') == 'high',
            'Independent high-confidence DNS burst finding missing')
    evidence_refs = independent[0].get('evidence_refs') or []
    require('E002' in evidence_refs and len(evidence_refs) >= 9,
            'DNS detection lacks aggregate + sufficient raw witnesses')
    details = independent[0].get('details') or {}
    require(details.get('dns_records') == 250 and details.get('distinct_exact_queries') == 250 and
            float(details.get('duration_seconds', -1)) == 3.552866 and
            details.get('aggregate_is_raw_dns_record') is False,
            'Independent DNS detection factual details changed')

    baseline_path, baseline = load_analysis(BASELINE_ID)
    post_path, post = load_analysis(POST_ID)
    saved_findings = (post.get('grounding') or {}).get('behavioral_findings', [])
    saved_rule = [f for f in saved_findings if f.get('rule_id') == RULE]
    require(len(saved_rule) == 1 and
            saved_rule[0].get('confidence_in_observed_pattern') == 'high',
            'Saved post-grounding high-confidence finding missing')
    require(len(post.get('events') or []) == 26, 'Post analysis did not save 26 events')

    sections = analysis.parse_sections(post['ai_output']['raw_text'], analysis.HEADINGS['log_analysis'])
    require(len(sections) >= 9, 'Post-fix parser failed to identify expected report sections')
    replay = network_grounding.review_requests(sections, post['events'])
    checks = Counter(r.get('check') for r in replay)
    require('network_vertical_scan_not_identified' not in checks,
            'Port-scan false-positive persists in DNS replay')
    require('network_dns_chunk_burst_not_identified' not in checks,
            'DNS recognized pattern still labelled fully missed')
    require(checks['network_dns_chunk_burst_missing_quantification'] == 1,
            'Expected DNS missing-quantification review request not reproduced')

    output_csv = io.StringIO(newline='')
    writer = csv.DictWriter(output_csv, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    timeline_bytes = output_csv.getvalue().encode('utf-8')
    study = f"""# NT-02 — Source-Verified Suspicious DNS Activity Case Study

**Project:** DEPI P5 — AI-assisted SOC log analysis  
**Source:** Zeek `dns.log` from the pinned `dikshitdhawan/NTA-Zeek-Threat-Detection-Lab` repository  
**Original source SHA-256:** `{SOURCE_SHA}`  
**Scope:** 581 original DNS records, 26 model-visible focused entries (two verified computed aggregates and 24 selected original Zeek rows).

## Evidence provenance and boundaries

Original source bytes, Git blob provenance, pinned commit, Zeek syntax and all four source-derived artifacts were verified again via the existing `NT02_Prepare_Focused_Evidence.py` derivation logic. The independently checked 24 selected raw Zeek rows preserve source line number, logical-line SHA-256, UID, epoch/UTC timestamp, originating client and resolver IP/port, query, query type and response code. **E001 is the full-source computed aggregate; E002 is the DNS-cluster computed aggregate. Neither is an observed individual DNS request.** E003–E026 are original source DNS entries.

## Verified DNS behavior

| Measure | Verified value |
|---|---|
| Original DNS records | **581** (258 distinct exact queries) |
| Client → resolver for burst | `192.168.16.132` → `192.168.16.131` |
| Pattern | Sequential `chunkNNN-hex.lab.test` subdomains |
| Matching burst DNS records | **250** |
| Distinct exact queries in burst | **250** |
| Burst first observation UTC | `{stats['cluster_start_utc']}` |
| Burst last observation UTC | `{stats['cluster_end_utc']}` |
| Burst interval | **3.552866 seconds** |
| Burst query type / response | 250 `A` records; 250 `NOERROR` |
| Full-source query types | 401 `A`; 180 `AAAA` |
| Full-source rcode values | 255 `NOERROR`; 326 `-` (not recorded) |
| Observed NXDOMAIN | **0** |
| Rule / confidence in observed pattern | `{RULE}` / **HIGH** |
| Confirmed tunneling or exfiltration | **NOT ESTABLISHED** |
| Authorization or actor intent | **UNKNOWN** |

**Interpretation:** The short high-diversity sequence supports a high-confidence observation of a chunk-style DNS query burst and an indicator compatible with DNS tunneling-like behavior. Hex-looking labels are not necessarily cryptographic hashes or recovered exfiltrated data. A `NOERROR` response is not confirmation of exfiltration. The `.test` suffix suggests test-style names and does not determine authorization or maliciousness; private addresses do not establish benign activity.

## Client / resolver attribution and context

`E024` is an original Zeek query at line **437**: client `192.168.16.132` → resolver `192.168.16.131`, `chunk250-ef566286fc3a33e1c288d41c.lab.test`. The baseline AI output incorrectly attributed this DNS query to `.131` as its initiating host. Not all entries come from the same client: the full source contains context rows from `.131` to `.1`, and their presence must not be recast as the 250-query burst.

## AI assessment, validation and human review

- **Baseline Mistral:** `{BASELINE_ID}`. Identified chunk-style DNS queries, but did not quantify the 250-query / 3.552866-second burst and did not clearly characterize DNS tunneling-like risk. Source/client attribution and report structure had errors; the original report is preserved.
- **Post-grounding Mistral:** `{POST_ID}`. Identified concentrated, diverse sequential DNS queries and potential DNS tunneling, but still omitted the source-verified 250 count, distinct 250 count and interval. Its timeline included an ellipsis placeholder and positioned computed aggregate E001 as if it were an individual event; the original report is preserved.
- **Deterministic detection:** `{RULE}` saved within `grounding.behavioral_findings` of the post-grounding analysis with HIGH confidence in the observed pattern. This is not proof of exfiltration, operator identity or malicious intent.
- **Live validator fix:** Existing test suite passed **275 tests** during installation, as reported by the project CLI. This finalization step does **not** rerun the full regression suite.
- **Post-fix read-only replay:** Reproduced **{len(replay)} network review request(s)**, including `{RULE.lower()}_missing_quantification` in semantic substance (actual flag name `network_dns_chunk_burst_missing_quantification`), without the inappropriate vertical-TCP-port-scan flag. This replay is not a rewrite of the historical saved AI validation fields.
- **Analyst review:** Both baseline and post-grounding review commands were **CLI-reported `Corrected`**. This finalization script does not inspect or certify the application's internal human-review storage schema.

## Verified source timeline

`NT-02-Verified-Timeline.csv` contains **24 chronologically sorted original Zeek DNS rows** E003–E026 with exact source-row provenance and client→resolver direction. The two computed aggregates E001/E002 are **not** represented as fabricated timeline DNS requests. Sampling is not an exhaustive timeline of all 581 DNS rows or the entire 250-query burst; summary counts come from full-source derivation.

## Investigation limits and next evidence

Seek permission/test authorization records; identify the DNS-originating process and resolver owner; inspect DNS server responses and relevant capture data; confirm whether any data was encoded or reconstructed; and correlate endpoint/network activity. No proof of successful tunneling, data theft, compromise or malicious intent can be inferred solely from the DNS log, despite the strong observed burst pattern.

## File safety

The original source, manifests, focused evidence, `Core`, `Results` and existing human reviews are read-only during finalization. New documents are written using exclusive creation after an explicit operator confirmation; previous documents are never overwritten.
"""
    study_bytes = study.encode('utf-8')

    inputs = [prep.SOURCE, prep.SOURCE_MANIFEST, prep.FOCUSED, prep.MAPPING,
              prep.STATS, prep.SELECTION, baseline_path, post_path]
    doc_manifest = {
        'case_id': 'NT-02',
        'status': 'source_verified_final_documentation',
        'source_records_verified': 581, 'source_distinct_exact_queries': 258,
        'focused_model_events': 26, 'computed_aggregate_refs': ['E001', 'E002'],
        'source_row_refs': 'E003-E026', 'verified_source_row_mappings': '24/24',
        'dns_cluster_query_count': 250, 'dns_cluster_distinct_queries': 250,
        'dns_cluster_duration_seconds': 3.552866,
        'dns_cluster_client': '192.168.16.132',
        'dns_cluster_resolver': '192.168.16.131',
        'dns_detection_rule': RULE, 'observed_pattern_confidence': 'high',
        'baseline_analysis_id': BASELINE_ID, 'post_grounding_analysis_id': POST_ID,
        'review_status_as_reported_by_cli': 'Corrected (both; unverified internal review schema)',
        'review_storage_schema_independently_checked': False,
        'network_replay_request_count': len(replay),
        'network_replay_request_categories': dict(checks),
        'full_regression_test_count': 275,
        'full_regression_certification_by_this_script': False,
        'verification_scope': 'source pin/hash; derivation byte equality; raw line/UID/UTC/client-resolver/port/query mappings; parser; independent grounded rule; saved post-grounding rule; read-only network validator replay',
        'inputs_sha256': {rel(Path(x)): sha(Path(x).read_bytes()) for x in inputs},
        'outputs_sha256': {TIMELINE.name: sha(timeline_bytes), CASE_STUDY.name: sha(study_bytes)},
        'safety_and_limits': [
            'E001 and E002 are computed summaries, not individual DNS events',
            '24 selected source records are a sample of 581, not all 581',
            'Pattern indicator is not proof of tunneling/exfiltration/authorization/malicious intent',
            'CLI-reported human review is not independently validated against review storage schema',
            'The final manifest cannot include its own SHA-256 without a circular hash',
        ],
    }
    manifest_bytes = (json.dumps(doc_manifest, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    return [(TIMELINE, timeline_bytes), (CASE_STUDY, study_bytes),
            (FINAL_MANIFEST, manifest_bytes)], checks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check', action='store_true', help='Read-only verification')
    modes.add_argument('--finalize', action='store_true', help='Create three new files only after confirmation')
    args = ap.parse_args()
    print('=== NT-02 VERIFIED FINAL DOCUMENTATION ===')
    outputs, replay = make_outputs()
    print('Original source pin/Git blob/source manifest: PASS')
    print('Source-derived 4 artifacts exact byte/hash equality: PASS')
    print('Original DNS records: 581 | Exact queries: 258')
    print('DNS burst: 250 queries; 250 distinct; 3.552866 seconds')
    print('Client -> Resolver: 192.168.16.132 -> 192.168.16.131')
    print('E001/E002: verified computed aggregates (NOT raw DNS queries)')
    print('E003-E026: 24/24 raw Zeek line/UID/time/direction/port/query/hash mappings: PASS')
    print('Project parser: NETWORK, 26 records, warnings=[]')
    print('Independent and saved grounded detection: NETWORK_DNS_CHUNK_BURST / HIGH')
    print('Post-fix network semantic replay:', dict(replay))
    print('Human reviews: CLI-reported Corrected; internal schema not certified here')
    print('Core / Results / Original Logs / Existing Reviews: UNCHANGED')
    print('\n=== DOCUMENTS TO CREATE (EXCLUSIVE - NO OVERWRITE) ===')
    for p, data in outputs:
        print('CREATE:', p, '| bytes:', len(data), '| SHA256:', sha(data))
    if args.check:
        print('\nSTATUS: NT-02 READY TO FINALIZE - READ-ONLY PASS')
        return
    if input('\nType FINALIZE to create these 3 files (Enter cancels): ').strip() != 'FINALIZE':
        print('CANCELLED: No project files written')
        return
    created = []
    try:
        for p, data in outputs:
            with p.open('xb') as fd:
                created.append(p)
                fd.write(data)
                fd.flush()
            require(p.read_bytes() == data, 'Output bytes mismatch: ' + str(p))
    except Exception:
        for p in reversed(created):
            p.unlink(missing_ok=True)
        raise
    print('\n=== FINAL STATUS ===')
    print('Timeline: 24 chronological original Zeek DNS records, raw line and hash verified')
    print('Case Study: CREATED')
    print('Final Verification Manifest: CREATED')
    print('Output SHA-256: VERIFIED')
    print('Original Data / Core / Results / Human Reviews: UNCHANGED')
    print('STATUS: NT-02 DOCUMENTATION COMPLETE (review schema verification separate)')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ERROR:', exc, file=sys.stderr)
        sys.exit(1)
