"""DNS detection tests: positive, negative, attribution, semantics and boundaries."""
import unittest
from copy import deepcopy
from Core import dns_grounding as d


def sample(client='192.168.16.132', resolver='192.168.16.131', count=250, unique=250, duration=3.552866):
    st = '2026-05-26T16:05:30.002227Z'
    end = '2026-05-26T16:05:33.555093Z'
    aggregate = {'ref': 'E002', 'fields': {
        'record_kind': d.AGG, 'src_ip': client, 'dst_ip': resolver,
        'matching_dns_records': count, 'matching_distinct_exact_queries': unique,
        'duration_seconds': duration, 'query_pattern': 'chunkNNN-hex.lab.test',
        'first_observed_utc': st, 'last_observed_utc': end,
        'source_sha256': 'a'*64,
        'matching_query_type_counts.A': count,
        'matching_response_code_counts.NOERROR': count,
    }}
    samples=[]
    for n in range(1, 17):
        samples.append({'ref': f'E{n+2:03}', 'fields': {
            'record_kind': d.RAW, 'src_ip': client, 'dst_ip': resolver,
            'query': f'chunk{n:03}-{n:024x}.lab.test',
            'proto': 'udp', 'qtype_name': 'A', 'rcode_name': 'NOERROR',
            'timestamp': st, 'source_line_sha256': 'b'*64,
        }})
    return [aggregate, *samples]


class TestDNSGrounding(unittest.TestCase):
    def test_positive_high(self):
        result=d.detect_dns(sample())
        self.assertEqual(result['behavioral_findings'][0]['rule_id'],d.RULE)
        self.assertEqual(result['behavioral_findings'][0]['confidence_in_observed_pattern'],'high')
    def test_distinct_ip_generalization(self):
        self.assertEqual(len(d.detect_dns(sample('10.1.1.10','10.1.1.53'))['behavioral_findings']),1)
    def test_aggregate_not_raw(self):
        self.assertFalse(d.detect_dns(sample()[:1])['behavioral_findings'])
    def test_bad_client(self):
        x=sample()
        for r in x[1:]:r['fields']['src_ip']='192.168.16.10'
        self.assertFalse(d.detect_dns(x)['behavioral_findings'])
    def test_low_count(self):
        self.assertFalse(d.detect_dns(sample(count=8, unique=8))['behavioral_findings'])
    def test_too_many_unique(self):
        self.assertFalse(d.detect_dns(sample(count=100, unique=101))['behavioral_findings'])
    def test_slow_burst(self):
        self.assertFalse(d.detect_dns(sample(duration=360))['behavioral_findings'])
    def test_missing_hash(self):
        x=sample();del x[0]['fields']['source_sha256']
        self.assertFalse(d.detect_dns(x)['behavioral_findings'])
    def test_malformed_ref(self):
        x=sample();x[0]['ref']='AGG1'
        self.assertFalse(d.detect_dns(x)['behavioral_findings'])
    def test_no_chunk_sequence(self):
        x=sample()
        for r in x[1:]:r['fields']['query']='ntp.ubuntu.com'
        self.assertFalse(d.detect_dns(x)['behavioral_findings'])
    def test_mixed_qtypes(self):
        x=sample();x[2]['fields']['qtype_name']='TXT'
        self.assertEqual(len(d.detect_dns(x)['behavioral_findings']),1)
    def test_wrong_aggregate_pattern(self):
        x=sample();x[0]['fields']['query_pattern']='wrong.test'
        self.assertFalse(d.detect_dns(x)['behavioral_findings'])
    def test_duplicate_queries(self):
        x=sample()
        for r in x[1:]:r['fields']['query']='chunk001-aaaaaaaaaaaaaaaaaaaaaaaa.lab.test'
        self.assertFalse(d.detect_dns(x)['behavioral_findings'])
    def test_context(self):
        self.assertEqual(len(d.detect_dns(sample())['context_observations']),1)
    def test_prompt_notes(self):
        self.assertTrue(any('DNS GROUNDING' in z for z in d.prompt_notes(sample())))
    def test_clean_prompt(self):
        self.assertFalse(d.prompt_notes([]))
    def test_missing_burst_flag(self):
        s={'EXECUTIVE SUMMARY':'The queries seem to be related to chunks of data and could be reconnaissance.'}
        self.assertIn('network_dns_chunk_burst_not_identified', [x['check'] for x in d.review_requests(s,sample())])
    def test_complete_claim_no_burst_flag(self):
        s={'EXECUTIVE SUMMARY':'High-frequency DNS query burst with sequential chunk-style names; exfiltration not established.'}
        self.assertNotIn('network_dns_chunk_burst_not_identified', [x['check'] for x in d.review_requests(s,sample())])
    def test_exfiltration_flag(self):
        s={'SUSPICIOUS ACTIVITIES':'Confirmed data exfiltration was observed [E002].'}
        self.assertIn('network_dns_exfiltration_outcome_unsupported', [x['check'] for x in d.review_requests(s,sample())])
    def test_exfiltration_negated(self):
        s={'SUSPICIOUS ACTIVITIES':'No confirmed data exfiltration was observed [E002].'}
        self.assertNotIn('network_dns_exfiltration_outcome_unsupported', [x['check'] for x in d.review_requests(s,sample())])
    def test_aggregate_misread(self):
        s={'SIGNIFICANT SECURITY EVENTS':'[E002] is a single query to lab.test.'}
        self.assertIn('network_dns_aggregate_misread_as_query', [x['check'] for x in d.review_requests(s,sample())])
    def test_aggregate_explained(self):
        s={'SIGNIFICANT SECURITY EVENTS':'[E002] is not a single query; it is a computed aggregate.'}
        self.assertNotIn('network_dns_aggregate_misread_as_query', [x['check'] for x in d.review_requests(s,sample())])
    def test_no_dns_events(self):
        self.assertFalse(d.detect_dns([{'ref':'E001','fields':{'record_kind':'other'}}])['behavioral_findings'])
    def test_nested_counts(self):
        x=sample(); a=x[0]['fields']
        a['matching_query_type_counts']={'A':a.pop('matching_query_type_counts.A')}
        a['matching_response_code_counts']={'NOERROR':a.pop('matching_response_code_counts.NOERROR')}
        self.assertEqual(len(d.detect_dns(x)['behavioral_findings']),1)


if __name__=='__main__':unittest.main()
