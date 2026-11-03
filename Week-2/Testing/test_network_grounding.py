import unittest
from copy import deepcopy
from Core import network_grounding as n

SHA = 'a' * 64
SRC, DST = '192.168.16.132', '192.168.16.130'


def fixture(flows=1000, ports=950, witness_count=7):
    agg = {
        'ref': 'E001', 'fields': {
            'record_kind': n.AGGREGATE_KIND, 'src_ip': SRC, 'dst_ip': DST,
            'scan_pair_tcp_records': flows, 'scan_pair_distinct_destination_ports': ports,
            'scan_pair_conn_states.REJ': flows - 12,
            'scan_pair_conn_states.S0': 12,
            'scan_pair_first_utc': '2026-05-26T06:07:27Z',
            'scan_pair_last_utc': '2026-05-26T06:19:45Z',
            'source_sha256': SHA,
        }}
    samples = [
        {'ref': f'E{i+2:03d}', 'fields': {
            'record_kind': n.RAW_KIND, 'proto': 'tcp', 'src_ip': SRC, 'dst_ip': DST,
            'dst_port': i + 1000,
        }} for i in range(witness_count)
    ]
    return [agg] + samples


class TestNetworkGrounding(unittest.TestCase):
    def test_true_vertical_pattern(self):
        result = n.detect_network(fixture())
        f = result['behavioral_findings'][0]
        self.assertEqual(f['rule_id'], n.RULE)
        self.assertEqual(f['confidence_in_observed_pattern'], 'high')
        self.assertEqual(f['details']['tcp_records'], 1000)
        self.assertFalse(f['details']['aggregate_is_raw_connection'])
        self.assertFalse(f['details']['full_source_integrity_checked_in_this_function'])
        self.assertIn('E001', f['evidence_refs'])
        self.assertNotIn('confirmed compromise', f['observation'].lower())

    def test_flat_fields_from_parser(self):
        items = fixture()
        self.assertEqual(len(n.detect_network(items)['behavioral_findings']), 1)

    def test_one_port_not_scan(self):
        self.assertEqual(n.detect_network(fixture(flows=1000, ports=1))['behavioral_findings'], [])

    def test_flow_lower_than_port_count_rejected(self):
        self.assertEqual(n.detect_network(fixture(flows=200, ports=1000))['behavioral_findings'], [])

    def test_wrong_direction_raw_samples(self):
        events = fixture()
        for e in events[1:]:
            e['fields']['src_ip'], e['fields']['dst_ip'] = DST, SRC
        self.assertEqual(n.detect_network(events)['behavioral_findings'], [])

    def test_no_raw_samples(self):
        self.assertEqual(n.detect_network(fixture()[:1])['behavioral_findings'], [])

    def test_missing_aggregate_not_mislabeled(self):
        self.assertEqual(n.detect_network(fixture()[1:])['behavioral_findings'], [])

    def test_wrong_record_kind_no_false_alarm(self):
        events = fixture()
        events[0]['fields']['record_kind'] = n.RAW_KIND
        self.assertEqual(n.detect_network(events)['behavioral_findings'], [])

    def test_bad_hash_rejected(self):
        events = fixture()
        events[0]['fields']['source_sha256'] = 'not a hash'
        self.assertEqual(n.detect_network(events)['behavioral_findings'], [])

    def test_bad_time_rejected(self):
        events = fixture()
        events[0]['fields']['scan_pair_first_utc'] = '2026-05-26'
        self.assertEqual(n.detect_network(events)['behavioral_findings'], [])

    def test_duplicate_refs_not_inflated(self):
        events = fixture()
        events.extend(deepcopy(events[1:]))
        f = n.detect_network(events)['behavioral_findings'][0]
        self.assertEqual(len(f['evidence_refs']), 8)

    def test_missing_scan_mention_flag(self):
        sections = {'EXECUTIVE SUMMARY': 'Multiple repeated connections might be misconfiguration.',
                    'SIGNIFICANT SECURITY EVENTS': '', 'SUSPICIOUS ACTIVITIES': ''}
        req = n.review_requests(sections, fixture())
        self.assertIn('network_vertical_scan_not_identified', [x['check'] for x in req])

    def test_scan_mention_not_flagged(self):
        sec = {'EXECUTIVE SUMMARY': 'High confidence vertical port scan pattern; authorization unknown.'}
        self.assertNotIn('network_vertical_scan_not_identified', [x['check'] for x in n.review_requests(sec, fixture())])

    def test_aggregate_as_individual_flag(self):
        sections = {'SIGNIFICANT SECURITY EVENTS': '- [E001] Connection attempt to 192.168.16.130 on port 80'}
        req = n.review_requests(sections, fixture())
        self.assertIn('network_aggregate_misread_as_raw_event', [x['check'] for x in req])

    def test_aggregate_negated_does_not_flag(self):
        sections = {'EVIDENCE REFERENCES': 'E001 is not an individual connection attempt.'}
        self.assertNotIn('network_aggregate_misread_as_raw_event', [x['check'] for x in n.review_requests(sections, fixture())])

    def test_notes_bound_no_ips(self):
        notes = n.prompt_notes(fixture())
        self.assertTrue(any('vertical TCP port scan' in s for s in notes))
        self.assertTrue(all(SRC not in s for s in notes))
        self.assertTrue(all(len(s) < 700 for s in notes))

    def test_no_notes_on_benign(self):
        self.assertEqual(n.prompt_notes(fixture(flows=1000, ports=1)), [])

    def test_malformed_state_totals_not_accepted(self):
        events = fixture()
        events[0]['fields']['scan_pair_conn_states.REJ'] = 400
        self.assertEqual(n.detect_network(events)['behavioral_findings'], [])

    def test_unknown_approval_and_compromise(self):
        result = n.detect_network(fixture())['behavioral_findings'][0]
        self.assertIn('authorization', result['outcome'])
        self.assertIn('NOT established', result['outcome'])


if __name__ == '__main__':
    unittest.main()
