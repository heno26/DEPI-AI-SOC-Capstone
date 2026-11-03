"""Isolated network semantic validation tests. No network calls or writes."""
import unittest
from Core import network_semantics as n


def rows():
    return [
        {'ref': 'E001', 'fields': {'record_kind': 'VERIFIED_FULL_SOURCE_AGGREGATE_NOT_RAW_ZEEK_EVENT', 'src_ip': '192.168.16.132', 'dst_ip': '192.168.16.130'}},
        {'ref': 'E002', 'fields': {'record_kind': n.RAW_KIND, 'src_ip': '192.168.16.130', 'dst_ip': '192.168.16.1', 'src_port': 49949, 'dst_port': 53, 'proto': 'udp'}},
        {'ref': 'E003', 'fields': {'record_kind': n.RAW_KIND, 'src_ip': '192.168.16.132', 'dst_ip': '192.168.16.130', 'src_port': 43200, 'dst_port': 80, 'proto': 'tcp'}},
        {'ref': 'E004', 'fields': {'record_kind': n.RAW_KIND, 'src_ip': '192.168.16.132', 'dst_ip': '192.168.16.130', 'src_port': 43201, 'dst_port': 81, 'proto': 'tcp'}},
        {'ref': 'E011', 'fields': {'record_kind': n.RAW_KIND, 'src_ip': '192.168.16.132', 'dst_ip': '192.168.16.130', 'src_port': 44372, 'dst_port': 64112, 'proto': 'tcp'}},
        {'ref': 'E031', 'fields': {'record_kind': n.RAW_KIND, 'src_ip': '192.168.16.130', 'dst_ip': '192.168.16.1', 'src_port': 51814, 'dst_port': 53, 'proto': 'udp'}},
    ]


def checks(text, section='SIGNIFICANT SECURITY EVENTS', evs=None):
    return n.review_requests({section: text}, rows() if evs is None else evs)


class TestSemanticAttribution(unittest.TestCase):
    def test_mismatched_e002_destination(self):
        f = checks('- [E002] Original sampled flow from 192.168.16.130 to 192.168.16.132 on port 49949')
        self.assertIn('network_direction_mismatch', [x['check'] for x in f])
        self.assertIn('network_port_role_mismatch', [x['check'] for x in f])

    def test_mismatched_e011_direction(self):
        f = checks('- [E011] Flow from 192.168.16.130 to 192.168.16.132')
        self.assertIn('network_direction_mismatch', [x['check'] for x in f])

    def test_mismatched_e031_direction_and_port(self):
        f = checks('| Flow from 192.168.16.130 to 192.168.16.132 on port 51814 | [E031] |', 'INCIDENT TIMELINE')
        self.assertEqual({x['check'] for x in f}, {'network_direction_mismatch', 'network_port_role_mismatch'})

    def test_correct_dns_direction(self):
        self.assertEqual(checks('- [E002] UDP DNS flow from 192.168.16.130 to 192.168.16.1 on port 53'), [])

    def test_correct_tcp_direction(self):
        self.assertEqual(checks('- [E011] TCP flow from 192.168.16.132 to 192.168.16.130 on port 64112'), [])

    def test_explicit_source_port_not_swap(self):
        self.assertEqual(checks('- [E002] flow from 192.168.16.130 to 192.168.16.1 source port 49949 destination port 53'), [])

    def test_source_port_called_on_port(self):
        f = checks('- [E002] flow on port 49949')
        self.assertEqual([x['check'] for x in f], ['network_port_role_mismatch'])

    def test_unknown_port_is_not_called_swap(self):
        self.assertEqual(checks('- [E002] flow on port 9999'), [])

    def test_aggregate_not_individual(self):
        self.assertEqual(checks('- [E001] Aggregate from 192.168.16.130 to 192.168.16.132 on port 49949'), [])

    def test_unknown_ref_not_flagged(self):
        self.assertEqual(checks('- [E095] flow from 192.168.16.1 to 192.168.16.130 on port 444'), [])

    def test_unreferenced_statement_not_checked(self):
        self.assertEqual(checks('Original flow from 192.168.16.130 to 192.168.16.132 on port 49949'), [])

    def test_bare_ref_unbracketed_not_auto_flagged(self):
        self.assertEqual(checks('Reference E002: from 192.168.16.130 to 192.168.16.132'), [])

    def test_ref_range_expansion_with_grouped_mismatch(self):
        f = checks('- [E003] - [E004], [E011]: flows from 192.168.16.130 to 192.168.16.132')
        self.assertEqual(sum(x['check'] == 'network_direction_mismatch' for x in f), 3)

    def test_no_enumerating_huge_ranges(self):
        self.assertEqual(n._refs_in_line('[E001] - [E99999]'), ['E001', 'E99999'])

    def test_false_benign_causality(self):
        f = checks('No malicious activity is evident as the source and destination are within the same network.', 'EXECUTIVE SUMMARY')
        self.assertEqual([x['check'] for x in f], ['private_network_not_benign'])

    def test_private_because_benign(self):
        f = checks('These connections are safe because both systems use private IP addresses.', 'EXECUTIVE SUMMARY')
        self.assertEqual([x['check'] for x in f], ['private_network_not_benign'])

    def test_private_internal_not_proof_statement(self):
        self.assertEqual(checks('The hosts are within the same network, but that does not prove benign activity.', 'EXECUTIVE SUMMARY'), [])

    def test_internal_context_neutral(self):
        self.assertEqual(checks('Traffic stayed within the same network. Authorization is unknown.', 'EXECUTIVE SUMMARY'), [])

    def test_no_malware_confirmed_not_due_to_private(self):
        self.assertEqual(checks('No confirmed malware; network scanning is observed from 192.168.16.132.', 'EXECUTIVE SUMMARY'), [])

    def test_nonraw_kind_skipped(self):
        samples = [{'ref': 'E002', 'fields': {'record_kind': 'OTHER_EVENT', 'src_ip': '192.168.16.130', 'dst_ip': '192.168.16.1', 'src_port': 49949, 'dst_port': 53}}]
        self.assertEqual(checks('- [E002] from 192.168.16.130 to 192.168.16.132 on port 49949', evs=samples), [])

    def test_invalid_ipv4_does_not_crash(self):
        self.assertEqual(checks('- [E002] from 999.999.999.999 to 192.168.16.132'), [])

    def test_zero_input(self):
        self.assertEqual(n.review_requests({}, rows()), [])

    def test_no_evidence_records(self):
        self.assertEqual(checks('- [E002] from 192.168.16.130 to 192.168.16.132', evs=[]), [])

    def test_ignore_irrelevant_section(self):
        self.assertEqual(checks('- [E002] from 192.168.16.130 to 192.168.16.132', 'RECOMMENDED INVESTIGATION STEPS'), [])

    def test_conflict_summarized_in_message(self):
        f = checks('- [E011] from 192.168.16.130 to 192.168.16.132')
        self.assertIn('192.168.16.132 -> 192.168.16.130', f[0]['message'])
        self.assertEqual(f[0]['severity'], 'high')

    def test_dedupe_same_ref(self):
        f = checks('- [E002] and [E002] from 192.168.16.130 to 192.168.16.132')
        self.assertEqual(sum(x['check'] == 'network_direction_mismatch' for x in f), 1)

    def test_max_flag_count(self):
        lines = '\n'.join('- [E011] from 192.168.16.130 to 192.168.16.132' for _ in range(99))
        self.assertLessEqual(len(checks(lines)), 30)


if __name__ == '__main__':
    unittest.main()
