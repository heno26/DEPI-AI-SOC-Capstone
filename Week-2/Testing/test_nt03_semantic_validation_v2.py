"""NT-03 semantic review accuracy on explicit claims and source-derived features."""
import unittest
from Core import analysis, network_semantics as ns, network_grounding as ng
from Testing.test_nt03_retry_grounding import fixture as retry_fixture


def rows():
    f=retry_fixture()
    for event in f[2:]:
        if event['fields']['conn_state']=='SF':
            event['fields'].update(orig_bytes='149',resp_bytes='141272')
        else:
            event['fields'].update(orig_bytes='0',resp_bytes='0')
    # Typical NT03 exception: source port 51834 belongs to TCP/23, not TCP/80.
    f.append({'ref':'E100', 'fields':{
        'record_kind':'ZEEK_CONN_ORIGINAL_SOURCE_ROW','proto':'tcp',
        'src_ip':'192.168.1.199','dst_ip':'46.101.251.172',
        'src_port':51834,'dst_port':23,'conn_state':'S1',
        'orig_bytes':'639','resp_bytes':'627'}})
    return f


def flags(text, events=None, section='EXECUTIVE SUMMARY'):
    return ng.review_requests({section: text}, rows() if events is None else events)


def codes(text, events=None, section='EXECUTIVE SUMMARY'):
    return [x['check'] for x in flags(text,events,section)]


class NT03SemanticValidationV2(unittest.TestCase):
    def test_01_singular_heading_maps(self):
        s=analysis.parse_sections('## SUSPICIOUS ACTIVITY\n- [E001] Event',analysis.HEADINGS['log_analysis'])
        self.assertEqual(s['SUSPICIOUS ACTIVITIES'],'- [E001] Event')

    def test_02_normal_plural_maps(self):
        s=analysis.parse_sections('## SUSPICIOUS ACTIVITIES\n- [E001] Event',analysis.HEADINGS['log_analysis'])
        self.assertEqual(s['SUSPICIOUS ACTIVITIES'],'- [E001] Event')

    def test_03_unknown_heading_not_folded(self):
        s=analysis.parse_sections('## SUSPICIOUS ACTIVITIES\n- [E001] A\n## INCIDENTAL FINDINGS\nOther',analysis.HEADINGS['log_analysis'])
        self.assertEqual(s['SUSPICIOUS ACTIVITIES'],'- [E001] A')

    def test_04_true_missing_timeline_stays_missing(self):
        s=analysis.parse_sections('## SUSPICIOUS ACTIVITY\n- [E001] A',analysis.HEADINGS['log_analysis'])
        self.assertNotIn('INCIDENT TIMELINE',s)

    def test_05_post_report_denial_flagged(self):
        text=('A large number of repeated TCP connections from 192.168.1.199 to '
              '46.101.251.172 on port 80, with variations in source ports and '
              'no evidence of successful connection or data transfer. The activity '
              'could be potentially malicious, such as scanning or probing.')
        self.assertIn('network_observed_tcp_data_contradiction',codes(text))

    def test_06_explicit_c2_success_denial_not_flagged(self):
        self.assertNotIn('network_observed_tcp_data_contradiction',
                         codes('No evidence of successful C2 connection or data exfiltration.'))

    def test_07_malicious_transfer_denial_not_flagged(self):
        self.assertNotIn('network_observed_tcp_data_contradiction',
                         codes('No evidence of successful malicious file transfer.'))

    def test_08_only_s0_not_flagged(self):
        events=rows()
        for e in events:
            if e.get('fields',{}).get('record_kind')=='ZEEK_CONN_ORIGINAL_SOURCE_ROW':
                e['fields']['conn_state']='S0'
        self.assertNotIn('network_observed_tcp_data_contradiction',
                         codes('No evidence of successful connection or data transfer.',events))

    def test_09_sf_without_bytes_not_flagged(self):
        events=rows()
        for e in events:
            e['fields'].pop('orig_bytes',None)
            e['fields'].pop('resp_bytes',None)
        self.assertNotIn('network_observed_tcp_data_contradiction',
                         codes('No evidence of successful connection or data transfer.',events))

    def test_10_sf_with_zero_response_not_flagged(self):
        events=rows()
        for e in events:
            if e['fields'].get('conn_state')=='SF':
                e['fields']['resp_bytes']='0'
        self.assertNotIn('network_observed_tcp_data_contradiction',
                         codes('No evidence of successful connection or data transfer.',events))

    def test_11_positive_twoway_bytes_required(self):
        self.assertIn('network_observed_tcp_data_contradiction',
                      codes('No evidence of completed TCP connection or data exchange.'))

    def test_12_unlabelled_group_wrong_port(self):
        text='Repeated connections to destination on port 80; source ports (51834, 59224, 59228, 59236).'
        self.assertIn('network_source_port_group_mismatch',codes(text,section='SUSPICIOUS ACTIVITIES'))

    def test_13_unlabelled_group_correct_port(self):
        text='Repeated connections to destination on port 80; source ports (59224, 59228, 59236, 59240).'
        self.assertNotIn('network_source_port_group_mismatch',codes(text,section='SUSPICIOUS ACTIVITIES'))

    def test_14_ambiguous_multiple_destinations_no_guess(self):
        text='TCP source ports (51834, 59224, 59228, 59236) were observed.'
        self.assertNotIn('network_source_port_group_mismatch',codes(text))

    def test_15_unknown_port_no_false_positive(self):
        text='Connections on port 80; source ports (65500, 59224, 59228, 59236).'
        self.assertNotIn('network_source_port_group_mismatch',codes(text))

    def test_16_aggregate_only_no_semantic_attribution(self):
        text='No evidence of successful connection or data transfer; on port 80 source ports (51834, 59224, 59228).'
        self.assertEqual(ns.review_requests({'EXECUTIVE SUMMARY':text},rows()[:2]),[])

    def test_17_legacy_explicit_evidence_port_mismatch(self):
        r={'ref':'E008','fields':{'record_kind':'ZEEK_CONN_ORIGINAL_SOURCE_ROW',
             'src_ip':'192.168.1.199','dst_ip':'46.101.251.172',
             'src_port':59224,'dst_port':80}}
        self.assertIn('network_destination_port_mismatch',
                      [x['check'] for x in ns.review_requests({'SIGNIFICANT SECURITY EVENTS':
                       '[E008] Connection from 192.168.1.199 to 46.101.251.172 on port 23'},[r])])

    def test_18_retry_mention_without_numbers_flagged(self):
        text='[E002] Cluster of TCP retry events involving repeated same four-tuple rows.'
        cs=codes(text)
        self.assertNotIn('network_tcp_retry_pattern_not_identified',cs)
        self.assertIn('network_tcp_retry_missing_quantification',cs)

    def test_19_no_retry_mention_still_high_flagged(self):
        cs=codes('Repeated HTTP communication was observed.')
        self.assertIn('network_tcp_retry_pattern_not_identified',cs)
        self.assertNotIn('network_tcp_retry_missing_quantification',cs)

    def test_20_quantified_report_succeeds(self):
        text=('4 repeated source-port groups with 17 raw rows and source ports '
              '59224, 59228, 59236, 59240; a 16.64 seconds interval, '
              'possible retries from S0 to SF.')
        cs=codes(text)
        self.assertNotIn('network_tcp_retry_missing_quantification',cs)
        self.assertNotIn('network_tcp_retry_pattern_not_identified',cs)

    def test_21_only_groups_no_rows_flags(self):
        text=('4 repeated source-port groups: 59224, 59228, 59236, 59240; '
              '16.64 seconds observed; possible retry behavior.')
        fs=[f for f in flags(text) if f['check']=='network_tcp_retry_missing_quantification']
        self.assertEqual(len(fs),1)
        self.assertIn('raw_row_count',fs[0]['value'])

    def test_22_only_row_count_no_interval_flags(self):
        text='4 repeated source-port groups, 17 raw rows, ports 59224, 59228, 59236, 59240; retry.'
        fs=[f for f in flags(text) if f['check']=='network_tcp_retry_missing_quantification']
        self.assertIn('verified_interval_example',fs[0]['value'])

    def test_23_no_cross_type_impact_dns_aggregate_only(self):
        ev={'ref':'E001','fields':{'record_kind':'VERIFIED_DNS_QUERY_CLUSTER_AGGREGATE_NOT_RAW_ZEEK_EVENT'}}
        self.assertNotIn('network_tcp_retry_missing_quantification',codes('Some retry events.',[ev]))

    def test_24_no_cross_type_impact_udp_only(self):
        ev=rows()
        for row in ev:
            if row['fields'].get('proto')=='tcp': row['fields']['proto']='udp'
        self.assertNotIn('network_tcp_retry_missing_quantification',codes('Some retry events.',ev))


if __name__ == '__main__':
    unittest.main()
