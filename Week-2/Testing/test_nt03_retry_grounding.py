"""NT-03 regression coverage for conservative TCP retry-like grounding and attribution."""
import unittest
from datetime import datetime, timedelta, timezone
from Core import tcp_retry_grounding as r
from Core import network_grounding as ng
from Core import network_semantics as ns
from Core import grounded_detection as gd


def fixture():
    events = [
        {'ref':'E001','fields':{'record_kind':'VERIFIED_FULL_SOURCE_CONNECTION_AGGREGATE_NOT_RAW_ZEEK_EVENT'}},
        {'ref':'E002','fields':{'record_kind':'VERIFIED_TCP_CLUSTER_AGGREGATE_NOT_RAW_ZEEK_EVENT'}},
    ]
    start = datetime(2019, 1, 10, 20, 6, 29, tzinfo=timezone.utc)
    index = 3
    for port, gaps in ((59224,(7.161,8.240,16.640)), (59228,(7.213,8.560,16.640)),
                       (59236,(7.236,8.320,16.640,32.640)), (59240,(7.219,8.640,16.640))):
        t = start
        for i in range(len(gaps)+1):
            if i: t += timedelta(seconds=gaps[i-1])
            fields = {'record_kind':r.RAW_KIND, 'timestamp':t.isoformat().replace('+00:00','Z'),
                      'src_ip':'192.168.1.199','dst_ip':'46.101.251.172',
                      'src_port':port,'dst_port':80, 'proto':'tcp',
                      'conn_state':'SF' if i == len(gaps) else 'S0',
                      'history':'ShADadttfF' if i == len(gaps) else 'S'}
            events.append({'ref':f'E{index:03d}', 'fields':fields, 'raw':str(fields),'source_kind':'generic'})
            index += 1
    return events


class TestNT03RetryGrounding(unittest.TestCase):
    def test_four_groups_and_evidence_refs(self):
        x = r.detect_tcp_retry_sequences(fixture())['behavioral_findings']
        self.assertEqual(len(x),1)
        self.assertEqual(x[0]['rule_id'], r.RULE)
        self.assertEqual(x[0]['details']['repeated_source_port_groups'],4)
        self.assertEqual(x[0]['details']['repeated_source_port_rows'],17)
        self.assertEqual(len(x[0]['evidence_refs']),17)
        self.assertNotIn('E001',x[0]['evidence_refs'])
        self.assertNotIn('E002',x[0]['evidence_refs'])
        self.assertIn('NOT prove', x[0]['outcome'])

    def test_persisted_grounded_detection(self):
        x = gd.detect(fixture())
        self.assertIn(r.RULE, [f['rule_id'] for f in x['behavioral_findings']])
        self.assertEqual(x['final_incident_verdict'],'human_review_required')

    def test_model_prompt_notes_present(self):
        notes = ng.prompt_notes(fixture())
        self.assertTrue(any('TCP GROUNDING' in s for s in notes))
        self.assertTrue(all('46.101.251.172' not in s for s in notes))

    def test_missing_behavior_detected(self):
        flags=ng.review_requests({'EXECUTIVE SUMMARY':'Traffic to HTTP endpoint could be web browsing.'}, fixture())
        self.assertIn('network_tcp_retry_pattern_not_identified',[x['check'] for x in flags])

    def test_identified_not_flagged(self):
        flags=ng.review_requests({'SUSPICIOUS ACTIVITIES':'Possible repeated TCP source-port reuse with S0 to SF transitions.'}, fixture())
        self.assertNotIn('network_tcp_retry_pattern_not_identified',[x['check'] for x in flags])

    def test_no_label_dependence(self):
        f=fixture()
        for ev in f[2:]:
            ev['fields']['label']='Benign'
            ev['fields']['detailed-label']='-'
        self.assertEqual(len(r.detect_tcp_retry_sequences(f)['behavioral_findings']),1)

    def test_aggregate_only_never_detection(self):
        self.assertEqual(r.detect_tcp_retry_sequences(fixture()[:2])['behavioral_findings'],[])

    def test_single_sourceport_not_triggered(self):
        self.assertEqual(r.detect_tcp_retry_sequences(fixture()[:6])['behavioral_findings'],[])

    def test_single_attempts_not_triggered(self):
        f=fixture()
        f=f[:2]+[e for e in f[2:] if e['fields']['conn_state']=='SF']
        self.assertEqual(r.detect_tcp_retry_sequences(f)['behavioral_findings'],[])

    def test_only_s0_not_triggered(self):
        f=fixture()
        f=f[:2]+[e for e in f[2:] if e['fields']['conn_state']=='S0']
        self.assertEqual(r.detect_tcp_retry_sequences(f)['behavioral_findings'],[])

    def test_udp_comparison_not_triggered(self):
        f=fixture()
        for ev in f[2:]:ev['fields']['proto']='udp'
        self.assertEqual(r.detect_tcp_retry_sequences(f)['behavioral_findings'],[])

    def test_destination_separation(self):
        f=fixture()[:10] # two complete source-port groups only
        for ev in f[6:]:ev['fields']['dst_ip']='46.101.251.173'
        self.assertEqual(r.detect_tcp_retry_sequences(f)['behavioral_findings'],[])

    def test_incomplete_timezone_rejected(self):
        f=fixture()
        for ev in f[2:]:ev['fields']['timestamp']='2019-01-10T20:06:29'
        self.assertEqual(r.detect_tcp_retry_sequences(f)['behavioral_findings'],[])

    def test_duplicate_refs_do_not_inflate(self):
        f=fixture()
        self.assertEqual(len(r.detect_tcp_retry_sequences(f+f[2:])['behavioral_findings']),1)
        self.assertEqual(len(r.detect_tcp_retry_sequences(f+f[2:])['behavioral_findings'][0]['evidence_refs']),17)

    def test_explicit_mismatch_existing_e008(self):
        event={'ref':'E008','fields':{'record_kind':r.RAW_KIND,'src_ip':'192.168.1.199',
                                    'dst_ip':'46.101.251.172','src_port':59224,'dst_port':80,'proto':'tcp'}}
        flags=ns.review_requests({'SIGNIFICANT SECURITY EVENTS':
            '- [E008] Connection from 192.168.1.199 to 46.101.251.172 on port 23 (Telnet)'},[event])
        self.assertIn('network_destination_port_mismatch',[x['check'] for x in flags])

    def test_correct_port_not_flagged(self):
        event={'ref':'E008','fields':{'record_kind':r.RAW_KIND,'src_ip':'192.168.1.199',
                                    'dst_ip':'46.101.251.172','src_port':59224,'dst_port':80}}
        flags=ns.review_requests({'SIGNIFICANT SECURITY EVENTS':
            '- [E008] Connection from 192.168.1.199 to 46.101.251.172 on port 80'},[event])
        self.assertNotIn('network_destination_port_mismatch',[x['check'] for x in flags])

    def test_ambiguous_grouped_port_not_flagged(self):
        e=fixture()[2:4]
        flags=ns.review_requests({'SIGNIFICANT SECURITY EVENTS':
            '[E003], [E004] connections from 192.168.1.199 to 46.101.251.172 on port 23'}, e)
        self.assertNotIn('network_destination_port_mismatch',[x['check'] for x in flags])

    def test_undefined_port_not_swap(self):
        event={'ref':'E008','fields':{'record_kind':r.RAW_KIND,'src_ip':'192.168.1.199',
                                    'dst_ip':'46.101.251.172','src_port':59224,'dst_port':80}}
        flags=ns.review_requests({'SIGNIFICANT SECURITY EVENTS':'[E008] flow on port 9999'},[event])
        self.assertEqual(flags,[])

if __name__ == '__main__':
    unittest.main()
