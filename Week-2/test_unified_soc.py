"""Offline tests for the optional unified router; no Ollama or file writes to Week-2."""
from __future__ import annotations
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

import unified_soc as u


def sample_windows():
    return {
        'evidence_id':'E003', '_synthetic_fixture':'yes',
        'event_id':1, 'provider':'Microsoft-Windows-Sysmon', 'computer':'WIN-TEST',
        'timestamp':'2020-01-02T03:04:05Z',
        'event_data':{
            'Image':r'C:\Tools\plink.exe',
            'CommandLine':'plink.exe 10.0.0.2 -P 80 -R 127.0.0.3:4444:127.0.0.2:3389 -pw supersecret',
            'ProcessGuid':'{test-guid}', 'ProcessId':'2312'
        },
    }


def win_net(port):
    return {'_synthetic_fixture':'yes','event_id':3,'provider':'Microsoft-Windows-Sysmon',
            'event_data':{'Image':r'C:\Tools\plink.exe','ProcessGuid':'{test-guid}',
                          'ProcessId':'2312','Initiated':'true','DestinationIp':'127.0.0.2','DestinationPort':str(port)}}


def linux_ssh():
    return 'Jun 15 01:00:00 linux-test sshd[21]: Failed password for root from 10.0.0.8 port 55000 ssh2'


def network_aggregate():
    return {'record_kind':'VERIFIED_FULL_SOURCE_AGGREGATE_NOT_RAW_ZEEK_EVENT',
            'src_ip':'192.168.16.132','dst_ip':'192.168.16.130',
            'scan_pair_tcp_records':1000,'scan_pair_distinct_destination_ports':950,
            'scan_pair_conn_states':{'REJ':988,'S0':12},
            'scan_pair_first_utc':'2026-05-26T06:07:27Z','scan_pair_last_utc':'2026-05-26T06:19:45Z',
            'source_sha256':'a'*64, '_synthetic_fixture':'yes'}


def network_sample(port):
    return {'record_kind':'ZEEK_CONN_ORIGINAL_SOURCE_ROW', 'src_ip':'192.168.16.132',
            'dst_ip':'192.168.16.130','proto':'tcp','dst_port':port, '_synthetic_fixture':'yes'}


class UnifiedClassification(TestCase):
    def write(self, folder, name, events):
        p = Path(folder)/name
        p.write_text(json.dumps(events), encoding='utf-8')
        return p

    def test_mixed_classification_one_event_at_a_time(self):
        with TemporaryDirectory() as d:
            p = self.write(d,'test_mixed.json',[sample_windows(),win_net(3389), linux_ssh(),
                                                network_aggregate(),network_sample(443),
                                                {'unfamiliar_event':'something completely unknown'}])
            parsed, manifest, counts = u.load_and_route(p)
            self.assertEqual([m['family'] for m in manifest],
                             ['windows','windows','linux','network','network','unknown'])
            self.assertEqual(parsed['source_type'], 'mixed')
            self.assertEqual([e['ref'] for e in parsed['events']], ['E001','E002','E003','E004','E005','E006'])
            self.assertEqual(manifest[0]['original_evidence_id'], 'E003')
            self.assertEqual(manifest[0]['confidence'],'high')
            self.assertEqual(parsed['evidence_class'],'synthetic_fixture')
            self.assertEqual(parsed['sha256'],u.log_parser.sha256_file(p))
            self.assertEqual(counts['unknown'],1)

    def test_nt01_no_longer_generic(self):
        with TemporaryDirectory() as d:
            parsed, _, counts=u.load_and_route(self.write(d,'NT-01-focused.json',
                                                                [network_aggregate()]+[network_sample(1000+i) for i in range(7)]))
            self.assertEqual(parsed['events'][0]['source_kind'],'network')
            self.assertEqual(counts['network'],8)
            self.assertTrue(any(x['rule_id']=='NETWORK_VERTICAL_PORT_SCAN' or 'SCAN' in x['rule_id']
                                for x in u.grounded_detection.detect(parsed['events'])['behavioral_findings']))

    def test_zeek_tsv_with_explicit_field_header(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'conn.log'
            p.write_text('#separator \u005cx09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n'
                         '1792712486.123\tC1\t192.168.16.132\t44000\t192.168.16.130\t80\ttcp\tREJ\n', encoding='utf-8')
            parsed, _, counts=u.load_and_route(p)
            self.assertEqual(counts['network'],1)
            self.assertEqual(parsed['events'][0]['fields']['id.orig_h'],'192.168.16.132')
            self.assertEqual(parsed['events'][0]['src_ip'],'192.168.16.132')
            self.assertEqual(parsed['events'][0]['timestamp_raw'],'1792712486.123')

    def test_apache_combined_log_enrichment(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'access.log'
            p.write_text('192.0.2.11 - - [07/Oct/2025:02:14:03 +0000] "GET /3.php?x=1 HTTP/1.1" 200 128\n', encoding='utf-8')
            parsed, _, counts=u.load_and_route(p)
            self.assertEqual(counts['network'],1)
            self.assertEqual(parsed['events'][0]['fields']['http_path'],'/3.php')
            self.assertEqual(parsed['events'][0]['timestamp_utc'],'2025-10-07T02:14:03+00:00')

    def test_syslog_and_linux_audit(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'audit.log'
            p.write_text('type=PROCTITLE msg=audit(1700000.234:2): argv=["sudo","chmod","u+s","/bin/example"]\n'
                         +linux_ssh()+'\n', encoding='utf-8')
            parsed,_,counts=u.load_and_route(p)
            self.assertEqual(counts['linux'],2)

    def test_windows_plink_facts_and_no_invented_processes(self):
        with TemporaryDirectory() as d:
            p=self.write(d,'windows.json',[sample_windows(),win_net(3389),win_net(3389)])
            parsed,_,_=u.load_and_route(p)
            facts=u.plink_evidence(parsed['events'])
            self.assertEqual(len(facts),1)
            self.assertEqual(facts[0]['process_creation_records'],1)
            self.assertEqual(facts[0]['tcp_connection_records'],2)
            self.assertTrue(facts[0]['command_line_password_present'])
            self.assertNotIn('supersecret', json.dumps(facts))
            flags=u.check_ai_claims({
                'EXECUTIVE SUMMARY':'This activity does not appear malicious at first glance.',
                'SIGNIFICANT SECURITY EVENTS':'A user is running plink.exe multiple times.',
                'SUSPICIOUS ACTIVITIES':'A reverse SSH tunnel was established.'},parsed['events'])
            self.assertEqual({x['check'] for x in flags},{'plink_unverified_benign_reassurance',
                                                           'plink_process_vs_connections','plink_unproven_tunnel_success'})
            self.assertEqual(u.check_ai_claims({'EXECUTIVE SUMMARY':'No evidence that the tunnel was established'},parsed['events']),[])

    def test_no_guessing_from_file_name(self):
        with TemporaryDirectory() as d:
            p=self.write(d,'Windows.json',[{'foo':'bar'}])
            _,_,counts=u.load_and_route(p)
            self.assertEqual(counts['unknown'],1)

    def test_wazuh_windows_origin_and_unknown_wazuh(self):
        with TemporaryDirectory() as d:
            base={'rule':{'id': '3000','level': 5},'agent':{'id':'42','name':'test'},'decoder':{'name':'json'}}
            w={**base,'data':{'win':{'system':{'eventID':'4625'},'eventdata':{'targetUserName':'t'}}}}
            p=self.write(d,'wazuh.json',[w,base])
            parsed,_,counts=u.load_and_route(p)
            self.assertEqual(counts['windows'],1)
            self.assertEqual(counts['wazuh'],1)
            self.assertEqual(parsed['events'][0]['source_kind'],'wazuh')  # Core triage still works

    def test_redaction_keeps_input_unchanged_and_hides_sensitive_data(self):
        with TemporaryDirectory() as d:
            p=self.write(d,'x.json',[sample_windows()]); before=p.read_bytes()
            parsed,_,_=u.load_and_route(p)
            safe=u.redact_object(parsed['events'][0])
            self.assertIn('-pw [REDACTED]',safe['fields']['event_data.CommandLine'])
            self.assertNotIn('supersecret', json.dumps(safe))
            self.assertIn('supersecret',p.read_text())
            self.assertEqual(p.read_bytes(),before)
            self.assertIn('supersecret',parsed['events'][0]['raw'])

    def test_tcp_sample_not_duplicate_process(self):
        with TemporaryDirectory() as d:
            p=self.write(d,'x.json',[win_net(3389)])
            routed,_,_=u.load_and_route(p)
            self.assertEqual(u.plink_evidence(routed['events']),[])

    def test_unsupported_ambiguous_is_unknown(self):
        e={'ref':'E001','source_kind':'generic','raw':'EventID=1 type=SYSCALL', 'fields':{}}
        self.assertEqual(u.classify_event(e)['family'],'unknown')

    def test_api_does_not_mutate_core_reference_function(self):
        original=u.log_parser.reference_notes
        with u._extra_notes(['CLEAN NOTE']):
            self.assertIsNot(u.log_parser.reference_notes, original)
        self.assertIs(u.log_parser.reference_notes, original)


if __name__=='__main__':
    import unittest
    unittest.main()

class UnifiedWorkflow(TestCase):
    def test_real_pipeline_with_mock_model_and_sandboxed_outputs(self):
        """Tests integration into Core analysis/store, not a claim of actual Mistral success."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            p = root / 'mixed.json'
            p.write_text(json.dumps([sample_windows(), win_net(3389),
                                     linux_ssh(), network_aggregate(), network_sample(1234),
                                     {'unsupported':'unknown source'}]), encoding='utf-8')
            model_response = '\n'.join(f'## {name}\nInsufficient evidence to confirm compromise.'
                                       for name in u.analysis.HEADINGS['log_analysis'])
            captured_prompts = []
            def fake_generate(prompt, **kwargs):
                captured_prompts.append(prompt)
                return u.ollama_client.GenerationResult(
                    text=model_response, model=kwargs['model'],
                    options_used=dict(u.config.GENERATION), attempts=[{'attempt':1}],
                    done_reason='stop', wall_seconds=1.0)

            with mock.patch.object(u.config, 'RESULTS_DIR', root/'Results'), \
                 mock.patch.object(u.config, 'VALIDATION_DIR', root/'Validation'), \
                 mock.patch.object(u.ollama_client, 'check_environment', return_value={
                     'server_up': True, 'installed': [u.config.PRIMARY_MODEL]}), \
                 mock.patch.object(u.ollama_client, 'generate', side_effect=fake_generate):
                manifest = u.run_ai(p, max_events_per_call=16)
                self.assertEqual(len(manifest['analysis_runs']),3)
                self.assertEqual(manifest['unknown_refs_not_sent_to_ai'],['E006'])
                self.assertEqual([r['family'] for r in manifest['analysis_runs']],
                                 ['windows','linux','network'])
                out = next((root/'Results').glob('UNIFIED-*/manifest.json'))
                self.assertTrue(out.is_file())
                self.assertTrue(out.with_name('report.md').is_file())
                for r in manifest['analysis_runs']:
                    rec = json.loads((root/'Results'/r['analysis_id']/'analysis.json').read_text())
                    self.assertEqual(rec['review']['status'],'Pending Review')
                    self.assertEqual(rec['unified']['family'],r['family'])
                    self.assertEqual(rec['input']['sha256'],u.log_parser.sha256_file(p))
                    self.assertNotIn('supersecret',json.dumps(rec))
                self.assertEqual(len(captured_prompts),3)
                self.assertTrue(any('WINDOWS GROUNDED FACT' in x for x in captured_prompts))
                self.assertNotIn('supersecret','\n'.join(captured_prompts))

class MixedArtifact(TestCase):
    def test_mix_existing_json_list_with_text_items(self):
        with TemporaryDirectory() as d:
            root=Path(d)
            a=root/'mixed_source.json'
            a.write_text(json.dumps([sample_windows(),linux_ssh(),network_sample(9000)]),encoding='utf-8')
            b=root/'other.log'
            b.write_text(linux_ssh()+'\n',encoding='utf-8')
            dest=root/'mix2.json'
            u.create_mixed_file([a,b],dest)
            _,_,counts=u.load_and_route(dest)
            self.assertEqual(counts['windows'],1)
            self.assertEqual(counts['linux'],2)
            self.assertEqual(counts['network'],1)

    def test_mix_no_overwrite_and_retains_provenance(self):
        with TemporaryDirectory() as d:
            root=Path(d)
            a=root/'win.json'; a.write_text(json.dumps([sample_windows(),win_net(3389)]),encoding='utf-8')
            b=root/'linux.log'; b.write_text(linux_ssh()+'\n',encoding='utf-8')
            c=root/'net.json'; c.write_text(json.dumps([network_aggregate(),network_sample(1000)]),encoding='utf-8')
            dest=root/'mixed.json'
            original=[p.read_bytes() for p in (a,b,c)]
            u.create_mixed_file([a,b,c],dest)
            parsed,decisions,counts=u.load_and_route(dest)
            self.assertEqual(dict(counts),{'windows':2,'linux':1,'network':2})
            self.assertEqual(parsed['events'][2]['meta']['original_source']['file'],'linux.log')
            self.assertEqual(parsed['events'][0]['meta']['original_source']['sha256'],u.log_parser.sha256_file(a))
            self.assertNotIn('supersecret',dest.read_text())
            self.assertEqual([p.read_bytes() for p in (a,b,c)],original)
            with self.assertRaises(FileExistsError):
                u.create_mixed_file([a,b,c],dest)
