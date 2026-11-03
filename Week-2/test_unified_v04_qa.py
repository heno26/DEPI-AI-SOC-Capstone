"""V0.4 regression controls. Offline with fixed, synthetic inputs; no Ollama."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unified_soc_v04_candidate as u

class SourceReferencesAndQuality(unittest.TestCase):
    def test_json_source_evidence_id_is_hidden_in_ai_copy(self):
        original = {'ref':'E001', 'raw': json.dumps({'provider':'Microsoft-Windows-Sysmon',
                    'evidence_id':'E023', 'event_id':1,
                    'event_data':{'Image':r'C:\\Tools\\plink.exe',
                    'CommandLine':'plink.exe -pw SECRET123 -R 8080:127.0.0.1:3389',
                    'ProcessGuid':'{test-guid}'}}),
                    'fields':{'evidence_id':'E023', 'provider':'Microsoft-Windows-Sysmon'},
                    'meta':{'original_evidence_id':'E023',
                            'original_source':{'file':'rt.json', 'ref':'E001'}},
                    'source_kind':'windows'}
        safe = u.model_safe_events([original])[0]
        self.assertIn('E023', original['raw'])
        self.assertNotIn('E023', safe['raw'])
        self.assertNotIn('SECRET123', safe['raw'])
        self.assertIsInstance(json.loads(safe['raw']), dict)
        self.assertNotIn('E023', json.dumps(safe))
        self.assertEqual(safe['ref'],'E001')
        self.assertIn('[E001]', u.log_parser.render_event(safe))

    def test_linux_original_ref_cannot_be_mistaken_for_canonical(self):
        event = {'ref':'E019','raw':'2024-08-06T01:10:00Z Linux-Audit PROCTITLE ref=E001 argv=["sudo","setcap","cap_setuid+ep","./x"]',
                 'fields':{'ref':'E001', 'audit_serial':'11'},'meta':{},'source_kind':'linux'}
        safe = u.model_safe_events([event])[0]
        self.assertNotIn('ref=E001', u.log_parser.render_event(safe))
        self.assertIn('[E019]', u.log_parser.render_event(safe))
        self.assertEqual(event['raw'].split()[2], 'PROCTITLE')
        self.assertEqual(safe['fields']['ref'],'SOURCE_ID_WITHHELD')

    def test_source_ref_embedded_in_json_string_is_hidden(self):
        original = json.dumps({'full_log': 'PROCTITLE ref=E001 argv=["sudo"]',
                                'nested':{'ref':'E032', 'text':'evidence_id=E010'}})
        cleaned = u.suppress_source_refs(original)
        self.assertNotIn('ref=E001', cleaned)
        self.assertNotIn('E032', cleaned)
        self.assertNotIn('E010', cleaned)
        self.assertIn('PROCTITLE', cleaned)

    def test_timeline_preserves_source_id_only_in_provenance(self):
        ev = {'ref':'E040', 'timestamp_raw':'2024-08-06T14:01:04.626000Z',
              'raw':'Auditd PROCTITLE ref=E001', 'fields':{},
              'meta':{'unified':{'family':'linux'},
                      'original_source':{'file':'linux.log','ref':'E001'}},
              'source_kind':'linux'}
        src=u.source_evidence_timeline([ev])
        self.assertEqual(src[0]['ref'], 'E040')
        self.assertEqual(src[0]['source_timestamp'],'2024-08-06T14:01:04.626000Z')
        self.assertEqual(src[0]['original_record'],'linux.log:E001')
        self.assertIn('arguments',src[0]['observation'])

    def test_prompt_uses_canonical_in_batch_reference_example(self):
        before = u.analysis.load_prompt('log_analysis')
        self.assertIn('such as [E003]', before[0])
        with u._extra_notes(['SAFE'], valid_ref='E021'):
            template, version, sha, _ = u.analysis.load_prompt('log_analysis')
            self.assertIn('such as [E021]', template)
            self.assertNotIn('such as [E003]', template)
            self.assertIn('unified-v04-canonical-ref', version)
            self.assertEqual(len(sha), 64)
        self.assertEqual(u.analysis.load_prompt('log_analysis'), before)

    def test_gate_blocks_incomplete_or_high_severity_drafts(self):
        blocked=u.final_quality_gate([{'qa':{'missing_or_truncated_output':True,
                                            'high_severity_flags':2}},
                                      {'qa':{'missing_or_truncated_output':False,
                                            'high_severity_flags':0}}])
        self.assertEqual(blocked['status'],'BLOCKED_PENDING_CORRECTION')
        self.assertEqual(blocked['incomplete_batch_count'],1)
        self.assertEqual(blocked['high_severity_flag_count'],2)
        self.assertFalse(blocked['human_approval_recorded'])
        self.assertEqual(u.final_quality_gate([{'qa':{'missing_or_truncated_output':False,
                                                        'high_severity_flags':0}}])['status'],
                         'HUMAN_REVIEW_REQUIRED')

    def test_report_placeholder_detected_even_when_not_token_truncated(self):
        sections={'SIGNIFICANT SECURITY EVENTS':'- ... (continued for all events)'}
        flags=u.report_safety_review(sections, '\n'.join(sections.values()), [], 'linux')
        self.assertEqual([f['check'] for f in flags],['ai_unfinished_placeholder'])

    def test_whole_pipeline_records_canonical_timeline_with_mock_model(self):
        from test_unified_soc import sample_windows, network_sample, linux_ssh
        from Core.ollama_client import GenerationResult
        from Core.analysis import HEADINGS
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            inp=root/'mixed.json'
            inp.write_text(json.dumps([sample_windows(),linux_ssh(),network_sample(8080)]),encoding='utf8')
            output='\n'.join('## '+heading+'\nInsufficient evidence.' for heading in HEADINGS['log_analysis'])
            prompted=[]
            def model(prompt, **kwargs):
                prompted.append(prompt)
                return GenerationResult(text=output, model=kwargs['model'],options_used=dict(u.config.GENERATION),
                                        attempts=[{'attempt':1}],done_reason='stop')
            with patch.object(u.config,'RESULTS_DIR',root/'Results'),\
                 patch.object(u.config,'VALIDATION_DIR',root/'Validation'),\
                 patch.object(u.ollama_client,'check_environment',return_value={'server_up':True,
                                               'installed':[u.config.PRIMARY_MODEL]}),\
                 patch.object(u.ollama_client,'generate',side_effect=model):
                manifest=u.run_ai(inp)
            self.assertEqual(len(prompted),3)
            self.assertIn('source_evidence_timeline',manifest)
            self.assertEqual([x['ref'] for x in manifest['source_evidence_timeline']],['E001','E002','E003'])
            self.assertNotIn('supersecret','\n'.join(prompted))
            # Source legacy evidence_id=E003 is NOT copied into the model's
            # visible version of Windows E001; other canonical E003 belongs to Network.
            self.assertNotIn('"evidence_id": "E003"', prompted[0])
            self.assertIn('SOURCE_ID_WITHHELD',prompted[0])
            self.assertEqual(manifest['acceptance_gate']['status'],'HUMAN_REVIEW_REQUIRED')
            unified=next((root/'Results').glob('UNIFIED-*/report.md')).read_text()
            self.assertIn('Source-derived evidence timeline (Python, not AI)',unified)
            self.assertIn('| E003 |',unified)
            self.assertIn('QA acceptance gate',unified)

if __name__ == '__main__':
    unittest.main()
