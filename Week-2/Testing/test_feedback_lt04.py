"""LT-04 curated feedback and narrow semantic-review regression checks."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Core import feedback_learning, feedback_semantics


def lt04_events():
    return [
        {'ref': 'E001', 'source_kind': 'linux', 'host': 'combo',
         'raw': 'Jul 27 14:41:57 combo syslog: syslogd startup succeeded', 'fields': {}},
        {'ref': 'E003', 'source_kind': 'linux', 'host': 'combo',
         'raw': 'Jul 27 14:41:57 combo kernel: BIOS-e820: 00000000ffb00000 - 0000000100000000 (reserved)', 'fields': {}},
        {'ref': 'E004', 'source_kind': 'linux', 'host': 'combo',
         'raw': 'Jul 27 14:41:57 combo syslog: klogd startup succeeded', 'fields': {}}
    ]


class Flags:
    def __init__(self): self.items = []
    def add(self, check, severity, value, message, section=None):
        self.items.append({'check': check, 'severity': severity, 'section': section})


class LT04FeedbackTests(unittest.TestCase):
    def flags(self, sections, events=None):
        f=Flags()
        feedback_semantics.add_review_requests(f, sections, events if events is not None else lt04_events())
        return {x['check'] for x in f.items}

    def test_unsupported_bios_claim_flagged(self):
        flags=self.flags({'POTENTIAL ATTACK INDICATORS': 'Potential: Unauthorized changes to the BIOS memory map ([E003]) may lead to privilege escalation or system compromise.'})
        self.assertIn('bios_boot_threat_inference_review', flags)

    def test_correct_bios_description_not_flagged(self):
        flags=self.flags({'POTENTIAL ATTACK INDICATORS': 'BIOS-e820 enumerates reserved memory during kernel startup [E003]; no observed tampering.'})
        self.assertNotIn('bios_boot_threat_inference_review', flags)

    def test_negated_bios_claim_not_flagged(self):
        flags=self.flags({'POTENTIAL ATTACK INDICATORS': 'There is no evidence of unauthorized changes to the BIOS memory map [E003].'})
        self.assertNotIn('bios_boot_threat_inference_review', flags)

    def test_no_lt04_flag_on_unrelated_non_linux_event(self):
        ev={'ref': 'E001','source_kind':'windows','host':'combo', 'raw':'BIOS-e820: kernel: syslogd startup succeeded', 'fields':{}}
        flags=self.flags({'POTENTIAL ATTACK INDICATORS': 'Unauthorized changes to the BIOS memory map [E001].'}, [ev])
        self.assertNotIn('bios_boot_threat_inference_review', flags)

    def test_confirmed_firmware_change_context_not_mislabeled(self):
        events=lt04_events()+[{'ref':'E005','source_kind':'linux','host':'combo',
            'raw':'Jul 27 14:42:00 combo kernel: unauthorized firmware modification detected', 'fields':{}}]
        flags=self.flags({'POTENTIAL ATTACK INDICATORS': 'Unauthorized changes to the BIOS memory map [E005].'}, events)
        self.assertNotIn('bios_boot_threat_inference_review', flags)

    def test_wrong_host_flagged(self):
        flags=self.flags({'LOG SOURCE': 'Source type: combo (presumably custom), hosts: localhost, time span: July 27'})
        self.assertIn('linux_syslog_host_mismatch_review',flags)
        self.assertIn('linux_syslog_source_host_confusion_review',flags)

    def test_correct_host_and_source_not_flagged(self):
        flags=self.flags({'LOG SOURCE': 'Source type: Linux Syslog, hosts: combo'})
        self.assertNotIn('linux_syslog_host_mismatch_review', flags)
        self.assertNotIn('linux_syslog_source_host_confusion_review', flags)

    def test_missing_source_host_is_not_invented(self):
        events=[dict(e,host=None) for e in lt04_events()]
        flags=self.flags({'LOG SOURCE': 'hosts: localhost, source type: combo'}, events)
        self.assertNotIn('linux_syslog_host_mismatch_review', flags)

    def test_curated_feedback_only_when_approved(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'kb.json'
            with patch.object(feedback_learning,'KB_PATH',path):
                notes=feedback_learning.prompt_guidance(lt04_events())
                self.assertFalse(any('LT04_BOOT_BASELINE' in n for n in notes))
                path.write_text(json.dumps({'schema_version':'soc-feedback-1',
                   'validated_lesson_ids':['LT04_BOOT_BASELINE']}),encoding='utf-8')
                notes=feedback_learning.prompt_guidance(lt04_events())
                self.assertTrue(any('LT04_BOOT_BASELINE' in n for n in notes))
                self.assertTrue(any('localhost' in n for n in notes))
                audit=feedback_learning.feedback_audit(lt04_events())
                self.assertIn('LT04_BOOT_BASELINE', audit['applied_reviewed_lesson_ids'])

    def test_feedback_does_not_bleed_to_ssh_or_windows(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'kb.json'
            path.write_text(json.dumps({'schema_version':'soc-feedback-1',
                'validated_lesson_ids':['LT04_BOOT_BASELINE']}), encoding='utf-8')
            with patch.object(feedback_learning,'KB_PATH',path):
                for ev in (
                    {'ref':'E001','source_kind':'linux','raw':'Jul 01 host sshd: Failed password','host':'host'},
                    {'ref':'E001','source_kind':'windows','raw':'Windows Event ID 1 BIOS-e820: syslogd startup succeeded','host':'host'},
                ):
                    self.assertFalse(any('LT04_BOOT_BASELINE' in n for n in feedback_learning.prompt_guidance([ev])))

if __name__ == '__main__':
    unittest.main()
