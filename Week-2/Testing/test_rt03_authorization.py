"""RT-03 semantic guardrails: all fixture events in this file are SYNTHETIC.

Rules produce requests for human review, not proof of an attack or a hallucination.
"""
import json
import unittest
from Core import log_parser, validator


def sysmon_event(ref="E001", image="winrshost.exe", extra=None):
    content = {"event_id": 1, "provider": "Microsoft-Windows-Sysmon",
               "event_data": {"Image": "C:\\Windows\\System32\\" + image,
                              "User": "insecurebank\\Administrator", "IntegrityLevel": "High"}}
    if extra:
        content["event_data"].update(extra)
    return {"ref": ref, "event_id": "1", "source_kind": "windows", "raw": json.dumps(content)}


class RT03AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.events = [sysmon_event(), sysmon_event("E002", "cmd.exe"), sysmon_event("E003", "ipconfig.exe")]

    def checks(self, sections, events=None):
        text = "\n".join("## " + k + "\n" + v for k,v in sections.items())
        return [f["check"] for f in validator.validate_output(text, sections,
                    self.events if events is None else events, [], [])]

    def test_authorized_actor_positive_claim(self):
        checks = self.checks({"EXECUTIVE SUMMARY": "The actions were initiated by an authorized user and tools. [E001]"})
        self.assertIn("unsupported_authorization_status", checks)

    def test_approved_scope_positive_claim(self):
        checks = self.checks({"EXECUTIVE SUMMARY": "Actions are within the approved scope. [E001]"})
        self.assertIn("unsupported_approved_scope", checks)

    def test_approved_scope_and_authorized_claim_both_detected(self):
        checks = self.checks({"EXECUTIVE SUMMARY":
            "The actions are within the approved scope as they were initiated by an authorized user and tools. However, further investigation is needed."})
        self.assertIn("unsupported_approved_scope", checks)
        self.assertIn("unsupported_authorization_status", checks)

    def test_cautious_followup_after_positive_claim_does_not_hide_it(self):
        checks = self.checks({"CONFIDENCE AND UNCERTAINTY":
            "Low: The actions are initiated by an authorized user and tools, but more evidence is needed to confirm scope."})
        self.assertIn("unsupported_authorization_status", checks)

    def test_administrator_identity_is_not_authorization_claim(self):
        checks = self.checks({"SIGNIFICANT SECURITY EVENTS":
            "- [E001] Process ran as insecurebank\\Administrator with High IntegrityLevel."})
        self.assertNotIn("unsupported_authorization_status", checks)
        self.assertNotIn("unsupported_approved_scope", checks)

    def test_question_asking_whether_user_authorized_not_flagged(self):
        checks = self.checks({"CONFIDENCE AND UNCERTAINTY":
            "We must verify whether the command was initiated by an authorized user."})
        self.assertNotIn("unsupported_authorization_status", checks)

    def test_if_hypothetical_not_flagged(self):
        checks = self.checks({"EXECUTIVE SUMMARY":
            "If it was initiated by an authorized user, the action could be routine."})
        self.assertNotIn("unsupported_authorization_status", checks)

    def test_negated_scope_not_flagged(self):
        checks = self.checks({"EXECUTIVE SUMMARY":
            "The evidence does not establish that actions were within approved scope."})
        self.assertNotIn("unsupported_approved_scope", checks)

    def test_recommendation_section_not_flagged(self):
        checks = self.checks({"RECOMMENDED INVESTIGATION STEPS":
            "Verify whether this was initiated by an authorized user in approved scope."})
        self.assertNotIn("unsupported_authorization_status", checks)
        self.assertNotIn("unsupported_approved_scope", checks)

    def test_only_non_windows_ignored(self):
        events = [dict(e, source_kind="linux") for e in self.events]
        checks = self.checks({"EXECUTIVE SUMMARY": "An authorized user initiated the actions in approved scope."}, events)
        self.assertNotIn("unsupported_authorization_status", checks)
        self.assertNotIn("unsupported_approved_scope", checks)

    def test_explicit_approval_record_suppresses_heuristic(self):
        events = [sysmon_event(extra={"AuthorizationStatus": "Approved"})]
        checks = self.checks({"EXECUTIVE SUMMARY":
            "Actions were initiated by an authorized user within approved scope."}, events)
        self.assertNotIn("unsupported_authorization_status", checks)
        self.assertNotIn("unsupported_approved_scope", checks)

    def test_winrm_prompt_notes_caution_about_authorization(self):
        notes = " ".join(log_parser.reference_notes(self.events)).lower()
        self.assertIn("winrshost.exe", notes)
        self.assertIn("not proof of authorization", notes)


if __name__ == "__main__":
    unittest.main()
