"""RT-02 semantic validation regression tests. All fixture events are SYNTHETIC.

These are deterministic unit tests, NOT a rerun of the local LLM and NOT
an assertion that an intrusion occurred.
"""
import json
import unittest
from Core import analysis, log_parser, validator


def windows_event(ref, event_id, data=None):
    d = data or {}
    raw = json.dumps({"event_id": event_id, "provider": "Microsoft-Windows-Security-Auditing",
                      "event_data": d})
    return {"ref": ref, "event_id": str(event_id), "source_kind": "windows", "raw": raw}


class RT02SemanticsTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            windows_event("E001", 1102, {"SubjectUserName": "Administrator"}),
            windows_event("E002", 5145, {"ShareName": r"\\*\IPC$", "RelativeTargetName": "winreg", "SubjectUserName": "user01"}),
            windows_event("E003", 5145, {"ShareName": r"\\*\IPC$", "RelativeTargetName": "lsarpc", "SubjectUserName": "user01"}),
            windows_event("E004", 5145, {"ShareName": r"\\*\IPC$", "RelativeTargetName": "srvsvc", "SubjectUserName": "user01"}),
        ]

    def checks(self, sections, events=None):
        raw = "\n".join("## " + k + "\n" + v for k, v in sections.items())
        return validator.validate_output(raw, sections, events if events is not None else self.events, [], [])

    def test_detects_event_1102_false_logon(self):
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E001] Administrator logged on (Event ID 1102)"})
        self.assertIn("eventid_semantic_mismatch", {x["check"] for x in f})

    def test_detects_event_1102_false_creation(self):
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E001] Windows event log creation"})
        self.assertIn("eventid_semantic_mismatch", {x["check"] for x in f})

    def test_detects_false_logon_with_reference_only(self):
        f = self.checks({"INCIDENT TIMELINE": "| 2019-01-20T07:29:57Z | Administrator logged on | Source | Host | [E001] |"})
        self.assertIn("eventid_semantic_mismatch", {x["check"] for x in f})

    def test_correct_event_1102_passes(self):
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E001] Security audit log was cleared (Event ID 1102)"})
        self.assertNotIn("eventid_semantic_mismatch", {x["check"] for x in f})

    def test_logon_at_unrelated_event_not_flagged(self):
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E002] Administrator logged on"})
        self.assertNotIn("eventid_semantic_mismatch", {x["check"] for x in f})

    def test_detects_named_pipe_system_file_overclaim(self):
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E002], [E003], [E004] User user01 accessed system files"})
        self.assertIn("possible_5145_access_overclaim", {x["check"] for x in f})

    def test_named_pipe_access_check_is_not_flagged(self):
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E002], [E003] IPC$ named pipe access checks recorded"})
        self.assertNotIn("possible_5145_access_overclaim", {x["check"] for x in f})

    def test_detects_unverified_maintenance(self):
        f = self.checks({"SUSPICIOUS ACTIVITIES": "- Access outside of approved maintenance windows is suspicious [E002]"})
        self.assertIn("unsupported_maintenance_window", {x["check"] for x in f})

    def test_detects_unverified_unauthorized(self):
        f = self.checks({"POTENTIAL ATTACK INDICATORS": "- Unauthorized access to system files [E002]"})
        self.assertIn("unsupported_authorization_status", {x["check"] for x in f})

    def test_cautious_uncertainty_not_flagged(self):
        f = self.checks({"MISSING INFORMATION": "Whether access was unauthorized; review maintenance windows"})
        sem = {"eventid_semantic_mismatch", "possible_5145_access_overclaim",
               "unsupported_maintenance_window", "unsupported_authorization_status"}
        self.assertFalse({x["check"] for x in f} & sem)

    def test_reference_notes_present_for_windows_event_ids(self):
        notes = " ".join(log_parser.reference_notes(self.events))
        self.assertIn("1102", notes)
        self.assertIn("CLEARED", notes)
        self.assertIn("5145", notes)
        self.assertIn("ACCESS CHECK", notes)

    def test_timeline_rounded_timestamp_tolerance(self):
        event = dict(self.events[0], timestamp_raw="2019-01-20T07:29:57.8638931Z", timestamp_utc="2019-01-20T07:29:57.863893+00:00")
        row = {"timestamp": "2019-01-20T07:29:57.864Z", "event": "test", "refs_found": ["E001"]}
        flags = analysis.timeline_flags([row], [event])
        self.assertNotIn("timeline_timestamp_mismatch", {f["check"] for f in flags})

    def test_timeline_incorrect_time_still_detected(self):
        event = dict(self.events[0], timestamp_raw="2019-01-20T07:29:57.8638931Z", timestamp_utc="2019-01-20T07:29:57.863893+00:00")
        row = {"timestamp": "2019-01-20T07:30:47.864Z", "event": "test", "refs_found": ["E001"]}
        flags = analysis.timeline_flags([row], [event])
        self.assertIn("timeline_timestamp_mismatch", {f["check"] for f in flags})

    def test_timeline_wrong_reference_still_detected(self):
        event_a = dict(self.events[0], timestamp_raw="2019-01-20T07:29:57.8638931Z", timestamp_utc="2019-01-20T07:29:57.863893+00:00")
        event_b = dict(self.events[1], timestamp_raw="2019-01-20T07:30:10.6451168Z", timestamp_utc="2019-01-20T07:30:10.645116+00:00")
        row = {"timestamp": "2019-01-20T07:29:57.864Z", "event": "test", "refs_found": ["E002"]}
        flags = analysis.timeline_flags([row], [event_a, event_b])
        self.assertIn("timeline_timestamp_mismatch", {f["check"] for f in flags})

    def test_does_not_flag_other_sources(self):
        other = [dict(e, source_kind="linux") for e in self.events]
        f = self.checks({"SIGNIFICANT SECURITY EVENTS": "- [E001] Administrator logged on"}, events=other)
        self.assertNotIn("eventid_semantic_mismatch", {x["check"] for x in f})


if __name__ == "__main__":
    unittest.main()
