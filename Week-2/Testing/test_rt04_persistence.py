"""RT-04 deterministic guardrails: SYNTHETIC events only, for regression coverage.

Each flag is an analyst review request, not a proof of malicious intent.
"""
import json
import unittest
from Core import log_parser, validator

PAYLOAD = r"C:\Users\IEUser\AppData\Roaming\A1\payload.exe"

def ev(ref, event_id, image="a.exe", **data):
    d = {"Image": "C:\\Users\\IEUser\\Downloads\\" + image, "User": "IEWIN7\\IEUser"}
    if event_id == 13:
        d.update({"TargetObject": r"HKU\SID\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                  "Details": '"' + PAYLOAD + '",explorer.exe'})
    if event_id == 11:
        d.update({"TargetFilename": PAYLOAD})
    d.update(data)
    return {"source_kind": "windows", "ref": ref, "event_id": str(event_id),
            "raw": json.dumps({"event_id": event_id, "provider": "Microsoft-Windows-Sysmon", "event_data": d}),
            "fields": {"event_data." + k: v for k, v in d.items()}}

class RT04PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.events = [ev("E001", 1), ev("E002", 11), ev("E003", 13),
                       ev("E005", 1, image="payload.exe", LogonId="0xA"),
                       ev("E007", 1, image="payload.exe", LogonId="0xA")]

    def check(self, section, line, events=None):
        sections = {section: line}
        text = "## " + section + "\n" + line
        return {f["check"] for f in validator.validate_output(text, sections, self.events if events is None else events, [], [])}

    def test_claim_downloaded_from_domain_flagged(self):
        s = "A user downloaded and executed a.exe from a suspicious domain [E001]."
        self.assertIn("unsupported_download_origin", self.check("EXECUTIVE SUMMARY", s))

    def test_downloaded_to_local_folder_flagged(self):
        s = "[E001] User downloaded a.exe to C:\\Users\\IEUser\\Downloads."
        self.assertIn("unsupported_download_origin", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_positive_download_with_followup_still_flagged(self):
        s = "The user downloaded a.exe from the internet, but the source needs verification [E001]."
        self.assertIn("unsupported_download_origin", self.check("EXECUTIVE SUMMARY", s))

    def test_downloads_path_not_claim(self):
        s = "[E001] a.exe executed from the user's Downloads directory."
        self.assertNotIn("unsupported_download_origin", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_hypothetical_download_not_flagged(self):
        s = "The file may have been downloaded by a user."
        self.assertNotIn("unsupported_download_origin", self.check("EXECUTIVE SUMMARY", s))

    def test_recommendation_not_flagged(self):
        s = "Investigate whether a.exe was downloaded from the Internet."
        self.assertNotIn("unsupported_download_origin", self.check("RECOMMENDED INVESTIGATION STEPS", s))

    def test_download_evidence_suppresses_heuristic(self):
        proof = ev("E010", 1, SourceUrl="https://sample.invalid/a.exe")
        s = "[E001] User downloaded a.exe."
        self.assertNotIn("unsupported_download_origin", self.check("SIGNIFICANT SECURITY EVENTS", s, self.events + [proof]))

    def test_file_created_but_cited_only_registry_flagged(self):
        s = "[E003] A new process 'payload.exe' was created with Winlogon Shell persistence."
        self.assertIn("sysmon_13_semantic_mismatch", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_registry_set_correct_not_flagged(self):
        s = "[E003] Winlogon Shell registry value was set to include payload.exe."
        self.assertNotIn("sysmon_13_semantic_mismatch", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_file_created_proper_file_ref_not_flagged(self):
        s = "[E002] The file payload.exe was created on disk."
        self.assertNotIn("sysmon_13_semantic_mismatch", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_combined_correct_evidence_not_flagged(self):
        s = "[E002, E003] File payload.exe was created and registry value was set."
        self.assertNotIn("sysmon_13_semantic_mismatch", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_multiple_sessions_without_distinct_logons_flagged(self):
        s = "[E005, E007] Multiple executions of payload.exe across different sessions."
        self.assertIn("unsupported_multiple_sessions", self.check("POTENTIAL ATTACK INDICATORS", s))

    def test_multiple_executions_not_sessions_not_flagged(self):
        s = "[E005, E007] Multiple executions of payload.exe observed."
        self.assertNotIn("unsupported_multiple_sessions", self.check("SIGNIFICANT SECURITY EVENTS", s))

    def test_distinct_logons_of_same_image_suppress_session_flag(self):
        different = [e.copy() for e in self.events]
        different[-1] = ev("E007", 1, image="payload.exe", LogonId="0xB")
        s = "[E005, E007] Multiple executions of payload.exe across different logon sessions."
        self.assertNotIn("unsupported_multiple_sessions", self.check("SIGNIFICANT SECURITY EVENTS", s, different))

    def test_reference_notes_sysmon_11_13_and_downloads(self):
        notes = " ".join(log_parser.reference_notes(self.events))
        self.assertIn("EventID 13 = REGISTRY VALUE SET", notes)
        self.assertIn("EventID 11 = FILE CREATION", notes)
        self.assertIn("Downloads alone does NOT establish", notes)

    def test_irrelevant_linux_not_flagged(self):
        linux = [dict(e, source_kind="linux") for e in self.events]
        s = "A user downloaded a.exe from a suspicious domain."
        self.assertNotIn("unsupported_download_origin", self.check("EXECUTIVE SUMMARY", s, linux))

if __name__ == "__main__":
    unittest.main()
