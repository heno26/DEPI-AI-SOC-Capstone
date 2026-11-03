"""Week 2 automated tests.

IMPORTANT - what these tests are and are NOT:
  * Unit tests of parser / validator / store code: real code, synthetic inputs.
  * SIMULATED Ollama tests: a fake HTTP server returns canned text. This is NOT Mistral and says nothing
    about model quality, speed or GPU use.
  * Nothing here involves a genuine Wazuh alert.
Run:  python -m unittest Testing/test_week2.py -v     (from the Week-2 folder)
"""
import gzip
import json
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config
from Core import alert_triage, analysis, log_parser, ollama_client, store, validator

DATA = ROOT / "Data"
BAD = ROOT / "Testing" / "test_cases"

# ---------------------------------------------------------------- fake Ollama (SIMULATION)
class FakeOllama:
    def __init__(self, models=("mistral:7b-instruct-v0.3-q4_K_S", "llama3.2:3b"), responses=None):
        self.models = list(models)
        self.responses = list(responses or [])  # each: ("ok", text, done_reason) | ("http500", body) | ("empty",)
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": m} for m in outer.models]})
                elif self.path == "/api/version":
                    self._send(200, {"version": "SIMULATED"})
                else:
                    self._send(404, {})

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n))
                outer.requests.append(body)
                r = outer.responses.pop(0) if outer.responses else ("ok", "## EXECUTIVE SUMMARY\nx", "stop")
                if r[0] == "ok":
                    self._send(200, {"response": r[1], "done_reason": r[2], "eval_count": 100, "eval_duration": 2_000_000_000, "total_duration": 3_000_000_000})
                elif r[0] == "http500":
                    self._send(500, {"error": r[1]})
                elif r[0] == "empty":
                    self._send(200, {"response": "", "done_reason": "stop"})

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def load(rel):
    return log_parser.load_file(DATA / rel)


# ---------------------------------------------------------------- parser
class ParserTests(unittest.TestCase):
    def test_windows(self):
        p = load("Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
        self.assertEqual(p["source_type"], "windows")
        self.assertEqual(len(p["events"]), 8)
        self.assertEqual(p["events"][0]["event_id"], "4625")
        self.assertEqual(p["events"][6]["event_id"], "4624")
        self.assertEqual(p["events"][0]["timestamp_raw"], "2026-10-14 09:02:11")
        self.assertIsNone(p["events"][0]["timestamp_utc"])  # no timezone -> not normalised
        self.assertEqual(p["evidence_class"], "synthetic_fixture")

    def test_windows_4688(self):
        p = load("Windows/SYNTHETIC_W2-01_windows_process_creation_4688.log")
        self.assertTrue(all(e["source_kind"] == "windows" for e in p["events"]))
        self.assertIn("certutil", p["events"][2]["raw"])

    def test_linux(self):
        p = load("Linux/SYNTHETIC_TC-01_linux_ssh_bruteforce_then_wget.log")
        self.assertEqual(p["source_type"], "linux")
        self.assertEqual(p["events"][0]["src_ip"], "203.0.113.45")
        self.assertEqual(p["events"][0]["timestamp_raw"], "Oct 14 02:11:03")
        self.assertIsNone(p["events"][0]["timestamp_utc"])

    def test_network(self):
        p = load("Network/SYNTHETIC_W2-02_network_firewall_ids.log")
        self.assertEqual(p["source_type"], "network")
        self.assertEqual(p["events"][0]["src_ip"], "203.0.113.77")
        self.assertEqual(p["events"][0]["timestamp_utc"], "2026-10-15T08:00:01+00:00")

    def test_wazuh_formats(self):
        for name, n in (("SYNTHETIC_wazuh_alert_single.json", 1), ("SYNTHETIC_wazuh_alerts_array.json", 4),
                        ("SYNTHETIC_wazuh_alerts.ndjson", 3), ("SYNTHETIC_wazuh_alerts.ndjson.gz", 3),
                        ("SYNTHETIC_wazuh_indexer_style_hits.json", 2)):
            p = load("Wazuh/" + name)
            self.assertEqual(len(p["events"]), n, name)
            self.assertEqual(p["source_type"], "wazuh")
            self.assertEqual(p["evidence_class"], "synthetic_fixture")
        p = load("Wazuh/SYNTHETIC_wazuh_alerts_array.json")
        m = p["events"][1]["meta"]
        self.assertEqual(m["rule_level"], "10")
        self.assertEqual(m["agent_name"], "SYNTH-WIN-01")
        self.assertEqual(p["events"][1]["user"], "svc_test")
        self.assertEqual(p["events"][2]["meta"]["rule_id"], "SYNTH-0003")  # placeholder, never a real ID

    def test_missing_fields_safe(self):
        d = Path(tempfile.mkdtemp())
        f = d / "min.json"
        f.write_text(json.dumps([{"rule": {"description": "only description"}}, {"foo": "bar"}]))
        p = log_parser.load_file(f)
        self.assertIsNone(p["events"][0]["timestamp_raw"])
        self.assertIsNone(p["events"][0]["meta"]["agent_id"])
        self.assertEqual(p["evidence_class"], "user_supplied_unverified")
        self.assertIn("rule.level=None", log_parser.render_event(p["events"][0]))
        shutil.rmtree(d)

    def test_invalid_inputs(self):
        for name in ("empty.log", "invalid.json", "binary.bin", "only_comments.log"):
            with self.assertRaises(log_parser.InputError, msg=name):
                log_parser.load_file(BAD / name)
        with self.assertRaises(log_parser.InputError):
            log_parser.load_file(BAD / "does_not_exist.log")

    def test_ndjson_partial_corruption_reported(self):
        p = log_parser.load_file(BAD / "ndjson_with_bad_line.ndjson")
        self.assertEqual(len(p["events"]), 2)
        self.assertTrue(any("Skipped 1" in w for w in p["warnings"]))

    def test_original_not_modified(self):
        f = DATA / "Linux/SYNTHETIC_TC-07_linux_benign_admin.log"
        before = log_parser.sha256_file(f)
        log_parser.load_file(f)
        out, n = log_parser.sanitize_file(f, out_dir=tempfile.mkdtemp())
        self.assertEqual(before, log_parser.sha256_file(f))
        self.assertTrue(out.exists())

    def test_sanitize_redacts(self):
        d = Path(tempfile.mkdtemp())
        f = d / "s.log"
        f.write_text("login ok password=Hunter2 token=abc123 key AKIAABCDEFGHIJKLMNOP bob@example.test\n")
        out, n = log_parser.sanitize_file(f, mask_emails=True, out_dir=d / "o")
        t = out.read_text()
        self.assertNotIn("Hunter2", t)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", t)
        self.assertNotIn("bob@example.test", t)
        self.assertIn("password=Hunter2", f.read_text())

    def test_sanitize_json_stays_valid(self):
        d = Path(tempfile.mkdtemp())
        f = d / "a.json"
        f.write_text(json.dumps({"rule": {"level": 3}, "data": {"password": "Hunter2", "user": "bob"}, "full_log": "x token=zzz9"}))
        out, n = log_parser.sanitize_file(f, out_dir=d / "o")
        obj = json.loads(out.read_text())  # must still be valid JSON
        self.assertEqual(obj["data"]["password"], "[REDACTED]")
        self.assertEqual(obj["data"]["user"], "bob")
        self.assertNotIn("zzz9", out.read_text())

    def test_auth_stats_code_computed(self):
        p = load("Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
        facts = " ".join(log_parser.auth_stats(p["events"]))
        self.assertIn("6 failed logons from source 10.20.5.99 against 6 distinct", facts)
        self.assertIn("successful logon for account svc_backup", facts)

    def test_reference_notes_only_for_present_ids(self):
        p = load("Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
        txt = " ".join(log_parser.reference_notes(p["events"]))
        self.assertIn("4625", txt)
        self.assertIn("4732", txt)
        self.assertNotIn("4688", txt)

    def test_injection_scan(self):
        p = log_parser.load_file(BAD / "SYNTHETIC_injection_attempt.log")
        self.assertTrue(validator.injection_scan(p["events"]))


# ---------------------------------------------------------------- validator
def run_validate(text, rel, headings=()):
    p = load(rel)
    secs = analysis.parse_sections(text, list(headings)) if headings else {}
    return validator.validate_output(text, secs, p["events"], log_parser.auth_stats(p["events"]), list(headings))


class ValidatorTests(unittest.TestCase):
    W = "Network/SYNTHETIC_TC-08_network_waf_sqli_blocked.log"

    def checks(self, flags):
        return {f["check"] for f in flags}

    def test_unsupported_and_altered_ip(self):
        fl = run_validate("Attacker 203.0.113.61 and also 203.00.113.61 plus 192.0.2.250.", self.W)
        vals = {f["value"]: f for f in fl if f["check"] == "unsupported_ip"}
        self.assertNotIn("203.0.113.61", vals)
        self.assertIn("203.00.113.61", vals)
        self.assertIn("resembles", vals["203.00.113.61"]["message"])
        self.assertIn("192.0.2.250", vals)

    def test_malformed_ip_like(self):
        fl = run_validate("Source was 203.00113.90 here.", "Generic/SYNTHETIC_TC-11_cloudtrail_nomfa_priv_changes.log")
        self.assertIn("malformed_ip_like", self.checks(fl))

    def test_supported_values_not_flagged(self):
        fl = run_validate("[E001] src 203.0.113.61 rule 942100 at 2026-10-14T11:30:01Z request WAF-8801 on waf01.", self.W)
        self.assertEqual([f for f in fl if f["check"] in ("unsupported_ip", "unsupported_timestamp", "possible_fabricated_rule_id")], [])

    def test_timestamp_and_nonexistent_ref(self):
        fl = run_validate("At 2026-10-14 and 20260-10-14 time 11:59:59 see [E099].", self.W)
        c = self.checks(fl)
        self.assertIn("unsupported_timestamp", c)
        self.assertIn("nonexistent_evidence_ref", c)
        self.assertTrue(any(f["value"] == "20260-10-14" for f in fl))

    def test_hash_cve_url_domain_email(self):
        fl = run_validate("hash d41d8cd98f00b204e9800998ecf8427e CVE-2026-9999 hxxp://evil[.]example/x other-bad.example a@evil.example", self.W)
        c = self.checks(fl)
        for k in ("unsupported_hash", "unsupported_cve", "unsupported_url", "unsupported_domain", "unsupported_email"):
            self.assertIn(k, c)

    def test_fabricated_rule_and_agent_id(self):
        fl = run_validate("This is Wazuh rule id 5710 on agent 042.", self.W)
        self.assertIn("possible_fabricated_rule_id", self.checks(fl))
        self.assertIn("possible_fabricated_agent_id", self.checks(fl))

    def test_defang_altered(self):
        d = Path(tempfile.mkdtemp())
        f = d / "r.log"
        f.write_text("2026-10-14 10:00:00 mail01 note sender=billing@invoices-portal[.]example url=hxxps://secure-login-portal[.]example/auth\n")
        p = log_parser.load_file(f)
        fl = validator.validate_output("IOC: secure-login-portal.example", {}, p["events"], [], [])
        self.assertIn("ioc_format_altered", self.checks(fl))
        fl2 = validator.validate_output("IOC: secure-login-portal[.]example", {}, p["events"], [], [])
        self.assertNotIn("ioc_format_altered", self.checks(fl2))

    def test_event_semantics(self):
        fl = run_validate("EventID 4625 shows the user successfully logged on. EventID 4732 means a member was removed.",
                          "Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
        self.assertEqual(sum(1 for f in fl if f["check"] == "eventid_semantic_mismatch"), 2)
        ok = run_validate("EventID 4625 is a failed logon, then 4624 succeeded.", "Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
        self.assertNotIn("eventid_semantic_mismatch", self.checks(ok))

    def test_attribution_and_certainty(self):
        fl = run_validate("This is the Lazarus group. Confirmed data theft occurred.", self.W)
        self.assertIn("unsupported_attribution", self.checks(fl))
        self.assertIn("unsupported_conclusion", self.checks(fl))
        ok = run_validate("There is no evidence of ransomware and data theft is not confirmed.", self.W)
        self.assertNotIn("unsupported_attribution", self.checks(ok))

    def test_none_claim_vs_signals(self):
        text = "## SUSPICIOUS ACTIVITIES\nNone identified\n"
        fl = run_validate(text, "Windows/SYNTHETIC_TC-09_windows_edr_lsass_prevented.log", ["SUSPICIOUS ACTIVITIES"])
        self.assertIn("none_claim_vs_signals", self.checks(fl))
        benign = run_validate(text, "Windows/SYNTHETIC_TC-13_windows_approved_patch_maintenance.log", ["SUSPICIOUS ACTIVITIES"])
        self.assertNotIn("none_claim_vs_signals", self.checks(benign))

    def test_uncited_finding(self):
        text = "## SUSPICIOUS ACTIVITIES\n- Something bad happened here\n- Cited item [E001]\n"
        fl = run_validate(text, self.W, ["SUSPICIOUS ACTIVITIES"])
        self.assertEqual(sum(1 for f in fl if f["check"] == "finding_without_evidence_ref"), 1)

    def test_truncation_and_missing_sections(self):
        p = load(self.W)
        fl = validator.validate_output("## EXECUTIVE SUMMARY\nx", {"EXECUTIVE SUMMARY": "x"}, p["events"], [], ["EXECUTIVE SUMMARY", "LOG SOURCE"], truncated=True)
        self.assertIn("output_truncated", self.checks(fl))
        self.assertIn("missing_section", self.checks(fl))

    def test_ioc_context_no_reputation(self):
        p = load(self.W)
        rows = validator.ioc_context(p["events"])
        ips = [r for r in rows if r["type"] == "ipv4"]
        self.assertTrue(any(r["value"] == "203.0.113.61" and "documentation" in r["scope"] for r in ips))
        self.assertTrue(all(r["reputation"] == "External reputation not checked." for r in rows))


# ---------------------------------------------------------------- Ollama client (SIMULATED server)
class ClientTests(unittest.TestCase):
    def test_not_running(self):
        with self.assertRaises(ollama_client.OllamaNotRunning):
            ollama_client.installed_models(url="http://127.0.0.1:9")

    def test_refuses_remote_host(self):
        with self.assertRaises(ollama_client.OllamaError):
            ollama_client.installed_models(url="http://example.com:11434")

    def test_model_missing(self):
        s = FakeOllama(models=["llama3.2:3b"])
        try:
            with self.assertRaises(ollama_client.ModelNotInstalled):
                ollama_client.generate("hi", url=s.url)
            self.assertEqual(s.requests, [])  # no silent fallback to another model
        finally:
            s.close()

    def test_retry_on_repeat_limit_records_settings(self):
        s = FakeOllama(responses=[("http500", "prediction aborted, token repeat limit reached"), ("ok", "done", "stop")])
        try:
            r = ollama_client.generate("hi", url=s.url)
            self.assertTrue(r.retry_used)
            self.assertEqual(len(r.attempts), 2)
            self.assertEqual(r.attempts[0]["options"]["repeat_penalty"], 1.15)
            self.assertEqual(r.attempts[1]["options"]["repeat_penalty"], config.RETRY_OVERRIDES["repeat_penalty"])
            self.assertEqual({q["model"] for q in s.requests}, {config.PRIMARY_MODEL})
        finally:
            s.close()

    def test_no_retry_on_other_errors(self):
        s = FakeOllama(responses=[("http500", "out of memory")])
        try:
            with self.assertRaises(ollama_client.GenerationFailed) as cm:
                ollama_client.generate("hi", url=s.url)
            self.assertEqual(len(cm.exception.attempts), 1)
        finally:
            s.close()

    def test_repeat_limit_twice_fails_clearly(self):
        s = FakeOllama(responses=[("http500", "token repeat limit reached")] * 2)
        try:
            with self.assertRaises(ollama_client.GenerationFailed) as cm:
                ollama_client.generate("hi", url=s.url)
            self.assertEqual(len(cm.exception.attempts), 2)
        finally:
            s.close()

    def test_empty_and_truncated(self):
        s = FakeOllama(responses=[("empty",), ("ok", "partial", "length")])
        try:
            r = ollama_client.generate("hi", url=s.url)
            self.assertTrue(r.truncated)
            self.assertTrue(r.retry_used)
        finally:
            s.close()

    def test_options_sent_and_configurable(self):
        s = FakeOllama()
        try:
            ollama_client.generate("hi", url=s.url, options={"temperature": 0.0, "num_predict": 77})
            o = s.requests[0]["options"]
            self.assertEqual((o["temperature"], o["num_predict"], o["repeat_penalty"]), (0.0, 77, 1.15))
        finally:
            s.close()


# ---------------------------------------------------------------- full workflow (SIMULATED model output)
SIM_LOG = """## EXECUTIVE SUMMARY
Six failed logons (EventID 4625) from 10.20.5.99 then success. Linked to 203.0.113.9 and Lazarus.
## LOG SOURCE
Windows Security, DC01 and FS02.
## SIGNIFICANT SECURITY EVENTS
- Failed logons [E001] [E002]
- EventID 4625 succeeded for svc_backup [E007]
## SUSPICIOUS ACTIVITIES
- svc_backup added to Administrators [E008]
- Something with no reference
## EVIDENCE REFERENCES
[E001] failed logon
## INCIDENT TIMELINE
| Timestamp | Event | Source | Host/User | Evidence Ref |
|---|---|---|---|---|
| 2026-10-14 09:02:11 | failed logon alice | DC01 | alice | E001 |
| 2026-10-14 09:59:59 | success | DC01 | svc_backup | E007 |
## EXTRACTED IOCS
- 10.20.5.99 [E001]. External reputation not checked.
## POTENTIAL ATTACK INDICATORS
- Possible password spraying [E001]
## CONFIDENCE AND UNCERTAINTY
Medium.
## MISSING INFORMATION
Asset owner of 10.20.5.99.
## RECOMMENDED INVESTIGATION STEPS
1. Check the source host.
"""
SIM_TRIAGE = """## ALERT SUMMARY
Authorized scan.
## VERDICT
Likely False Positive
## CONFIDENCE
High - registered scanner.
## PRIORITY
P2 High
## EVIDENCE SUPPORTING MALICIOUS ACTIVITY
None
## EVIDENCE SUPPORTING BENIGN ACTIVITY
None
## RELEVANT IOCS
10.10.1.50 [E001]. External reputation not checked.
## MISSING INFORMATION
None
## ESCALATION
No - scheduled.
## ANALYST ACTIONS
1. Verify schedule.
"""
SIM_DET = """### SUGGESTION 1
Detection Gap: Failed logons are not correlated per source [E001].
Supporting Evidence: [E001] to [E006] show one source and many accounts.
Suggested Improvement: Correlate failures by source and count distinct accounts.
Expected Benefit: Earlier spray detection.
False-Positive Risk: Shared NAT addresses.
### SUGGESTION 2
Detection Gap: Admin group change after logon not linked [E008].
Supporting Evidence: [E007] then [E008].
Suggested Improvement: Correlate 4624 with 4732 from the same actor.
Expected Benefit: Faster escalation.
False-Positive Risk: Planned admin work.
"""


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.res, self.log = self.tmp / "Results", self.tmp / "Validation"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_log_analysis_end_to_end(self):
        s = FakeOllama(responses=[("ok", SIM_LOG, "stop")])
        try:
            p = load("Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
            rec = analysis.run_task("log_analysis", p, url=s.url)
        finally:
            s.close()
        self.assertEqual(rec["review"]["status"], "Pending Review")
        self.assertEqual(rec["model"]["name"], config.PRIMARY_MODEL)
        self.assertEqual(rec["prompt"]["version"], "w2-1.0")
        self.assertEqual(rec["input"]["sha256"], p["sha256"])
        checks = {f["check"] for f in rec["validation"]["flags"]}
        for expected in ("unsupported_ip", "unsupported_attribution", "eventid_semantic_mismatch", "finding_without_evidence_ref", "timeline_timestamp_mismatch"):
            self.assertIn(expected, checks)
        ip_flag = next(f for f in rec["validation"]["flags"] if f["check"] == "unsupported_ip")
        self.assertEqual(ip_flag["value"], "203.0.113.9")
        self.assertEqual(ip_flag["section"], "EXECUTIVE SUMMARY")
        self.assertEqual(len(rec["ai_output"]["timeline_rows"]), 2)
        self.assertEqual(len(rec["evidence_timeline"]), 8)

    def test_prompt_has_nonce_delimiters_and_untrusted_input(self):
        p = log_parser.load_file(BAD / "SYNTHETIC_injection_attempt.log")
        s = FakeOllama()
        try:
            rec = analysis.run_task("log_analysis", p, url=s.url)
        finally:
            s.close()
        prompt = s.requests[0]["prompt"]
        n = prompt.count("BEGIN LOG DATA ")
        self.assertEqual(n, 2)  # one mention in rules + one delimiter
        nonce = prompt.split("BEGIN LOG DATA ")[-1].split("\n")[0]
        self.assertIn(f"END LOG DATA {nonce}", prompt)
        self.assertLess(prompt.index(f"BEGIN LOG DATA {nonce}"), prompt.index("ignore all previous instructions"))
        self.assertIn("prompt_injection_in_input", {f["check"] for f in rec["validation"]["flags"]})

    def test_triage_end_to_end(self):
        s = FakeOllama(responses=[("ok", SIM_TRIAGE, "stop")])
        try:
            p = load("Generic/SYNTHETIC_TC-04_siem_alert_authorized_scan.log")
            rec = analysis.run_task("alert_triage", p, url=s.url)
        finally:
            s.close()
        t = rec["triage"]
        self.assertEqual(t["recommended_classification"], "Likely False Positive")
        self.assertEqual(t["recommended_priority"], "P2 High")
        self.assertEqual(t["original_severity"]["value"], "Medium")  # kept separate from AI priority
        self.assertEqual(t["human_review_status"], "Pending Review")
        self.assertTrue(t["alert_id"].startswith("DERIVED-"))
        checks = {f["check"] for f in rec["validation"]["flags"]}
        self.assertIn("verdict_priority_inconsistent", checks)
        self.assertIn("benign_context_not_acknowledged", checks)

    def test_triage_one_wazuh_alert_of_many(self):
        p = load("Wazuh/SYNTHETIC_wazuh_alerts_array.json")
        units = alert_triage.alert_units(p)
        self.assertEqual(len(units), 4)
        s = FakeOllama()
        try:
            rec = analysis.run_task("alert_triage", p, selected_refs={units[1][1][0]["ref"]}, url=s.url)
        finally:
            s.close()
        self.assertEqual(rec["triage"]["alert_id"], "SYNTH-ALERT-0002")
        self.assertEqual(rec["triage"]["original_severity"], {"value": "10", "source_field": "rule.level"})
        self.assertEqual(rec["input"]["events_analysed"], ["E002"])
        self.assertTrue(any(f["check"] == "triage_unparsed_field" for f in rec["validation"]["flags"]))  # canned text lacks verdict

    def test_detection_end_to_end(self):
        s = FakeOllama(responses=[("ok", SIM_DET, "stop")])
        try:
            p = load("Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log")
            rec = analysis.run_task("detection_improvement", p, url=s.url)
        finally:
            s.close()
        self.assertEqual(len(rec["suggestions"]), 2)
        self.assertIn("No Wazuh rule is modified", rec["suggestions"][0]["human_review_requirement"])
        self.assertTrue(rec["suggestions"][0]["potential_false_positive_risk"].startswith("Shared NAT"))

    def test_truncated_output_flagged_high(self):
        s = FakeOllama(responses=[("ok", "## EXECUTIVE SUMMARY\ncut off", "length")])
        try:
            rec = analysis.run_task("log_analysis", load("Linux/SYNTHETIC_TC-07_linux_benign_admin.log"), url=s.url)
        finally:
            s.close()
        self.assertTrue(rec["ai_output"]["truncated"])
        self.assertTrue(any(f["check"] == "output_truncated" and f["severity"] == "high" for f in rec["validation"]["flags"]))

    def test_input_truncation_reported(self):
        d = self.tmp / "big.log"
        d.write_text("\n".join(f"2026-10-14 10:00:{i % 60:02d} HOST01 EventID=4625 Account=user{i} SourceIP=10.0.0.{i % 250 + 1}" for i in range(400)))
        p = log_parser.load_file(d)
        s = FakeOllama()
        try:
            rec = analysis.run_task("log_analysis", p, options={"num_ctx": 2048}, url=s.url)
        finally:
            s.close()
        self.assertLess(len(rec["input"]["events_analysed"]), 400)
        self.assertTrue(any(f["check"] == "input_truncated" for f in rec["validation"]["flags"]))

    def test_save_review_export(self):
        s = FakeOllama(responses=[("ok", SIM_LOG, "stop")])
        try:
            rec = analysis.run_task("log_analysis", load("Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log"), url=s.url)
        finally:
            s.close()
        base = store.save_result(rec, self.res, self.log)
        self.assertTrue((base / "analysis.json").exists() and (base / "report.md").exists() and (base / "raw_ai_output.txt").exists())
        self.assertTrue((self.log / "validation_log.csv").exists())
        disp = {rec["validation"]["flags"][0]["id"]: "Confirmed hallucination", rec["validation"]["flags"][1]["id"]: "False alarm"}
        store.apply_review(rec, {"status": "Corrected", "analyst": "Test Analyst", "incorrect_findings": ["4625 described as success"],
                                 "hallucinations": ["203.0.113.9"], "notes": "simulated review"}, disp, self.res, self.log)
        back = store.load_result(rec["analysis_id"], self.res)
        self.assertEqual(back["review"]["status"], "Corrected")
        self.assertEqual(len(back["review"]["history"]), 1)
        self.assertEqual(back["review"]["history"][0]["status"], "Pending Review")
        with self.assertRaises(ValueError):
            store.apply_review(rec, {"status": "AutoApproved"}, None, self.res, self.log)
        v, d = store.export_markdown(self.res, self.log, self.tmp / "Det")
        self.assertIn("Confirmed hallucination", v.read_text())
        self.assertIn("PENDING LOCAL EXECUTION", d.read_text())
        csv_text = (self.log / "validation_log.csv").read_text()
        self.assertIn("analyst_review", csv_text)
        self.assertIn("Corrected", csv_text)

    def test_parse_sections_tolerant(self):
        t = "**EXECUTIVE SUMMARY**\nabc\n### 2. LOG SOURCE:\ndef\n"
        s = analysis.parse_sections(t, ["EXECUTIVE SUMMARY", "LOG SOURCE"])
        self.assertEqual(s, {"EXECUTIVE SUMMARY": "abc", "LOG SOURCE": "def"})


class CliTests(unittest.TestCase):
    """SIMULATED model (fake server). Exercises app.py flows, error messages and the interactive review."""

    def setUp(self):
        import app
        from unittest import mock
        self.app, self.mock = app, mock
        self.tmp = Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(config, "RESULTS_DIR", self.tmp / "Results"),
                        mock.patch.object(config, "VALIDATION_DIR", self.tmp / "Validation")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp)

    def run_cli(self, argv):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.app.main(argv)
        return buf.getvalue()

    def test_ollama_down_clear_message_and_nothing_saved(self):
        with self.mock.patch.object(config, "OLLAMA_URL", "http://127.0.0.1:9"):
            out = self.run_cli(["analyze", str(DATA / "Linux/SYNTHETIC_TC-07_linux_benign_admin.log"), "--no-review"])
        self.assertIn("Cannot reach Ollama", out)
        self.assertEqual(store.list_results(), [])

    def test_invalid_file_message(self):
        s = FakeOllama()
        try:
            with self.mock.patch.object(config, "OLLAMA_URL", s.url):
                out = self.run_cli(["analyze", str(BAD / "invalid.json")])
        finally:
            s.close()
        self.assertIn("INPUT ERROR", out)
        self.assertEqual(s.requests, [])

    def test_missing_model_no_silent_switch(self):
        s = FakeOllama(models=["llama3.2:3b"])
        try:
            with self.mock.patch.object(config, "OLLAMA_URL", s.url):
                out = self.run_cli(["analyze", str(DATA / "Linux/SYNTHETIC_TC-07_linux_benign_admin.log")])
        finally:
            s.close()
        self.assertIn("ollama pull " + config.PRIMARY_MODEL, out)
        self.assertEqual(s.requests, [])

    def test_analyze_then_interactive_review(self):
        s = FakeOllama(responses=[("ok", SIM_LOG, "stop")])
        try:
            with self.mock.patch.object(config, "OLLAMA_URL", s.url):
                out = self.run_cli(["analyze", str(DATA / "Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log"), "--no-review"])
        finally:
            s.close()
        self.assertIn("Pending Review", out)
        rec = store.list_results()[0]
        n = len(rec["validation"]["flags"])
        answers = iter(["h"] + ["f"] * (n - 1) + ["c", "Test Analyst", "4625 shown as success", "x", "y", "203.0.113.9", "simulated"])
        # order of prompts: flags..., status, analyst, correct, incorrect, missing, hallucinations, notes
        answers = iter(["h"] + ["f"] * (n - 1) + ["c", "Test Analyst", "a", "4625 shown as success", "x", "203.0.113.9", "simulated"])
        with self.mock.patch("builtins.input", lambda p="": next(answers)):
            import io
            from contextlib import redirect_stdout
            with redirect_stdout(io.StringIO()):
                self.app.review_interactive(rec)
        back = store.load_result(rec["analysis_id"])
        self.assertEqual(back["review"]["status"], "Corrected")
        self.assertEqual(back["review"]["incorrect_findings"], ["4625 shown as success"])
        self.assertEqual(back["validation"]["flags"][0]["analyst_disposition"], "Confirmed hallucination")

    def test_cannot_approve_with_unreviewed_flags_without_confirmation(self):
        s = FakeOllama(responses=[("ok", SIM_LOG, "stop")])
        try:
            with self.mock.patch.object(config, "OLLAMA_URL", s.url):
                self.run_cli(["analyze", str(DATA / "Windows/SYNTHETIC_TC-02_windows_password_spray_admin_group.log"), "--no-review"])
        finally:
            s.close()
        rec = store.list_results()[0]
        n = len(rec["validation"]["flags"])
        answers = iter([""] * n + ["a", "Analyst", "no", "", "", "", "", ""])
        with self.mock.patch("builtins.input", lambda p="": next(answers)):
            import io
            from contextlib import redirect_stdout
            with redirect_stdout(io.StringIO()):
                self.app.review_interactive(rec)
        self.assertEqual(store.load_result(rec["analysis_id"])["review"]["status"], "Pending Review")


if __name__ == "__main__":
    unittest.main(verbosity=2)
