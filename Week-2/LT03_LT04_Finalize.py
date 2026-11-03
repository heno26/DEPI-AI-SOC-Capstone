#!/usr/bin/env python3
"""LT-03 + LT-04: source-derived evidence finalization (stdlib only).

Run from the DEPI Week-2 project root:
    python LT03_LT04_Finalize.py --case BOTH

Read-only integrity checks are performed before confirmation. This program
never changes originals, focused records, mappings, selection manifests, Core,
Results, or human reviews. It creates three case documents per selected case
in exclusive-create mode only after exact FINALIZE confirmation.

Review statuses are based on observed analyst console outputs, not an audit of
internal human-review storage. AI reports are not treated as source evidence.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCRIPT_VERSION = "1.0"
LT03_ID = "AN-20261018-234042-ec78"
LT03_ORIGINAL_ID = "AN-20261018-231218-e901"
LT04_ID = "AN-20261019-003000-126d"

DIR03 = Path("Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution")
DIR04 = Path("Data/Real-Datasets/Linux-Benign/LT-04-Normal-Operations")
SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[^:]+):\s*(?P<message>.*)$"
)


def need(ok, detail):
    if not ok:
        raise ValueError("VERIFICATION FAILED: " + str(detail))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def readj(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def enc(text):
    return text.encode("utf-8")


def csv_bytes(rows, columns):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, columns, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return enc(stream.getvalue())


def csv_rows(data):
    with io.StringIO(data.decode("utf-8-sig"), newline="") as stream:
        return list(csv.DictReader(stream))


def check_file_hash(label, data, expected):
    need(sha(data).lower() == str(expected).lower(), label + " SHA-256 differs from manifest")
    print(f"{label} SHA-256: MATCH")


def produce03(root):
    d = root / DIR03
    paths = {
        "source": d / "LT-03-Sysmon-original.log",
        "source_meta": d / "LT-03-Source-Manifest.json",
        "focused": d / "LT-03-focused.json",
        "mapping": d / "LT-03-evidence-mapping.csv",
        "selection": d / "LT-03-Selection-Manifest.json",
    }
    for name, path in paths.items():
        need(path.is_file(), f"LT-03 input missing ({name}): {path}")
    source, focused, mapping = (paths[k].read_bytes() for k in ("source", "focused", "mapping"))
    orig_meta, selection = (readj(paths[k]) for k in ("source_meta", "selection"))
    check_file_hash("LT-03 original", source, orig_meta["sha256"])
    need(len(source) == int(orig_meta["file_size_bytes"]), "LT-03 original file size")
    check_file_hash("LT-03 selection/source", source, selection["original_sha256"])
    check_file_hash("LT-03 focused", focused, selection["focused_sha256"])
    check_file_hash("LT-03 mapping", mapping, selection["mapping_sha256"])
    need(selection.get("test_id") == "LT-03", "LT-03 selection case ID")
    raw_lines = source.decode("utf-8-sig").splitlines()
    need(len(raw_lines) == 2 and raw_lines[0] == raw_lines[1], "LT-03 must have two exact source XML duplicate lines")
    rootxml = ET.fromstring(raw_lines[0])
    system, eventdata = rootxml.find("{*}System"), rootxml.find("{*}EventData")
    need(system is not None and eventdata is not None, "LT-03 XML sections")
    provider = system.find("{*}Provider")
    t = system.find("{*}TimeCreated")
    need(provider is not None and provider.get("Name") == "Linux-Sysmon", "LT-03 source provider")
    need(t is not None and t.get("SystemTime"), "LT-03 timestamp absent")
    timestamp = t.get("SystemTime")
    event_id = system.findtext("{*}EventID")
    record_id = system.findtext("{*}EventRecordID")
    host = system.findtext("{*}Computer")
    need(event_id == "1", "LT-03 event must be Sysmon Process Creation (1)")
    fields = {e.get("Name"): e.text or "" for e in eventdata.findall("{*}Data") if e.get("Name")}
    expected_fields = ("Image", "CommandLine", "ParentImage", "ProcessGuid", "ParentProcessGuid", "ProcessId", "ParentProcessId", "User")
    for key in expected_fields:
        need(fields.get(key), f"LT-03 missing source EventData {key}")
    command = fields["CommandLine"]
    ep = re.search(r"/dev/tcp/(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,5})(?!\d)", command)
    need(ep is not None, "LT-03 /dev/tcp target absent")
    ip, port = ep.groups()
    ipaddress.IPv4Address(ip)
    need(1 <= int(port) <= 65535, "LT-03 target port invalid")
    need(ipaddress.ip_address(ip).is_private, "LT-03 target IP is not RFC1918/private, review assessment")
    need(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z", timestamp), "LT-03 source UTC timestamp format")

    data = json.loads(focused.decode("utf-8-sig"))
    need(isinstance(data, dict) and len(data.get("events", [])) == 1, "LT-03 one focused event")
    need(data.get("source_type") == "linux", "LT-03 source_type in JSON")
    e = data["events"][0]
    need(e.get("ref") == "E001" and e.get("source_kind") == "linux", "LT-03 evidence reference/kind")
    need(e.get("timestamp_raw") == timestamp and e.get("timestamp_utc") == timestamp, "LT-03 exact timestamp")
    need(e.get("host") == host and e.get("user") == fields["User"], "LT-03 host/user mismatch")
    f = e.get("fields", {})
    for key in expected_fields:
        need(str(f.get(key)) == fields[key], f"LT-03 normalized field altered: {key}")
    need(str(f.get("EventID")) == event_id, "LT-03 normalized EventID")
    need(str(f.get("EventRecordID")) == record_id, "LT-03 normalized record ID")
    need(f.get("OriginalTimestampUTC") == timestamp, "LT-03 original timestamp in fields")
    need(f.get("CommandTargetIp") == ip and str(f.get("CommandTargetPort")) == port, "LT-03 extracted command endpoint")
    need(f.get("NetworkConnectionOutcome") == "unknown", "LT-03 outcome must be unknown")
    need(f.get("OriginalSourceLines") == [1, 2] and f.get("DuplicateRawRecords") == 2, "LT-03 duplicate context")
    for v in (command, fields["ProcessGuid"], timestamp, ip, port, "duplicate_source_lines=1,2"):
        need(v in e.get("raw", ""), "LT-03 model text missing source-bound item: " + v)
    rows = csv_rows(mapping)
    need(len(rows) == 2, "LT-03 mapping requires two original lines")
    for i, row in enumerate(rows, 1):
        need(row.get("focused_ref") == "E001", "LT-03 mapping focused ref")
        need(int(row.get("original_line", 0)) == i, "LT-03 mapping source line")
        need(row.get("event_record_id") == record_id, "LT-03 mapping record ID")
        need(row.get("process_guid") == fields["ProcessGuid"], "LT-03 mapping process GUID")
        need(row.get("timestamp_utc") == timestamp, "LT-03 mapping timestamp")
        need(row.get("raw_line_sha256") == sha(enc(raw_lines[i - 1])), "LT-03 mapping original line hash")
        need(row.get("relationship") == "exact_raw_xml_duplicate", "LT-03 duplicate relationship")
    need(selection["original_source_lines"] == [1, 2], "LT-03 selection source lines")
    need(selection["original_records"] == 2 and selection["unique_events"] == 1 and selection["focused_events"] == 1,
         "LT-03 selection counts")
    need(selection["event_record_id"] == record_id and selection["process_guid"] == fields["ProcessGuid"], "LT-03 selection IDs")
    need(selection["original_timestamp_utc"] == timestamp, "LT-03 selection UTC")
    print("LT-03: 2 source XML lines -> 1 unique event; mapping 2/2 PASS")

    cols = ["evidence_ref", "timestamp_utc", "provider", "host", "user", "event_id", "event_record_id", "image",
            "parent_image", "process_id", "parent_process_id", "process_guid", "command_line", "command_target_ip",
            "command_target_port", "original_source_lines", "network_outcome"]
    timeline = csv_bytes([dict(evidence_ref="E001", timestamp_utc=timestamp, provider="Linux-Sysmon", host=host,
          user=fields["User"], event_id=event_id, event_record_id=record_id, image=fields["Image"],
          parent_image=fields["ParentImage"], process_id=fields["ProcessId"], parent_process_id=fields["ParentProcessId"],
          process_guid=fields["ProcessGuid"], command_line=command, command_target_ip=ip,
          command_target_port=port, original_source_lines="1,2", network_outcome="unknown")], cols)
    study = f"""# LT-03 — Linux Bash Reverse-Shell Command: Verified Case Study

## Assessment

**Suspicious / high-confidence reverse-shell command pattern observed**, supported by Linux-Sysmon Process Creation [E001]. **TCP connection and interactive shell outcomes are unknown.** This is a **single-unique-event** detection test, not a multi-source incident reconstruction. The targeted `{ip}:{port}` is obtained **from CommandLine**, not a captured network session. `{ip}` is an RFC1918 private address; calling it a public Internet-routable IP is incorrect.

## Observed Source Evidence

- Provider: `Linux-Sysmon`; Event ID `1` (Process Creation); EventRecordID `{record_id}`.
- Exact source timestamp (UTC): `{timestamp}`.
- Host: `{host}`; recorded user: `{fields['User']}` (not evidence of privilege escalation).
- Image: `{fields['Image']}`; parent image: `{fields['ParentImage']}`.
- PID: `{fields['ProcessId']}`; parent PID: `{fields['ParentProcessId']}`.
- ProcessGuid: `{fields['ProcessGuid']}`.
- Source CommandLine (recorded text; **do not execute**):

```text
{command}
```

- Two source XML lines (`1`, `2`) are **byte-for-byte identical text records** including EventRecordID and ProcessGuid. They are represented by **one unique normalized event [E001]**; this is not evidence of two distinct executions.
- No Sysmon Event ID 3 network events were available in this 2-record sample. Absence of such a record here cannot rule out network activity outside the sample.

## Chain of Custody / Verified Links

- Original: `LT-03-Sysmon-original.log` — SHA-256 `{sha(source)}`.
- Focus: `LT-03-focused.json` — SHA-256 `{sha(focused)}`.
- Evidence mapping: `LT-03-evidence-mapping.csv` — SHA-256 `{sha(mapping)}`.
- `E001` maps to original lines `1` and `2`; both raw line hashes, process identifiers, EventRecordID, timestamp, and command-derived endpoint were verified against the XML.
- Full source-derived timeline: `LT-03-Verified-Timeline.csv` (one row, not two).

## AI Analysis and Analyst Corrections

- Initial analysis `{LT03_ORIGINAL_ID}`: automated validator reported **0** flags. Human analyst identified **invented netcat usage**, incorrect public/external IP implication, and imprecise source attribution. These are deficiencies in the generated narrative, not evidence of netcat execution.
- The upgraded validator's **read-only replay** raised **four review flags** for the two categories of error repeated in report sections. The source data and old AI result were not altered.
- Post-upgrade analysis `{LT03_ID}`: the repeated netcat and IP-scope claims were avoided, but the model remained insufficiently explicit about the Bash `/dev/tcp` reverse-shell pattern, source attribution, and duplicate evidence context.
- CLI-observed analyst disposition: **Corrected**. **This script does not independently verify the application's review-storage schema.**
- Automated flags assess validation rules; **0 flags does not prove a correct analysis**.

## Recommended Follow-up

1. Correlate `[E001]` ProcessGuid and PID with network/socket telemetry, firewall flows, and the destination-side logs, if available.
2. Determine whether a connection to `{ip}:{port}` was attempted at the network layer or established; investigate any follow-on shell activity.
3. Determine authorization and test-lab context before making attribution or containment recommendations.
4. Use deterministic detection for known `/dev/tcp` reverse-shell patterns, while separating **observed command** from **connection outcome**.

## Conclusion

Source-supported assessment: **suspicious Bash reverse-shell command pattern** [E001]; one observed unique Process Creation record; **network success, interactive access, malicious intent, and privilege escalation remain unconfirmed**. Original files, AI outputs, and human-review records are preserved.
"""
    manifest_facts = {
        "unique_source_records": 1, "original_xml_record_count": 2, "focused_event_count": 1,
        "evidence_mapping_verified": "2/2", "source_provider": "Linux-Sysmon",
        "timestamp_policy": "UTC timestamp exact as embedded in source XML",
        "security_assessment": "suspicious_reverse_shell_command_pattern_connection_outcome_unknown",
        "analysis_ids": [LT03_ORIGINAL_ID, LT03_ID],
        "human_review_status": "Corrected (console-observed only; review schema not independently inspected)",
        "input_sha256": {k: sha(paths[k].read_bytes()) for k in paths},
    }
    return d, {
        "LT-03-Verified-Timeline.csv": timeline,
        "LT-03-Case-Study.md": enc(study),
    }, manifest_facts


def produce04(root):
    d = root / DIR04
    paths = {
        "source": d / "LT-04-Linux-original.log",
        "source_meta": d / "LT-04-Source-Manifest.json",
        "focused": d / "LT-04-focused.log",
        "mapping": d / "LT-04-evidence-mapping.csv",
        "selection": d / "LT-04-Selection-Manifest.json",
    }
    for name, path in paths.items():
        need(path.is_file(), f"LT-04 input missing ({name}): {path}")
    source, focused, mapping = (paths[k].read_bytes() for k in ("source", "focused", "mapping"))
    source_meta, selection = (readj(paths[k]) for k in ("source_meta", "selection"))
    check_file_hash("LT-04 original", source, source_meta["sha256"])
    need(len(source) == int(source_meta["file_size_bytes"]), "LT-04 source size")
    check_file_hash("LT-04 selection/source", source, selection["source_sha256"])
    check_file_hash("LT-04 focused", focused, selection["focused_sha256"])
    check_file_hash("LT-04 mapping", mapping, selection["mapping_sha256"])
    need(selection.get("test_id") == "LT-04", "LT-04 selection case ID")
    src_line_bytes, focus_line_bytes = source.splitlines(), focused.splitlines()
    need(len(src_line_bytes) == 2000 and len(focus_line_bytes) == 18, "LT-04 source/focus line counts")
    need(selection["source_line_count"] == 2000 and selection["focused_line_count"] == 18,
         "LT-04 selection counts")
    need(selection.get("classification") == "benign_candidate_not_ground_truth", "LT-04 candidate label")
    mapping_rows = csv_rows(mapping)
    need(len(mapping_rows) == 18 and len(selection["original_source_lines"]) == 18, "LT-04 mapping count")
    line_set = set()
    events = []
    for i, (line, m) in enumerate(zip(focus_line_bytes, mapping_rows), 1):
        ref = f"E{i:03d}"
        source_n = int(m["original_source_line"])
        need(1 <= source_n <= 2000 and source_n not in line_set, "LT-04 mapping source line out of range/repeated")
        line_set.add(source_n)
        need(selection["original_source_lines"][i-1] == source_n, "LT-04 selection source-line mismatch")
        need(m["focused_ref"] == ref and int(m["focused_line"]) == i, "LT-04 evidence ref/line mismatch")
        original = src_line_bytes[source_n - 1]
        need(original == line, f"LT-04 focused file altered source line {source_n} ({ref})")
        need(m["source_line_sha256_excluding_newline"] == sha(original), "LT-04 source line hash mismatch " + ref)
        text = original.decode("utf-8")
        match = SYSLOG.fullmatch(text)
        need(match is not None, "LT-04 syslog parse failure " + ref)
        host = match.group("host")
        program = re.sub(r"\[\d+\]", "", match.group("program")).strip().lower()
        ts = f"{match.group('month')} {int(match.group('day'))} {match.group('clock')}"
        need(host == "combo" and m["original_host"] == "combo", "LT-04 hostname mismatch " + ref)
        need(m["original_program"] == program, "LT-04 program mismatch " + ref)
        need(m["original_syslog_timestamp_yearless"] == ts, "LT-04 timestamp mismatch " + ref)
        need(ts.startswith("Jul 27 "), "LT-04 unexpected date " + ref)
        # Yearless source timestamps are sortable by their explicit month/day/time
        # for this same-day subset; never assign a calendar year or timezone.
        hour, minute, second = (int(v) for v in match.group("clock").split(":"))
        need(0 <= hour < 24 and 0 <= minute < 60 and 0 <= second < 60, "LT-04 invalid timestamp")
        events.append({
            "evidence_ref": ref,
            "timestamp_as_recorded_year_and_timezone_unknown": ts,
            "host": host,
            "program": program,
            "event_message": match.group("message"),
            "original_source_line": source_n,
            "focused_line": i,
            "raw_syslog_event": text,
            "original_line_sha256": sha(original),
            "assessment_scope": "routine-looking_low-risk_candidate_not_confirmed_benign",
            "_sort": (7, 27, hour, minute, second, i),
        })
    sorted_events = sorted(events, key=lambda e: e["_sort"])
    for e in sorted_events:
        del e["_sort"]
    trim_notes = selection.get("parser_boundary_whitespace_normalization", [])
    need(isinstance(trim_notes, list), "LT-04 whitespace note type")
    for n in trim_notes:
        idx = int(n["focused_ref"][1:]) - 1
        need(0 <= idx < 18, "LT-04 whitespace note invalid ref")
        source_n = selection["original_source_lines"][idx]
        orig_text = src_line_bytes[source_n - 1].decode("utf-8")
        need(n["original_source_line"] == source_n, "LT-04 whitespace note wrong line")
        need(int(n["trailing_whitespace_chars_trimmed_by_parser"]) == len(orig_text) - len(orig_text.rstrip()),
             "LT-04 whitespace trim note mismatch")
        need(n["source_line_sha256_excluding_newline"] == sha(src_line_bytes[source_n - 1]),
             "LT-04 whitespace source hash mismatch")
    print(f"LT-04: source 2000 -> focus 18; mapping 18/18 PASS; parser display notes {len(trim_notes)}")
    cols = ("evidence_ref", "timestamp_as_recorded_year_and_timezone_unknown", "host", "program", "event_message",
            "original_source_line", "focused_line", "raw_syslog_event", "original_line_sha256", "assessment_scope")
    timeline = csv_bytes(sorted_events, cols)
    study = f"""# LT-04 — Linux Startup and Service Initialization: Verified Case Study

## Assessment

**Low-risk / benign candidate within the 18 selected records**, not verified benign ground truth for the entire host. Source events document ordinary-looking Linux startup messages. **No confirmed attack indicators were observed in this focused selection**. The 2,000-line original contains other potentially risky events; their exclusion must not be interpreted as a clean-host finding or a measured false-positive rate.

## Dataset and Evidence Provenance

- Source: Loghub `Linux/Linux_2k.log`, saved locally as `LT-04-Linux-original.log`.
- Source records: **2,000**; selected source-derived focused records: **18**.
- Host: **`combo`**, directly recorded in every selected syslog line. `localhost` in the original AI narrative is unsupported.
- Source SHA-256: `{sha(source)}`.
- Focused log SHA-256: `{sha(focused)}`.
- Mapping CSV SHA-256: `{sha(mapping)}`.
- `LT-04-evidence-mapping.csv` links `E001`–`E018` to original line numbers and raw line SHA-256 hashes.
- Focused file preserves the complete original selected syslog text, with line-ending normalization. Two documented parser-only trailing-whitespace differences **do not alter the source or focused file**; this script verified **{len(trim_notes)}** such note(s) against the source.
- Source timestamps show `Jul 27` and clock times **without an explicit year or timezone**. Neither is inferred. The verified CSV timeline is sorted by **recorded local clock time**, not by assumed UTC. For equal timestamps, source selection order is retained.

## Source-Supported Observations

- [E001], [E004]: startup-success messages for `syslogd` and `klogd`.
- [E002], [E003], [E005]–[E012], [E017], [E018]: kernel initialization and device/memory/protocol information, including the **BIOS-e820 memory map** [E003].
- [E013], [E015]: Bluetooth-related service startup-success messages.
- [E014], [E016]: network parameter initialization and loopback interface startup-success messages.
- **BIOS-e820 reserved-memory description [E003] is not evidence of unauthorized BIOS changes, credential compromise, or privilege escalation.**
- The source is not sufficient to establish authorization of all activity, system integrity, or absence of attacks outside the selected window.

## Timeline

- Full **18-row** source-verified timeline: `LT-04-Verified-Timeline.csv`.
- Every row contains an `E###` evidence ref and original source line number; **no placeholder rows (`...`) or invented UTC timestamps**.
- Messages are provided as observed, not as reconstructed outcomes. Process/service message text and source order are both traceable.

## Local AI Analysis and Human Review

- AI analysis ID: `{LT04_ID}`; model: local Mistral.
- Model correctly recognized system initialization, but suggested unsupported unauthorized BIOS modification/privilege escalation based on [E003]. It also treated the actual host `combo` as a source name and invented `localhost` as hostname.
- The old automated validator detected **one medium flag**: a timeline placeholder row with no evidence reference. Other semantic errors were documented by the human analyst.
- CLI-observed analyst review disposition: **Corrected**. This script does **not** independently inspect the review-storage schema or modify the model output.
- An event labeled `Benign Candidate` in this report is **not a true-negative ground truth claim** or a statistical false-positive-rate estimate.

## Missing Evidence and Next Checks

1. Confirm service and kernel startup context against complete boot and process telemetry, if available.
2. Check authorizations, maintenance windows, host configuration, and adjacent source events before determining broader host posture.
3. When presenting AI results, distinguish *routine-looking observed events* from a general "host is secure" assertion.
4. Keep the original yearless and timezone-less timestamps intact; external corroboration is needed before assigning absolute calendar times.
5. Add feedback rules against unsupported privilege-escalation inferences from `BIOS-e820` information and incorrect syslog hostname attribution, then run regression tests.

## Conclusion

The 18 selected log lines support a **low-risk Linux initialization candidate**, with **no evidence of a confirmed security incident in those lines**. They do not establish an entirely benign host. Human review corrected the model's false-positive inference and attribution/timeline errors. All original inputs, AI results, and reviews remain unchanged.
"""
    manifest_facts = {
        "original_source_records": 2000, "focused_event_count": 18,
        "evidence_mapping_verified": "18/18", "source_type": "Linux syslog",
        "timestamp_policy": "year and timezone absent; recorded Jul 27 clock time only; sort within same day",
        "assessment": "low_risk_benign_candidate_not_verified_host_ground_truth",
        "parser_trailing_whitespace_notes_verified": len(trim_notes),
        "analysis_ids": [LT04_ID],
        "human_review_status": "Corrected (console-observed only; review schema not independently inspected)",
        "input_sha256": {k: sha(paths[k].read_bytes()) for k in paths},
    }
    return d, {
        "LT-04-Verified-Timeline.csv": timeline,
        "LT-04-Case-Study.md": enc(study),
    }, manifest_facts


def main():
    p = argparse.ArgumentParser(description="Non-destructive LT-03/LT-04 final evidence documentation")
    p.add_argument("--case", choices=("LT-03", "LT-04", "BOTH"), default="BOTH")
    p.add_argument("--project-root", default=".", help="Week-2 project root (default: current directory)")
    args = p.parse_args()
    root = Path(args.project_root).resolve()
    need(root.is_dir(), "Invalid project root")
    ids = ("LT-03", "LT-04") if args.case == "BOTH" else (args.case,)
    print("=== LINUX LT-03 / LT-04 FINAL EVIDENCE VERIFICATION ===")
    print("Project:", root)
    cases = []
    # Entire preflight before any write (including manifest targets).
    for name in ids:
        print(f"\n=== {name} ===")
        d, payloads, details = produce03(root) if name == "LT-03" else produce04(root)
        doc_names = [*payloads, name + "-Final-Verification-Manifest.json"]
        for fn in doc_names:
            need(not (d / fn).exists(), f"Refusing to overwrite {d / fn}")
        document_hashes = {fn: sha(data) for fn, data in payloads.items()}
        final_meta = {
            "test_id": name, "verification_script": "LT03_LT04_Finalize.py", "script_version": SCRIPT_VERSION,
            "verification_result": "source_and_mapping_integrity_pass",
            "no_ai_inference_or_model_execution": True,
            "existing_original_focused_mapping_selection_core_results_reviews": "unchanged",
            "human_review_schema_independently_verified": False,
            **details,
            "created_document_sha256": document_hashes,
        }
        manifest_name = name + "-Final-Verification-Manifest.json"
        payloads[manifest_name] = enc(json.dumps(final_meta, indent=2, ensure_ascii=False) + "\n")
        cases.append((name, d, payloads))

    print("\n=== FILES TO CREATE (EXCLUSIVE; NO OVERWRITES) ===")
    for name, d, payloads in cases:
        for filename in payloads:
            print("CREATE:", d / filename)
    print("Original evidence / Core / Results / Reviews: UNCHANGED")
    answer = input("\nType FINALIZE to create these documents (Enter cancels): ").strip()
    if answer != "FINALIZE":
        print("CANCELLED: No new files were created")
        return 0
    created = []
    try:
        for name, d, payloads in cases:
            for filename, payload in payloads.items():
                path = d / filename
                with path.open("xb") as out:
                    created.append(path)
                    out.write(payload)
                need(path.read_bytes() == payload, f"Write-back mismatch {path}")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    print("\n=== FINAL STATUS ===")
    for name, d, payloads in cases:
        print(name + ": VERIFIED; CREATED " + str(len(payloads)) + " DOCUMENTS")
    print("Original / Focused / Mapping / Selection: PRESERVED")
    print("Core / Results / Human Reviews: UNCHANGED")
    print("Review status is CLI-observed; internal schema NOT independently inspected")
    print("STATUS: LINUX LT-03/LT-04 DOCUMENTATION COMPLETE")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, ET.ParseError) as exc:
        print("STOP:", exc, file=sys.stderr)
        sys.exit(1)
