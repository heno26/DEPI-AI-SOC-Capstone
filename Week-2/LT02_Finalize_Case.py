#!/usr/bin/env python3
"""LT-02 Auditd evidence finalization (non-destructive, standard library only).

Run from the Week-2 project root:
    python LT02_Finalize_Case.py

Creates only three new documents after explicit FINALIZE confirmation.
The original dataset, normalized sample, mapping, AI results, reviews,
application code, and prior cases are never modified.
"""

import csv
import hashlib
import io
import json
import re
import shlex
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

CASE_ID = "LT-02"
ANALYSIS_ID = "AN-20261018-221905-552c"
BASE = Path("Data/Real-Datasets/Linux-Attacks/LT-02-Privilege-Escalation")
SOURCE_FILE = "LT-02-Auditd-original.log"
FOCUSED_FILE = "LT-02-normalized-focused.log"
MAPPING_FILE = "LT-02-evidence-mapping.csv"
SOURCE_MANIFEST = "LT-02-Source-Manifest.json"
SELECTION_MANIFEST = "LT-02-Selection-Manifest.json"
TIMELINE_FILE = "LT-02-Verified-Timeline.csv"
CASE_FILE = "LT-02-Case-Study.md"
FINAL_MANIFEST = "LT-02-Final-Verification-Manifest.json"

AUDIT_RE = re.compile(
    r"type=PROCTITLE\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s+proctitle=([0-9A-Fa-f]+)"
)
NORMAL_RE = re.compile(
    r"(?P<utc>\S+) auditd PROCTITLE "
    r"ref=(?P<ref>E\d{3}) "
    r"audit_serial=(?P<serial>\d+) "
    r"source_line=(?P<source_line>\d+) "
    r"category=(?P<category>[a-z_]+) "
    r"argv=(?P<argv>\[.*?\]) "
    r"execution_result=not_available "
    r"authentication_result=not_available "
    r"host=not_recorded"
)

EXPECTED_PATTERNS = {
    ("sudo", "setcap", "cap_setuid+ep", "./priv_esc"): ("capability_change_candidate", 6),
    ("sudo", "chmod", "u+s", "vuln"): ("suid_change_candidate", 6),
    ("sudo", "systemctl", "status", "SplunkForwarder.service"): ("service_status_context", 3),
    ("sudo", "/opt/splunkforwarder/bin/splunk", "restart"): ("service_restart_context", 3),
    ("sudo", "systemctl", "status", "auditd.service"): ("service_status_context", 3),
}


def require(condition, description):
    if not condition:
        raise ValueError("FAIL: " + description)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def epoch_to_utc(epoch):
    whole, dot, fraction = epoch.partition(".")
    require(len(fraction) <= 6, "Audit timestamp has unsupported precision")
    dt = datetime.fromtimestamp(int(whole), tz=timezone.utc)
    if dot:
        dt += timedelta(microseconds=int(fraction.ljust(6, "0")))
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def render_csv(items, columns):
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(items)
    return buf.getvalue()


def build_case(rows, original_hash, focused_hash, mapping_hash):
    groups = defaultdict(list)
    for row in rows:
        groups[tuple(json.loads(row["command_argv_json"]))].append(row["evidence_id"])

    command_table = []
    for args, refs in sorted(groups.items(), key=lambda x: (-len(x[1]), x[0])):
        cmd = shlex.join(args)
        category = EXPECTED_PATTERNS[args][0]
        command_table.append(f"| `{cmd}` | {len(refs)} | {category} | {', '.join(refs)} |")

    first = rows[0]["timestamp_utc"]
    last = rows[-1]["timestamp_utc"]
    capability_refs = [r["evidence_id"] for r in rows if r["command_category"] == "capability_change_candidate"]
    suid_refs = [r["evidence_id"] for r in rows if r["command_category"] == "suid_change_candidate"]

    return f"""# LT-02 — Linux Auditd Privilege-Sensitive Commands: Verified Case Study

## Executive Summary

An analyst reviewed **21 normalized Linux Auditd `PROCTITLE` records** sampled from an original **108-record** attack-range dataset. Twelve selected records contain privilege-sensitive **command-line arguments**: six for `sudo chmod u+s vuln` ({', '.join(suid_refs)}) and six for `sudo setcap cap_setuid+ep ./priv_esc` ({', '.join(capability_refs)}). Nine selected records describe service inspection or restart commands, providing operational context.

**Assessment:** Potential privilege-escalation preparation / privilege-sensitive commands requiring investigation. **Neither successful execution, authorization status, nor successful privilege escalation is established** by this `PROCTITLE`-only evidence. The number of audit records must **not** be equated with a confirmed number of independent command invocations.

## Dataset and Chain of Custody

- Scenario: LT-02 — Linux Privilege Escalation Investigation.
- Source: Recorded Splunk Attack Data auditd sample (original file preserved).
- Original source: `{SOURCE_FILE}` — 108 `PROCTITLE` records.
- Focused sample: `{FOCUSED_FILE}` — 21 normalized records.
- Sample-selection strategy: deterministic time-stratified sampling across five command patterns.
- Evidence mapping: `{MAPPING_FILE}`; each `E001`–`E021` maps to the source line number, audit serial, original epoch, decoded arguments, and original raw-line SHA-256.
- Source SHA-256: `{original_hash}`.
- Focused SHA-256: `{focused_hash}`.
- Mapping SHA-256: `{mapping_hash}`.
- Original host and user identity: **not recorded** in these source records.

## Observed Commands (Focused Sample)

| Decoded argv / command | Audit records | Context category | Evidence refs |
|---|---:|---|---|
""" + "\n".join(command_table) + f"""

## Evidence-Derived Timeline

- Earliest selected timestamp (UTC): `{first}`.
- Latest selected timestamp (UTC): `{last}`.
- Verified, complete 21-row timeline: `{TIMELINE_FILE}`.
- Timestamps are converted from each original `msg=audit(<epoch>:<serial>)` value, retaining microsecond formatting. **No estimated event timestamps** are used.
- `PROCTITLE` reflects captured command arguments; it is **not** an execution-result or authentication-success record.

## Analysis and Human Review

- Original local AI analysis ID: `{ANALYSIS_ID}` (preserved; not rewritten here).
- Screenshot/CLI-observed human-review disposition: **Corrected**, with two medium validator findings categorized **Needs follow-up**.
- F001: Potential attack-indicator conclusion lacked explicit evidence references; the privilege-sensitive command records are cited above.
- F002: The model's incident timeline contained a placeholder (`...`) without evidence reference; the verified timeline CSV uses only source-derived records.
- Additional analyst findings: unsupported benign classification; unsupported attribution to administrators despite absent `uid` / `auid` / `euid`; repeated `PROCTITLE` records described as independently confirmed attempts; `auditd.service` and `SplunkForwarder.service` incorrectly treated as domains, and `auditd` source label treated as a confirmed hostname.
- **Scope of review check:** Human review status and decisions were observed in the interactive CLI. This finalization script does **not** independently inspect or certify the internal review storage schema.

## Missing Evidence / Recommended Investigation

1. Correlate the audit serials with `SYSCALL`, `EXECVE`, `PATH`, and appropriate audit-event records to investigate execution outcomes and affected files.
2. Retrieve sudo/authentication/audit user context, including `auid`, `uid`, `euid`, session information, and authorization/change records.
3. Verify target file metadata and mode bits for `vuln`, and file capabilities for `./priv_esc`; establish whether any modifications actually persisted.
4. Look for subsequent execution, `setuid` calls or effective-UID changes, and actual unauthorized access or privilege escalation.
5. Investigate SplunkForwarder/auditd service activity in context; do not infer maliciousness from use of `sudo` or an apparent restart alone.
6. Classify `*.service` values as systemd service-unit names unless independent evidence supports a domain interpretation. External reputation was **not** checked.

## Conclusion

The records demonstrate audit-log observation of potentially privilege-sensitive command arguments, **not** a confirmed successful privilege escalation or identified attacker. The original evidence, selected normalized sample, AI report, and analyst review remain unchanged. This case study and verified timeline provide an evidence-grounded companion to the preserved AI output.
"""


def preflight(project_root):
    base = project_root / BASE
    files = {name: base / name for name in (SOURCE_FILE, FOCUSED_FILE, MAPPING_FILE, SOURCE_MANIFEST, SELECTION_MANIFEST)}
    outputs = (base / TIMELINE_FILE, base / CASE_FILE, base / FINAL_MANIFEST)
    for path in files.values():
        require(path.is_file(), f"Missing required input: {path}")
    for path in outputs:
        require(not path.exists(), f"Output already exists: {path} — nothing overwritten")

    source_bytes = files[SOURCE_FILE].read_bytes()
    focused_bytes = files[FOCUSED_FILE].read_bytes()
    mapping_bytes = files[MAPPING_FILE].read_bytes()
    source_sha = digest(source_bytes)
    focused_sha = digest(focused_bytes)
    mapping_sha = digest(mapping_bytes)
    source_meta = load_json(files[SOURCE_MANIFEST])
    selection_meta = load_json(files[SELECTION_MANIFEST])

    require(source_sha.lower() == str(source_meta["sha256"]).lower(), "Original source SHA-256 mismatch")
    require(focused_sha.lower() == str(selection_meta["focused_sha256"]).lower(), "Focused log SHA-256 mismatch")
    require(mapping_sha.lower() == str(selection_meta["mapping_sha256"]).lower(), "Mapping CSV SHA-256 mismatch")
    require(source_sha.lower() == str(selection_meta["original_source_sha256"]).lower(), "Selection manifest source mismatch")
    if "file_size_bytes" in source_meta:
        require(len(source_bytes) == source_meta["file_size_bytes"], "Original source size mismatch")

    source_lines = source_bytes.decode("utf-8-sig").splitlines()
    focused_lines = focused_bytes.decode("utf-8-sig").splitlines()
    with io.StringIO(mapping_bytes.decode("utf-8-sig"), newline="") as stream:
        mapping_rows = list(csv.DictReader(stream))

    require(len(source_lines) == 108, "Expected 108 original source lines")
    require(len(focused_lines) == 21, "Expected 21 focused records")
    require(len(mapping_rows) == 21, "Expected 21 mapping records")
    require(selection_meta.get("focused_record_count") == 21, "Selection manifest count mismatch")
    require(selection_meta.get("original_record_count") == 108, "Selection manifest source count mismatch")
    require(len(selection_meta["selected_source_lines"]) == 21, "Selection manifest source-line count mismatch")

    verified_serials = set()
    verified_source_lines = set()
    selected_patterns = Counter()
    timeline_rows = []
    previous_utc = None

    for index, (normalized, row) in enumerate(zip(focused_lines, mapping_rows), 1):
        match = NORMAL_RE.fullmatch(normalized)
        require(match is not None, f"Invalid normalized record E{index:03d}")
        m = match.groupdict()
        require(m["ref"] == row["evidence_id"] == f"E{index:03d}", f"Evidence ID mismatch at row {index}")
        require(m["serial"] == row["audit_serial"], f"Serial mismatch at row {index}")
        require(m["source_line"] == row["original_line_number"], f"Source line mismatch at row {index}")
        require(m["utc"] == row["timestamp_utc"], f"Timestamp mismatch at row {index}")
        require(m["category"] == row["command_category"], f"Category mismatch at row {index}")
        require(json.loads(m["argv"]) == json.loads(row["command_argv_json"]), f"Arguments mismatch at row {index}")
        require(1 <= int(m["source_line"]) <= 108, "Invalid source-line index")
        require(int(m["source_line"]) == selection_meta["selected_source_lines"][index - 1], "Selection manifest line mismatch")

        original_line = source_lines[int(m["source_line"]) - 1]
        original_match = AUDIT_RE.search(original_line)
        require(original_match is not None, f"Invalid original audit line {m['source_line']}")
        epoch, original_serial, hex_title = original_match.groups()
        require(epoch == row["original_epoch"] and original_serial == m["serial"], f"Original audit header mismatch for {m['ref']}")
        require(digest(original_line.encode("utf-8")) == row["raw_line_sha256"].lower(), f"Original line hash mismatch for {m['ref']}")
        decoded_args = [part.decode("utf-8", errors="replace") for part in bytes.fromhex(hex_title).split(b"\x00") if part]
        require(decoded_args == json.loads(m["argv"]), f"Decoded command mismatch for {m['ref']}")
        require(epoch_to_utc(epoch) == m["utc"], f"UTC conversion mismatch for {m['ref']}")
        args_key = tuple(decoded_args)
        require(args_key in EXPECTED_PATTERNS, f"Unknown command pattern at {m['ref']}")
        require(EXPECTED_PATTERNS[args_key][0] == m["category"], f"Unexpected command category at {m['ref']}")
        require(m["serial"] not in verified_serials, f"Duplicate audit serial at {m['ref']}")
        require(m["source_line"] not in verified_source_lines, f"Duplicate source line at {m['ref']}")
        require(previous_utc is None or m["utc"] >= previous_utc, "Focused records not chronologically ordered")
        previous_utc = m["utc"]
        verified_serials.add(m["serial"])
        verified_source_lines.add(m["source_line"])
        selected_patterns[args_key] += 1

        timeline_rows.append({
            "evidence_id": m["ref"],
            "timestamp_utc": m["utc"],
            "original_epoch": epoch,
            "audit_serial": m["serial"],
            "original_source_line": m["source_line"],
            "audit_record_type": "PROCTITLE",
            "command_argv_json": json.dumps(decoded_args, ensure_ascii=False, separators=(",", ":")),
            "command_category": m["category"],
            "execution_outcome": "not_established",
            "authentication_result": "not_available",
            "host": "not_recorded",
            "user": "not_recorded",
            "original_line_sha256": row["raw_line_sha256"],
        })

    for pattern, (_, required_count) in EXPECTED_PATTERNS.items():
        require(selected_patterns[pattern] == required_count, f"Unexpected selected count for: {pattern}")

    if selected_patterns[("sudo", "chmod", "u+s", "vuln")] != 6 or selected_patterns[("sudo", "setcap", "cap_setuid+ep", "./priv_esc")] != 6:
        raise ValueError("FAIL: Sensitive-command coverage mismatch")

    csv_columns = list(timeline_rows[0].keys())
    timeline_text = render_csv(timeline_rows, csv_columns)
    case_text = build_case(mapping_rows, source_sha, focused_sha, mapping_sha)
    manifest = {
        "test_id": CASE_ID,
        "analysis_id": ANALYSIS_ID,
        "status": "documentation_complete",
        "human_review_status": "Corrected (observed in analyst CLI; review storage schema not independently validated)",
        "human_review_flags": {"F001": "needs_follow_up", "F002": "needs_follow_up"},
        "original_record_count": len(source_lines),
        "verified_focused_records": len(timeline_rows),
        "unique_audit_serials_in_focus": len(verified_serials),
        "sensitive_records_in_focus": 12,
        "context_records_in_focus": 9,
        "timestamp_standard": "UTC derived from original audit epoch; microsecond formatting",
        "claims_not_established": ["execution success", "authentication success", "actor identity", "authorization", "actual privilege escalation"],
        "artifacts_sha256": {
            SOURCE_FILE: source_sha,
            FOCUSED_FILE: focused_sha,
            MAPPING_FILE: mapping_sha,
            TIMELINE_FILE: digest(timeline_text.encode("utf-8")),
            CASE_FILE: digest(case_text.encode("utf-8")),
        },
        "source_data_modified": False,
        "ai_results_modified": False,
        "application_code_modified": False,
    }
    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    return outputs, (timeline_text, case_text, manifest_text), selected_patterns


def main():
    print("=== LT-02 FINAL EVIDENCE VERIFICATION ===")
    outputs, texts, patterns = preflight(Path.cwd())
    print("Original SHA-256: MATCH")
    print("Focused SHA-256: MATCH")
    print("Mapping SHA-256: MATCH")
    print("Evidence-to-source/serial/argv/epoch/hash: 21/21 PASS")
    print("Source records: 108 | Focused: 21 | Sensitive: 12 | Administrative context: 9")
    print("No authenticated user, host, execution success, or privilege-escalation outcome inferred.")
    print("Human review: Corrected (CLI-observed; internal review schema not verified)")
    print("\n=== FILES TO CREATE (NO OVERWRITES) ===")
    for path in outputs:
        print("CREATE:", path)
    try:
        response = input("\nType FINALIZE to create these documents (Enter cancels): ").strip()
    except EOFError:
        response = ""
    if response != "FINALIZE":
        print("CANCELLED: No files created.")
        return

    created = []
    try:
        for path, content in zip(outputs, texts):
            with path.open("x", encoding="utf-8", newline="") as handle:
                created.append(path)
                handle.write(content)
        for path, content in zip(outputs, texts):
            require(digest(path.read_bytes()) == digest(content.encode("utf-8")), f"Written document integrity mismatch: {path}")
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError as exc:
                print(f"WARNING: Could not roll back {path}: {exc}", file=sys.stderr)
        raise

    print("\n=== FINAL STATUS ===")
    print("SOURCE AND FOCUSED EVIDENCE: PRESERVED")
    print("ORIGINAL-TO-FOCUSED MAPPING: 21/21 VERIFIED")
    print("VERIFIED TIMELINE: CREATED")
    print("CASE STUDY: CREATED")
    print("INTEGRITY MANIFEST: CREATED")
    print("CORE / RESULTS / SAVED REVIEW: UNCHANGED")
    print("STATUS: LT-02 DOCUMENTATION COMPLETE (review schema verification separate)")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"STOP — {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
