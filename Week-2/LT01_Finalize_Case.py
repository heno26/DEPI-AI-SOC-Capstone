"""LT-01 final evidence verification and documentation (read/verify inputs, create new outputs only).
Run from the Week-2 project directory: python LT01_Finalize_Case.py
No third-party dependencies. No originals, Results, Core, or reviews are modified.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TEST_ID = "LT-01"
ANALYSIS_ID = "AN-20261018-183730-901f"
TARGET_IP = "183.62.140.253"
EXPECTED_EVENTS = 42
EXPECTED_FAILED_IN_FOCUS = 13
EXPECTED_FULL_SOURCE_FAILURES_FOR_IP = 286


def fail(message: str) -> None:
    raise SystemExit(f"STOP: {message}")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().lower()


def sha_file(path: Path) -> str:
    return sha(path.read_bytes())


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"Cannot read JSON {path}: {error}")
    if not isinstance(data, dict):
        fail(f"Expected JSON object: {path}")
    return data


def check_equal(actual, expected, label: str) -> None:
    if actual != expected:
        fail(f"{label}: expected {expected!r}, found {actual!r}")


def parse_line(raw_line: str) -> dict:
    match = re.match(
        r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s*(?P<message>.*)$",
        raw_line,
    )
    if not match:
        fail(f"Unexpected selected SSH log format: {raw_line[:140]!r}")
    return match.groupdict()


def classify(message: str) -> str:
    m = message.lower()
    if "failed password" in m:
        return "failed_password"
    if "accepted password" in m or "accepted publickey" in m:
        return "accepted_authentication"
    if "invalid user" in m:
        return "invalid_user_reference"
    if "authentication failure" in m:
        return "pam_authentication_failure"
    if "disconnect" in m or "connection closed" in m:
        return "session_disconnection"
    if "connection" in m:
        return "connection_context"
    return "other_sshd_context"


def extract_failed_details(message: str) -> tuple[str, str] | None:
    m = re.search(
        r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+",
        message,
        re.IGNORECASE,
    )
    return (m.group(1), m.group(2)) if m else None


def to_csv(records: list[dict], fieldnames: list[str]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue().encode("utf-8")


def main() -> None:
    root = Path.cwd()
    if not (root / "app.py").is_file() or not (root / "Core").is_dir():
        fail("Run this script from the Week-2 project root (app.py/Core required).")

    base = root / "Data" / "Real-Datasets" / "Linux-Attacks" / "LT-01-SSH-Brute-Force"
    source = base / "OpenSSH_2k-original.log"
    focused = base / "LT-01-focused.log"
    mapping_file = base / "LT-01-evidence-mapping.csv"
    source_manifest_file = base / "LT-01-Source-Manifest.json"
    selection_manifest_file = base / "LT-01-Selection-Manifest.json"
    timeline_file = base / "LT-01-Verified-Timeline.csv"
    case_file = base / "LT-01-Case-Study.md"
    final_manifest_file = base / "LT-01-Final-Verification-Manifest.json"
    outputs = [timeline_file, case_file, final_manifest_file]

    print("=== LT-01 FINAL EVIDENCE VERIFICATION ===")
    inputs = [source, focused, mapping_file, source_manifest_file, selection_manifest_file]
    for path in inputs:
        if not path.is_file():
            fail(f"Missing input: {path}")
    for path in outputs:
        if path.exists():
            fail(f"Output already exists (nothing will be overwritten): {path}")
    result_dir = root / "Results" / ANALYSIS_ID
    if not result_dir.is_dir():
        fail(f"Saved analysis folder not found: {result_dir}")

    s_manifest = load_json(source_manifest_file)
    f_manifest = load_json(selection_manifest_file)
    if sha_file(source) != str(s_manifest.get("sha256", "")).lower():
        fail("Original source SHA-256 differs from acquisition manifest")
    if sha_file(focused) != str(f_manifest.get("focused_sha256", "")).lower():
        fail("Focused file SHA-256 differs from selection manifest")
    if str(f_manifest.get("original_source_sha256", "")).lower() != sha_file(source):
        fail("Selection manifest references a different original source")

    source_lines = source.read_text(encoding="utf-8-sig").splitlines()
    focused_lines = focused.read_text(encoding="utf-8-sig").splitlines()
    check_equal(len(source_lines), 2000, "Original line count")
    check_equal(len(focused_lines), EXPECTED_EVENTS, "Focused event count")
    check_equal(f_manifest.get("selected_event_count"), EXPECTED_EVENTS, "Manifest selected count")
    check_equal(f_manifest.get("investigation_ip"), TARGET_IP, "Investigated IP")

    with mapping_file.open("r", encoding="utf-8-sig", newline="") as inp:
        mapper = csv.DictReader(inp)
        mapping = list(mapper)
    required = {
        "evidence_id", "original_line_number", "timestamp_as_recorded",
        "sshd_pid", "raw_line_sha256",
    }
    if not mapping or not required.issubset(set(mapping[0])):
        fail(f"Mapping missing columns: {sorted(required)}")
    check_equal(len(mapping), EXPECTED_EVENTS, "Mapping row count")
    check_equal(f_manifest.get("selected_source_lines"),
                [int(r["original_line_number"]) for r in mapping], "Selection line sequence")

    event_rows: list[dict] = []
    previous_line_no = 0
    failed_users = Counter()
    focused_failures = 0
    accepted = 0
    for i, (row, focused_line) in enumerate(zip(mapping, focused_lines), 1):
        check_equal(row["evidence_id"], f"E{i:03d}", "Evidence ID")
        line_no = int(row["original_line_number"])
        if line_no <= previous_line_no or not (1 <= line_no <= len(source_lines)):
            fail(f"Invalid mapping line order at {row['evidence_id']}")
        previous_line_no = line_no
        original_line = source_lines[line_no - 1]
        check_equal(focused_line, original_line, f"Raw line for {row['evidence_id']}")
        check_equal(row["raw_line_sha256"].lower(), sha(original_line.encode("utf-8")), "Line SHA-256")
        data = parse_line(original_line)
        check_equal(row["timestamp_as_recorded"], data["time"], "Raw timestamp")
        check_equal(row["sshd_pid"], data["pid"], "Raw sshd PID")
        event_type = classify(data["message"])
        username, source_ip = "", ""
        failed = extract_failed_details(data["message"])
        if event_type == "failed_password":
            if failed is None:
                fail(f"Failed password line could not be parsed: {row['evidence_id']}")
            username, source_ip = failed
            focused_failures += 1
            failed_users[username] += 1
        if event_type == "accepted_authentication":
            accepted += 1
        event_rows.append({
            "evidence_id": row["evidence_id"],
            "source_line_number": line_no,
            "timestamp_as_recorded": data["time"],
            "year": "NOT_IN_SOURCE",
            "timezone": "NOT_IN_SOURCE",
            "host": data["host"],
            "service": "sshd",
            "pid": data["pid"],
            "event_type": event_type,
            "username_if_explicit": username,
            "source_ip_if_explicit": source_ip,
            "raw_log_line": original_line,
            "raw_line_sha256": row["raw_line_sha256"].lower(),
        })

    expected_corrected_timestamps = {
        "E003": "Dec 10 10:54:29",
        "E009": "Dec 10 10:54:31",
        "E012": "Dec 10 10:54:33",
    }
    observed_timestamps = {r["evidence_id"]: r["timestamp_as_recorded"] for r in event_rows}
    for ref, correct_time in expected_corrected_timestamps.items():
        check_equal(observed_timestamps[ref], correct_time, f"Human-reviewed timestamp for {ref}")
    check_equal(focused_failures, EXPECTED_FAILED_IN_FOCUS, "Focused Failed password count")
    check_equal(accepted, 0, "Focused successful authentication count")
    check_equal({r["host"] for r in event_rows}, {"LabSZ"}, "Focused host")
    if any(r["source_ip_if_explicit"] not in ("", TARGET_IP) for r in event_rows):
        fail("Some failed password events refer to an unexpected source IP")
    source_ip_failed_count = 0
    all_fail_count = 0
    for line in source_lines:
        details = extract_failed_details(line)
        if details:
            all_fail_count += 1
            if details[1] == TARGET_IP:
                source_ip_failed_count += 1
    check_equal(source_ip_failed_count, EXPECTED_FULL_SOURCE_FAILURES_FOR_IP,
                "Original-source failure lines for target IP")

    # This is a log-window comparison; no date year or UTC offset is inferred.
    time_first = event_rows[0]["timestamp_as_recorded"]
    time_last = event_rows[-1]["timestamp_as_recorded"]
    usernames_text = ", ".join(f"`{u}` ({n} failed password lines)"
                               for u, n in sorted(failed_users.items()))
    print("Original SHA-256: MATCH")
    print("Focused SHA-256: MATCH")
    print(f"Mapping: {len(mapping)}/{EXPECTED_EVENTS} RAW LINE/PID/TIMESTAMP/HASH MATCH")
    print(f"Focused failed password lines: {focused_failures}")
    print(f"Focused accepted authentication lines: {accepted}")
    print(f"Original-source target IP failures: {source_ip_failed_count}")
    print(f"Time range (as recorded): {time_first} to {time_last} (year/TZ not given)")
    print("Saved analysis folder: PRESENT")

    timeline_columns = list(event_rows[0].keys())
    timeline_bytes = to_csv(event_rows, timeline_columns)
    relative_source = source.relative_to(root).as_posix()
    relative_focus = focused.relative_to(root).as_posix()
    relative_map = mapping_file.relative_to(root).as_posix()
    notes = f"""# LT-01 — SSH Authentication Failure Cluster: Final Case Study

## Scope and evidence provenance

- **Test case:** LT-01 — Suspected SSH Brute Force / Password Guessing.
- **Data source:** Recorded OpenSSH dataset, `logpai/loghub`, `OpenSSH_2k.log` (local preserved copy: `{relative_source}`).
- **Focused input:** `{relative_focus}` (**42** log lines).
- **Evidence mapping:** `{relative_map}`; original source line numbers and per-line SHA-256 checks verified.
- **Host recorded:** `LabSZ`.
- **Observed log time window:** `{time_first}` through `{time_last}`. **Year and timezone are not present in these records and are not inferred.**
- **AI analysis:** `{ANALYSIS_ID}`; local Mistral 7B.
- **Human review:** `Corrected`, per analyst's saved review CLI result. The exact saved-review JSON schema was not independently checked by this documentation script.

## Verified observations

1. The complete provided dataset contains **2,000** OpenSSH log lines and **{all_fail_count}** parseable `Failed password` lines; **{source_ip_failed_count}** of those name the investigated IP **`{TARGET_IP}`**.
2. The deliberately selected **42-event focused excerpt** contains **{focused_failures}** explicit `Failed password` lines and **no `Accepted password` or `Accepted publickey` lines**. Absence of acceptance in the excerpt does **not** establish the absence of successful logons elsewhere.
3. The focused failed-password records refer to: {usernames_text}. Log messages with `invalid user` do not prove those are valid system accounts.
4. Multiple failed authentication records against different usernames in a short recorded window are **consistent with suspected SSH password-guessing/brute-force behavior**. Intent, approval context, source-IP reputation, account compromise, and campaign scope are not independently established.

## Model validation and human correction

- **Automated validation:** 6 flags in the original saved analysis: 3 medium severity missing-evidence-reference findings and 3 high severity timeline timestamp mismatches.
- **Analyst disposition:** medium missing-reference flags marked **needs follow-up**; three timestamp mismatches marked **confirmed hallucination / error**. Overall human review: **Corrected**.
- **Timestamp correction (from original source lines and mapping):**
  - `E003`: **Dec 10 10:54:29**, not the model's **Dec 10 10:54:27**.
  - `E009`: **Dec 10 10:54:31**, not the model's **Dec 10 10:54:29**.
  - `E012`: **Dec 10 10:54:33**, not the model's **Dec 10 10:54:31**.
- The attached **verified timeline CSV** includes all 42 selected events in source order and retains each event's timestamp exactly as recorded; it does not rewrite the original AI output.

## Investigation outcome

**Disposition:** Suspicious SSH authentication failure cluster — further investigation warranted. **Successful compromise is not established by this excerpt.**

**Priority next steps:** Inspect full authentication and session history around the cluster for successful logons or correlated session activity; review account validity and authorized testing; enrich the observed source IP using trusted intelligence; investigate additional hosts and time windows. Treat the investigated IP as an **observed indicator**, not automatically as a confirmed malicious IOC.

## Integrity and traceability

- Original source SHA-256: `{sha_file(source)}`.
- Focused dataset SHA-256: `{sha_file(focused)}`.
- Source, selected log lines, mapping and local analyst results were **read but not modified** by this finalization script.
- Full evidence mapping, source line hashes, and event-by-event timestamps are preserved in the timeline and original mapping file.
"""
    case_bytes = notes.encode("utf-8")
    manifest = {
        "test_id": TEST_ID,
        "analysis_id": ANALYSIS_ID,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_url": s_manifest.get("source_url"),
        "source_sha256": sha_file(source),
        "focused_sha256": sha_file(focused),
        "mapping_sha256": sha_file(mapping_file),
        "source_manifest_sha256": sha_file(source_manifest_file),
        "selection_manifest_sha256": sha_file(selection_manifest_file),
        "original_event_lines": len(source_lines),
        "focused_events": len(event_rows),
        "focus_failed_password_lines": focused_failures,
        "focused_accepted_authentication_lines": accepted,
        "original_dataset_failed_password_lines_from_investigated_ip": source_ip_failed_count,
        "investigated_ip": TARGET_IP,
        "review_status": "Corrected (analyst CLI screenshot; not independently read from saved-review schema)",
        "automated_flags_in_saved_analysis": 6,
        "model_timeline_mismatches": ["E003", "E009", "E012"],
        "timestamp_year_timezone": "Not present; not inferred",
        "verified_timeline_sha256": sha(timeline_bytes),
        "case_study_sha256": sha(case_bytes),
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    pending = [(timeline_file, timeline_bytes), (case_file, case_bytes), (final_manifest_file, manifest_bytes)]
    print("\n=== NEW DOCUMENTS TO WRITE ===")
    for path, _ in pending:
        print("CREATE:", path.relative_to(root))
    confirmation = input("\nType FINALIZE to write new files (or Enter to cancel): ").strip()
    if confirmation != "FINALIZE":
        print("CANCELLED: No files created")
        return
    created = []
    try:
        for path, payload in pending:
            with path.open("xb") as out:
                out.write(payload)
            created.append(path)
            if sha_file(path) != sha(payload):
                raise RuntimeError(f"Write verification failed: {path.name}")
    except Exception as exc:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError as cleanup_err:
                print("WARNING: Could not remove partial new output:", path, cleanup_err)
        fail(f"Output creation failed; partial outputs rollback attempted: {exc}")

    print("\n=== FINAL STATUS ===")
    print("SOURCE AND FOCUSED EVIDENCE: PRESERVED")
    print("MAPPING: 42/42 VERIFIED")
    print("VERIFIED TIMELINE: CREATED")
    print("CASE STUDY: CREATED")
    print("INTEGRITY MANIFEST: CREATED")
    print("Data originals / Results / Core / reviews: NO MODIFICATION")
    print("STATUS: LT-01 DOCUMENTATION COMPLETE (human-review schema verification separate)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCANCELLED")
        sys.exit(130)
