#!/usr/bin/env python3
"""DEPI P5 / SIEM-02 - safe Apache access-log replay to OpenObserve.

Only standard Python libraries are required (Python 3.10+).
--check reads the ZIP and validates/parses events without writing or uploading.
--upload performs the same checks, then asks for auth and explicit consent.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
from getpass import getpass
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib import error, request
from zipfile import ZipFile, BadZipFile

ZIP_PATH = Path(r"D:\organization-x.zip")
EXPECTED_ZIP_SHA256 = "1429caba2803c3e8c90e9fb287bc04f6f8249f8bb34712b39127044e134d631f"
ZIP_MEMBER = "organization-x/log/apache2/web-access.log"
EXPECTED_RECORDS = 3872
STREAM_NAME = "depi_web_access"
INGEST_URL = f"http://127.0.0.1:5080/api/default/{STREAM_NAME}/_json"
BATCH_SIZE = 200

# Parse the stable prefix of Apache combined-format records. Some records may
# have optional trailing fields; preserve the original line for evidence.
APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+' 
    r'\[(?P<date>[^\]]+)\]\s+' 
    r'"(?P<request>[^\"]*)"\s+' 
    r'(?P<status>[1-5][0-9]{2})\s+(?P<size>\S+)'
)


def source_records():
    if not ZIP_PATH.is_file():
        raise ValueError(f"Source ZIP not found: {ZIP_PATH}")
    content = ZIP_PATH.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != EXPECTED_ZIP_SHA256:
        raise ValueError(f"Source SHA-256 mismatch (observed {digest}); no data sent")

    try:
        with ZipFile(ZIP_PATH) as archive:
            # Reading only the target log: labels/YAML are never accessed.
            original = archive.read(ZIP_MEMBER)
    except (KeyError, BadZipFile, OSError) as exc:
        raise ValueError(f"Cannot read Apache log from ZIP: {exc}") from exc

    originals = original.splitlines(keepends=True)
    events = []
    codes = Counter()
    methods = Counter()
    for line_no, original_line in enumerate(originals, start=1):
        line = original_line.decode("utf-8", errors="replace").rstrip("\r\n")
        match = APACHE.match(line)
        if not match:
            raise ValueError(f"Unrecognized Apache entry on source line {line_no}; no data sent")
        try:
            ts = datetime.strptime(match['date'], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp on source line {line_no}: {exc}") from exc

        parts = match['request'].split()
        method = parts[0] if parts else "-"
        request_target = parts[1] if len(parts) > 1 else "-"
        version = parts[2] if len(parts) > 2 else "-"
        status = int(match['status'])
        response_size = int(match['size']) if match['size'].isdigit() else None
        utc = ts.astimezone(timezone.utc)
        codes[status] += 1
        methods[method] += 1
        events.append({
            "event_type": "apache_access",
            "project": "DEPI-P5",
            "source": "Apache-Web-Logs",
            "dataset": "zenodo_organization_x",
            "replay_mode": True,
            "test_event": False,
            "src_ip": match['ip'],
            "http_method": method,
            "http_path": request_target.split('?', 1)[0],
            "request_target": request_target,
            "http_version": version,
            "http_status": status,
            "response_bytes": response_size,
            "original_event_utc": utc.isoformat().replace("+00:00", "Z"),
            "original_minute_utc": utc.strftime("%Y-%m-%dT%H:%MZ"),
            "source_line_number": line_no,
            "source_line_sha256": hashlib.sha256(original_line).hexdigest(),
            "raw_log": line,
            # No _timestamp: OpenObserve sets ingestion-time timestamp.
        })

    if len(events) != EXPECTED_RECORDS:
        raise ValueError(f"Expected {EXPECTED_RECORDS} lines, parsed {len(events)}; no data sent")
    if sum(codes.values()) != EXPECTED_RECORDS:
        raise ValueError("Parsed status count inconsistent; no data sent")
    return events, methods, codes


def send_batch(batch, auth):
    body = json.dumps(batch, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    req = request.Request(
        INGEST_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": auth},
    )
    try:
        with request.urlopen(req, timeout=45) as resp:
            http_code = resp.status
            data = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise RuntimeError(f"OpenObserve HTTP {exc.code}; check server/token (do not retry blindly)") from exc
    except (error.URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"OpenObserve request failed: {type(exc).__name__} (do not retry blindly)") from exc

    statuses = data.get("status", []) if isinstance(data, dict) else []
    entry = next((x for x in statuses if isinstance(x, dict) and x.get("name") == STREAM_NAME), None)
    if (http_code != 200 or data.get("code") != 200 or entry is None
            or entry.get("successful") != len(batch) or entry.get("failed") != 0):
        raise RuntimeError("OpenObserve response rejected/partial; inspect stored count before any retry")


def upload(events):
    print(f"Target: {INGEST_URL}")
    print(f"Records to send: {len(events)} in batches of {BATCH_SIZE}")
    print("NOTE: This writes replay logs to OpenObserve (not the Week-2 project).")
    if input("Type UPLOAD to start: ").strip() != "UPLOAD":
        print("CANCELLED: nothing uploaded")
        return
    auth = __import__("os").environ.get("SIEM_AUTH_HEADER", "").strip()
    if not auth.startswith("Basic ") or len(auth) < 15:
        raise ValueError("Invalid Basic Authorization header; nothing uploaded")
    acknowledged = 0
    for start in range(0, len(events), BATCH_SIZE):
        batch = events[start:start + BATCH_SIZE]
        try:
            send_batch(batch, auth)
        except RuntimeError as exc:
            raise RuntimeError(f"Stopped at source row {start + 1}; {acknowledged} records confirmed so far. {exc}") from exc
        acknowledged += len(batch)
        print(f"Batch accepted: {acknowledged}/{len(events)} | failed=0", flush=True)
    print(f"STATUS: SIEM-02 WEB LOG UPLOAD PASS | accepted={acknowledged} | failed=0")
    print("Original event times are in original_event_utc; _timestamp is replay ingestion time.")
    print("Do not upload the same ZIP a second time: duplicates can result.")


def main():
    parser = argparse.ArgumentParser(description="DEPI P5 Apache / OpenObserve replay")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Verify ZIP and parse all records, no writes")
    mode.add_argument("--upload", action="store_true", help="Verify then upload with confirmation")
    args = parser.parse_args()

    print("=== SIEM-02 SOURCE VALIDATION ===")
    events, methods, codes = source_records()
    print("ZIP SHA256: MATCH")
    print(f"Apache records: {len(events)}")
    print(f"HTTP methods: {dict(methods)}")
    print(f"HTTP status codes: {dict(codes)}")
    print(f"Original first UTC: {events[0]['original_event_utc']}")
    print("Ground-truth YAML: NOT READ")
    print("Week-2 Core / Results / Reviews: UNCHANGED")
    if args.check:
        print("STATUS: SIEM-02 PREFLIGHT PASS - READ ONLY")
    else:
        upload(events)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyboardInterrupt) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        sys.exit(1)
