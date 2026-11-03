#!/usr/bin/env python3
"""NT-02: safe, pinned, verifiable acquisition of an original Zeek dns.log.

Stdlib only. Does not modify Core, Results or historical evidence.
Use --check for read-only remote verification; --acquire to create two NEW files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO = "dikshitdhawan/NTA-Zeek-Threat-Detection-Lab"
COMMIT = "bb2817e4a783dd2578383aa6e3f0adab12052904"
REMOTE_PATH = "Zeek-Logs/dns_anomaly/dns.log"
EXPECTED_BYTES = 104260
EXPECTED_GIT_BLOB_SHA1 = "752daa17b27eb584d8fbedd2da4322c661c30e30"
URL = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{REMOTE_PATH}"
REL_DIR = Path("Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly")
ORIGINAL_NAME = "NT-02-Zeek-dns-original.log"
MANIFEST_NAME = "NT-02-Source-Manifest.json"


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def git_blob_sha1(data: bytes) -> str:
    prefix = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(prefix + data).hexdigest()


def get_project_root() -> Path:
    root = Path.cwd().resolve()
    if not (root / "app.py").is_file() or not (root / "Core").is_dir():
        fail("Run from the Week-2 project root (expected app.py and Core/).")
    return root


def inspect_zeek(data: bytes) -> dict:
    try:
        text_data = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail(f"Source cannot be decoded as UTF-8: {exc}")
    lines = text_data.splitlines()
    path_values = []
    fields = []
    first_data_line = None
    data_rows = 0
    for line_no, line in enumerate(lines, 1):
        if line.startswith("#path\t"):
            path_values.append(line.split("\t", 1)[1])
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        if line and not line.startswith("#"):
            data_rows += 1
            if first_data_line is None:
                first_data_line = (line_no, line)
    if not path_values or any(p != "dns" for p in path_values):
        fail(f"Unexpected Zeek #path metadata: {path_values!r} (expected dns)")
    minimum = {"ts", "uid", "id.orig_h", "id.resp_h", "query"}
    if not minimum.issubset(fields):
        fail(f"Zeek dns.log missing expected fields: {sorted(minimum.difference(fields))}")
    if not data_rows or first_data_line is None:
        fail("Zeek dns.log has no data rows")
    # Sample-format sanity test; full row validation belongs to next inspection step.
    if len(first_data_line[1].split("\t")) != len(fields):
        fail("First data row column count does not match #fields")
    return {
        "physical_lines": len(lines),
        "zeek_path": "dns",
        "columns": len(fields),
        "field_names": fields,
        "data_rows_unvalidated": data_rows,
        "first_data_line_number": first_data_line[0],
        "first_data_line_preview": first_data_line[1][:260],
    }


def retrieve() -> bytes:
    print("Retrieving pinned source (remote READ ONLY)...")
    req = Request(URL, headers={"User-Agent": "DEPI-P5-NT02-Verification/1.0"})
    try:
        with urlopen(req, timeout=90) as response:
            return response.read(EXPECTED_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        fail(f"Source retrieval failed: {type(exc).__name__}: {exc}")


def exclusive_write(path: Path, payload: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true", help="Verify remote data, create no files")
    modes.add_argument("--acquire", action="store_true", help="Verify then save two new files with confirmation")
    args = parser.parse_args()

    root = get_project_root()
    directory = root / REL_DIR
    source = directory / ORIGINAL_NAME
    manifest = directory / MANIFEST_NAME

    print("=== NT-02 VERIFIED DNS SOURCE ACQUISITION ===")
    print("Project:", root)
    print("Repository:", REPO)
    print("Pinned commit:", COMMIT)
    print("Repository path:", REMOTE_PATH)
    print("Expected bytes:", f"{EXPECTED_BYTES:,}")
    print("Expected Git Blob SHA-1:", EXPECTED_GIT_BLOB_SHA1)

    # Fail closed on preexisting paths, preventing replacement of evidence.
    existing = [p for p in (source, manifest) if p.exists()]
    if existing:
        fail("Output path already exists; no overwrite allowed: " + ", ".join(map(str, existing)))

    acquired_at = datetime.now(timezone.utc).isoformat()
    content = retrieve()
    actual_bytes = len(content)
    actual_blob = git_blob_sha1(content)
    sha256 = hashlib.sha256(content).hexdigest()

    print("\n=== SOURCE INTEGRITY VERIFICATION ===")
    print("Expected bytes:", EXPECTED_BYTES)
    print("Actual bytes:", actual_bytes)
    print("Expected Git Blob SHA-1:", EXPECTED_GIT_BLOB_SHA1)
    print("Actual Git Blob SHA-1:  ", actual_blob)
    print("Computed SHA-256:", sha256)
    if actual_bytes != EXPECTED_BYTES:
        fail("File size MISMATCH (nothing saved)")
    if actual_blob.lower() != EXPECTED_GIT_BLOB_SHA1.lower():
        fail("Pinned Git Blob SHA-1 MISMATCH (nothing saved)")
    print("Size: MATCH | Git Blob SHA-1: MATCH")

    format_info = inspect_zeek(content)
    print("\n=== ZEEK DNS FORMAT PREVIEW ===")
    print("#path:", format_info["zeek_path"])
    print("Physical lines:", format_info["physical_lines"])
    print("Data rows (initial count only):", format_info["data_rows_unvalidated"])
    print("Number of columns:", format_info["columns"])
    print("Field names:", ", ".join(format_info["field_names"]))
    print("First data line:", format_info["first_data_line_number"])
    print("First data record (truncated):", format_info["first_data_line_preview"])
    print("\nNOTE: DNS anomaly/tunneling NOT established by acquisition checks.")

    if args.check:
        print("\nFiles created: 0")
        print("Original evidence / Core / Results / historical reviews: UNCHANGED")
        print("STATUS: NT-02 READY FOR VERIFIED ACQUISITION (READ-ONLY CHECK PASS)")
        return

    metadata = {
        "case_id": "NT-02",
        "scenario_label": "Suspicious DNS Activity — evidence not yet classified",
        "provenance": {
            "repository": REPO,
            "commit": COMMIT,
            "path_in_repository": REMOTE_PATH,
            "pinned_raw_url": URL,
            "retrieved_at_utc": acquired_at,
            "third_party_source": True,
        },
        "original_filename": ORIGINAL_NAME,
        "file_size_bytes": actual_bytes,
        "sha256": sha256,
        "git_blob_sha1": actual_blob,
        "verified_git_blob_sha1": EXPECTED_GIT_BLOB_SHA1,
        "zeek_format_inspection": {k: v for k, v in format_info.items() if k != "first_data_line_preview"},
        "limitations": [
            "Content integrity confirms equivalence to pinned Git object, not absence of tampering before Git publication.",
            "Source is a third-party repository, not locally generated live telemetry.",
            "DNS anomaly/tunneling, malicious intent, successful exfiltration and authorization are not established.",
            "Full event parsing and candidate selection require a separate read-only inspection.",
        ],
    }
    meta_bytes = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    print("\n=== FILES TO CREATE (NO OVERWRITES) ===")
    print("CREATE:", source)
    print("CREATE:", manifest)
    confirm = input("Type ACQUIRE to write the two verified files (Enter cancels): ").strip()
    if confirm != "ACQUIRE":
        print("STATUS: CANCELLED (NO FILES CREATED)")
        return

    directory.mkdir(parents=True, exist_ok=True)
    made = []
    try:
        exclusive_write(source, content)
        made.append(source)
        exclusive_write(manifest, meta_bytes)
        made.append(manifest)
        if hashlib.sha256(source.read_bytes()).hexdigest() != sha256:
            fail("Saved original SHA-256 MISMATCH")
        saved_manifest = json.loads(manifest.read_text(encoding="utf-8"))
        if saved_manifest.get("sha256") != sha256:
            fail("Saved manifest does not match source digest")
    except Exception:
        for path in reversed(made):
            path.unlink(missing_ok=True)
        raise

    print("\n=== FINAL STATUS ===")
    print("Saved source SHA-256: MATCH")
    print("Saved source Git Blob SHA-1: MATCH")
    print("Source:", source.relative_to(root))
    print("Manifest:", manifest.relative_to(root))
    print("Core / Results / previous evidence: UNCHANGED")
    print("STATUS: NT-02 SOURCE ACQUISITION VERIFIED - DNS FORMAT INSPECTION NEXT")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyboardInterrupt, FileExistsError) as exc:
        print("STOP:", str(exc) or type(exc).__name__)
        sys.exit(1)
