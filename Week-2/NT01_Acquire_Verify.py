#!/usr/bin/env python3
"""NT-01 source acquisition: pinned GitHub Zeek conn.log, verified, no overwrite.

This program does not execute traffic captures, modify Core, or alter existing evidence.
Run from the Week-2 project root on Windows using Python 3.10+.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO = "dikshitdhawan/NTA-Zeek-Threat-Detection-Lab"
COMMIT = "bb2817e4a783dd2578383aa6e3f0adab12052904"
RELPATH = "Zeek-Logs/port_scan/conn.log"
EXPECTED_SIZE = 8_200_705
EXPECTED_GIT_BLOB_SHA1 = "6f967cad3e15891e527d01490840fa3aec26aeed"
SOURCE_URL = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{RELPATH}"

BASE = Path("Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning")
SOURCE = BASE / "NT-01-Zeek-conn-original.log"
MANIFEST = BASE / "NT-01-Source-Manifest.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    """Git blob ID SHA1('blob ' + length + NUL + exact file bytes)."""
    h = hashlib.sha1()
    h.update(f"blob {len(data)}\0".encode("ascii"))
    h.update(data)
    return h.hexdigest()


def run() -> None:
    print("=== NT-01 VERIFIED NETWORK SOURCE ACQUISITION ===")
    print(f"Project: {Path.cwd()}")
    print(f"Repository: {REPO}")
    print(f"Pinned commit: {COMMIT}")
    print(f"Source path: {RELPATH}")

    if not Path("Core").is_dir() or not Path("app.py").is_file():
        raise RuntimeError("Run this script from Week-2 project root (Core/ and app.py required).")
    if SOURCE.exists() or MANIFEST.exists():
        raise RuntimeError("Output already exists. No evidence file will be overwritten.")

    req = Request(SOURCE_URL, headers={"User-Agent": "DEPI-P5-NT01-source-verifier/1.0"})
    print("\nDownloading the pinned source file (read-only remote retrieval)...")
    try:
        with urlopen(req, timeout=120) as response:
            payload = response.read(EXPECTED_SIZE + 1)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Download failed: {exc}") from exc

    length = len(payload)
    actual_blob = git_blob_sha1(payload)
    digest = sha256(payload)
    print("\n=== SOURCE INTEGRITY VERIFICATION ===")
    print(f"Expected bytes: {EXPECTED_SIZE}")
    print(f"Actual bytes: {length}")
    print(f"Expected Git Blob SHA-1: {EXPECTED_GIT_BLOB_SHA1}")
    print(f"Actual Git Blob SHA-1:   {actual_blob}")

    if length != EXPECTED_SIZE or actual_blob.lower() != EXPECTED_GIT_BLOB_SHA1.lower():
        raise RuntimeError("Size or Git Blob SHA-1 mismatch. No output files created.")

    # Work on a text preview, not on transformed/saved original evidence.
    lines = payload.decode("utf-8-sig", errors="replace").splitlines()
    if not lines:
        raise RuntimeError("Empty source content. No output files created.")

    print("Size: MATCH")
    print("Git Blob SHA-1: MATCH")
    print(f"Computed SHA-256: {digest}")
    print(f"Total source lines: {len(lines)}")
    print("\n=== CONTENT PREVIEW (TRUNCATED DISPLAY ONLY) ===")
    for i, line in enumerate(lines[:8], 1):
        print(f"Line {i}: {line[:300]}")

    metadata = {
        "test_id": "NT-01",
        "scenario": "Network Port Scanning",
        "status": "source_integrity_verified_content_analysis_pending",
        "provenance": "Public third-party controlled-lab Zeek telemetry; attack labels require independent validation",
        "repository": REPO,
        "repository_commit": COMMIT,
        "source_repository_path": RELPATH,
        "download_url": SOURCE_URL,
        "git_blob_sha1": actual_blob,
        "sha256": digest,
        "file_size_bytes": length,
        "source_line_count": len(lines),
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
        "year_timezone_assessment": "Requires inspection of Zeek timestamps and metadata",
        "notes": "Source unchanged; no attack counts, connection state, or attribution assumed from README.",
    }
    manifest_bytes = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    BASE.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        with SOURCE.open("xb") as f:
            created.append(SOURCE)
            f.write(payload)
        with MANIFEST.open("xb") as f:
            created.append(MANIFEST)
            f.write(manifest_bytes)
    except Exception:
        # Only remove exact files created by this invocation, never pre-existing data.
        for p in reversed(created):
            p.unlink(missing_ok=True)
        raise

    # Verify saved evidence using fresh reads.
    if SOURCE.stat().st_size != EXPECTED_SIZE or sha256(SOURCE.read_bytes()) != digest:
        raise RuntimeError("Saved evidence verification failed. Stop and inspect before continuing.")
    print("\n=== FINAL STATUS ===")
    print(f"Original source saved: {SOURCE}")
    print(f"Source manifest saved: {MANIFEST}")
    print("Saved SHA-256: MATCH")
    print("Core / Results / previous evidence: UNCHANGED")
    print("STATUS: NT-01 SOURCE ACQUISITION VERIFIED - FORMAT INSPECTION NEXT")


if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"\nSTOP: {exc}", file=sys.stderr)
        sys.exit(1)
