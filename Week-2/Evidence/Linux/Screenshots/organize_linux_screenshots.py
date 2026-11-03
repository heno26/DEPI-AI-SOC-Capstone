#!/usr/bin/env python3
"""DEPI P5 Week-2 Linux screenshot organizer.

Conservative by design: --check makes no changes; --organize exclusively
creates a sibling Organized-Screenshots directory from a staging directory,
copying matching originals byte-for-byte, never overwriting or moving them.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import quote

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
CATALOG_FILE = "screenshot_catalog.json"
DEST_DIR = "Organized-Screenshots"


def normalized_stem(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inventory(source_dir: Path, catalog: list[dict]):
    originals = sorted(
        (f for f in source_dir.iterdir()
         if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS),
        key=lambda f: f.name.lower(),
    )
    index: dict[str, list[Path]] = {}
    for item in originals:
        index.setdefault(normalized_stem(item.stem), []).append(item)

    tracked: set[Path] = set()
    rows: list[dict] = []
    ambiguous: list[str] = []
    for entry in catalog:
        matches = index.get(normalized_stem(entry["stem"]), [])
        if len(matches) > 1:
            ambiguous.append(entry["stem"])
        path = matches[0] if len(matches) == 1 else None
        if path is not None:
            tracked.add(path)
        rows.append({"entry": entry, "file": path, "state":
                     "MATCH" if path else "AMBIGUOUS" if matches else "MISSING"})
    extras = [f for f in originals if f not in tracked]
    return rows, extras, ambiguous


def print_preflight(source_dir: Path, rows, extras, ambiguous):
    found = [r for r in rows if r["file"]]
    missing = [r for r in rows if r["state"] == "MISSING"]
    print("=== DEPI P5 LINUX SCREENSHOT EVIDENCE PREFLIGHT ===")
    print("Source:", source_dir)
    print("Catalog entries:", len(rows))
    print("Matched images:", len(found))
    print("Unmatched catalog entries:", len(missing))
    print("Ambiguous matches:", len(ambiguous))
    print("Other image files in source folder:", len(extras))
    for r in missing:
        print("MISSING:", r["entry"]["stem"])
    for name in ambiguous:
        print("AMBIGUOUS:", name)
    for path in extras:
        print("UNRECOGNIZED:", path.name)
    if found:
        print("\n=== MATCHED SCREENSHOTS ===")
        for r in found:
            e = r["entry"]
            print(f'{e["group"]:<5} [{e["status"]:<22}] {r["file"].name}')
    return found


def organize(source_dir: Path, rows, extras):
    dest = source_dir.parent / DEST_DIR
    if dest.exists():
        raise RuntimeError(
            f"STOP: Destination already exists: {dest}. "
            "No files were overwritten. Use --check to inspect first."
        )
    if any(r["state"] == "AMBIGUOUS" for r in rows):
        raise RuntimeError("STOP: Ambiguous file matches. No files copied.")
    if not (source_dir / "README.md").is_file():
        raise RuntimeError("STOP: README.md not found beside organizer.")

    stage = Path(tempfile.mkdtemp(
        prefix=f".{DEST_DIR}-staging-", dir=str(source_dir.parent)))
    try:
        shutil.copy2(source_dir / "README.md", stage / "README.md")
        copy_manifest = []
        for r in rows:
            e, original = r["entry"], r["file"]
            if original is None:
                continue
            category = stage / e["category"]
            category.mkdir(parents=True, exist_ok=True)
            target = category / original.name
            # The staging directory is newly created; do not replace files.
            with original.open("rb") as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            original_digest = sha256(original)
            target_digest = sha256(target)
            if original_digest != target_digest:
                raise RuntimeError(f"STOP: Hash mismatch copying {original.name}")
            copy_manifest.append({
                "catalog_id": e["id"],
                "source_name": original.name,
                "copy_relative_path": target.relative_to(stage).as_posix(),
                "sha256": target_digest,
                "bytes": target.stat().st_size,
                "category": e["category"],
                "evidence_caption_en": e["caption_en"],
                "review_status": e["status"],
            })

        with (stage / "Screenshot-Inventory.csv").open(
            "x", encoding="utf-8-sig", newline=""
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(["catalog_id", "case", "category", "status", "expected_stem",
                             "matched_filename", "copy_relative_path", "sha256", "size_bytes"])
            by_id = {r["catalog_id"]: r for r in copy_manifest}
            for r in rows:
                e = r["entry"]
                record = by_id.get(e["id"], {})
                writer.writerow([e["id"], e["group"], e["category"], r["state"], e["stem"],
                                 record.get("source_name", ""), record.get("copy_relative_path", ""),
                                 record.get("sha256", ""), record.get("bytes", "")])

        report = {
            "project": "DEPI P5 Week-2 Linux screenshot evidence",
            "source_folder": str(source_dir),
            "destination_folder": str(dest),
            "originals_changed": False,
            "method": "byte-for-byte copy with SHA-256 verified; no overwrite",
            "catalog_entries": len(rows),
            "matched_count": len(copy_manifest),
            "unmatched_catalog": [r["entry"]["stem"] for r in rows if r["file"] is None],
            "unrecognized_original_files": [p.name for p in extras],
            "copies": copy_manifest,
        }
        with (stage / "Screenshot-Integrity-Manifest.json").open(
            "x", encoding="utf-8", newline="\n"
        ) as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")

        with (stage / "Gallery.md").open("x", encoding="utf-8") as handle:
            handle.write("# Linux Evidence Gallery (verified copies)\n\n")
            handle.write("Refer to [README.md](README.md) for full explanations. "
                         "Links below point to matched copied images only.\n\n")
            for record in copy_manifest:
                link = quote(record["copy_relative_path"], safe="/-._~")
                handle.write(f'- **{record["catalog_id"]}:** '
                             f'[{record["source_name"]}]({link}) — '
                             f'{record["evidence_caption_en"]}\n')
        # Atomic finalization for a new destination; never replace existing path.
        if dest.exists():
            raise RuntimeError("STOP: Target appeared during preparation; no overwrite permitted.")
        os.rename(stage, dest)
        print("\n=== ORGANIZATION COMPLETE ===")
        print("Destination:", dest)
        print("Screenshots copied and SHA-256 verified:", len(copy_manifest))
        print("Missing catalog screenshots:", len(report["unmatched_catalog"]))
        print("Source screenshot files: UNCHANGED")
        print("Evidence / Wazuh / Core / Results: UNCHANGED")
        print("Manifest:", dest / "Screenshot-Integrity-Manifest.json")
        print("STATUS: ORGANIZED SCREENSHOT COPIES CREATED")
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Read-only preview of matches and gaps")
    mode.add_argument("--organize", action="store_true", help="Create verified copies; original images untouched")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    metadata_file = root / CATALOG_FILE
    if not metadata_file.exists():
        raise RuntimeError(f"Missing {CATALOG_FILE} next to organizer")
    catalog = json.loads(metadata_file.read_text(encoding="utf-8"))["screenshots"]
    rows, extras, ambiguous = inventory(root, catalog)
    print_preflight(root, rows, extras, ambiguous)
    if args.check:
        print("\nSTATUS: READ-ONLY CHECK COMPLETE (NO CHANGES MADE)")
    else:
        organize(root, rows, extras)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"\n{exc}", file=sys.stderr)
        sys.exit(1)
