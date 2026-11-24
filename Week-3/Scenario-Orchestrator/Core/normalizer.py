import argparse
import hashlib
import json
import sys

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence_loader import identify_alert, sha256_file
from schema import create_normalized_record, ALLOWED_ALERT_TYPES


def normalize_file(path):

    source_hash = sha256_file(path)

    with path.open("r", encoding="utf-8") as f:
        doc = json.load(f)

    if not isinstance(doc, dict):
        raise ValueError("JSON root must be an object")

    alert_type, alert_rule = identify_alert(doc, path.name)

    if alert_type not in ALLOWED_ALERT_TYPES:
        raise ValueError(f"Unsupported alert type: {alert_type}")

    original_id = doc.get("event_id")

    internal_id = hashlib.sha256(
        (path.name + source_hash).encode("utf-8")
    ).hexdigest()

    evidence = doc.get("evidence") or doc.get("correlation")

    if not isinstance(evidence, dict):
        raise ValueError("Missing valid evidence object")

    ai = doc.get("ai_triage")

    if not isinstance(ai, dict):
        raise ValueError("Missing valid AI triage object")

    record = create_normalized_record(
        internal_id=internal_id,
        original_event_id=original_id,
        source_filename=path.name,
        source_sha256=source_hash,
        alert_type=alert_type,
        alert_rule=alert_rule,
        source_document=doc
    )

    record["provenance"]["source_integrity_verified"] = (
        sha256_file(path) == source_hash
    )

    record["provenance"]["processing_history"].append({
        "stage": "NORMALIZATION",
        "status": "COMPLETED",
        "source_sha256": source_hash
    })

    return record


def main():

    parser = argparse.ArgumentParser(
        description="DEPI P5 Unified Evidence Normalizer"
    )

    parser.add_argument("--evidence", required=True)
    parser.add_argument("--out", required=True)

    args = parser.parse_args()

    evidence_dir = Path(args.evidence)
    output_dir = Path(args.out)

    if not evidence_dir.is_dir():
        raise SystemExit("Evidence directory does not exist")

    files = sorted(
        evidence_dir.glob("*_AI_Triage*.json")
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    records = []
    failures = []

    for path in files:

        try:
            record = normalize_file(path)
            records.append(record)

            print(
                f"PASS | {path.name} | "
                f"{record['classification']['alert_type']}"
            )

        except Exception as exc:

            failures.append({
                "filename": path.name,
                "error": str(exc)
            })

            print(f"FAIL | {path.name} | {exc}")

    dataset = {
        "project": "DEPI-P5",
        "component": "Scenario Orchestrator",
        "schema_version": "1.0",
        "total_records": len(records),
        "failed_records": len(failures),
        "records": records,
        "failures": failures
    }

    output_path = output_dir / "normalized_evidence.json"

    if output_path.exists():
        raise SystemExit(
            "Output already exists. Refusing to overwrite."
        )

    output_path.write_text(
        json.dumps(dataset, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n===== NORMALIZATION SUMMARY =====")
    print(f"Discovered: {len(files)}")
    print(f"Normalized: {len(records)}")
    print(f"Failed: {len(failures)}")
    print(f"Output: {output_path}")

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
