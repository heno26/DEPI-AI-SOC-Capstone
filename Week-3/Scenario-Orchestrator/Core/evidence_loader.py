import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def identify_alert(doc, filename):
    trigger = doc.get("source_trigger") or {}
    key = str(trigger.get("key", ""))
    rule = str(doc.get("alert_rule", ""))

    candidates = [
        key.split("/", 1)[0],
        rule,
        str(doc.get("phase", "")),
        filename
    ]

    mappings = {
        "SIEM_AUTH_002_SSH_BRUTE_FORCE": "SSH_BRUTE_FORCE",
        "SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR": "MALWARE",
        "SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS": "WEB_HIGH_RATE",
        "SIEM_WEB_004_XSS_ATTACK_DETECTED": "XSS",
        "SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT": "EXCHANGE",
    }

    for candidate in candidates:
        for rule_name, alert_type in mappings.items():
            if rule_name in candidate:
                return alert_type, rule_name

    return "UNKNOWN", None


def inspect_file(path):
    result = {
        "filename": path.name,
        "sha256": sha256_file(path),
        "status": "REJECTED",
        "errors": [],
    }

    try:
        with path.open("r", encoding="utf-8") as file:
            doc = json.load(file)

        if not isinstance(doc, dict):
            raise ValueError("JSON root must be an object")

        alert_type, rule = identify_alert(doc, path.name)

        result.update({
            "event_id": doc.get("event_id"),
            "alert_type": alert_type,
            "alert_rule": rule,
            "ai_triage_present": isinstance(
                doc.get("ai_triage") or doc.get("ai_result"), dict
            ),
            "evidence_present": isinstance(
                doc.get("evidence") or doc.get("correlation"), dict
            ),
            "qa_status": doc.get("qa_status"),
            "human_validation_required":
                doc.get("human_validation_required"),
            "original_model": doc.get("model"),
        })

        if not result["event_id"]:
            result["errors"].append("Missing event_id")

        if alert_type == "UNKNOWN":
            result["errors"].append("Unknown alert type")

        if not result["ai_triage_present"]:
            result["errors"].append("Missing AI triage object")

        if not result["evidence_present"]:
            result["errors"].append("Missing evidence object")

        if doc.get("human_validation_required") is not True:
            result["errors"].append(
                "Human validation requirement not explicitly true"
            )

        result["status"] = (
            "READY_FOR_AI_REPROCESSING"
            if not result["errors"]
            else "REVIEW_REQUIRED"
        )

    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        result["errors"].append(
            f"{type(exc).__name__}: {str(exc)}"
        )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="DEPI P5 Scenario Orchestrator - Evidence Loader"
    )

    parser.add_argument("--evidence", required=True)
    parser.add_argument("--out", required=True)

    args = parser.parse_args()

    evidence_dir = Path(args.evidence)
    output_dir = Path(args.out)

    if not evidence_dir.is_dir():
        raise SystemExit(f"Evidence directory not found: {evidence_dir}")

    files = sorted(evidence_dir.glob("*_AI_Triage*.json"))

    results = [inspect_file(path) for path in files]

    ready = sum(
        item["status"] == "READY_FOR_AI_REPROCESSING"
        for item in results
    )

    review = sum(
        item["status"] == "REVIEW_REQUIRED"
        for item in results
    )

    rejected = sum(
        item["status"] == "REJECTED"
        for item in results
    )

    manifest = {
        "project": "DEPI-P5",
        "component": "Scenario Orchestrator - Evidence Loader",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(evidence_dir),
        "source_files_read_only": True,
        "total_files": len(results),
        "ready_for_ai_reprocessing": ready,
        "review_required": review,
        "rejected": rejected,
        "files": results,
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = output_dir / "evidence_manifest.json"

    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n===== EVIDENCE LOADER RESULTS =====")

    for item in results:
        print(
            f"{item['filename']} | "
            f"{item['status']} | "
            f"{item.get('alert_type', 'UNKNOWN')}"
        )

        for error in item["errors"]:
            print(f"  WARNING: {error}")

    print("\n===== SUMMARY =====")
    print(f"Total files: {len(results)}")
    print(f"Ready: {ready}")
    print(f"Review required: {review}")
    print(f"Rejected: {rejected}")
    print(f"\nManifest: {manifest_path}")


if __name__ == "__main__":
    main()
