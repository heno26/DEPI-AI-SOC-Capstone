"""
DEPI P5 - Scenario Orchestrator
Version: 1.0.0

Central integration engine for evidence processing,
AI reprocessing, semantic validation and incident creation.

All incidents require human validation.
No external response actions are executed.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import uuid

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.0.0"

READY = "READY_FOR_AI_REPROCESSING"
AI_PASS = "PASS_SCHEMA_HUMAN_REVIEW_REQUIRED"
VALIDATION_PASS = {"PASS", "PASS_WITH_WARNINGS"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_json(path):
    return Path(path).read_text(
        encoding="utf-8-sig"
    ) and json.loads(
        Path(path).read_text(encoding="utf-8-sig")
    )


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def sha256_file(path):
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def execute(script, arguments, log_path):
    command = [
        sys.executable,
        str(script),
        *[str(item) for item in arguments]
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    write_json(log_path, {
        "timestamp": utc_now(),
        "command": command,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    })

    return result.returncode


def require_success(code, stage):
    if code != 0:
        raise RuntimeError(
            f"{stage} failed with exit code {code}"
        )


def find_existing_ai(project, identity, alert_type):
    candidates = []

    directory = project / "Runs" / "Reprocessing"

    for path in directory.rglob("result.json"):
        try:
            result = load_json(path)

            if not isinstance(result, dict):
                continue

            if (
                result.get("internal_id")
                == identity["internal_id"]

                and result.get("source_filename")
                == identity["source_filename"]

                and result.get("source_sha256")
                == identity["source_sha256"]

                and result.get("alert_type")
                == alert_type

                and result.get("processing_status")
                == AI_PASS

                and result.get("human_validation_required")
                is True

                and isinstance(result.get("analysis"), dict)
            ):
                candidates.append((
                    result.get("generated_at_utc", ""),
                    path
                ))

        except (OSError, ValueError, TypeError):
            continue

    candidates.sort(
        key=lambda item: (item[0], str(item[1])),
        reverse=True
    )

    return candidates[0][1] if candidates else None


def verify_ai_result(path, identity, alert_type):
    result = load_json(path)

    expected = {
        "internal_id": identity["internal_id"],
        "source_filename": identity["source_filename"],
        "source_sha256": identity["source_sha256"],
        "alert_type": alert_type,
        "processing_status": AI_PASS
    }

    for key, value in expected.items():
        if result.get(key) != value:
            raise ValueError(
                f"AI result mismatch: {key}"
            )

    if result.get("human_validation_required") is not True:
        raise ValueError("Human validation gate missing")

    if not isinstance(result.get("analysis"), dict):
        raise ValueError("Invalid AI analysis")

    return result


def run(args):
    project = Path(args.project).resolve()
    evidence_dir = Path(args.evidence).resolve()

    core = project / "Core"

    run_id = (
        "ORCH-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )

    workspace = (
        project / "Runs" / "Orchestration" / run_id
    )

    workspace.mkdir(parents=True, exist_ok=False)

    runs = workspace / "Runs"
    logs = workspace / "Logs"

    manifest_path = runs / "evidence_manifest.json"

    dataset_path = (
        runs / "Normalized" / "normalized_evidence.json"
    )

    incident_store = (
        runs / "Incidents" / "incidents.json"
    )

    incident_store.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    validation_dir = runs / "Validation"

    report_path = workspace / "execution_report.json"

    report = {
        "project": "DEPI-P5",
        "component": "Scenario Orchestrator",
        "version": VERSION,
        "run_id": run_id,
        "mode": "DRY_RUN" if args.dry_run else "LAB_EXECUTION",
        "started_at_utc": utc_now(),
        "status": "RUNNING",
        "human_validation_required": True,
        "external_response_executed": False,
        "records": []
    }

    print("=" * 60)
    print("DEPI P5 - SCENARIO ORCHESTRATOR V1.0")
    print("=" * 60)
    print(f"Run ID: {run_id}")
    print(f"Mode: {report['mode']}")

    try:
        # Stage 1: Evidence discovery and manifest

        code = execute(
            core / "evidence_loader.py",
            [
                "--evidence", evidence_dir,
                "--out", runs
            ],
            logs / "01_evidence_loader.json"
        )

        require_success(code, "Evidence Loader")

        manifest = load_json(manifest_path)

        # Stage 2: Normalize into isolated workspace

        code = execute(
            core / "normalizer.py",
            [
                "--evidence", evidence_dir,
                "--out", dataset_path.parent
            ],
            logs / "02_normalizer.json"
        )

        require_success(code, "Normalizer")

        dataset = load_json(dataset_path)

        print(f"Evidence files: {len(manifest['files'])}")
        print(f"Normalized records: {len(dataset['records'])}")

        # Stage 3: Process each evidence record

        for item in manifest["files"]:

            filename = item["filename"]

            entry = {
                "source_filename": filename,
                "source_sha256": item.get("sha256"),
                "manifest_status": item.get("status"),
                "status": "PENDING",
                "human_validation_required": True,
                "ai_mode": None,
                "validation_status": None,
                "incident_created": False
            }

            report["records"].append(entry)

            print()
            print("-" * 60)
            print(f"Evidence: {filename}")

            try:
                if Path(filename).name != filename:
                    raise ValueError("Invalid evidence filename")

                source_path = evidence_dir / filename

                if sha256_file(source_path) != item["sha256"]:
                    raise ValueError(
                        "Original evidence SHA256 mismatch"
                    )

                if item.get("status") != READY:
                    entry["status"] = "MANUAL_REVIEW_REQUIRED"
                    print("SKIPPED: Manual review required")
                    continue

                matches = [
                    record
                    for record in dataset["records"]
                    if record["identity"]["source_filename"]
                    == filename
                ]

                if len(matches) != 1:
                    raise ValueError(
                        "Expected exactly one normalized record"
                    )

                record = matches[0]
                identity = record["identity"]

                internal_id = identity["internal_id"]

                alert_type = record["classification"]["alert_type"]

                entry["internal_id"] = internal_id
                entry["alert_type"] = alert_type

                if identity["source_sha256"] != item["sha256"]:
                    raise ValueError(
                        "Normalized evidence hash mismatch"
                    )

                if not identity.get("original_event_id"):
                    raise ValueError("Original event ID missing")

                if record.get("provenance", {}).get(
                    "source_integrity_verified"
                ) is not True:
                    raise ValueError(
                        "Source integrity not verified"
                    )

                # Stage 4: Select existing AI result

                existing = None

                if not args.force_ai:
                    existing = find_existing_ai(
                        project,
                        identity,
                        alert_type
                    )

                entry["ai_mode"] = (
                    "REUSE" if existing else "NEW_PROCESSING"
                )

                print(f"Alert type: {alert_type}")
                print(f"AI mode: {entry['ai_mode']}")

                if args.dry_run:
                    entry["status"] = "DRY_RUN_READY"

                    if existing:
                        entry["existing_ai_result"] = str(existing)

                    print("PASS: Candidate ready")
                    continue

                # Stage 5: Reuse or execute AI

                if existing:
                    reuse_dir = (
                        runs / "ReusedAI" / internal_id
                    )

                    reuse_dir.mkdir(
                        parents=True,
                        exist_ok=False
                    )

                    result_path = reuse_dir / "result.json"

                    shutil.copy2(existing, result_path)

                    entry["reused_from"] = str(existing)

                    entry["reused_result_sha256"] = (
                        sha256_file(result_path)
                    )

                    print("Existing AI result reused")

                else:
                    code = execute(
                        core / "ai_reprocessor.py",
                        [
                            "--project", workspace,
                            "--event-id", internal_id
                        ],
                        logs / f"{internal_id}_ai.json"
                    )

                    require_success(code, "AI Reprocessing")

                    result_candidates = []

                    for path in (
                        runs / "Reprocessing"
                    ).rglob("result.json"):

                        candidate = load_json(path)

                        if candidate.get("internal_id") == internal_id:
                            result_candidates.append(path)

                    if len(result_candidates) != 1:
                        raise ValueError(
                            "Unexpected number of AI result files"
                        )

                    result_path = result_candidates[0]

                result = verify_ai_result(
                    result_path,
                    identity,
                    alert_type
                )

                entry["ai_result"] = str(result_path)

                entry["ai_result_sha256"] = sha256_file(
                    result_path
                )

                # Stage 6: Fresh semantic validation

                code = execute(
                    core / "semantic_validator.py",
                    [
                        "--dataset", dataset_path,
                        "--result", result_path,
                        "--out", validation_dir
                    ],
                    logs / f"{internal_id}_validation.json"
                )

                validation_path = (
                    validation_dir
                    / f"{internal_id[:16]}_semantic_validation.json"
                )

                if not validation_path.is_file():
                    raise RuntimeError(
                        "Semantic validation report missing"
                    )

                validation = load_json(validation_path)

                entry["validation_status"] = validation.get(
                    "validation_status"
                )

                entry["validation_report"] = str(validation_path)

                entry["validation_summary"] = validation.get(
                    "summary", {}
                )

                entry["validation_sha256"] = sha256_file(
                    validation_path
                )

                if (
                    validation.get("internal_id") != internal_id

                    or validation.get("source_sha256")
                    != identity["source_sha256"]

                    or validation.get("human_validation_required")
                    is not True
                ):
                    raise ValueError(
                        "Validation identity or human gate mismatch"
                    )

                if (
                    code != 0

                    or entry["validation_status"]
                    not in VALIDATION_PASS

                    or validation.get("summary", {}).get("errors")
                    != 0
                ):
                    entry["status"] = "VALIDATION_BLOCKED"
                    print("BLOCKED: Semantic validation failed")
                    continue

                print(
                    "Validation:",
                    entry["validation_status"]
                )

                # Stage 7: Final evidence integrity check

                if sha256_file(source_path) != item["sha256"]:
                    raise ValueError(
                        "Evidence changed during processing"
                    )

                if sha256_file(result_path) != entry["ai_result_sha256"]:
                    raise ValueError(
                        "AI result changed during validation"
                    )

                analysis = result["analysis"]

                severity = analysis["severity"]
                confidence = analysis["confidence"]

                # Stage 8: Create isolated investigation record

                code = execute(
                    core / "incident_manager.py",
                    [
                        "--store", incident_store,
                        "create",
                        "--internal-id", internal_id,
                        "--alert-type", alert_type,
                        "--severity", severity,
                        "--confidence", confidence,
                        "--evidence-reference", source_path,
                        "--validation-reference", validation_path,
                        "--source-hash", item["sha256"]
                    ],
                    logs / f"{internal_id}_incident.json"
                )

                require_success(code, "Incident Creation")

                store = load_json(incident_store)

                incidents = [
                    incident
                    for incident in store["incidents"]
                    if incident["internal_id"] == internal_id
                ]

                if len(incidents) != 1:
                    raise RuntimeError(
                        "Incident creation could not be verified"
                    )

                incident = incidents[0]

                entry["incident_created"] = True

                entry["incident_id"] = incident["incident_id"]

                if (
                    incident.get("incident_status") != "NEW"

                    or incident.get("approval_status") != "PENDING"

                    or incident.get("response_status") != "NOT_STARTED"
                ):
                    raise RuntimeError(
                        "Unexpected initial incident state"
                    )

                entry["status"] = "INCIDENT_PENDING_HUMAN_REVIEW"

                print(
                    f"Incident created: {incident['incident_id']}"
                )

                print("Human approval required")

            except Exception as error:
                entry["status"] = "FAILED"
                entry["error"] = str(error)

                print(f"FAILED: {error}")

            finally:
                write_json(report_path, report)

        failures = [
            entry for entry in report["records"]
            if entry["status"] in {
                "FAILED",
                "VALIDATION_BLOCKED"
            }
        ]

        report["status"] = (
            "COMPLETED_WITH_ERRORS"
            if failures else "COMPLETED"
        )

    except Exception as error:
        report["status"] = "FAILED"
        report["fatal_error"] = str(error)

        print(f"FATAL: {error}")

    finally:
        entries = report["records"]

        report["finished_at_utc"] = utc_now()

        report["summary"] = {
            "total_records": len(entries),
            "status_counts": dict(Counter(
                entry["status"] for entry in entries
            )),
            "ai_reuse_candidates": sum(
                entry["ai_mode"] == "REUSE"
                for entry in entries
            ),
            "new_ai_candidates": sum(
                entry["ai_mode"] == "NEW_PROCESSING"
                for entry in entries
            ),
            "incidents_created": sum(
                entry["incident_created"]
                for entry in entries
            )
        }

        write_json(report_path, report)

        print()
        print("=" * 60)
        print("EXECUTION SUMMARY")
        print("=" * 60)

        print(json.dumps(report["summary"], indent=2))

        print(f"Run status: {report['status']}")
        print(f"Report: {report_path}")

    return 0 if report["status"] == "COMPLETED" else 1


def main():
    parser = argparse.ArgumentParser(
        description="DEPI P5 Scenario Orchestrator V1.0"
    )

    parser.add_argument("--project", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force-ai", action="store_true")

    args = parser.parse_args()

    sys.exit(run(args))


if __name__ == "__main__":
    main()
