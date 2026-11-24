"""
DEPI P5 - SOAR Playbook Engine
Version: 1.0.0

Generates incident-specific response plans.
Simulation only. No external security actions.
"""

import argparse
import hashlib
import json
import sys
import uuid

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.0.0"

VALIDATION_PASS = {"PASS", "PASS_WITH_WARNINGS"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_json(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8-sig")
    )


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("x", encoding="utf-8") as handle:
        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False
        )


def sha256_file(path):
    return hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_definitions(definitions):

    require(
        definitions.get("execution_mode") == "SIMULATION_ONLY",
        "Unsafe execution mode"
    )

    require(
        definitions.get("human_approval_required") is True,
        "Human approval requirement missing"
    )

    require(
        definitions.get("external_actions_enabled") is False,
        "External actions must remain disabled"
    )

    playbooks = definitions["playbooks"]

    require(
        isinstance(playbooks, dict) and bool(playbooks),
        "No playbooks available"
    )

    ids = set()

    for alert_type, playbook in playbooks.items():

        playbook_id = playbook["playbook_id"]

        require(
            playbook_id not in ids,
            "Duplicate playbook ID"
        )

        ids.add(playbook_id)

        for phase in (
            "investigation",
            "proposed_response",
            "recovery"
        ):

            steps = playbook.get(phase)

            require(
                isinstance(steps, list)
                and bool(steps)
                and all(
                    isinstance(step, str) and step.strip()
                    for step in steps
                ),
                f"Invalid {phase} steps for {alert_type}"
            )

    return playbooks


def make_steps(steps, prefix):

    return [
        {
            "step_id": f"{prefix}-{index:02d}",
            "description": description,
            "status": "NOT_EXECUTED"
        }
        for index, description in enumerate(steps, 1)
    ]


def build_plan(incident, record, playbooks, definition_hash):

    incident_id = incident["incident_id"]
    alert_type = incident["alert_type"]

    require(
        incident.get("incident_status") == "NEW",
        "Incident is not in NEW state"
    )

    require(
        incident.get("approval_status") == "PENDING",
        "Expected pending human approval"
    )

    require(
        incident.get("response_status") == "NOT_STARTED",
        "Response already started"
    )

    require(
        record.get("status")
        == "INCIDENT_PENDING_HUMAN_REVIEW",
        "Orchestration record not eligible"
    )

    require(
        record.get("incident_created") is True,
        "Incident creation not verified"
    )

    require(
        record.get("incident_id") == incident_id,
        "Incident ID mismatch"
    )

    require(
        record.get("internal_id") == incident["internal_id"],
        "Internal ID mismatch"
    )

    require(
        record.get("alert_type") == alert_type,
        "Alert type mismatch"
    )

    require(
        record.get("human_validation_required") is True,
        "Human validation gate missing"
    )

    require(
        record.get("validation_status") in VALIDATION_PASS,
        "Semantic validation did not pass"
    )

    require(
        alert_type in playbooks,
        f"No playbook for {alert_type}"
    )

    validation_path = Path(record["validation_report"])

    require(
        validation_path.is_file(),
        "Validation report missing"
    )

    require(
        sha256_file(validation_path)
        == record["validation_sha256"],
        "Validation report integrity mismatch"
    )

    validation = load_json(validation_path)

    require(
        validation.get("internal_id") == incident["internal_id"],
        "Validation internal ID mismatch"
    )

    require(
        validation.get("source_sha256")
        == record["source_sha256"],
        "Validation source hash mismatch"
    )

    require(
        validation.get("validation_status")
        == record["validation_status"],
        "Validation status mismatch"
    )

    require(
        validation.get("human_validation_required") is True,
        "Validation human gate missing"
    )

    require(
        validation.get("summary", {}).get("errors") == 0,
        "Validation errors detected"
    )

    result_path = Path(record["ai_result"])

    require(
        result_path.is_file(),
        "AI result missing"
    )

    require(
        sha256_file(result_path)
        == record["ai_result_sha256"],
        "AI result integrity mismatch"
    )

    result = load_json(result_path)

    require(
        result.get("internal_id") == incident["internal_id"],
        "AI result identity mismatch"
    )

    require(
        result.get("source_sha256") == record["source_sha256"],
        "AI source hash mismatch"
    )

    require(
        result.get("processing_status")
        == "PASS_SCHEMA_HUMAN_REVIEW_REQUIRED",
        "AI result not eligible"
    )

    require(
        result.get("human_validation_required") is True,
        "AI human gate missing"
    )

    playbook = playbooks[alert_type]

    return {
        "project": "DEPI-P5",
        "component": "SOAR Playbook Engine",
        "version": VERSION,
        "generated_at_utc": utc_now(),

        "plan_id": "PLAN-" + uuid.uuid4().hex[:12].upper(),

        "incident_id": incident_id,
        "internal_id": incident["internal_id"],
        "alert_type": alert_type,

        "playbook_id": playbook["playbook_id"],
        "playbook_name": playbook["name"],
        "playbook_definition_sha256": definition_hash,

        "severity": incident["severity"],
        "confidence": incident["confidence"],

        "execution_mode": "SIMULATION_ONLY",
        "plan_status": "PENDING_HUMAN_APPROVAL",

        "human_approval_required": True,
        "approval_status": "PENDING",

        "response_authorized": False,
        "response_executed": False,
        "external_actions_enabled": False,

        "evidence": {
            "source_filename": record["source_filename"],
            "source_sha256": record["source_sha256"],
            "ai_result": str(result_path),
            "ai_result_sha256": record["ai_result_sha256"],
            "validation_report": str(validation_path),
            "validation_sha256": record["validation_sha256"],
            "validation_status": record["validation_status"],
            "validation_summary": validation["summary"],
            "validation_findings": validation.get("findings", [])
        },

        "investigation": make_steps(
            playbook["investigation"], "INV"
        ),

        "proposed_response": make_steps(
            playbook["proposed_response"], "RES"
        ),

        "recovery": make_steps(
            playbook["recovery"], "REC"
        )
    }


def run(args):

    project = Path(args.project).resolve()
    workspace = Path(args.run).resolve()

    definitions_path = project / "Scenarios" / "playbooks.json"

    report_path = workspace / "execution_report.json"

    store_path = workspace / "Runs" / "Incidents" / "incidents.json"

    definitions = load_json(definitions_path)
    definition_hash = sha256_file(definitions_path)

    playbooks = validate_definitions(definitions)

    report = load_json(report_path)
    store = load_json(store_path)

    require(
        report.get("mode") == "LAB_EXECUTION",
        "Expected lab execution report"
    )

    require(
        report.get("status") == "COMPLETED",
        "Orchestration run not completed"
    )

    require(
        report.get("external_response_executed") is False,
        "Unexpected external response state"
    )

    require(
        report.get("run_id") == workspace.name,
        "Orchestration run ID mismatch"
    )

    initial_store_hash = sha256_file(store_path)

    output = (
        workspace / "Runs" / "Playbooks"
        / ("PB-RUN-" + uuid.uuid4().hex[:12])
    )

    output.mkdir(parents=True, exist_ok=False)

    results = []

    incident_ids = set()

    print("=" * 60)
    print("DEPI P5 - SOAR PLAYBOOK ENGINE V1.0")
    print("=" * 60)

    for incident in store["incidents"]:

        incident_id = incident["incident_id"]

        entry = {
            "incident_id": incident_id,
            "alert_type": incident["alert_type"],
            "status": "PENDING"
        }

        results.append(entry)

        try:

            require(
                incident_id not in incident_ids,
                "Duplicate incident ID"
            )

            incident_ids.add(incident_id)

            matches = [
                record
                for record in report["records"]
                if record.get("incident_id") == incident_id
            ]

            require(
                len(matches) == 1,
                "Expected exactly one orchestration record"
            )

            plan = build_plan(
                incident,
                matches[0],
                playbooks,
                definition_hash
            )

            plan_path = output / f"{incident_id}_playbook.json"

            write_json(plan_path, plan)

            entry["playbook_id"] = plan["playbook_id"]
            entry["plan_path"] = str(plan_path)
            entry["plan_sha256"] = sha256_file(plan_path)
            entry["status"] = "PLAN_PENDING_APPROVAL"

            print(
                f"PASS: {incident_id} -> "
                f"{plan['playbook_id']} -> PENDING APPROVAL"
            )

        except Exception as error:

            entry["status"] = "BLOCKED"
            entry["error"] = str(error)

            print(f"BLOCKED: {incident_id}: {error}")

    unchanged = sha256_file(store_path) == initial_store_hash

    counts = dict(Counter(
        item["status"] for item in results
    ))

    successful = counts.get("PLAN_PENDING_APPROVAL", 0)

    blocked = counts.get("BLOCKED", 0)

    completed = (
        blocked == 0
        and unchanged
        and successful > 0
    )

    summary = {
        "project": "DEPI-P5",
        "component": "SOAR Playbook Engine",
        "version": VERSION,
        "generated_at_utc": utc_now(),
        "orchestration_run_id": report["run_id"],
        "execution_mode": "SIMULATION_ONLY",
        "status": "COMPLETED" if completed else "REVIEW_REQUIRED",
        "total_incidents": len(results),
        "plans_created": successful,
        "blocked_incidents": blocked,
        "human_approval_required": True,
        "responses_executed": 0,
        "external_actions_executed": 0,
        "incident_store_unchanged": unchanged,
        "status_counts": counts,
        "records": results
    }

    summary_path = output / "playbook_summary.json"

    write_json(summary_path, summary)

    print("\n===== PLAYBOOK SUMMARY =====")
    print(f"Incidents: {len(results)}")
    print(f"Plans created: {successful}")
    print(f"Blocked: {blocked}")
    print(f"Incident store unchanged: {unchanged}")
    print("Responses executed: 0")
    print(f"Status: {summary['status']}")
    print(f"Report: {summary_path}")

    return 0 if completed else 1


def main():

    parser = argparse.ArgumentParser(
        description="DEPI P5 SOAR Playbook Engine V1.0"
    )

    parser.add_argument("--project", required=True)
    parser.add_argument("--run", required=True)

    args = parser.parse_args()

    try:
        return run(args)

    except Exception as error:
        print(f"FATAL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
