"""
DEPI P5 - Response Simulator
Version: 1.0.0

Validates response authorization and simulates approved
response steps without executing external actions.
"""

import argparse
import hashlib
import json
import sys
import uuid
from incident_manager import verify_approved_plan

from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.2.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_json(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8-sig")
    )


def sha256_file(path):
    return hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, data):

    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open("x", encoding="utf-8") as handle:

        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False
        )


def _original_validate_authorization(incident, plan):

    require(
        incident["incident_id"] == plan["incident_id"],
        "Incident ID mismatch"
    )

    require(
        incident["internal_id"] == plan["internal_id"],
        "Internal ID mismatch"
    )

    require(
        incident["alert_type"] == plan["alert_type"],
        "Alert type mismatch"
    )

    require(
        plan.get("execution_mode") == "SIMULATION_ONLY",
        "Unsafe execution mode"
    )

    require(
        plan.get("external_actions_enabled") is False,
        "External actions are prohibited"
    )

    require(
        plan.get("human_approval_required") is True,
        "Human approval requirement missing"
    )

    require(
        incident.get("approval_status") == "APPROVED",
        "Human approval has not been granted"
    )

    require(
        incident.get("incident_status") != "CLOSED",
        "Incident is already closed"
    )

    require(
        incident.get("response_status") == "IN_PROGRESS",
        "Response lifecycle has not been started"
    )

    require(
        plan["evidence"]["validation_status"]
        in {"PASS", "PASS_WITH_WARNINGS"},
        "Semantic validation did not pass"
    )

    return True


def validate_integrity(plan, project):

    evidence = plan["evidence"]

    definitions = (
        project / "Scenarios" / "playbooks.json"
    )

    require(
        sha256_file(definitions)
        == plan["playbook_definition_sha256"],
        "Playbook definitions integrity mismatch"
    )

    result_path = Path(evidence["ai_result"])

    validation_path = Path(
        evidence["validation_report"]
    )

    require(
        sha256_file(result_path)
        == evidence["ai_result_sha256"],
        "AI result integrity mismatch"
    )

    require(
        sha256_file(validation_path)
        == evidence["validation_sha256"],
        "Validation report integrity mismatch"
    )

    validation = load_json(validation_path)

    require(
        validation.get("internal_id")
        == plan["internal_id"],
        "Validation identity mismatch"
    )

    require(
        validation.get("validation_status")
        == evidence["validation_status"],
        "Validation status mismatch"
    )

    require(
        validation.get("summary", {}).get("errors") == 0,
        "Semantic validation errors detected"
    )

    require(
        validation.get("human_validation_required") is True,
        "Validation human gate missing"
    )

    return True


def _original_simulate_steps(plan):

    results = []

    for phase in (
        "investigation",
        "proposed_response",
        "recovery"
    ):

        for step in plan[phase]:

            results.append({
                "phase": phase,
                "step_id": step["step_id"],
                "description": step["description"],
                "status": "SIMULATED",
                "external_action_executed": False,
                "timestamp_utc": utc_now()
            })

    return results



def validate_authorization(incident, plan):

    _original_validate_authorization(incident, plan)

    require(
        incident.get("incident_status") == "RESPONSE_IN_PROGRESS",
        "Incident is not in RESPONSE_IN_PROGRESS state"
    )

    require(
        incident.get("source_sha256")
        == plan["evidence"].get("source_sha256"),
        "Incident source hash mismatch"
    )

    require(
        plan.get("response_executed") is False,
        "Playbook already marked as executed"
    )

    require(
        plan.get("plan_status") == "PENDING_HUMAN_APPROVAL",
        "Unexpected playbook state"
    )

    audit_actions = {
        item.get("action")
        for item in incident.get("audit_history", [])
    }

    require(
        "HUMAN_APPROVAL_APPROVE" in audit_actions,
        "Human approval audit record missing"
    )

    require(
        "RESPONSE_STARTED" in audit_actions,
        "Response start audit record missing"
    )

    return True


def verify_original_evidence(incident, plan):

    evidence_path = Path(
        incident["evidence_reference"]
    ).resolve()

    require(
        evidence_path.is_file(),
        "Original evidence file missing"
    )

    require(
        sha256_file(evidence_path)
        == incident["source_sha256"],
        "Original evidence integrity mismatch"
    )

    require(
        sha256_file(evidence_path)
        == plan["evidence"]["source_sha256"],
        "Playbook source evidence mismatch"
    )


def receipt_path(workspace, incident_id):

    require(
        isinstance(incident_id, str)
        and incident_id.startswith("INC-")
        and all(
            char.isalnum() or char == "-"
            for char in incident_id
        ),
        "Invalid incident identifier"
    )

    return (
        Path(workspace)
        / "Runs"
        / "ExecutionReceipts"
        / f"{incident_id}.json"
    )


def simulate_steps_secure(
    plan,
    incident,
    workspace,
    plan_sha256
):

    verify_original_evidence(incident, plan)

    receipt = receipt_path(
        workspace,
        incident["incident_id"]
    )

    receipt.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    execution = {
        "project": "DEPI-P5",
        "component": "Response Execution Receipt",
        "version": VERSION,
        "execution_id": uuid.uuid4().hex,
        "incident_id": incident["incident_id"],
        "internal_id": incident["internal_id"],
        "plan_sha256": plan_sha256,
        "source_sha256": incident["source_sha256"],
        "execution_mode": "SIMULATION_ONLY",
        "status": "IN_PROGRESS",
        "external_actions_executed": 0,
        "started_at_utc": datetime.now(
            timezone.utc
        ).isoformat()
    }

    # Exclusive creation prevents simultaneous execution.

    try:

        with receipt.open(
            "x",
            encoding="utf-8"
        ) as handle:

            json.dump(
                execution,
                handle,
                indent=2
            )

            handle.flush()

            import os
            os.fsync(handle.fileno())

    except FileExistsError:

        raise ValueError(
            "Response execution receipt already exists"
        )

    try:

        steps = _original_simulate_steps(plan)

        require(
            len(steps) > 0,
            "No simulation steps generated"
        )

        require(
            all(
                step.get("status") == "SIMULATED"
                and step.get(
                    "external_action_executed"
                ) is False
                for step in steps
            ),
            "Unsafe simulation result"
        )

        execution["status"] = "COMPLETED"
        execution["steps_count"] = len(steps)
        execution["steps"] = steps

        execution["completed_at_utc"] = datetime.now(
            timezone.utc
        ).isoformat()

    except Exception as exc:

        execution["status"] = "FAILED"
        execution["error"] = str(exc)

        temporary = receipt.with_suffix(
            f".{uuid.uuid4().hex}.tmp"
        )

        temporary.write_text(
            json.dumps(execution, indent=2),
            encoding="utf-8"
        )

        temporary.replace(receipt)

        raise

    temporary = receipt.with_suffix(
        f".{uuid.uuid4().hex}.tmp"
    )

    temporary.write_text(
        json.dumps(execution, indent=2),
        encoding="utf-8"
    )

    temporary.replace(receipt)

    return steps



def run(args):

    project = Path(args.project).resolve()

    workspace = Path(args.run).resolve()

    playbook_run = Path(args.playbooks).resolve()

    store_path = (
        workspace / "Runs" / "Incidents" / "incidents.json"
    )

    store_hash = sha256_file(store_path)

    store = load_json(store_path)

    summary = load_json(
        playbook_run / "playbook_summary.json"
    )

    require(
        summary.get("orchestration_run_id") == workspace.name,
        "Orchestration run mismatch"
    )

    require(
        summary.get("status") == "COMPLETED",
        "Playbook generation not completed"
    )

    output = (
        workspace / "Runs" / "Responses"
        / ("SIM-" + uuid.uuid4().hex[:12])
    )

    output.mkdir(
        parents=True,
        exist_ok=False
    )

    records = []

    print("=" * 60)
    print("DEPI P5 - RESPONSE SIMULATOR V1.2")
    print("=" * 60)

    for item in summary["records"]:

        incident_id = item["incident_id"]

        if args.incident_id and incident_id != args.incident_id:
            continue

        entry = {
            "incident_id": incident_id,
            "status": "PENDING",
            "external_action_executed": False,
            "steps": []
        }

        records.append(entry)

        try:

            require(
                item["status"] == "PLAN_PENDING_APPROVAL",
                "Playbook plan not eligible"
            )

            plan_path = Path(item["plan_path"])

            require(
                plan_path.resolve().parent == playbook_run,
                "Unexpected plan location"
            )

            require(
                sha256_file(plan_path) == item["plan_sha256"],
                "Playbook plan integrity mismatch"
            )

            plan = load_json(plan_path)

            matches = [
                incident
                for incident in store["incidents"]
                if incident["incident_id"] == incident_id
            ]

            require(
                len(matches) == 1,
                "Incident lookup failed"
            )

            incident = matches[0]

            validate_integrity(plan, project)

            validate_authorization(incident, plan)

            approved_path, approved_hash, _ = verify_approved_plan(
                store_path, incident
            )

            require(
                approved_path == plan_path.resolve()
                and approved_hash == item["plan_sha256"],
                "Selected playbook was not approved"
            )

            verify_original_evidence(incident, plan)

            entry["status"] = "AUTHORIZED"

            if not args.check_only:

                entry["steps"] = simulate_steps_secure(plan, incident, workspace, sha256_file(plan_path))

                entry["status"] = "SIMULATION_COMPLETED"

            print(
                f"{entry['status']}: {incident_id}"
            )

        except Exception as error:

            entry["status"] = "BLOCKED"

            entry["reason"] = str(error)

            print(
                f"BLOCKED: {incident_id}: {error}"
            )

        write_json(
            output / f"{incident_id}_response.json",
            entry
        )

    unchanged = (
        sha256_file(store_path) == store_hash
    )

    blocked = sum(
        item["status"] == "BLOCKED"
        for item in records
    )

    authorized = sum(
        item["status"] in {"AUTHORIZED", "SIMULATION_COMPLETED"}
        for item in records
    )

    simulated = sum(
        item["status"] == "SIMULATION_COMPLETED"
        for item in records
    )

    report = {
        "project": "DEPI-P5",
        "component": "Response Simulator",
        "version": VERSION,
        "generated_at_utc": utc_now(),
        "orchestration_run_id": workspace.name,
        "mode": "CHECK_ONLY" if args.check_only else "SIMULATION_ONLY",
        "total_incidents": len(records),
        "blocked_incidents": blocked,
        "authorized_incidents": authorized,
        "simulated_incidents": simulated,
        "external_actions_executed": 0,
        "incident_store_unchanged": unchanged,
        "records": records
    }

    report_path = output / "response_summary.json"

    write_json(report_path, report)

    print("\n===== RESPONSE SUMMARY =====")

    print(f"Incidents: {len(records)}")
    print(f"Blocked: {blocked}")
    print(f"Authorized: {authorized}")
    print(f"Simulated: {simulated}")
    print("External actions: 0")
    print(f"Incident store unchanged: {unchanged}")
    print(f"Report: {report_path}")

    if not unchanged or not records:
        return 1

    if args.check_only:
        return 0

    return 0 if blocked == 0 else 2


def main():

    parser = argparse.ArgumentParser(
        description="DEPI P5 Response Simulator"
    )

    parser.add_argument("--project", required=True)

    parser.add_argument("--run", required=True)

    parser.add_argument("--playbooks", required=True)

    parser.add_argument("--incident-id")

    parser.add_argument(
        "--check-only",
        action="store_true"
    )

    args = parser.parse_args()

    try:

        return run(args)

    except Exception as error:

        print(f"FATAL: {error}", file=sys.stderr)

        return 1


if __name__ == "__main__":
    sys.exit(main())
