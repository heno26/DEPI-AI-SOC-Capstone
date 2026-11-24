import argparse
import hashlib
import os
import time
from contextlib import contextmanager
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


VERSION = "1.2.0"

INCIDENT_STATES = {
    "NEW",
    "UNDER_INVESTIGATION",
    "PENDING_APPROVAL",
    "RESPONSE_IN_PROGRESS",
    "RESOLVED",
    "CLOSED"
}

APPROVAL_STATES = {
    "PENDING",
    "APPROVED",
    "REJECTED"
}

RESPONSE_STATES = {
    "NOT_STARTED",
    "APPROVED",
    "IN_PROGRESS",
    "COMPLETED",
    "FAILED",
    "CANCELLED"
}

TRANSITIONS = {
    "NEW": {"UNDER_INVESTIGATION"},
    "UNDER_INVESTIGATION": {"PENDING_APPROVAL"},
    "PENDING_APPROVAL": {"UNDER_INVESTIGATION"},
    "RESPONSE_IN_PROGRESS": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set()
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_store(path):
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        return {
            "schema_version": VERSION,
            "incidents": []
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Cannot read incident store: {exc}")

    if not isinstance(data, dict) or not isinstance(
        data.get("incidents"), list
    ):
        raise ValueError("Invalid incident store structure.")

    return data


def save_store(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_name(path.name + ".tmp")

    temp_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    temp_path.replace(path)


def find_incident(data, incident_id):
    for incident in data["incidents"]:
        if incident["incident_id"] == incident_id:
            return incident

    return None


def create_incident(args):
    data = load_store(args.store)

    for existing in data["incidents"]:
        if existing["internal_id"] == args.internal_id:
            raise ValueError(
                "DUPLICATE: An incident already exists for this alert. "
                f"Incident ID: {existing['incident_id']}"
            )

    now = utc_now()

    incident_id = (
        "INC-" +
        datetime.now(timezone.utc).strftime("%Y%m%d") +
        "-" +
        uuid.uuid4().hex[:8].upper()
    )

    incident = {
        "incident_id": incident_id,
        "project": "DEPI-P5",
        "component": "Incident Manager",
        "version": VERSION,

        "internal_id": args.internal_id,
        "alert_type": args.alert_type.upper(),

        "severity": args.severity,
        "confidence": args.confidence,

        "incident_status": "NEW",
        "approval_status": "PENDING",
        "response_status": "NOT_STARTED",

        "evidence_reference": args.evidence_reference,
        "validation_reference": args.validation_reference,
        "source_sha256": args.source_hash,

        "created_at_utc": now,
        "updated_at_utc": now,

        "audit_history": []
    }

    add_audit(
        incident,
        "INCIDENT_CREATED",
        "Incident created from an existing SIEM alert."
    )

    data["incidents"].append(incident)
    save_store(args.store, data)

    print(json.dumps(incident, indent=2, ensure_ascii=False))


def add_audit(incident, action, details):
    incident["audit_history"].append({
        "timestamp_utc": utc_now(),
        "action": action,
        "details": details
    })

    incident["updated_at_utc"] = utc_now()


def get_incident(args):
    data = load_store(args.store)
    incident = find_incident(data, args.incident_id)

    if not incident:
        raise ValueError("Incident not found.")

    print(json.dumps(incident, indent=2, ensure_ascii=False))


def list_incidents(args):
    data = load_store(args.store)

    print(json.dumps(
        data["incidents"],
        indent=2,
        ensure_ascii=False
    ))




@contextmanager
def store_lock(store):
    store = store.resolve()
    store.parent.mkdir(parents=True, exist_ok=True)
    lock = store.with_suffix(".lock")
    deadline = time.monotonic() + 15

    while True:
        try:
            fd = os.open(
                str(lock),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY
            )
            os.close(fd)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise ValueError("Incident store is locked.")
            time.sleep(0.1)

    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def validate_plan(store, incident, plan_path):
    path = Path(plan_path).resolve()
    root = store.resolve().parent.parent / "Playbooks"

    if path.parent.parent != root.resolve():
        raise ValueError("Unexpected approved plan location.")

    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    plan = json.loads(raw)

    summary = json.loads(
        (path.parent / "playbook_summary.json").read_text(
            encoding="utf-8-sig"
        )
    )

    records = [
        r for r in summary["records"]
        if r["incident_id"] == incident["incident_id"]
    ]

    if len(records) != 1:
        raise ValueError("Playbook summary identity mismatch.")

    record = records[0]

    if (
        summary.get("status") != "COMPLETED"
        or summary.get("orchestration_run_id")
        != root.parent.parent.name
        or record.get("status") != "PLAN_PENDING_APPROVAL"
        or Path(record["plan_path"]).resolve() != path
        or record.get("plan_sha256") != digest
    ):
        raise ValueError("Playbook summary integrity mismatch.")

    checks = [
        plan.get("incident_id") == incident["incident_id"],
        plan.get("internal_id") == incident["internal_id"],
        plan.get("alert_type") == incident["alert_type"],
        plan.get("execution_mode") == "SIMULATION_ONLY",
        plan.get("external_actions_enabled") is False,
        plan.get("human_approval_required") is True,
        plan.get("response_executed") is False,
        plan.get("plan_status") == "PENDING_HUMAN_APPROVAL",
        plan["evidence"].get("source_sha256")
        == incident["source_sha256"],
        plan["evidence"].get("validation_status")
        in {"PASS", "PASS_WITH_WARNINGS"}
    ]

    if not all(checks):
        raise ValueError("Approved playbook verification failed.")

    evidence = plan["evidence"]

    for key, hash_key in (
        ("ai_result", "ai_result_sha256"),
        ("validation_report", "validation_sha256")
    ):
        actual = hashlib.sha256(
            Path(evidence[key]).read_bytes()
        ).hexdigest()

        if actual != evidence[hash_key]:
            raise ValueError("Playbook evidence integrity mismatch.")

    validation = json.loads(
        Path(evidence["validation_report"]).read_bytes()
    )

    if (
        validation.get("internal_id") != incident["internal_id"]
        or validation.get("summary", {}).get("errors") != 0
        or validation.get("validation_status")
        != evidence["validation_status"]
        or validation.get("human_validation_required") is not True
    ):
        raise ValueError("Semantic validation gate failed.")

    source_hash = hashlib.sha256(
        Path(incident["evidence_reference"]).read_bytes()
    ).hexdigest()

    if source_hash != incident["source_sha256"]:
        raise ValueError("Original evidence integrity mismatch.")

    return path, digest, plan


def verify_approved_plan(store, incident):
    if incident.get("approval_status") != "APPROVED":
        raise ValueError("Human approval required.")

    if not incident.get("approved_plan_path"):
        raise ValueError("Approved playbook binding missing.")

    path, digest, plan = validate_plan(
        store, incident, incident["approved_plan_path"]
    )

    if digest != incident.get("approved_plan_sha256"):
        raise ValueError("Approved playbook hash mismatch.")

    approvals = [
        a for a in incident.get("audit_history", [])
        if a.get("action") == "HUMAN_APPROVAL_APPROVE"
    ]

    if not approvals or approvals[-1].get("details") != (
        "Approved playbook SHA256: " + digest
    ):
        raise ValueError("Approval binding audit mismatch.")

    return path, digest, plan


def verify_execution_receipt(store, incident):
    incident_id = incident["incident_id"]

    if not incident_id.startswith("INC-") or not all(
        c.isalnum() or c == "-" for c in incident_id
    ):
        raise ValueError("Invalid incident identifier.")

    receipt_path = (
        store.resolve().parent.parent
        / "ExecutionReceipts"
        / (incident_id + ".json")
    )

    if not receipt_path.is_file():
        raise ValueError("Execution receipt missing.")

    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)

    checks = [
        receipt.get("status") == "COMPLETED",
        receipt.get("incident_id") == incident_id,
        receipt.get("internal_id") == incident["internal_id"],
        receipt.get("source_sha256") == incident["source_sha256"],
        receipt.get("execution_mode") == "SIMULATION_ONLY",
        receipt.get("external_actions_executed") == 0,
        incident.get("approval_status") == "APPROVED"
    ]

    if not all(checks):
        raise ValueError("Execution receipt verification failed.")

    evidence = Path(incident["evidence_reference"])

    if not evidence.is_file():
        raise ValueError("Original evidence missing.")

    if hashlib.sha256(evidence.read_bytes()).hexdigest() != incident["source_sha256"]:
        raise ValueError("Original evidence integrity mismatch.")

    steps = receipt.get("steps", [])

    if not isinstance(steps, list) or not steps:
        raise ValueError("Execution receipt has no valid steps.")

    if receipt.get("steps_count") != len(steps):
        raise ValueError("Execution receipt step count mismatch.")

    for step in steps:
        if (
            step.get("status") != "SIMULATED"
            or step.get("external_action_executed") is not False
        ):
            raise ValueError("Unsafe execution receipt steps.")

    _, plan_hash, plan = verify_approved_plan(store, incident)

    if receipt.get("plan_sha256") != plan_hash:
        raise ValueError("Receipt approved plan hash mismatch.")

    expected = [
        (phase, step["step_id"], step["description"])
        for phase in (
            "investigation", "proposed_response", "recovery"
        )
        for step in plan[phase]
    ]

    actual = [
        (step["phase"], step["step_id"], step["description"])
        for step in steps
    ]

    if actual != expected:
        raise ValueError("Receipt approved steps mismatch.")

    return hashlib.sha256(raw).hexdigest()


def transition_incident(args):
    data = load_store(args.store)
    incident = find_incident(data, args.incident_id)

    if not incident:
        raise ValueError("Incident not found.")

    current = incident["incident_status"]
    target = args.target.upper()

    if target not in TRANSITIONS.get(current, set()):
        raise ValueError(
            f"Invalid transition: {current} -> {target}"
        )

    if (
        current == "RESPONSE_IN_PROGRESS"
        and target == "RESOLVED"
        and incident["response_status"] != "COMPLETED"
    ):
        raise ValueError(
            "Response must be COMPLETED before incident resolution."
        )

    if target in {"RESOLVED", "CLOSED"}:
        if incident["response_status"] != "COMPLETED":
            raise ValueError("Completed response required.")

        receipt_hash = verify_execution_receipt(
            args.store, incident
        )

        if receipt_hash != incident.get("execution_receipt_sha256"):
            raise ValueError("Execution receipt hash mismatch.")

    incident["incident_status"] = target

    add_audit(
        incident,
        "INCIDENT_STATUS_CHANGED",
        f"{current} -> {target}"
    )

    save_store(args.store, data)

    print(f"PASS: Incident status changed to {target}")


def approval_action(args):
    data = load_store(args.store)
    incident = find_incident(data, args.incident_id)

    if not incident:
        raise ValueError("Incident not found.")

    if incident["incident_status"] != "PENDING_APPROVAL":
        raise ValueError(
            "Approval requires PENDING_APPROVAL incident status."
        )

    if incident["approval_status"] != "PENDING":
        raise ValueError("Approval has already been decided.")

    action = args.decision.upper()

    if action == "APPROVE":
        if not args.plan or not args.plan_sha256:
            raise ValueError("Explicit playbook approval required.")

        path, digest, _ = validate_plan(
            args.store, incident, args.plan
        )

        if digest != args.plan_sha256:
            raise ValueError("Reviewed playbook hash mismatch.")

        incident["approved_plan_path"] = str(path)
        incident["approved_plan_sha256"] = digest
        incident["approval_status"] = "APPROVED"
        incident["response_status"] = "APPROVED"

    elif action == "REJECT":
        incident["approval_status"] = "REJECTED"
        incident["response_status"] = "CANCELLED"
        incident["incident_status"] = "UNDER_INVESTIGATION"

    add_audit(
        incident,
        "HUMAN_APPROVAL_" + action,
        (
            "Approved playbook SHA256: "
            + incident["approved_plan_sha256"]
            if action == "APPROVE"
            else "Human rejection recorded."
        )
    )

    save_store(args.store, data)

    print(f"PASS: Approval decision recorded: {action}")


def start_response(args):
    data = load_store(args.store)
    incident = find_incident(data, args.incident_id)

    if not incident:
        raise ValueError("Incident not found.")

    if incident["approval_status"] != "APPROVED":
        raise ValueError("Human approval is required.")

    if incident["incident_status"] != "PENDING_APPROVAL":
        raise ValueError("Incident is not awaiting response.")

    verify_approved_plan(args.store, incident)

    if incident["response_status"] != "APPROVED":
        raise ValueError("Response is not approved.")

    incident["incident_status"] = "RESPONSE_IN_PROGRESS"
    incident["response_status"] = "IN_PROGRESS"

    add_audit(
        incident,
        "RESPONSE_STARTED",
        "Response workflow marked as started. "
        "No external action was executed."
    )

    save_store(args.store, data)

    print(
        "PASS: Response workflow started. "
        "No external response action was executed."
    )


def complete_response(args):
    data = load_store(args.store)
    incident = find_incident(data, args.incident_id)

    if not incident:
        raise ValueError("Incident not found.")

    if incident["incident_status"] != "RESPONSE_IN_PROGRESS":
        raise ValueError("Incident response is not in progress.")

    if incident["response_status"] != "IN_PROGRESS":
        raise ValueError("Response is not in progress.")

    receipt_hash = verify_execution_receipt(
        args.store, incident
    )

    incident["execution_receipt_sha256"] = receipt_hash
    incident["response_status"] = "COMPLETED"

    add_audit(
        incident,
        "RESPONSE_COMPLETED",
        "Response workflow completed successfully. "
        "No external response action was executed."
    )

    save_store(args.store, data)

    print("PASS: Response workflow marked as COMPLETED.")


def fail_response(args):
    data = load_store(args.store)
    incident = find_incident(data, args.incident_id)

    if not incident:
        raise ValueError("Incident not found.")

    if incident["incident_status"] != "RESPONSE_IN_PROGRESS":
        raise ValueError("Incident response is not in progress.")

    if incident["response_status"] != "IN_PROGRESS":
        raise ValueError("Response is not in progress.")

    incident.pop("approved_plan_path", None)
    incident.pop("approved_plan_sha256", None)
    incident.pop("execution_receipt_sha256", None)

    incident["response_status"] = "FAILED"
    incident["approval_status"] = "PENDING"
    incident["incident_status"] = "UNDER_INVESTIGATION"

    add_audit(
        incident,
        "RESPONSE_FAILED",
        "Response failed. Incident returned to investigation."
    )

    save_store(args.store, data)

    print(
        "PASS: Response marked as FAILED. "
        "Incident returned to UNDER_INVESTIGATION."
    )

def main():
    parser = argparse.ArgumentParser(
        description="DEPI-P5 Incident Manager v1.2"
    )

    parser.add_argument(
        "--store",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "Runs" / "Incidents" / "incidents.json"
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True
    )

    create = commands.add_parser("create")
    create.add_argument("--internal-id", required=True)
    create.add_argument("--alert-type", required=True)
    create.add_argument("--severity", required=True)
    create.add_argument("--confidence", required=True)
    create.add_argument("--evidence-reference", required=True)
    create.add_argument("--validation-reference", required=True)
    create.add_argument("--source-hash", required=True)
    create.set_defaults(func=create_incident)

    get = commands.add_parser("get")
    get.add_argument("--incident-id", required=True)
    get.set_defaults(func=get_incident)

    listing = commands.add_parser("list")
    listing.set_defaults(func=list_incidents)

    transition = commands.add_parser("transition")
    transition.add_argument("--incident-id", required=True)
    transition.add_argument("--target", required=True)
    transition.set_defaults(func=transition_incident)

    approval = commands.add_parser("approval")
    approval.add_argument("--incident-id", required=True)
    approval.add_argument(
        "--decision",
        choices=["APPROVE", "REJECT"],
        required=True
    )
    approval.add_argument("--plan", type=Path)
    approval.add_argument("--plan-sha256")
    approval.set_defaults(func=approval_action)

    response = commands.add_parser("response-start")
    response.add_argument("--incident-id", required=True)
    response.set_defaults(func=start_response)

    completion = commands.add_parser("response-complete")
    completion.add_argument("--incident-id", required=True)
    completion.set_defaults(func=complete_response)

    failure = commands.add_parser("response-fail")
    failure.add_argument("--incident-id", required=True)
    failure.set_defaults(func=fail_response)

    args = parser.parse_args()

    try:
        if args.command in {"get", "list"}:
            args.func(args)
        else:
            with store_lock(args.store):
                args.func(args)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"ERROR: {exc}\n")


if __name__ == "__main__":
    main()
