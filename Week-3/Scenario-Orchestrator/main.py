import argparse
import hashlib
import json
import subprocess
import sys

from pathlib import Path

VERSION = "1.2.0"

PROJECT = Path(__file__).resolve().parent
CORE = PROJECT / "Core"

ORCHESTRATOR = CORE / "orchestrator.py"
MANAGER = CORE / "incident_manager.py"
PLAYBOOK_ENGINE = CORE / "playbook_engine.py"
SIMULATOR = CORE / "response_simulator.py"

ORCHESTRATION_ROOT = PROJECT / "Runs" / "Orchestration"


def require(condition, message):

    if not condition:
        raise ValueError(message)


def load(path):

    return json.loads(
        Path(path).read_text(encoding="utf-8-sig")
    )


def sha(path):

    return hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()


def invoke(script, arguments):

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            *map(str, arguments)
        ]
    )

    require(
        result.returncode == 0,
        f"{script.name} failed: exit {result.returncode}"
    )


def resolve_run(run_id):

    require(
        Path(run_id).name == run_id
        and run_id.startswith("ORCH-"),
        "Invalid orchestration run ID"
    )

    workspace = (
        ORCHESTRATION_ROOT / run_id
    ).resolve()

    require(
        workspace.parent == ORCHESTRATION_ROOT.resolve(),
        "Invalid workspace location"
    )

    report = load(
        workspace / "execution_report.json"
    )

    require(
        report["run_id"] == run_id,
        "Orchestration identity mismatch"
    )

    require(
        report["status"] == "COMPLETED",
        "Orchestration run is not completed"
    )

    require(
        report["mode"] == "LAB_EXECUTION",
        "Dry-run cannot be used for response"
    )

    require(
        report["external_response_executed"] is False,
        "Unsafe orchestration state"
    )

    return workspace


def store_path(workspace):

    return (
        workspace / "Runs" / "Incidents"
        / "incidents.json"
    )


def get_incident(workspace, incident_id):

    records = [
        item
        for item in load(store_path(workspace))["incidents"]
        if item["incident_id"] == incident_id
    ]

    require(
        len(records) == 1,
        "Incident not found or duplicated"
    )

    return records[0]


def manager(workspace, *arguments):

    invoke(
        MANAGER,
        [
            "--store",
            store_path(workspace),
            *arguments
        ]
    )


def resolve_playbooks(workspace, playbook_id):

    require(
        Path(playbook_id).name == playbook_id
        and playbook_id.startswith("PB-RUN-"),
        "Invalid playbook run ID"
    )

    root = workspace / "Runs" / "Playbooks"

    directory = (root / playbook_id).resolve()

    require(
        directory.parent == root.resolve(),
        "Invalid playbook location"
    )

    summary = load(
        directory / "playbook_summary.json"
    )

    require(
        summary["status"] == "COMPLETED",
        "Playbook generation not completed"
    )

    require(
        summary["orchestration_run_id"] == workspace.name,
        "Playbook orchestration mismatch"
    )

    return directory


def get_plan(playbooks, incident_id):

    summary = load(
        playbooks / "playbook_summary.json"
    )

    records = [
        item for item in summary["records"]
        if item["incident_id"] == incident_id
    ]

    require(
        len(records) == 1,
        "Playbook not found or duplicated"
    )

    item = records[0]

    require(
        item["status"] == "PLAN_PENDING_APPROVAL",
        "Playbook is not eligible"
    )

    path = Path(item["plan_path"]).resolve()

    require(
        path.parent == playbooks.resolve(),
        "Unexpected playbook path"
    )

    require(
        sha(path) == item["plan_sha256"],
        "Playbook integrity mismatch"
    )

    return path, load(path)


def prepare(args):

    evidence = Path(args.evidence).resolve()

    require(
        evidence.is_dir(),
        "Evidence directory not found"
    )

    previous = set(
        ORCHESTRATION_ROOT.glob("ORCH-*")
    )

    arguments = [
        "--project", PROJECT,
        "--evidence", evidence
    ]

    if args.force_ai:
        arguments.append("--force-ai")

    invoke(ORCHESTRATOR, arguments)

    created = set(
        ORCHESTRATION_ROOT.glob("ORCH-*")
    ) - previous

    require(
        len(created) == 1,
        "Expected exactly one orchestration run"
    )

    workspace = resolve_run(
        next(iter(created)).name
    )

    root = workspace / "Runs" / "Playbooks"

    before = set(root.glob("PB-RUN-*"))

    invoke(
        PLAYBOOK_ENGINE,
        [
            "--project", PROJECT,
            "--run", workspace
        ]
    )

    generated = set(
        root.glob("PB-RUN-*")
    ) - before

    require(
        len(generated) == 1,
        "Expected exactly one playbook run"
    )

    playbooks = resolve_playbooks(
        workspace,
        next(iter(generated)).name
    )

    summary = load(
        playbooks / "playbook_summary.json"
    )

    print("\n===== PIPELINE PREPARATION =====")
    print(f"Run ID: {workspace.name}")
    print(f"Playbook ID: {playbooks.name}")
    print(f"Plans created: {summary['plans_created']}")
    print("Status: PENDING HUMAN REVIEW")
    print("External actions: 0")


def status(args):

    workspace = resolve_run(args.run)

    incidents = load(
        store_path(workspace)
    )["incidents"]

    print("\n===== SOC INCIDENT STATUS =====")

    for incident in incidents:

        print(
            f"{incident['incident_id']} | "
            f"{incident['alert_type']} | "
            f"{incident['incident_status']} | "
            f"{incident['approval_status']} | "
            f"{incident['response_status']}"
        )

    print(f"\nTotal incidents: {len(incidents)}")


def review(args):

    workspace = resolve_run(args.run)

    incident = get_incident(
        workspace, args.incident_id
    )

    if incident["incident_status"] == "NEW":

        manager(
            workspace,
            "transition",
            "--incident-id", args.incident_id,
            "--target", "UNDER_INVESTIGATION"
        )

    incident = get_incident(
        workspace, args.incident_id
    )

    require(
        incident["incident_status"]
        == "UNDER_INVESTIGATION",
        "Incident is not eligible for review"
    )

    require(
        incident["approval_status"] == "PENDING",
        "Approval already decided"
    )

    manager(
        workspace,
        "transition",
        "--incident-id", args.incident_id,
        "--target", "PENDING_APPROVAL"
    )

    print("Incident ready for human decision.")


def decision(args):

    workspace = resolve_run(args.run)

    incident = get_incident(
        workspace, args.incident_id
    )

    require(
        incident["incident_status"] == "PENDING_APPROVAL",
        "Incident is not awaiting approval"
    )

    action = args.command.upper()
    approval_arguments = []

    if action == "APPROVE":
        playbooks = resolve_playbooks(
            workspace, args.playbooks
        )

        plan_path, plan = get_plan(
            playbooks, args.incident_id
        )

        require(
            plan["incident_id"] == incident["incident_id"]
            and plan["internal_id"] == incident["internal_id"],
            "Incident and playbook mismatch"
        )

        digest = sha(plan_path)

        print(f"Playbook: {plan['playbook_name']}")
        print(f"Plan SHA256: {digest}")

        for phase in (
            "investigation", "proposed_response", "recovery"
        ):
            print(f"\n{phase.upper()}")
            for step in plan[phase]:
                print(f"  {step['description']}")

        approval_arguments = [
            "--plan", plan_path,
            "--plan-sha256", digest
        ]

    print(f"Incident: {args.incident_id}")
    print(f"Alert type: {incident['alert_type']}")
    print(f"Decision: {action}")
    print("Execution mode: SIMULATION_ONLY")

    confirmation = input(
        f"Type {action} to confirm: "
    ).strip()

    require(
        confirmation == action,
        "Human decision cancelled"
    )

    manager(
        workspace,
        "approval",
        "--incident-id", args.incident_id,
        "--decision", action,
        *approval_arguments
    )


def verify_receipt(workspace, incident, plan_path, plan):

    receipt_path = (
        workspace / "Runs" / "ExecutionReceipts"
        / f"{incident['incident_id']}.json"
    )

    require(
        receipt_path.is_file(),
        "Execution receipt missing"
    )

    receipt = load(receipt_path)

    require(
        incident.get("approved_plan_sha256") == sha(plan_path),
        "Playbook approval binding mismatch"
    )

    require(
        receipt["status"] == "COMPLETED",
        "Execution receipt not completed"
    )

    require(
        receipt["incident_id"] == incident["incident_id"]
        and receipt["internal_id"] == incident["internal_id"],
        "Execution receipt identity mismatch"
    )

    require(
        receipt["plan_sha256"] == sha(plan_path),
        "Receipt playbook hash mismatch"
    )

    require(
        receipt["source_sha256"]
        == incident["source_sha256"]
        == plan["evidence"]["source_sha256"],
        "Receipt source hash mismatch"
    )

    require(
        sha(incident["evidence_reference"])
        == incident["source_sha256"],
        "Original evidence integrity mismatch"
    )

    require(
        receipt["execution_mode"] == "SIMULATION_ONLY"
        and receipt["external_actions_executed"] == 0,
        "Unsafe execution receipt"
    )

    expected_steps = [
        (phase, step["step_id"], step["description"])
        for phase in (
            "investigation",
            "proposed_response",
            "recovery"
        )
        for step in plan[phase]
    ]

    actual_steps = [
        (
            step["phase"],
            step["step_id"],
            step["description"]
        )
        for step in receipt["steps"]
    ]

    require(
        expected_steps == actual_steps
        and len(actual_steps) > 0
        and receipt["steps_count"] == len(actual_steps),
        "Execution receipt steps mismatch"
    )

    require(
        all(
            step["status"] == "SIMULATED"
            and step["external_action_executed"] is False
            for step in receipt["steps"]
        ),
        "Unsafe execution steps"
    )

    return receipt_path, receipt


def respond(args):

    workspace = resolve_run(args.run)

    playbooks = resolve_playbooks(
        workspace, args.playbooks
    )

    incident = get_incident(
        workspace, args.incident_id
    )

    require(
        incident["approval_status"] == "APPROVED",
        "Human approval is required"
    )

    plan_path, plan = get_plan(
        playbooks, args.incident_id
    )

    require(
        plan["incident_id"] == incident["incident_id"]
        and plan["internal_id"] == incident["internal_id"],
        "Incident and playbook mismatch"
    )

    require(
        plan["execution_mode"] == "SIMULATION_ONLY"
        and plan["external_actions_enabled"] is False,
        "Unsafe playbook"
    )

    require(
        incident["response_status"] != "COMPLETED",
        "Response already completed"
    )

    receipt_path = (
        workspace / "Runs" / "ExecutionReceipts"
        / f"{args.incident_id}.json"
    )

    require(
        not receipt_path.exists(),
        "Existing execution receipt requires human review"
    )

    require(
        incident.get("approved_plan_sha256") == sha(plan_path)
        and Path(
            incident.get("approved_plan_path", "")
        ).resolve() == plan_path.resolve(),
        "Selected playbook was not approved"
    )

    if incident["incident_status"] == "PENDING_APPROVAL":

        manager(
            workspace,
            "response-start",
            "--incident-id", args.incident_id
        )

    incident = get_incident(
        workspace, args.incident_id
    )

    require(
        incident["incident_status"] == "RESPONSE_IN_PROGRESS"
        and incident["response_status"] == "IN_PROGRESS",
        "Response lifecycle is not active"
    )

    invoke(
        SIMULATOR,
        [
            "--project", PROJECT,
            "--run", workspace,
            "--playbooks", playbooks,
            "--incident-id", args.incident_id
        ]
    )

    receipt_path, receipt = verify_receipt(
        workspace, incident, plan_path, plan
    )

    manager(
        workspace,
        "response-complete",
        "--incident-id", args.incident_id
    )

    final = get_incident(
        workspace, args.incident_id
    )

    require(
        final["response_status"] == "COMPLETED",
        "Incident completion failed"
    )

    print("\n===== VERIFIED RESPONSE =====")
    print(f"Incident: {args.incident_id}")
    print(f"Simulated steps: {receipt['steps_count']}")
    print(f"Receipt: {receipt_path}")
    print(f"Receipt SHA256: {sha(receipt_path)}")
    print("External actions: 0")
    print("Response status: COMPLETED")


def close_incident(args):

    workspace = resolve_run(args.run)

    playbooks = resolve_playbooks(
        workspace, args.playbooks
    )

    incident = get_incident(
        workspace, args.incident_id
    )

    require(
        incident["approval_status"] == "APPROVED"
        and incident["response_status"] == "COMPLETED",
        "Completed approved response required"
    )

    plan_path, plan = get_plan(
        playbooks, args.incident_id
    )

    verify_receipt(
        workspace, incident, plan_path, plan
    )

    require(
        incident["incident_status"]
        in {"RESPONSE_IN_PROGRESS", "RESOLVED"},
        "Incident is not eligible for closure"
    )

    confirmation = input(
        "Type CLOSE to confirm incident closure: "
    ).strip()

    require(
        confirmation == "CLOSE",
        "Incident closure cancelled"
    )

    if incident["incident_status"] == "RESPONSE_IN_PROGRESS":

        manager(
            workspace,
            "transition",
            "--incident-id", args.incident_id,
            "--target", "RESOLVED"
        )

    manager(
        workspace,
        "transition",
        "--incident-id", args.incident_id,
        "--target", "CLOSED"
    )

    final = get_incident(
        workspace, args.incident_id
    )

    require(
        final["incident_status"] == "CLOSED",
        "Incident closure failed"
    )

    print("Incident closed successfully.")



def generate_report(args):

    workspace = resolve_run(args.run)

    playbooks = resolve_playbooks(
        workspace, args.playbooks
    )

    output = PROJECT / "Reports" / "HISTORICAL_LAB"

    invoke(
        CORE / "report_generator.py",
        [
            "--run", workspace,
            "--playbooks", playbooks,
            "--out", output,
            "--scope", "HISTORICAL_LAB"
        ]
    )


def main():

    parser = argparse.ArgumentParser(
        description="DEPI P5 - Unified SOC Pipeline"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=VERSION
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True
    )

    p = commands.add_parser("prepare")

    p.add_argument(
        "--evidence",
        required=True
    )

    p.add_argument(
        "--force-ai",
        action="store_true"
    )

    p.set_defaults(handler=prepare)

    p = commands.add_parser("status")

    p.add_argument("--run", required=True)

    p.set_defaults(handler=status)

    handlers = {
        "review": review,
        "approve": decision,
        "reject": decision,
        "respond": respond,
        "close": close_incident
    }

    for name, handler in handlers.items():

        p = commands.add_parser(name)

        p.add_argument("--run", required=True)

        p.add_argument(
            "--incident-id",
            required=True
        )

        if name in {"approve", "respond", "close"}:

            p.add_argument(
                "--playbooks",
                required=True
            )

        p.set_defaults(handler=handler)


    p = commands.add_parser(
        "report",
        help="Generate verified SOC reports"
    )

    p.add_argument("--run", required=True)

    p.add_argument("--playbooks", required=True)

    p.set_defaults(handler=generate_report)

    args = parser.parse_args()

    try:

        args.handler(args)

        return 0

    except Exception as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr
        )

        return 1


if __name__ == "__main__":

    sys.exit(main())
