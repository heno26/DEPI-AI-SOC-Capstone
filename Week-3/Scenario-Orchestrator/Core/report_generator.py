import argparse
import csv
import hashlib
import html
import json
import sys
import uuid

from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

VERSION = "1.0.0"

PROJECT = Path(__file__).resolve().parent.parent


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


def save(path, data):

    Path(path).write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def esc(value):

    if value is None:
        return "Not available"

    if isinstance(value, (dict, list)):

        value = json.dumps(
            value,
            indent=2,
            ensure_ascii=False
        )

    return html.escape(str(value))


def badge(value):

    value = str(value)

    if value in {
        "PASS", "COMPLETED", "APPROVED", "CLOSED"
    }:
        style = "green"

    elif value in {
        "FAIL", "FAILED", "REJECTED",
        "BLOCKED", "CANCELLED"
    }:
        style = "red"

    else:
        style = "amber"

    return (
        f'<span class="badge {style}">'
        f'{esc(value)}</span>'
    )


def table(headers, rows):

    result = "<table><thead><tr>"

    result += "".join(
        f"<th>{esc(header)}</th>"
        for header in headers
    )

    result += "</tr></thead><tbody>"

    for row in rows:

        result += "<tr>"

        result += "".join(
            f"<td>{esc(value)}</td>"
            for value in row
        )

        result += "</tr>"

    return result + "</tbody></table>"


def details(data):

    return table(
        ["Field", "Value"],
        list(data.items())
    )


def document(title, subtitle, content):

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>

<style>
* {{ box-sizing: border-box; }}

body {{
    background: #eef2f6;
    color: #243447;
    font-family: Arial, sans-serif;
    margin: 0;
    line-height: 1.6;
}}

main {{
    max-width: 1200px;
    margin: 30px auto;
    padding: 35px;
    background: white;
}}

header {{
    background: #10283f;
    color: white;
    padding: 35px;
    border-left: 8px solid #20b8b0;
}}

h1 {{ margin: 0; font-size: 30px; }}

h2 {{
    color: #10283f;
    margin-top: 35px;
    border-bottom: 2px solid #20b8b0;
    padding-bottom: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
    font-size: 13px;
}}

th {{
    background: #183b56;
    color: white;
    text-align: left;
}}

td, th {{
    padding: 11px;
    border: 1px solid #dce4eb;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
    vertical-align: top;
}}

tr:nth-child(even) {{
    background: #f4f7fa;
}}

.cards {{
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin: 25px 0;
}}

.card {{
    flex: 1 1 150px;
    background: #edf5f7;
    padding: 20px;
    border-top: 4px solid #20b8b0;
}}

.card strong {{
    font-size: 30px;
    display: block;
}}

.notice {{
    background: #fff5dc;
    border-left: 5px solid #e5a62c;
    padding: 15px;
    margin: 20px 0;
}}

.badge {{
    padding: 5px 9px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}}

.green {{ background: #d9f4e6; color: #17633d; }}
.red {{ background: #fde1e1; color: #a32424; }}
.amber {{ background: #fff0cd; color: #815600; }}

a {{ color: #087c87; }}

footer {{
    margin-top: 35px;
    padding-top: 15px;
    border-top: 1px solid #dce4eb;
    font-size: 12px;
    color: #627387;
}}

@media print {{
    body {{ background: white; }}
    main {{ margin: 0; padding: 0; }}
    tr {{ break-inside: avoid; }}
    h2 {{ break-after: avoid; }}
    header {{ print-color-adjust: exact; }}
    th {{ print-color-adjust: exact; }}
}}
</style>
</head>

<body>
<main>

<header>
<h1>{esc(title)}</h1>
<p>{esc(subtitle)}</p>
<p>DEPI P5 | AI-Assisted SOC Automation</p>
</header>

{content}

<footer>
DEPI P5 - Scenario Orchestrator |
Automated SOC Reporting |
Simulation-only laboratory environment
</footer>

</main>
</body>
</html>"""


def resolve_inputs(args):

    workspace = Path(args.run).resolve()

    playbooks = Path(args.playbooks).resolve()

    require(
        workspace.name.startswith("ORCH-"),
        "Invalid orchestration workspace"
    )

    require(
        playbooks.parent
        == (workspace / "Runs" / "Playbooks").resolve(),
        "Playbook workspace mismatch"
    )

    report_path = workspace / "execution_report.json"

    store_path = (
        workspace / "Runs" / "Incidents"
        / "incidents.json"
    )

    summary_path = playbooks / "playbook_summary.json"

    report = load(report_path)
    store = load(store_path)
    summary = load(summary_path)

    require(
        report["run_id"] == workspace.name,
        "Orchestration identity mismatch"
    )

    require(
        report["mode"] == "LAB_EXECUTION"
        and report["status"] == "COMPLETED",
        "Orchestration not eligible for reporting"
    )

    require(
        summary["orchestration_run_id"]
        == workspace.name
        and summary["status"] == "COMPLETED",
        "Playbook summary mismatch"
    )

    return (
        workspace, playbooks,
        report, store, summary,
        report_path, store_path, summary_path
    )


def collect_incident(
    incident,
    report,
    summary,
    workspace,
    playbooks
):

    incident_id = incident["incident_id"]

    matches = [
        record for record in report["records"]
        if record.get("incident_id") == incident_id
    ]

    require(
        len(matches) == 1,
        f"Orchestration record mismatch: {incident_id}"
    )

    record = matches[0]

    plans = [
        item for item in summary["records"]
        if item["incident_id"] == incident_id
    ]

    require(
        len(plans) == 1,
        f"Playbook record mismatch: {incident_id}"
    )

    item = plans[0]

    plan_path = Path(item["plan_path"]).resolve()

    require(
        plan_path.parent == playbooks,
        "Unexpected playbook path"
    )

    require(
        sha(plan_path) == item["plan_sha256"],
        "Playbook integrity mismatch"
    )

    plan = load(plan_path)

    require(
        plan["incident_id"] == incident_id
        and plan["internal_id"] == incident["internal_id"]
        and plan["alert_type"] == incident["alert_type"],
        "Incident and playbook identity mismatch"
    )

    require(
        record["internal_id"] == incident["internal_id"]
        and record["alert_type"] == incident["alert_type"],
        "Orchestration and incident identity mismatch"
    )

    evidence = plan["evidence"]

    source_path = Path(incident["evidence_reference"])

    ai_path = Path(evidence["ai_result"])

    validation_path = Path(evidence["validation_report"])

    checks = {
        "source_integrity": (
            sha(source_path)
            == incident["source_sha256"]
            == evidence["source_sha256"]
            == record["source_sha256"]
        ),
        "ai_result_integrity": (
            sha(ai_path)
            == evidence["ai_result_sha256"]
            == record["ai_result_sha256"]
        ),
        "validation_integrity": (
            sha(validation_path)
            == evidence["validation_sha256"]
            == record["validation_sha256"]
        ),
        "playbook_integrity": True
    }

    require(
        all(checks.values()),
        f"Evidence integrity failed: {incident_id}"
    )

    ai = load(ai_path)
    validation = load(validation_path)

    require(
        ai["internal_id"] == incident["internal_id"]
        and validation["internal_id"] == incident["internal_id"],
        "AI or validation identity mismatch"
    )

    require(
        ai["source_sha256"] == incident["source_sha256"]
        and validation["source_sha256"] == incident["source_sha256"],
        "AI or validation source hash mismatch"
    )

    require(
        validation["validation_status"]
        in {"PASS", "PASS_WITH_WARNINGS"}
        and validation["summary"]["errors"] == 0,
        "Semantic validation is not eligible"
    )

    require(
        ai["human_validation_required"] is True
        and validation["human_validation_required"] is True,
        "Human review requirement missing"
    )

    receipt_path = (
        workspace / "Runs" / "ExecutionReceipts"
        / f"{incident_id}.json"
    )

    receipt = None
    receipt_verified = False
    receipt_hash = None

    if receipt_path.is_file():

        receipt = load(receipt_path)
        receipt_hash = sha(receipt_path)

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
                step.get("phase"),
                step.get("step_id"),
                step.get("description")
            )
            for step in receipt.get("steps", [])
        ]

        receipt_verified = (
            receipt.get("status") == "COMPLETED"
            and receipt.get("incident_id") == incident_id
            and receipt.get("internal_id") == incident["internal_id"]
            and receipt.get("plan_sha256") == sha(plan_path)
            and receipt.get("source_sha256")
                == incident["source_sha256"]
            and receipt.get("execution_mode") == "SIMULATION_ONLY"
            and receipt.get("external_actions_executed") == 0
            and expected_steps == actual_steps
            and len(actual_steps) > 0
            and receipt.get("steps_count") == len(actual_steps)
            and all(
                step.get("status") == "SIMULATED"
                and step.get("external_action_executed") is False
                for step in receipt.get("steps", [])
            )
        )

    flags = []

    if (
        incident["response_status"] == "COMPLETED"
        and not receipt_verified
    ):

        flags.append(
            "Completed response lacks a verified execution receipt."
        )

    if (
        incident["incident_status"] == "CLOSED"
        and (
            incident["approval_status"] != "APPROVED"
            or incident["response_status"] != "COMPLETED"
            or not receipt_verified
        )
    ):

        flags.append(
            "Incident closure is inconsistent with response controls."
        )

    if receipt is not None and not receipt_verified:

        flags.append(
            "Execution receipt requires manual review."
        )

    return {
        "incident_id": incident_id,
        "internal_id": incident["internal_id"],
        "alert_type": incident["alert_type"],
        "severity": incident["severity"],
        "confidence": incident["confidence"],
        "incident_status": incident["incident_status"],
        "approval_status": incident["approval_status"],
        "response_status": incident["response_status"],
        "source_filename": record["source_filename"],
        "source_sha256": incident["source_sha256"],
        "source_path": str(source_path),
        "ai_mode": record.get("ai_mode"),
        "ai_model": ai.get("model"),
        "ai_analysis": ai.get("analysis"),
        "ai_result_sha256": sha(ai_path),
        "validation_status": validation["validation_status"],
        "validation_summary": validation["summary"],
        "validation_findings": validation.get("findings", []),
        "validation_sha256": sha(validation_path),
        "playbook_id": plan["playbook_id"],
        "playbook_name": plan["playbook_name"],
        "playbook_sha256": sha(plan_path),
        "investigation": plan["investigation"],
        "proposed_response": plan["proposed_response"],
        "recovery": plan["recovery"],
        "execution_receipt": receipt,
        "receipt_verified": receipt_verified,
        "receipt_sha256": receipt_hash,
        "integrity_checks": checks,
        "audit_history": incident.get("audit_history", []),
        "review_flags": flags
    }


def incident_html(record, scope):

    content = (
        '<p><a href="../Executive_Summary.html">'
        'Return to executive summary</a></p>'
    )

    content += (
        '<div class="notice">'
        f'Report scope: {esc(scope)}. '
        'All response actions are simulated.'
        '</div>'
    )

    content += "<h2>1. Incident Overview</h2>"

    content += details({
        key: record[key]
        for key in (
            "incident_id",
            "alert_type",
            "severity",
            "confidence",
            "incident_status",
            "approval_status",
            "response_status"
        )
    })

    content += "<h2>2. Evidence and Provenance</h2>"

    content += details({
        "Source file": record["source_filename"],
        "Source SHA256": record["source_sha256"],
        "AI result SHA256": record["ai_result_sha256"],
        "Validation SHA256": record["validation_sha256"],
        "Playbook SHA256": record["playbook_sha256"],
        "Integrity checks": record["integrity_checks"]
    })

    content += "<h2>3. AI Triage Analysis</h2>"

    content += details({
        "Model": record["ai_model"],
        "Processing mode": record["ai_mode"],
        "Human review required": True
    })

    analysis = record["ai_analysis"]

    if isinstance(analysis, dict):

        content += details(analysis)

    else:

        content += f"<p>{esc(analysis)}</p>"

    content += "<h2>4. Semantic Validation</h2>"

    content += badge(record["validation_status"])

    content += details(record["validation_summary"])

    for finding in record["validation_findings"]:

        if isinstance(finding, dict):

            content += details(finding)

        else:

            content += f"<p>{esc(finding)}</p>"

    content += "<h2>5. SOAR Playbook</h2>"

    content += details({
        "Playbook ID": record["playbook_id"],
        "Playbook name": record["playbook_name"]
    })

    for phase in (
        "investigation",
        "proposed_response",
        "recovery"
    ):

        content += (
            f"<h3>{esc(phase.replace('_', ' ').title())}</h3>"
        )

        content += table(
            ["Step ID", "Planned Action", "Plan Status"],
            [
                (
                    step["step_id"],
                    step["description"],
                    step["status"]
                )
                for step in record[phase]
            ]
        )

    content += "<h2>6. Response Execution</h2>"

    if record["execution_receipt"] is None:

        content += (
            "<p>No execution receipt is available. "
            "No completed simulation is claimed.</p>"
        )

    else:

        receipt = record["execution_receipt"]

        content += details({
            "Receipt status": receipt.get("status"),
            "Receipt verified": record["receipt_verified"],
            "Receipt SHA256": record["receipt_sha256"],
            "Execution mode": receipt.get("execution_mode"),
            "External actions": receipt.get(
                "external_actions_executed"
            )
        })

        content += table(
            ["Phase", "Step", "Description", "Status"],
            [
                (
                    step.get("phase"),
                    step.get("step_id"),
                    step.get("description"),
                    step.get("status")
                )
                for step in receipt.get("steps", [])
            ]
        )

    content += "<h2>7. Audit History</h2>"

    for event in record["audit_history"]:

        content += details(event)

    content += "<h2>8. Review Notes</h2>"

    if record["review_flags"]:

        for flag in record["review_flags"]:

            content += (
                f'<div class="notice">{esc(flag)}</div>'
            )

    else:

        content += (
            "<p>No additional lifecycle consistency "
            "flags were detected by the report generator.</p>"
        )

    return document(
        "SOC Incident Report",
        record["incident_id"] + " | " + record["alert_type"],
        content
    )


def executive_html(report):

    stats = report["statistics"]

    content = (
        '<div class="notice">'
        f'Report scope: {esc(report["report_scope"])}. '
        'Historical laboratory evidence and simulated responses. '
        'This report does not establish real-world containment.'
        '</div>'
    )

    cards = [
        ("Evidence records", stats["evidence_records"]),
        ("Incidents", stats["total_incidents"]),
        ("Manual review", stats["manual_review_records"]),
        ("Verified simulations", stats["verified_simulations"]),
        ("Closed incidents", stats["closed_incidents"])
    ]

    content += '<div class="cards">'

    for title, value in cards:

        content += (
            '<div class="card">'
            f'<strong>{esc(value)}</strong>'
            f'{esc(title)}</div>'
        )

    content += "</div>"

    content += "<h2>1. Executive Summary</h2>"

    content += (
        "<p>The SOC pipeline processes historical security "
        "evidence through AI-assisted triage, semantic "
        "validation, incident management and SOAR planning. "
        "Human approval is required before response simulation.</p>"
    )

    content += details({
        "Orchestration run": report["orchestration_run_id"],
        "Playbook run": report["playbook_run_id"],
        "Generated at UTC": report["generated_at_utc"],
        "Report scope": report["report_scope"],
        "Report status": report["status"]
    })

    content += "<h2>2. Incident Register</h2>"

    content += (
        "<table><thead><tr>"
        "<th>Incident</th><th>Alert Type</th>"
        "<th>Severity</th><th>Validation</th>"
        "<th>Incident Status</th><th>Approval</th>"
        "<th>Response</th></tr></thead><tbody>"
    )

    for record in report["incidents"]:

        incident_id = record["incident_id"]

        content += (
            "<tr>"
            f'<td><a href="Incident_Reports/{esc(incident_id)}.html">'
            f'{esc(incident_id)}</a></td>'
            f'<td>{esc(record["alert_type"])}</td>'
            f'<td>{badge(record["severity"])}</td>'
            f'<td>{badge(record["validation_status"])}</td>'
            f'<td>{badge(record["incident_status"])}</td>'
            f'<td>{badge(record["approval_status"])}</td>'
            f'<td>{badge(record["response_status"])}</td>'
            "</tr>"
        )

    content += "</tbody></table>"

    content += "<h2>3. Security Statistics</h2>"

    for key in (
        "alert_types",
        "severity_distribution",
        "validation_distribution",
        "incident_status_distribution",
        "approval_distribution",
        "response_distribution",
        "ai_processing_distribution"
    ):

        content += (
            f"<h3>{esc(key.replace('_', ' ').title())}</h3>"
        )

        content += table(
            ["Category", "Count"],
            stats[key].items()
        )

    content += "<h2>4. Manual Review Queue</h2>"

    for item in report["manual_review_queue"]:

        content += details(item)

    if not report["manual_review_queue"]:

        content += "<p>No manual-review records.</p>"

    content += "<h2>5. Lifecycle Consistency</h2>"

    for record in report["incidents"]:

        for flag in record["review_flags"]:

            content += (
                '<div class="notice">'
                f'{esc(record["incident_id"])}: '
                f'{esc(flag)}</div>'
            )

    if stats["lifecycle_review_flags"] == 0:

        content += (
            "<p>No additional lifecycle consistency "
            "flags were detected.</p>"
        )

    content += "<h2>6. Limitations and Human Review</h2><ul>"

    for limitation in report["limitations"]:

        content += f"<li>{esc(limitation)}</li>"

    content += "</ul>"

    return document(
        "SOC Executive & Technical Summary",
        "AI-Assisted SOC Automation and Incident Response",
        content
    )


def run(args):

    (
        workspace, playbooks,
        orchestration, store, summary,
        orchestration_path, store_path, summary_path
    ) = resolve_inputs(args)

    protected = {
        str(path): sha(path)
        for path in (
            orchestration_path,
            store_path,
            summary_path
        )
    }

    incidents = []

    for incident in store["incidents"]:

        incident_id = incident["incident_id"]

        require(
            incident_id.startswith("INC-")
            and all(
                char.isalnum() or char == "-"
                for char in incident_id
            ),
            "Invalid incident ID"
        )

        record = collect_incident(
            incident,
            orchestration,
            summary,
            workspace,
            playbooks
        )

        incidents.append(record)

    require(
        len(incidents) > 0,
        "No incidents available"
    )

    require(
        len({item["incident_id"] for item in incidents})
        == len(incidents),
        "Duplicate incident IDs"
    )

    manual = [
        {
            "source_filename": record.get("source_filename"),
            "manifest_status": record.get("manifest_status"),
            "status": record.get("status"),
            "human_validation_required": record.get(
                "human_validation_required"
            )
        }
        for record in orchestration["records"]
        if record.get("status") == "MANUAL_REVIEW_REQUIRED"
    ]

    def distribution(key):

        return dict(
            Counter(
                item.get(key) or "UNKNOWN"
                for item in incidents
            )
        )

    statistics = {
        "evidence_records": len(orchestration["records"]),
        "total_incidents": len(incidents),
        "manual_review_records": len(manual),
        "verified_simulations": sum(
            item["receipt_verified"]
            for item in incidents
        ),
        "closed_incidents": sum(
            item["incident_status"] == "CLOSED"
            for item in incidents
        ),
        "lifecycle_review_flags": sum(
            len(item["review_flags"])
            for item in incidents
        ),
        "alert_types": distribution("alert_type"),
        "severity_distribution": distribution("severity"),
        "validation_distribution": distribution("validation_status"),
        "incident_status_distribution": distribution("incident_status"),
        "approval_distribution": distribution("approval_status"),
        "response_distribution": distribution("response_status"),
        "ai_processing_distribution": distribution("ai_mode")
    }

    report = {
        "project": "DEPI-P5",
        "component": "SOC Report Generator",
        "version": VERSION,
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "orchestration_run_id": workspace.name,
        "playbook_run_id": playbooks.name,
        "report_scope": args.scope,
        "execution_mode": "SIMULATION_ONLY",
        "status": (
            "REVIEW_REQUIRED"
            if statistics["lifecycle_review_flags"] > 0
            else "GENERATED"
        ),
        "statistics": statistics,
        "manual_review_queue": manual,
        "incidents": incidents,
        "limitations": [
            "Historical laboratory evidence is used.",
            "AI severity and confidence require analyst validation.",
            "PASS_WITH_WARNINGS does not establish confirmed compromise.",
            "Missing evidence identifiers require manual review.",
            "Response actions are simulated, not live containment.",
            "Test fixture approvals are not real analyst decisions.",
            "SHA256 checks depend on trusted reference hashes.",
            "Replay protection is scoped to a single workspace.",
            "Direct incident manager calls may bypass receipt checks.",
            "Interactive confirmation is not analyst authentication."
        ]
    }

    output = (
        Path(args.out).resolve()
        / (
            "SOC-REPORT-"
            + datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%SZ"
            )
            + "-" + uuid.uuid4().hex[:8]
        )
    )

    output.mkdir(parents=True, exist_ok=False)

    incident_dir = output / "Incident_Reports"

    incident_dir.mkdir()

    save(
        output / "SOC_Final_Report.json",
        report
    )

    (output / "Executive_Summary.html").write_text(
        executive_html(report),
        encoding="utf-8"
    )

    fields = [
        "incident_id",
        "alert_type",
        "severity",
        "confidence",
        "incident_status",
        "approval_status",
        "response_status",
        "validation_status",
        "ai_mode",
        "receipt_verified",
        "source_filename",
        "source_sha256"
    ]

    with (output / "Incident_Register.csv").open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        writer.writerows(incidents)

    for record in incidents:

        path = (
            incident_dir
            / f'{record["incident_id"]}.html'
        )

        path.write_text(
            incident_html(record, args.scope),
            encoding="utf-8"
        )

    require(
        all(
            sha(path) == digest
            for path, digest in protected.items()
        ),
        "Protected report inputs changed"
    )

    manifest = {
        str(path.relative_to(output)): sha(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }

    save(
        output / "report_manifest.json",
        manifest
    )

    print("=" * 65)
    print("SOC REPORT GENERATION: PASS")
    print("=" * 65)
    print(f"Scope: {args.scope}")
    print(f"Evidence records: {statistics['evidence_records']}")
    print(f"Incidents: {statistics['total_incidents']}")
    print(f"Manual review: {statistics['manual_review_records']}")
    print(f"Verified simulations: {statistics['verified_simulations']}")
    print(f"Closed incidents: {statistics['closed_incidents']}")
    print(f"Report status: {report['status']}")
    print(f"Output: {output}")
    print("=" * 65)

    return 0


def main():

    parser = argparse.ArgumentParser(
        description="DEPI P5 - SOC Report Generator"
    )

    parser.add_argument("--run", required=True)

    parser.add_argument("--playbooks", required=True)

    parser.add_argument("--out", required=True)

    parser.add_argument(
        "--scope",
        required=True,
        choices=[
            "HISTORICAL_LAB",
            "TEST_FIXTURE"
        ]
    )

    args = parser.parse_args()

    try:

        return run(args)

    except Exception as exc:

        print(f"ERROR: {exc}", file=sys.stderr)

        return 1


if __name__ == "__main__":

    sys.exit(main())
