"""Export the dashboard data file (Dashboard/dashboard_data.js) from the pipeline outputs.

The dashboard is a static page (Dashboard/index.html) that reads `window.SOC_DATA` from this file,
so it opens offline by double-click (no web server, no CDN, no network).
Every KPI carries the repository file it was computed from.
"""
import json
import re

from build_reports import load_drafts
from common import DASHBOARD_DIR, OUTPUT_DIR, WEEK3, load_json, rel, utcnow_iso

TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration"]


def decision_matrix():
    p = WEEK3 / "SOAR" / "decision-matrix.md"
    rows = []
    for ln in p.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\|\s*(\d+)\s*\|(.*)\|\s*$", ln)
        if m:
            cells = [c.strip() for c in m.group(2).split("|")]
            if len(cells) >= 5:
                rows.append({"n": int(m.group(1)), "action": cells[0], "t0": cells[1], "t1": cells[2], "t2": cells[3],
                             "basis": cells[4]})
    return {"rows": rows, "source": rel(p)}


def _block(txt, name):
    m = re.search(rf"^  {name}:\s*\n((?:    .*\n|\s*\n)*)", txt, re.M)
    return m.group(1) if m else ""


def playbooks():
    """Read the Week-3 playbook YAML (fixed schema) without a YAML dependency."""
    out = []
    for f in sorted((WEEK3 / "SOAR" / "playbooks").glob("PB-0*.yaml")):
        txt = f.read_text(encoding="utf-8")
        g = lambda k: (re.search(rf"^{k}:\s*(.+)$", txt, re.M) or [None, ""])[1].strip()
        out.append({"id": g("playbook_id"), "rule": g("alert_rule"), "tier_max": g("tier_max"),
                    "auto": re.findall(r"^    - (\w+)\s*$", _block(txt, "auto"), re.M),
                    "propose": re.findall(r"^    - action: (\w+)", _block(txt, "propose"), re.M),
                    "prohibited": re.findall(r"^    - action: (\w+)", _block(txt, "prohibited"), re.M),
                    "source": rel(f)})
    return out


def sample(events, n):
    """First n/2 + last n/2 events (keeps start and end of long cases; nothing reordered)."""
    if len(events) <= n:
        return events
    h = n // 2
    return events[:h] + [{"gap": len(events) - n}] + events[-h:]


def compact_case(c):
    ai = c.get("ai") or {}
    return {
        "id": c["case_id"], "title": c["title"], "domain": c["domain"], "stage": c["stage_id"], "kind": c["source_kind"],
        "benign": c["benign_control"], "rule": c["detection_rule"], "playbook": c["playbook"], "dataset": c["dataset"],
        "severity": ai.get("severity"), "confidence": ai.get("confidence"), "qa": ai.get("qa_status"),
        "ai_summary": ai.get("summary"), "model": ai.get("model"),
        "trigger_latency": ai.get("trigger_to_ai_triage_seconds"),
        "analysis_id": ai.get("final_analysis_id"), "runs": ai.get("runs_total"), "flags": ai.get("validator_flags"),
        "flag_sev": ai.get("validator_severity_counts"), "hallucinations": ai.get("hallucinations_recorded"),
        "correct": ai.get("correct_findings"), "incorrect": ai.get("incorrect_findings"),
        "review": c["human_review"].get("status"), "analyst": c["human_review"].get("analyst"),
        "ai_source": ai.get("source"),
        "events_total": c["event_count_total"], "events": sample(c["events"], 12),
        "facts": {k: v for k, v in c["facts"].items() if k != "context_values"},
        "attack": c["attack"], "limitations": c["limitations"], "files": c["evidence_files"],
        "tickets": [{k: t[k] for k in ("ticket_id", "playbook_id", "tier", "qa_status", "review_status", "proposed_actions",
                                       "prohibited_actions", "auto_actions", "audit_lines", "file", "audit_file")}
                    for t in c["tickets"]],
    }


def build():
    model = load_json(OUTPUT_DIR / "incident.json")
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    drafts = load_drafts()
    cases = model["cases"]
    attack_cases = [c for c in cases if not c["benign_control"]]
    tickets = [t for c in cases for t in c["tickets"]]
    t1 = [i for i in life["items"] if i["tier"] == "T1"]
    q = model["week2_quality"]
    ind = [o for o in model["observables"] if o["role"] == "indicator"]

    kpis = [
        {"label": "Attack stages", "value": len(model["scenario"]["stages"]), "sub": "kill-chain stages in scenario",
         "source": "Week-4/Config/scenario.json"},
        {"label": "Evidence-backed cases", "value": len(attack_cases), "sub": f"+{len(cases) - len(attack_cases)} benign controls",
         "source": "Week-4/Output/incident.json"},
        {"label": "Timeline events", "value": model["timeline_events"], "sub": "verified source records on the timeline",
         "source": "Week-4/Output/incident_timeline.csv"},
        {"label": "Indicators", "value": len(ind), "sub": f"{len(model['cross_case_overlaps'])} cross-dataset overlaps",
         "source": "Week-4/Output/observables.csv"},
        {"label": "SOAR tickets", "value": len(tickets),
         "sub": f"{sum(1 for t in tickets if t['review_status'] == 'Pending Review')} pending review", "source": "Week-3/SOAR/tickets/"},
        {"label": "Proposals pending", "value": sum(1 for i in t1 if i["decision"].startswith("pending")),
         "sub": f"of {len(t1)} T1 proposals - nothing auto-executed", "source": "Week-4/Output/ir_lifecycle.json"},
        {"label": "Local-AI analyses", "value": q["analysis_runs"], "sub": f"{q['reviewed_runs']} human-reviewed",
         "source": q["source"]},
        {"label": "Trigger -> AI triage", "value": model["week2_siem_trigger_to_triage_seconds"]["mean"], "unit": "s",
         "sub": f"mean of {len(model['week2_siem_trigger_to_triage_seconds']['values'])} OpenObserve alerts",
         "source": "Week-2/Evidence/SIEM-OpenObserve/*.json"},
    ]

    tactics = {}
    for c in attack_cases:
        for a in c["attack"]:
            t = tactics.setdefault(a["tactic"], {})
            k = a["technique"]
            e = t.setdefault(k, {"technique": k, "name": a["name"], "cases": [], "confidence": []})
            e["cases"].append(c["case_id"])
            e["confidence"].append(a["confidence"])
    matrix = [{"tactic": tac, "techniques": list(tactics[tac].values())} for tac in TACTIC_ORDER if tac in tactics]

    timeline = []
    by = {c["case_id"]: c for c in cases}
    for st in sorted(model["scenario"]["stages"], key=lambda s: s["order"]):
        for cid in st["case_ids"]:
            for e in sample(by[cid]["events"], 6):
                timeline.append({"stage": st["stage_id"], "domain": st["domain"], "case": cid, **e})

    draft_rows = []
    for d in drafts.values():
        row = {"id": d["draft_id"], "status": d.get("status"), "review": (d.get("review") or {}).get("status", "Pending Review"),
               "file": d["_file"]}
        if d.get("status") == "generated":
            row.update(model=d["model"], seconds=d["wall_seconds"], tps=d["tokens_per_second"], done=d["done_reason"],
                       flags=len(d["validation"]["flags"]), flag_sev=d["validation"]["severity_counts"],
                       facts=len(d["facts"]), text=d.get("corrected_text") or d["text"])
        draft_rows.append(row)

    data = {
        "meta": {"generated_at_utc": utcnow_iso(), "data_generated_at_utc": model["generated_at_utc"],
                 "scenario": {k: model["scenario"][k] for k in ("scenario_id", "title", "simulation_type", "framework",
                                                               "boundary_statement")}},
        "kpis": kpis,
        "stages": model["scenario"]["stages"],
        "fp_controls": model["scenario"]["false_positive_controls"],
        "cases": [compact_case(c) for c in cases],
        "timeline": timeline,
        "attack_matrix": matrix,
        "observables": model["observables"],
        "overlaps": model["cross_case_overlaps"],
        "lifecycle": {"phases": life["phases"], "items": life["items"], "decisions_recorded": life["decisions_recorded"]},
        "soar": {"playbooks": playbooks(), "decision_matrix": decision_matrix()},
        "ai": {"week1": model["week1_benchmark"], "week2": q, "latency": model["week2_siem_trigger_to_triage_seconds"],
               "drafts": draft_rows, "draft_ids_expected": ["incident_report", "exec_briefing", "lessons_learned"]
                                                           + [f"stage_{s['stage_id']}" for s in model["scenario"]["stages"]]},
        "gates": life["open_gates"],
        "reports": [{"name": n, "file": f"../Reports/{n}"} for n in (
            "01_Final_Capstone_IR_Report.md", "02_Incident_Timeline.md", "03_Forensic_Evidence_Summary.md",
            "04_Containment_Recovery_Plan.md", "05_Executive_Briefing.md", "06_Lessons_Learned.md",
            "07_AI_Assisted_Reporting_Workflow.md")],
    }
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)
    out = DASHBOARD_DIR / "dashboard_data.js"
    out.write_text("/* Generated by Week-4/IR/build_dashboard.py - do not edit by hand. */\nwindow.SOC_DATA = "
                   + json.dumps(data, ensure_ascii=False) + ";\n", encoding="utf-8")
    return rel(out)


if __name__ == "__main__":
    print(build())
