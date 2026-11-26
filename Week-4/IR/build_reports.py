"""Render the seven Week-4 deliverables (Markdown) from the pipeline outputs.

Sources: Output/incident.json, Output/ir_lifecycle.json, Output/ai_drafts/*.json (+ reviews).
Every table is generated from those files; narrative sections that need prose come from the
local-AI drafts and are shown together with their validator flags and human-review status.
If a draft does not exist yet, the section says so instead of inventing text.
"""
from collections import Counter, defaultdict

from common import (AI_DRAFTS_DIR, OUTPUT_DIR, REPORTS_DIR, DRAFT_REVIEWS_LOG, load_json, load_jsonl, rel,
                    utcnow_iso)

STATUS_ICON = {"complete": "COMPLETE", "in_progress": "IN PROGRESS", "pending_analyst_decision": "PENDING ANALYST DECISION",
               "ai_complete_human_partial": "AI COMPLETE / HUMAN PARTIAL", "awaiting_local_ai_drafts": "AWAITING LOCAL AI DRAFTS",
               "ai_drafts_pending_review": "AI DRAFTS PENDING REVIEW", "not_applicable": "N/A", "incomplete": "INCOMPLETE"}


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(esc(x) for x in r) + " |")
    return "\n".join(out)


def load_drafts():
    reviews = {}
    for r in load_jsonl(DRAFT_REVIEWS_LOG):
        reviews[r["draft_id"]] = r
    drafts = {}
    if AI_DRAFTS_DIR.exists():
        for f in sorted(AI_DRAFTS_DIR.glob("*.json")):
            d = load_json(f)
            d["_file"] = rel(f)
            rv = reviews.get(d["draft_id"])
            if rv:
                d["review"] = rv
                corr = AI_DRAFTS_DIR / f'{d["draft_id"]}.corrected.md'
                if rv["status"] == "Corrected" and corr.exists():
                    d["corrected_text"] = corr.read_text(encoding="utf-8")
                    d["_corrected_file"] = rel(corr)
            drafts[d["draft_id"]] = d
    return drafts


def draft_block(drafts, did, title):
    d = drafts.get(did)
    if not d:
        return (f"### {title}\n\n> **PENDING** - no local-AI draft yet. Run `python -B Week-4/IR/ir_cli.py draft --only {did}` "
                f"on the machine with Ollama + Mistral, then `ir_cli.py review`.\n")
    if d.get("status") != "generated":
        return f"### {title}\n\n> **Draft generation failed:** {d.get('error')}\n"
    rv = d.get("review") or {"status": "Pending Review"}
    sev = d["validation"]["severity_counts"]
    head = (f"### {title}\n\n"
            f"*Local model:* `{d['model']}` | *time:* {d['wall_seconds']} s | *tokens/s:* {d['tokens_per_second']} | "
            f"*validator flags:* {len(d['validation']['flags'])} (high {sev.get('high', 0)}, medium {sev.get('medium', 0)}, "
            f"low {sev.get('low', 0)}) | *human review:* **{rv['status']}**"
            + (f" by {rv.get('analyst')}" if rv.get("analyst") else "") + f" | *file:* `{d['_file']}`\n\n")
    if d.get("corrected_text"):
        body = d["corrected_text"]
        head += f"> Analyst-corrected version (`{d['_corrected_file']}`). Original AI text kept in the JSON file.\n\n"
    else:
        body = d["text"]
        if rv["status"] == "Pending Review":
            head += "> DRAFT - AI-generated, not yet validated by an analyst.\n\n"
    flags = d["validation"]["flags"]
    fl = ""
    if flags:
        fl = "\n\n<details><summary>Validator flags</summary>\n\n" + table(
            ["ID", "Check", "Severity", "Value", "Message"],
            [[f.get("id", ""), f["check"], f["severity"], f.get("value", "")[:80], f["message"]] for f in flags]) + "\n\n</details>\n"
    return head + body.strip() + fl + "\n"


def signoff():
    return ("\n## Human sign-off\n\n" + table(["Role", "Name", "Decision (Approved / Corrected / Rejected)", "Date", "Signature"],
                                              [["SOC analyst", "", "", "", ""], ["IR lead", "", "", "", ""],
                                               ["Project supervisor", "", "", "", ""]]) + "\n")


def header(title, model):
    sc = model["scenario"]
    return (f"# {title}\n\n**Project:** DEPI Project 5 - AI-Assisted SOC Automation & Full Incident Response Capstone  \n"
            f"**Week:** 4 - Full Capstone IR Simulation & Reporting  \n**Scenario:** {sc['scenario_id']} - {sc['title']}  \n"
            f"**Generated:** {utcnow_iso()} by `Week-4/IR/build_reports.py` from `Week-4/Output/` (data generated "
            f"{model['generated_at_utc']})  \n**Status:** DRAFT - acceptance pending human sign-off\n\n")


def boundary(model):
    return "## Simulation boundary\n\n" + "\n".join(f"- {b}" for b in model["scenario"]["boundary_statement"]) + "\n"


# --------------------------------------------------------------------------------------------
def r_timeline(model):
    by = {c["case_id"]: c for c in model["cases"]}
    out = [header("Incident Timeline", model), boundary(model),
           "\nFull machine-readable timeline (every source event): `Week-4/Output/incident_timeline.csv` "
           f"({model['timeline_events']} events). Below: first 4 + last 4 events per case.\n",
           "\nTimestamp quality legend: `original_utc` = original UTC time in the dataset; `original_with_offset` = original "
           "local time with offset; `no_year_no_timezone` = syslog time without year/zone (never inferred); "
           "`original_no_timezone` = original time, zone not recorded.\n"]
    for st in sorted(model["scenario"]["stages"], key=lambda s: s["order"]):
        out.append(f"\n## {st['stage_id']} - {st['name']} ({st['kill_chain']}, {st['domain']})\n")
        for cid in st["case_ids"]:
            c = by[cid]
            out.append(f"\n### {cid} - {c['title']}\n")
            ev = c["events"]
            shown = ev if len(ev) <= 8 else ev[:4] + [None] + ev[-4:]
            rows = [[e["ts_original"], e["ts_quality"], e["ref"], e["summary"]] if e else
                    ["...", "", "", f"{len(ev) - 8} more verified events in incident_timeline.csv"] for e in shown]
            out.append(table(["Original timestamp", "Quality", "Ref", "Event"], rows))
            if c["event_count_total"] > len(ev):
                out.append(f"\n*Selected evidence shown; the full source contains {c['event_count_total']} records - see source files.*")
            out.append("\nSources: " + ", ".join(f"`{f['path']}`" for f in c["evidence_files"]) + "\n")
    return "\n".join(out)


def r_forensic(model):
    out = [header("Forensic Evidence Summary", model), boundary(model),
           "\n## Chain of custody\n\n- Week-4 reads Week-1..3 artifacts read-only; no evidence file is modified.\n"
           "- SHA-256 below was computed by `correlate.py` at build time. Re-run `ir_cli.py build` and compare to detect change.\n"
           "- Original raw datasets and their own manifests stay in `Week-2/Data/Real-Datasets/*/` (source manifests, "
           "final verification manifests).\n- The large malware EVTX referenced by Week-2 is not in the repository; its "
           "derived ingest JSON and Sysmon evidence are.\n"]
    out.append("\n## Evidence inventory\n")
    rows = []
    for c in model["cases"]:
        for f in c["evidence_files"]:
            rows.append([c["case_id"], c["stage_id"], f["path"], f["sha256"]])
    out.append(table(["Case", "Stage", "File", "SHA-256"], rows))
    out.append("\n## Case findings and evidentiary limits\n")
    for c in model["cases"]:
        ai = c.get("ai") or {}
        out.append(f"\n### {c['case_id']} - {c['title']} ({'benign control' if c['benign_control'] else c['stage_id']})\n")
        out.append(f"- Source kind: {c['source_kind']}; dataset: `{c['dataset']}`; source records: {c['event_count_total']}")
        tq = Counter(e["ts_quality"] for e in c["events"])
        out.append("- Timestamp quality: " + ", ".join(f"{k} x{v}" for k, v in tq.items()))
        if ai:
            if c["source_kind"] == "siem_alert":
                out.append(f"- AI triage (local {ai.get('model')}): severity {ai.get('severity')}, confidence {ai.get('confidence')}, "
                           f"QA {ai.get('qa_status')}; trigger->triage {ai.get('trigger_to_ai_triage_seconds')} s")
            else:
                out.append(f"- Final Week-2 analysis {ai['final_analysis_id']} ({ai['runs_total']} runs): {ai['validator_flags']} "
                           f"validator flags; human review **{ai['review_status']}**; analyst-recorded hallucination entries "
                           f"{ai['hallucinations_recorded']}")
        for a in c["attack"]:
            out.append(f"- ATT&CK {a['technique']} {a['name']} - *{a['confidence']}*")
        for lim in c["limitations"]:
            out.append(f"- Limitation: {lim}")
    out.append("\n## Observables (IOCs and context)\n\nReputation: not checked for any value (no live TI feed). "
               "Full list: `Week-4/Output/observables.csv`.\n")
    out.append(table(["Role", "Type", "Value", "Cases", "Scope"],
                     [[o["role"], o["type"], o["value"], ", ".join(o["cases"]), o["scope"] or ""] for o in model["observables"]]))
    out.append("\n## Cross-dataset overlaps found by correlation\n")
    out.append(table(["Value", "Type", "Role", "Cases"],
                     [[o["value"], o["type"], o["role"], ", ".join(o["cases"])] for o in model["cross_case_overlaps"]]))
    return "\n".join(out) + signoff()


def r_plan(model, life):
    out = [header("Containment, Eradication & Recovery Plan", model), boundary(model),
           "\n**Tiers** (from Week-3 decision matrix): T0 = read-only check; T1 = proposal, requires a recorded analyst "
           "decision, executed out-of-band by a human; T2 = automation prohibited by design.\n\n"
           "Record a decision: `python -B Week-4/IR/ir_cli.py decide --item <ITEM_ID> --decision approved|rejected|done "
           "--analyst \"Name\" --note \"...\"` (append-only log `Week-4/Simulation/analyst_decisions.jsonl`). Rule-based "
           "suggestions (`Week-4/IR/suggest.py`) can be accepted with `ir_cli.py accept-suggestions --analyst \"Name\"`; "
           "the log marks those decisions as accepted suggestions.\n"]
    out.append("\n## Phase status\n")
    out.append(table(["Phase", "Status", "Detail"],
                     [[p["name"], STATUS_ICON.get(p["status"], p["status"]), p["detail"]] for p in life["phases"]]))
    for ph in ("containment", "eradication", "recovery"):
        out.append(f"\n## {ph.capitalize()}\n")
        rows = [[i["case_id"], i["stage_id"], i["tier"], i["action"],
                 (("[data] " if i["check"]["completed_from_repo"] else "[not in repo] ") + i["check"]["result"]) if i.get("check") else "",
                 i["decision"] + (f" ({i['decided_by']}" + (", rule suggestion accepted" if i.get("decision_via") == "accepted_rule_suggestion" else "") + ")" if i.get("decided_by") else "")
                 + (f" - suggested: {i['suggested_decision']}" if i["decision"].startswith("pending") and i.get("suggested_decision") else ""),
                 i["item_id"]]
                for i in life["items"] if i["phase"] == ph]
        out.append(table(["Case", "Stage", "Tier", "Action", "Automated read-only check (T0)", "Decision", "Item ID"], rows))
    out.append("\n## Prohibited automation (Week-3 Tier 2)\n")
    out.append(table(["Case", "Action", "Reason", "Tickets"],
                     [[i["case_id"], i["action"], i["basis"], ", ".join(i.get("tickets", []))]
                      for i in life["items"] if i["phase"] == "prohibited"]))
    return "\n".join(out) + signoff()


def _stage_findings(model, life, drafts):
    by = {c["case_id"]: c for c in model["cases"]}
    out = []
    for st in sorted(model["scenario"]["stages"], key=lambda s: s["order"]):
        out.append(f"\n### {st['stage_id']} - {st['name']}\n\n*Analyst question:* {st['question_for_analysts']}\n")
        rows = []
        for cid in st["case_ids"]:
            c = by[cid]
            ai = c.get("ai") or {}
            rows.append([cid, c["title"], ", ".join(a["technique"] for a in c["attack"]),
                         ai.get("severity") or "-", c["human_review"]["status"], c["event_count_total"]])
        out.append(table(["Case", "Finding", "ATT&CK", "AI severity", "Human review", "Records"], rows))
        out.append("\n" + draft_block(drafts, f"stage_{st['stage_id']}", f"AI stage summary - {st['stage_id']}"))
    return "\n".join(out)


def r_final(model, life, drafts):
    q, w1 = model["week2_quality"], model["week1_benchmark"]
    attack = [c for c in model["cases"] if not c["benign_control"]]
    tickets = [t for c in model["cases"] for t in c["tickets"]]
    t1 = [i for i in life["items"] if i["tier"] == "T1"]
    out = [header("Final Capstone Incident Response Report", model), boundary(model)]
    out.append("\n## 1. Exercise at a glance\n")
    out.append(table(["Metric", "Value", "Source"], [
        ["Attack stages", len(model["scenario"]["stages"]), "Week-4/Config/scenario.json"],
        ["Evidence-backed attack cases", len(attack), "Week-4/Output/incident.json"],
        ["Benign controls", len(model["cases"]) - len(attack), "Week-4/Output/incident.json"],
        ["Source events on the timeline", model["timeline_events"], "Week-4/Output/incident_timeline.csv"],
        ["Indicators / context observables", f"{sum(1 for o in model['observables'] if o['role']=='indicator')} / "
                                             f"{sum(1 for o in model['observables'] if o['role']=='context')}", "Week-4/Output/observables.csv"],
        ["Cross-dataset overlaps", len(model["cross_case_overlaps"]), "Week-4/Output/observables.csv"],
        ["Week-3 SOAR tickets", len(tickets), "Week-3/SOAR/tickets/"],
        ["T1 response proposals / pending decision", f"{len(t1)} / {sum(1 for i in t1 if i['decision'].startswith('pending'))}",
         "Week-4/Output/ir_lifecycle.json"],
        ["Week-2 local-AI analysis runs / human-reviewed", f"{q['analysis_runs']} / {q['reviewed_runs']}", q["source"]],
        ["Mean OpenObserve trigger -> AI triage (s)", model["week2_siem_trigger_to_triage_seconds"]["mean"], "Week-2/Evidence/SIEM-OpenObserve/"],
    ]))
    out.append("\n## 2. AI incident report draft (Week-1 Incident-Report prompt, local Mistral)\n")
    out.append(draft_block(drafts, "incident_report", "Incident report draft"))
    out.append("\n## 3. Findings by stage\n")
    out.append(_stage_findings(model, life, drafts))
    done = [i for i in life["items"] if i.get("check") and i["check"]["completed_from_repo"]]
    out.append("\n## 4. Read-only checks answered from repository data (T0)\n")
    out.append("These checks only read Week-2 datasets (`Week-4/IR/t0_checks.py`); the analyst still records the decision.\n")
    out.append(table(["Case", "Check", "Result", "Source"],
                     [[i["case_id"], i["action"], i["check"]["result"], i["check"]["source"]] for i in done]))
    out.append("\n## 5. NIST SP 800-61 lifecycle status\n")
    out.append(table(["Phase", "Status", "Detail"],
                     [[p["name"], STATUS_ICON.get(p["status"], p["status"]), p["detail"]] for p in life["phases"]]))
    out.append("\nDetailed actions: `Reports/04_Containment_Recovery_Plan.md`.\n")
    out.append("\n## 6. AI assistance across the project\n")
    out.append(table(["Model", "Manual quality /5", "Unsupported-fact severity /3", "Keyword recall (not accuracy)", "Tokens/s"],
                     [[m["model"], m["manual_quality_mean"], m["manual_unsupported_severity_mean"], m["avg_auto_recall"],
                       m["avg_tokens_per_sec"]] for m in w1["models"]]))
    out.append(f"\nWeek-2: {q['analysis_runs']} runs, {q['validator_flags_total']} validator flags "
               f"({q['validator_flags_by_severity'].get('high', 0)} high). Of {q['reviewed_runs']} human-reviewed runs, "
               f"{q['reviewed_runs_corrected']} were Corrected and {q['reviewed_runs_approved']} Approved; analysts recorded "
               f"{q['analyst_correct_findings']} correct vs {q['analyst_incorrect_findings']} incorrect AI findings. "
               f"Source: `{q['source']}`.\n")
    out.append("\n## 7. Open acceptance gates carried into Week 4\n")
    out.append("\n".join(f"- (Week-2) {g}" for g in life["open_gates"]["week2"]))
    out.append("\n".join([""] + [f"- (Week-3) {g}" for g in life["open_gates"]["week3"]]))
    out.append("\n\n## 8. Deliverable index\n")
    out.append(table(["Deliverable", "File"], [
        ["Final Capstone IR Report", "Week-4/Reports/01_Final_Capstone_IR_Report.md"],
        ["Incident timeline", "Week-4/Reports/02_Incident_Timeline.md + Output/incident_timeline.csv"],
        ["Forensic evidence summary", "Week-4/Reports/03_Forensic_Evidence_Summary.md"],
        ["Containment / recovery plan", "Week-4/Reports/04_Containment_Recovery_Plan.md"],
        ["Executive briefing", "Week-4/Reports/05_Executive_Briefing.md"],
        ["Lessons learned", "Week-4/Reports/06_Lessons_Learned.md"],
        ["AI-assisted reporting workflow", "Week-4/Reports/07_AI_Assisted_Reporting_Workflow.md"],
        ["SOC dashboard", "Week-4/Dashboard/index.html"],
    ]))
    return "\n".join(out) + "\n" + signoff()


def r_exec(model, life, drafts):
    attack = [c for c in model["cases"] if not c["benign_control"]]
    t1 = [i for i in life["items"] if i["tier"] == "T1"]
    out = [header("Executive Briefing", model)]
    out.append("## Key figures (generated from data)\n")
    out.append(table(["", ""], [
        ["What was exercised", f"{len(model['scenario']['stages'])}-stage composite intrusion (network, web, auth, endpoint, email)"],
        ["Evidence", f"{len(attack)} attack cases + {len(model['cases']) - len(attack)} benign controls, all from historical lab data"],
        ["AI role", "Local Mistral 7B drafts triage and reports; every output is validated and human-reviewed"],
        ["Response status", f"{len(t1)} response proposals; {sum(1 for i in t1 if i['decision'].startswith('pending'))} awaiting decision; nothing auto-executed"],
        ["Impact", "Unknown - no confirmed data loss, exploitation or account compromise in the evidence"],
    ]))
    out.append("\n" + draft_block(drafts, "exec_briefing", "Briefing text (local AI draft)"))
    return "\n".join(out) + signoff()


def r_lessons(model, life, drafts):
    q, w1 = model["week2_quality"], model["week1_benchmark"]
    best = max(w1["models"], key=lambda m: m["manual_quality_mean"] or 0)
    out = [header("Lessons Learned", model)]
    out.append("## Data-derived observations\n")
    obs = [
        f"Week-1: the best manual-quality model was `{best['model']}` at {best['manual_quality_mean']}/5 - no local model is "
        f"suitable for autonomous triage; keyword recall overstated quality.",
        f"Week-2: {q['validator_flags_total']} validator review requests across {q['analysis_runs']} runs; most frequent: "
        + ", ".join(f"`{k}` ({v})" for k, v in q["top_flag_checks"][:3]) + ".",
        f"Week-2: {q['reviewed_runs_corrected']} of {q['reviewed_runs']} reviewed AI analyses needed correction; human review "
        f"remained the final gate.",
        f"Week-3: all {sum(len(c['tickets']) for c in model['cases'])} SOAR tickets are still `Pending Review`; Tier-2 automation "
        f"stayed blocked.",
        f"Week-4: correlation across separate datasets found {len(model['cross_case_overlaps'])} shared observables "
        + "(" + "; ".join(f"{o['value']} in {', '.join(o['cases'])}" for o in model["cross_case_overlaps"]) + ").",
        "Threat-intelligence enrichment is a stub: no indicator reputation could be checked.",
    ]
    out.append("\n".join(f"- {o}" for o in obs))
    out.append("\n\n## Open gates\n")
    out.append("\n".join(f"- {g}" for g in life["open_gates"]["week2"] + life["open_gates"]["week3"]))
    out.append("\n\n" + draft_block(drafts, "lessons_learned", "Lessons-learned narrative (local AI draft)"))
    return "\n".join(out) + signoff()


def r_workflow(model, drafts):
    out = [header("AI-Assisted Reporting Workflow", model)]
    out.append("""## Workflow

```
Week-2 evidence + Week-3 tickets
        |
        v
correlate.py ---------> Output/incident.json  (cases, timeline, observables, ATT&CK)
        |
        v
ir_lifecycle.py ------> Output/ir_lifecycle.json (NIST phases, proposals, decisions)
        |
        v
ai_report_drafter.py
   1. builds a numbered fact sheet [E001..] from the two files (code, no hand-typed values)
   2. fills a prompt (Week-1 Incident-Report prompt reused; Week-4 prompts in Week-4/Prompts)
   3. calls LOCAL Ollama via Week-2 Core/ollama_client.py (loopback only, 1 controlled retry)
   4. validates the text with Week-2 Core/validator.py against the fact sheet
   5. saves Output/ai_drafts/<id>.json  (review status: Pending Review)
        |
        v
Human analyst: ir_cli.py review --draft <id> --status Approved|Corrected|Rejected
   (Corrected text goes in Output/ai_drafts/<id>.corrected.md)
        |
        v
build_reports.py + build_dashboard.py -> Reports/*.md, Dashboard/index.html
```

## Human gates

1. No draft is used as final text until an analyst records a review.
2. Validator flags are requests for review, not proof of hallucination; passing them is not proof of correctness.
3. Response proposals are never executed by the pipeline; decisions are recorded in `Simulation/analyst_decisions.jsonl`.
4. Model, prompt hash, options, attempts, timing and flags are saved with every draft for audit.
""")
    out.append("\n## Draft runs\n")
    if not drafts:
        out.append("> **PENDING** - no drafts yet. Run `python -B Week-4/IR/ir_cli.py draft` on the Ollama machine.\n")
    else:
        rows = []
        for d in drafts.values():
            rv = (d.get("review") or {}).get("status", "Pending Review")
            if d.get("status") == "generated":
                rows.append([d["draft_id"], d["model"], d["prompt_file"], len(d["facts"]), d["wall_seconds"],
                             d["tokens_per_second"], d["done_reason"], len(d["validation"]["flags"]), rv])
            else:
                rows.append([d["draft_id"], "-", d.get("prompt_file", ""), len(d.get("facts", [])), "-", "-", "failed", "-", rv])
        out.append(table(["Draft", "Model", "Prompt", "Facts", "Seconds", "Tok/s", "Done", "Flags", "Review"], rows))
        allf = Counter(f["check"] for d in drafts.values() if d.get("status") == "generated" for f in d["validation"]["flags"])
        if allf:
            out.append("\n\n**Validator checks raised on drafts:** " + ", ".join(f"`{k}` x{v}" for k, v in allf.most_common()))
    return "\n".join(out) + "\n"


def build():
    model = load_json(OUTPUT_DIR / "incident.json")
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    drafts = load_drafts()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    files = {
        "01_Final_Capstone_IR_Report.md": r_final(model, life, drafts),
        "02_Incident_Timeline.md": r_timeline(model),
        "03_Forensic_Evidence_Summary.md": r_forensic(model),
        "04_Containment_Recovery_Plan.md": r_plan(model, life),
        "05_Executive_Briefing.md": r_exec(model, life, drafts),
        "06_Lessons_Learned.md": r_lessons(model, life, drafts),
        "07_AI_Assisted_Reporting_Workflow.md": r_workflow(model, drafts),
    }
    for name, text in files.items():
        (REPORTS_DIR / name).write_text(text, encoding="utf-8")
    return list(files)


if __name__ == "__main__":
    for f in build():
        print("wrote", f)
