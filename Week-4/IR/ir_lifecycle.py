"""Week 4 NIST SP 800-61 / SANS incident-response lifecycle for the composite tabletop.

Input : Output/incident.json (from correlate.py), Week-3 tickets (inside incident.json),
        Config/response_catalog.json, Simulation/analyst_decisions.jsonl (human decisions).
Output: Output/ir_lifecycle.json

Phase status is COMPUTED, never asserted:
  * Detection & analysis  -> from evidence files, AI triage records and recorded human reviews.
  * Containment / eradication / recovery -> from proposals and the analyst decision log.
    No proposal is executed by this code. A phase is only "complete" when every T1 proposal in it
    has a recorded analyst decision.
  * Post-incident -> from lessons-learned inputs and AI-draft reviews.
"""
import re
import string

from common import (OUTPUT_DIR, DECISIONS_LOG, DRAFT_REVIEWS_LOG, AI_DRAFTS_DIR, WEEK1, WEEK2, WEEK3,
                    load_config, load_json, load_jsonl, rel, utcnow_iso, write_json)

PHASES = ["containment", "eradication", "recovery"]


class _Strict(dict):
    def __missing__(self, key):
        raise KeyError(key)


def _fmt_value(v):
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return str(v)


def fill_soft(template, facts):
    """Fill only placeholders that exist in facts (used for Week-3 ticket templates)."""
    def rep(m):
        k = m.group(1)
        return _fmt_value(facts[k]) if k in facts else m.group(0)
    return re.sub(r"\{(\w+)\}", rep, template)


def fill(template, facts, case_id):
    keys = [f[1] for f in string.Formatter().parse(template) if f[1]]
    vals = _Strict({k: _fmt_value(facts[k]) for k in keys if k in facts})
    try:
        return template.format_map(vals)
    except KeyError as e:
        raise SystemExit(f"response_catalog.json: placeholder {e} not found in facts of {case_id}")


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:48]


def latest_decisions():
    out = {}
    for row in load_jsonl(DECISIONS_LOG):
        out[row["item_id"]] = row          # last decision wins; full history stays in the log
    return out


def build_items(model):
    catalog = load_config("response_catalog.json")["cases"]
    decisions = latest_decisions()
    items = []
    for c in model["cases"]:
        if c["benign_control"]:
            continue
        cid = c["case_id"]
        # Week-3 ticket proposals (containment) + prohibited actions
        seen_t2 = {}
        for t in c["tickets"]:
            for pa in t["proposed_detail"]:
                iid = f'{cid}:containment:{pa["action"]}:{t["ticket_id"][:8]}'
                raw = pa.get("template") or pa["action"]
                filled = fill_soft(raw, c["facts"])
                basis = f'Week-3 {t["playbook_id"]} ticket {t["ticket_id"][:12]}: {pa.get("rationale", "")}'.strip()
                if filled != raw:
                    basis += " [template placeholder filled by Week-4 from Week-2 evidence]"
                items.append({"item_id": iid, "case_id": cid, "stage_id": c["stage_id"], "phase": "containment",
                              "tier": "T1", "action": filled, "basis": basis, "source": t["file"],
                              "ticket_id": t["ticket_id"]})
            for pr in t["prohibited_detail"]:
                if pr["action"] in seen_t2:
                    seen_t2[pr["action"]]["tickets"].append(t["ticket_id"][:12])
                    continue
                it = {"item_id": f'{cid}:prohibited:{pr["action"]}', "case_id": cid, "stage_id": c["stage_id"],
                      "phase": "prohibited", "tier": "T2", "action": pr["action"], "basis": pr.get("reason", ""),
                      "source": t["file"], "tickets": [t["ticket_id"][:12]]}
                seen_t2[pr["action"]] = it
                items.append(it)
        for n, entry in enumerate(catalog.get(cid, []), 1):
            text = fill(entry["action"], c["facts"], cid)
            iid = f'{cid}:{entry["phase"]}:{n}-{_slug(entry["action"])[:24]}'
            items.append({"item_id": iid, "case_id": cid, "stage_id": c["stage_id"], "phase": entry["phase"],
                          "tier": entry["tier"], "action": text, "basis": "Week-4 response catalog",
                          "source": "Week-4/Config/response_catalog.json"})
    for it in items:
        d = decisions.get(it["item_id"])
        if it["tier"] == "T2":
            it["decision"] = "prohibited_by_design"
        elif d:
            it["decision"] = d["decision"]
            it["decided_by"] = d.get("analyst")
            it["decided_utc"] = d.get("ts_utc")
            it["decision_note"] = d.get("note", "")
            it["decision_via"] = d.get("via", "cli")
        else:
            it["decision"] = "pending_analyst_decision" if it["tier"] == "T1" else "pending_analyst_check"
    return items


def phase_status(items, phase):
    mine = [i for i in items if i["phase"] == phase]
    open_ = [i for i in mine if i["decision"].startswith("pending")]
    if not mine:
        status = "not_applicable"
    elif not open_:
        status = "complete"
    elif len(open_) < len(mine):
        status = "in_progress"
    else:
        status = "pending_analyst_decision"
    return {"status": status, "items": len(mine), "open": len(open_),
            "approved": sum(1 for i in mine if i["decision"] == "approved"),
            "rejected": sum(1 for i in mine if i["decision"] == "rejected"),
            "done_checks": sum(1 for i in mine if i["decision"] == "done"),
            "t1": sum(1 for i in mine if i["tier"] == "T1"), "t0": sum(1 for i in mine if i["tier"] == "T0")}


def open_gates(md_path):
    """Numbered items under an 'Open limitations' heading in a Week-N final report."""
    lines = md_path.read_text(encoding="utf-8-sig").splitlines()
    out, on = [], False
    for ln in lines:
        if re.match(r"^#+ .*Open limitations", ln):
            on = True
            continue
        if on and re.match(r"^#+ ", ln):
            if out:
                break
            continue
        if on:
            m = re.match(r"^\s*\d+\.\s+(.*)", ln)
            if m:
                out.append(m.group(1).strip())
            elif out and ln.startswith("   ") and ln.strip():
                out[-1] += " " + ln.strip()          # wrapped continuation line
    return [re.sub(r"\*\*", "", x) for x in out]


def draft_reviews():
    rows = {}
    for r in load_jsonl(DRAFT_REVIEWS_LOG):
        rows[r["draft_id"]] = r
    return rows


def build(model=None):
    import t0_checks
    model = model or load_json(OUTPUT_DIR / "incident.json")
    items = build_items(model)
    checks = t0_checks.build(model, {"items": items})
    for it in items:
        if it["item_id"] in checks:
            ch = checks[it["item_id"]]
            it["check"] = {k: ch[k] for k in ("completed_from_repo", "result", "evidence", "source")}
    import suggest
    suggest.annotate(items, model["cases"])
    cases = model["cases"]
    attack_cases = [c for c in cases if not c["benign_control"]]
    siem = [c for c in cases if c["source_kind"] == "siem_alert"]
    dataset = [c for c in attack_cases if c["source_kind"] == "dataset_case"]
    reviewed = [c for c in cases if c["source_kind"] == "dataset_case"
                and (c["human_review"]["status"] in ("Approved", "Corrected"))]

    prep_refs = ["Week-1/Setup/Ollama-Setup-Guide.md", "Week-1/SOC-Prompts/Incident-Report.txt",
                 "Week-1/Privacy/Privacy-Ethics-Checklist.md", "Week-3/SOAR/decision-matrix.md",
                 "Week-3/SOAR/playbooks/PB-01.yaml", "Week-3/SOAR/playbooks/PB-02.yaml",
                 "Week-3/SOAR/playbooks/PB-03.yaml", "Week-3/SOAR/playbooks/PB-04.yaml"]
    root = WEEK1.parent
    prep_present = [p for p in prep_refs if (root / p).exists()]

    drafts = sorted(AI_DRAFTS_DIR.glob("*.json")) if AI_DRAFTS_DIR.exists() else []
    reviews = draft_reviews()

    phases = [
        {"phase_id": "preparation", "name": "Preparation",
         "status": "complete" if len(prep_present) == len(prep_refs) else "incomplete",
         "detail": f"{len(prep_present)}/{len(prep_refs)} preparation artifacts present (local AI lab, prompts, privacy checklist, SOAR playbooks).",
         "refs": prep_present},
        {"phase_id": "detection", "name": "Detection",
         "status": "complete",
         "detail": f"{len(siem)} OpenObserve alert rules fired with saved evidence; {len(dataset)} dataset attack cases with verified timelines; "
                   f"{len([c for c in cases if c['benign_control']])} benign controls.",
         "refs": sorted({f['path'] for c in cases for f in c['evidence_files']})[:6]},
        {"phase_id": "triage", "name": "Triage & analysis",
         "status": "ai_complete_human_partial",
         "detail": f"AI triage present for {sum(1 for c in cases if c['ai'])}/{len(cases)} cases (local Mistral). "
                   f"Human review recorded for {len(reviewed)}/{len([c for c in cases if c['source_kind']=='dataset_case'])} dataset cases; "
                   f"all {len(siem)} SIEM alerts remain REVIEW_REQUIRED / Pending Review in Week-2/3.",
         "refs": ["Week-2/Results/AN-*/analysis.json", "Week-2/Evidence/SIEM-OpenObserve/", "Week-3/SOAR/tickets/"]},
    ]
    for ph in PHASES:
        st = phase_status(items, ph)
        phases.append({"phase_id": ph, "name": ph.capitalize(), **st,
                       "detail": f"{st['items']} items ({st['t1']} T1 proposals, {st['t0']} T0 checks); {st['open']} awaiting analyst decision.",
                       "refs": ["Week-4/Config/response_catalog.json", "Week-3/SOAR/tickets/", rel(DECISIONS_LOG)]})
    phases.append({
        "phase_id": "post_incident", "name": "Post-incident activity",
        "status": ("complete" if drafts and all(d.stem in reviews for d in drafts) else
                   "ai_drafts_pending_review" if drafts else "awaiting_local_ai_drafts"),
        "detail": f"{len(drafts)} local-AI report drafts found; {sum(1 for d in drafts if d.stem in reviews)} reviewed by an analyst.",
        "refs": [rel(AI_DRAFTS_DIR), rel(DRAFT_REVIEWS_LOG)]})

    gates = {"week2": open_gates(WEEK2 / "Week-2-Final-Report.md"),
             "week3": open_gates(WEEK3 / "Week-3-Final-Report.md")}

    out = {"generated_at_utc": utcnow_iso(), "generator": "Week-4/IR/ir_lifecycle.py",
           "phases": phases, "items": items, "open_gates": gates,
           "decision_log": rel(DECISIONS_LOG), "decisions_recorded": len(load_jsonl(DECISIONS_LOG)),
           "draft_reviews": list(reviews.values())}
    write_json(OUTPUT_DIR / "ir_lifecycle.json", out)
    return out


if __name__ == "__main__":
    o = build()
    for p in o["phases"]:
        print(f'{p["phase_id"]:<14} {p["status"]:<28} {p["detail"]}')
    print("gates:", len(o["open_gates"]["week2"]), len(o["open_gates"]["week3"]))
