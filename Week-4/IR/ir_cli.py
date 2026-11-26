"""Week 4 command line.

  python -B Week-4/IR/ir_cli.py build                 correlate -> lifecycle -> reports -> dashboard (no AI)
  python -B Week-4/IR/ir_cli.py draft [--only ...]    local Mistral drafts (needs Ollama), then rebuild
  python -B Week-4/IR/ir_cli.py decide --item ID --decision approved|rejected|done|deferred --analyst NAME [--note ..]
  python -B Week-4/IR/ir_cli.py review --draft ID [ID ...] --status Approved|Corrected|Rejected --analyst NAME [--note ..]
  python -B Week-4/IR/ir_cli.py revalidate            re-run the validator on saved drafts (no model call)
  python -B Week-4/IR/ir_cli.py status                phase status + pending items
  python -B Week-4/IR/ir_cli.py export-decisions      write Simulation/decisions_to_fill.csv (open in Excel)
  python -B Week-4/IR/ir_cli.py import-decisions [CSV] record every filled row at once (all-or-nothing)
  python -B Week-4/IR/ir_cli.py accept-suggestions --analyst NAME   accept the rule-based suggestions (Config rules in suggest.py)
"""
import argparse
import csv
import sys
from pathlib import Path

import ai_report_drafter
import build_dashboard
import build_reports
import correlate
import ir_lifecycle
from common import DECISIONS_LOG, DRAFT_REVIEWS_LOG, OUTPUT_DIR, WEEK4_DIR, append_jsonl, load_json, utcnow_iso

CSV_DEFAULT = WEEK4_DIR / "Simulation" / "decisions_to_fill.csv"
CSV_COLS = ["item_id", "stage", "case_id", "tier", "phase", "action", "automated_check_result", "suggested_decision",
            "suggestion_basis", "allowed_decisions", "decision", "analyst", "note"]


def allowed_for(tier):
    return ("done", "deferred") if tier == "T0" else ("approved", "rejected", "deferred")

DECISIONS = ("approved", "rejected", "done", "deferred")
REVIEWS = ("Approved", "Corrected", "Rejected")


def cmd_build(_a=None):
    m = correlate.build()
    life = ir_lifecycle.build(m)
    reps = build_reports.build()
    dash = build_dashboard.build()
    print(f"cases={len(m['cases'])} timeline_events={m['timeline_events']} observables={len(m['observables'])} "
          f"overlaps={len(m['cross_case_overlaps'])} proposals={len(life['items'])}")
    print("reports:", ", ".join(reps))
    print("dashboard:", dash)


def cmd_draft(a):
    if not (OUTPUT_DIR / "incident.json").exists():
        cmd_build()
    for row in ai_report_drafter.run(a.only, False, a.model, a.num_ctx, a.num_predict, a.timeout):
        print(" | ".join(str(x) for x in row))
    cmd_build()


def cmd_decide(a):
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    ids = {i["item_id"]: i for i in life["items"]}
    it = ids.get(a.item)
    if not it:
        raise SystemExit(f"Unknown item id {a.item}. See Reports/04_Containment_Recovery_Plan.md or `ir_cli.py status`.")
    if it["tier"] == "T2":
        raise SystemExit("T2 items are prohibited automation by design; no decision can be recorded.")
    if a.decision not in allowed_for(it["tier"]):
        raise SystemExit(f"{it['tier']} items accept: {' / '.join(allowed_for(it['tier']))}")
    if a.decision in ("rejected", "deferred") and not a.note:
        raise SystemExit("rejected / deferred needs --note explaining why")
    append_jsonl(DECISIONS_LOG, {"ts_utc": utcnow_iso(), "item_id": a.item, "decision": a.decision,
                                 "analyst": a.analyst, "note": a.note or "", "tier": it["tier"]})
    print(f"recorded {a.decision} for {a.item} by {a.analyst}")
    cmd_build()


def cmd_review(a):
    from common import AI_DRAFTS_DIR
    for d in a.draft:
        if not (AI_DRAFTS_DIR / f"{d}.json").exists():
            raise SystemExit(f"No draft {d} in {AI_DRAFTS_DIR}. Run `ir_cli.py draft` first. Nothing recorded.")
        if load_json(AI_DRAFTS_DIR / f"{d}.json").get("status") != "generated":
            raise SystemExit(f"Draft {d} failed to generate; re-run `ir_cli.py draft --only {d}`. Nothing recorded.")
        if a.status == "Corrected" and not (AI_DRAFTS_DIR / f"{d}.corrected.md").exists():
            raise SystemExit(f"Write the corrected text to Output/ai_drafts/{d}.corrected.md first. Nothing recorded.")
    for d in a.draft:
        append_jsonl(DRAFT_REVIEWS_LOG, {"ts_utc": utcnow_iso(), "draft_id": d, "status": a.status,
                                         "analyst": a.analyst, "note": a.note or ""})
        print(f"recorded review {a.status} for {d} by {a.analyst}")
    cmd_build()


def cmd_revalidate(_a):
    for did, before, after in ai_report_drafter.revalidate():
        print(f"{did:<16} validator flags {before} -> {after}")
    cmd_build()


def cmd_export(a):
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    out = Path(a.file) if a.file else CSV_DEFAULT
    if out.exists() and not a.force:
        raise SystemExit(f"{out} already exists (it may hold your answers). Use --force to overwrite.")
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    order = {"containment": 0, "eradication": 1, "recovery": 2}
    for i in sorted([i for i in life["items"] if i["tier"] != "T2"], key=lambda i: (i["stage_id"], i["case_id"], order[i["phase"]])):
        ch = i.get("check")
        rows.append({"item_id": i["item_id"], "stage": i["stage_id"], "case_id": i["case_id"], "tier": i["tier"],
                     "phase": i["phase"], "action": i["action"],
                     "automated_check_result": (("[data] " if ch["completed_from_repo"] else "[not in repo] ") + ch["result"]) if ch else "",
                     "suggested_decision": i.get("suggested_decision") or "",
                     "suggestion_basis": i.get("suggestion_basis") or "",
                     "allowed_decisions": " / ".join(allowed_for(i["tier"])),
                     "decision": "" if i["decision"].startswith("pending") else i["decision"],
                     "analyst": i.get("decided_by") or "", "note": i.get("decision_note") or ""})
    with open(out, "w", encoding="utf-8-sig", newline="") as fh:      # BOM so Excel shows Arabic notes correctly
        w = csv.DictWriter(fh, fieldnames=CSV_COLS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {out}\nFill: decision, analyst, note. Save as 'CSV UTF-8'. Then: ir_cli.py import-decisions")


def _read_csv(path):
    for enc in ("utf-8-sig", "cp1256", "cp1252"):
        try:
            with open(path, encoding=enc, newline="") as fh:
                return list(csv.DictReader(fh))
        except UnicodeDecodeError:
            continue
    raise SystemExit(f"Cannot read {path}: save it from Excel as 'CSV UTF-8'.")


def cmd_import(a):
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    items = {i["item_id"]: i for i in life["items"]}
    path = Path(a.file) if a.file else CSV_DEFAULT
    rows = _read_csv(path)
    if rows and ";" in next(iter(rows[0])):
        raise SystemExit("The file was saved with ';' separators. In Excel use Save As -> 'CSV UTF-8 (Comma delimited)'.")
    errors, todo = [], []
    for n, r in enumerate(rows, 2):
        dec = (r.get("decision") or "").strip().lower()
        if not dec:
            continue
        iid = (r.get("item_id") or "").strip()
        it = items.get(iid)
        if not it:
            errors.append(f"row {n}: unknown item_id {iid!r}")
            continue
        if it["tier"] == "T2":
            errors.append(f"row {n}: {iid} is T2 (prohibited automation) - no decision can be recorded")
            continue
        if dec not in allowed_for(it["tier"]):
            errors.append(f"row {n}: {iid} ({it['tier']}) decision {dec!r} not allowed; use {' / '.join(allowed_for(it['tier']))}")
        analyst = (r.get("analyst") or "").strip()
        if not analyst:
            errors.append(f"row {n}: {iid} has a decision but no analyst name")
        note = (r.get("note") or "").strip()
        if dec in ("rejected", "deferred") and not note:
            errors.append(f"row {n}: {iid} '{dec}' needs a note explaining why")
        if it["decision"] == dec and it.get("decided_by") == analyst:
            continue                                   # already recorded, nothing new
        todo.append({"ts_utc": utcnow_iso(), "item_id": iid, "decision": dec, "analyst": analyst, "note": note,
                     "tier": it["tier"], "via": "decisions_csv"})
    if errors:
        print("Nothing was recorded. Fix these rows and run again:")
        for e in errors:
            print("  -", e)
        raise SystemExit(1)
    for t in todo:
        append_jsonl(DECISIONS_LOG, t)
    print(f"recorded {len(todo)} decision(s) from {path}")
    cmd_build()


def cmd_accept(a):
    """Record the rule-based suggestion for every item that has no decision yet."""
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    todo = []
    for i in life["items"]:
        if i["tier"] == "T2" or not i["decision"].startswith("pending") or not i.get("suggested_decision"):
            continue
        todo.append({"ts_utc": utcnow_iso(), "item_id": i["item_id"], "decision": i["suggested_decision"],
                     "analyst": a.analyst, "note": "Accepted rule suggestion: " + i["suggestion_basis"],
                     "tier": i["tier"], "via": "accepted_rule_suggestion"})
    from collections import Counter
    print(f"About to record {len(todo)} decisions as {a.analyst}: {dict(Counter(t['decision'] for t in todo))}")
    if not a.yes:
        if input("Type YES to record them: ").strip() != "YES":
            raise SystemExit("Nothing recorded.")
    for t in todo:
        append_jsonl(DECISIONS_LOG, t)
    print(f"recorded {len(todo)} decision(s)")
    cmd_build()


def cmd_status(_a):
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    for p in life["phases"]:
        print(f'{p["name"]:<26} {p["status"]:<28} {p["detail"]}')
    pend = [i for i in life["items"] if i["decision"].startswith("pending")]
    print(f"\n{len(pend)} items awaiting a decision:")
    for i in pend:
        print(f'  [{i["tier"]}] {i["item_id"]}\n        {i["action"][:140]}')


def main(argv=None):
    try:
        sys.stdout.reconfigure(errors="replace")   # Windows consoles without UTF-8
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description="DEPI P5 Week-4 IR simulation CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    d = sub.add_parser("draft")
    d.add_argument("--only", nargs="*")
    d.add_argument("--model", default=None)
    d.add_argument("--num-ctx", type=int, default=6144)
    d.add_argument("--num-predict", type=int, default=1500)
    d.add_argument("--timeout", type=int, default=1800, help="seconds per draft")
    c = sub.add_parser("decide")
    c.add_argument("--item", required=True)
    c.add_argument("--decision", required=True, choices=DECISIONS)
    c.add_argument("--analyst", required=True)
    c.add_argument("--note")
    r = sub.add_parser("review")
    r.add_argument("--draft", required=True, nargs="+")
    r.add_argument("--status", required=True, choices=REVIEWS)
    r.add_argument("--analyst", required=True)
    r.add_argument("--note")
    sub.add_parser("status")
    sub.add_parser("revalidate")
    e = sub.add_parser("export-decisions")
    e.add_argument("--file")
    e.add_argument("--force", action="store_true")
    i = sub.add_parser("import-decisions")
    i.add_argument("file", nargs="?")
    acc = sub.add_parser("accept-suggestions")
    acc.add_argument("--analyst", required=True)
    acc.add_argument("--yes", action="store_true")
    a = ap.parse_args(argv)
    {"build": cmd_build, "draft": cmd_draft, "decide": cmd_decide, "review": cmd_review, "status": cmd_status,
     "export-decisions": cmd_export, "import-decisions": cmd_import, "accept-suggestions": cmd_accept, "revalidate": cmd_revalidate}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
