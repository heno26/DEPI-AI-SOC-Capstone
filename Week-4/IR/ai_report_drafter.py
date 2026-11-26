"""Week 4 AI-assisted reporting: local Mistral drafts + deterministic validation.

Flow per draft (the "AI-assisted reporting workflow" deliverable):
  1. Build a numbered FACT SHEET ([E001]...) from Output/incident.json + Output/ir_lifecycle.json.
     Facts are produced by code from repository evidence; nothing is typed by hand.
  2. Fill a prompt template (Week-1 Incident-Report prompt is reused unchanged for the IR report).
  3. Send it to the LOCAL Ollama server through the Week-2 client (loopback only, one controlled retry).
  4. Validate the output with the Week-2 validator against the fact sheet (unsupported IPs,
     timestamps, hashes, references, certainty claims, missing sections, truncation).
  5. Save Output/ai_drafts/<draft_id>.json with text, model stats, flags and review status
     "Pending Review". A human records Approved / Corrected / Rejected with `ir_cli.py review`.

Usage (from the repository root):
  python -B Week-4/IR/ai_report_drafter.py                # all drafts
  python -B Week-4/IR/ai_report_drafter.py --only exec_briefing
  python -B Week-4/IR/ai_report_drafter.py --dry-run      # write prompts only, no model call
"""
import argparse
import hashlib
import re
import sys

from common import (AI_DRAFTS_DIR, OUTPUT_DIR, PROMPTS_DIR, WEEK1, import_week2, load_json, rel, utcnow_iso,
                    write_json)

import_week2()
import config as w2config                          # noqa: E402  Week-2 settings (model, generation)
from Core import ollama_client                     # noqa: E402
from Core.analysis import parse_sections            # noqa: E402
from Core.validator import summarize_flags, validate_output  # noqa: E402

REVIEW_LINE = "DRAFT - AI-generated, requires human analyst validation before use."

DRAFTS = {
    "incident_report": {"prompt": WEEK1 / "SOC-Prompts" / "Incident-Report.txt",
                        "headings": ["INCIDENT TITLE", "EXECUTIVE SUMMARY", "TIMELINE", "IMPACT", "ROOT CAUSE",
                                     "ACTIONS TAKEN", "RECOMMENDATIONS", "OPEN QUESTIONS", "REVIEW STATUS"]},
    "exec_briefing": {"prompt": PROMPTS_DIR / "executive_briefing.txt",
                      "headings": ["BRIEFING TITLE", "SITUATION", "WHAT WE KNOW", "WHAT WE DO NOT KNOW",
                                   "DECISIONS NEEDED", "RISK IF NO ACTION", "REVIEW STATUS"]},
    "lessons_learned": {"prompt": PROMPTS_DIR / "lessons_learned.txt",
                        "headings": ["WHAT WORKED", "WHAT DID NOT WORK", "AI ASSISTANCE LESSONS",
                                     "DETECTION AND VISIBILITY GAPS", "PROCESS IMPROVEMENTS", "OPEN ITEMS",
                                     "REVIEW STATUS"]},
}
STAGE_DRAFT = {"prompt": PROMPTS_DIR / "stage_summary.txt",
               "headings": ["STAGE SUMMARY", "EVIDENCE OBSERVED", "ATTACK TECHNIQUES", "WHAT IS NOT ESTABLISHED",
                            "ANALYST QUESTION", "REVIEW STATUS"]}


HEADING_ALIASES = {"ATT&CK TECHNIQUES": "ATTACK TECHNIQUES", "RECOMMENDATION": "RECOMMENDATIONS"}
_INLINE = re.compile(r"^(\s*\d+\.\s*)([A-Z][A-Z &/]+?)\s*:\s*(\S.*)$", re.M)
_HEAD_ONLY = re.compile(r"^(\s*\d+\.\s*)([A-Z][A-Z &/]+?)\s*:?\s*$", re.M)


def normalize_headings(text, headings):
    """Mistral often writes '1. STAGE SUMMARY: text' on one line; the Week-2 parser expects the heading on
    its own line. Split such lines (only for the expected headings) and map heading aliases. Content is unchanged."""
    want = {h.upper() for h in headings}

    def canon(h):
        h = h.strip().upper()
        return HEADING_ALIASES.get(h, h)

    def inline(m):
        h = canon(m.group(2))
        return f"{m.group(1)}{h}\n{m.group(3)}" if h in want else m.group(0)

    def only(m):
        h = canon(m.group(2))
        return f"{m.group(1)}{h}" if h in want else m.group(0)

    return _HEAD_ONLY.sub(only, _INLINE.sub(inline, text))


def validate_text(text, did, facts_rows, truncated=False):
    headings = spec(did)["headings"]
    norm = normalize_headings(text, headings)
    sections = parse_sections(norm, headings)
    events = [{"ref": r["ref"], "raw": r["raw"]} for r in facts_rows]
    flags = validate_output(norm, sections, events, [r["raw"] for r in facts_rows], headings, truncated=truncated)
    if REVIEW_LINE not in text:
        flags.append({"check": "review_status_line_missing", "severity": "medium", "section": "REVIEW STATUS",
                      "value": "", "message": "Required review status sentence not reproduced exactly.",
                      "analyst_disposition": "Unreviewed", "id": f"F{len(flags) + 1:03d}"})
    return sections, flags


def revalidate():
    """Re-run validation on saved drafts (no model call). Keeps the first validation as validation_original."""
    out = []
    for f in sorted(AI_DRAFTS_DIR.glob("*.json")):
        d = load_json(f)
        if d.get("status") != "generated":
            continue
        sections, flags = validate_text(d["text"], d["draft_id"], d["facts"], d.get("truncated", False))
        d.setdefault("validation_original", d["validation"])
        d["sections"] = sections
        d["validation"] = {"flags": flags, "severity_counts": summarize_flags(flags),
                           "heading_normalization": "inline 'N. HEADING: text' split before parsing (Week-4)",
                           "disclaimer": d["validation"].get("disclaimer")}
        write_json(f, d)
        out.append((d["draft_id"], len(d["validation_original"]["flags"]), len(flags)))
    return out


# --------------------------------------------------------------------------------------------
# Fact sheets
# --------------------------------------------------------------------------------------------
class Facts:
    def __init__(self):
        self.rows = []

    def add(self, text, source):
        ref = f"E{len(self.rows) + 1:03d}"
        self.rows.append({"ref": ref, "raw": f"[{ref}] {text}", "text": text, "source": source})
        return ref

    def lines(self):
        return [r["raw"] for r in self.rows]

    def as_events(self):
        # Shape expected by Week-2 validator.validate_output
        return [{"ref": r["ref"], "raw": r["raw"]} for r in self.rows]


def _case_line(c, max_events=3):
    ai = c.get("ai") or {}
    bits = [f'{c["case_id"]} "{c["title"]}" ({c["domain"]})']
    kf = []
    for k, v in c["facts"].items():
        if k == "context_values" or isinstance(v, dict):
            continue
        vs = ", ".join(map(str, v[:6])) if isinstance(v, list) else str(v)
        if len(vs) <= 160:
            kf.append(f"{k}={vs}")
    if kf:
        bits.append("key facts: " + "; ".join(kf))
    allev = c["events"]
    h = max_events // 2
    ev = allev if len(allev) <= max_events else allev[:h] + allev[-h:]
    if ev:
        bits.append("events: " + "; ".join(f'{e["ts_original"]} {e["summary"]}' for e in ev))
    if c["event_count_total"] > len(ev):
        bits.append(f'{c["event_count_total"]} source records in total')
    if ai.get("severity"):
        bits.append(f'AI severity {ai["severity"]}, confidence {ai.get("confidence")}, QA {ai.get("qa_status")}')
    if c["human_review"].get("status"):
        bits.append(f'human review: {c["human_review"]["status"]}')
    return ". ".join(bits)


def facts_stage(model, life, stage):
    F = Facts()
    by = {c["case_id"]: c for c in model["cases"]}
    F.add(f'Stage {stage["stage_id"]} "{stage["name"]}" ({stage["kill_chain"]}, domain {stage["domain"]}) of tabletop '
          f'scenario {model["scenario"]["scenario_id"]}. This stage is represented by historical lab evidence; the link to '
          f'other stages is a scenario construct.', "Week-4/Config/scenario.json")
    for cid in stage["case_ids"]:
        c = by[cid]
        F.add(_case_line(c, 4), c["evidence_files"][0]["path"])
        for a in c["attack"]:
            F.add(f'{cid} ATT&CK {a["technique"]} {a["name"]} ({a["tactic"]}), confidence label: {a["confidence"]}. Basis: {a["basis"]}',
                  "Week-4/Config/attack_mapping.json")
        for lim in c["limitations"][:3]:
            F.add(f"{cid} NOT ESTABLISHED (unverified hypothesis or limitation - do not state as fact): {lim}",
                  c["evidence_files"][0]["path"])
        for i in life["items"]:
            if i["case_id"] == cid and i.get("check") and i["check"]["completed_from_repo"]:
                F.add(f'{cid} read-only check result: {i["check"]["result"]}', i["check"]["source"])
        props = [i for i in life["items"] if i["case_id"] == cid and i["tier"] == "T1"]
        for i in props[:3]:
            F.add(f'{cid} proposal ({i["phase"]}, not executed, {i["decision"]}): {i["action"]}', i["source"])
    F.add(f'Analyst question for this stage: {stage["question_for_analysts"]}', "Week-4/Config/scenario.json")
    return F


def facts_incident(model, life):
    F = Facts()
    sc = model["scenario"]
    F.add(f'Incident ID {sc["scenario_id"]}: {sc["title"]}. Simulation type: composite tabletop built from historical lab '
          f'datasets replayed in Weeks 2-3; not a live production incident.', "Week-4/Config/scenario.json")
    by = {c["case_id"]: c for c in model["cases"]}
    for st in sorted(sc["stages"], key=lambda s: s["order"]):
        for cid in st["case_ids"]:
            c = by[cid]
            first = c["events"][0] if c["events"] else None
            F.add(f'Stage {st["stage_id"]} {st["name"]}: {c["case_id"]} {c["title"]}'
                  + (f'; first source record {first["ts_original"]}: {first["summary"]}' if first else "")
                  + f'; human review {c["human_review"]["status"]}', c["evidence_files"][0]["path"])
    w3 = [t for c in model["cases"] for t in c["tickets"]]
    F.add(f'Week-3 SOAR dispatcher created {len(w3)} tickets automatically (Tier 0 actions: parse, enrich stub, create ticket, '
          f'notify, audit). No remediation was executed.', "Week-3/SOAR/tickets/")
    for ph in life["phases"]:
        if ph["phase_id"] in ("containment", "eradication", "recovery"):
            F.add(f'{ph["name"]} phase status: {ph["status"]}; {ph["detail"]}', "Week-4/Output/ir_lifecycle.json")
    for o in model["cross_case_overlaps"]:
        F.add(f'Observable {o["value"]} ({o["type"]}, {o["role"]}) appears in cases {", ".join(o["cases"])}.', "Week-4/Output/observables.csv")
    for i in life["items"]:
        if i.get("check") and i["check"]["completed_from_repo"]:
            F.add(f'Read-only check ({i["case_id"]}): {i["check"]["result"]}', i["check"]["source"])
    F.add("Impact: Unknown. No evidence in the datasets confirms data loss, successful exploitation or account compromise.",
          "Week-2 case studies / evidence limitations")
    F.add("Root cause: Unknown. Initial access vector for the composite scenario is not established by the evidence.",
          "Week-4/Config/scenario.json")
    for st in sc["stages"]:
        F.add(f'Open question ({st["stage_id"]}): {st["question_for_analysts"]}', "Week-4/Config/scenario.json")
    return F


def facts_exec(model, life):
    F = Facts()
    sc = model["scenario"]
    attack = [c for c in model["cases"] if not c["benign_control"]]
    F.add(f'Tabletop exercise {sc["scenario_id"]} covered {len(sc["stages"])} attack stages across network, endpoint, web, '
          f'authentication and email, using {len(attack)} evidence-backed cases from historical lab datasets.', "Week-4/Config/scenario.json")
    for st in sorted(sc["stages"], key=lambda s: s["order"]):
        F.add(f'Stage {st["stage_id"]} {st["name"]}: cases {", ".join(st["case_ids"])}.', "Week-4/Config/scenario.json")
    high = [c for c in model["cases"] if (c.get("ai") or {}).get("severity") == "High"]
    F.add(f'{len(high)} SIEM alert cases were rated High by the local AI triage ({", ".join(c["case_id"] for c in high)}); '
          f'AI ratings are not analyst sign-off.', "Week-2/Evidence/SIEM-OpenObserve/")
    t1 = [i for i in life["items"] if i["tier"] == "T1"]
    pend = [i for i in t1 if i["decision"].startswith("pending")]
    F.add(f'{len(t1)} response proposals exist; {len(pend)} are waiting for an analyst decision. Nothing has been executed.',
          "Week-4/Output/ir_lifecycle.json")
    for c in model["cases"]:
        if c["case_id"] in ("SIEM-EXCH-005", "RT-04", "SIEM-MAL-003"):
            F.add(f'{c["case_id"]} {c["title"]}: ' + "; ".join(c["limitations"][:2]), c["evidence_files"][0]["path"])
    for i in life["items"]:
        if i["case_id"] in ("SIEM-EXCH-005", "SIEM-AUTH-002") and i.get("check") and i["check"]["completed_from_repo"]:
            F.add(f'Read-only check ({i["case_id"]}): {i["check"]["result"]}', i["check"]["source"])
    F.add("Business impact, data loss and attacker identity are unknown.", "Week-2 case studies / evidence limitations")
    return F


def facts_lessons(model, life):
    F = Facts()
    w1 = model["week1_benchmark"]
    for m in w1["models"]:
        F.add(f'Week-1 benchmark {m["model"]}: manual quality mean {m["manual_quality_mean"]}/5 over {m["manual_reviews"]} '
              f'reviews; automatic keyword recall {m["avg_auto_recall"]} (keyword recall is not accuracy); '
              f'{m["avg_tokens_per_sec"]} tokens/s.', w1["sources"][0])
    q = model["week2_quality"]
    F.add(f'Week-2: {q["analysis_runs"]} local Mistral analysis runs; validator raised {q["validator_flags_total"]} review flags '
          f'({q["validator_flags_by_severity"].get("high", 0)} high, {q["validator_flags_by_severity"].get("medium", 0)} medium).',
          q["source"])
    F.add(f'Week-2: {q["reviewed_runs"]} runs have a recorded human review: {q["reviewed_runs_corrected"]} Corrected, '
          f'{q["reviewed_runs_approved"]} Approved; analysts recorded {q["analyst_correct_findings"]} correct and '
          f'{q["analyst_incorrect_findings"]} incorrect AI findings.', q["source"])
    top = ", ".join(f"{k} ({v})" for k, v in q["top_flag_checks"][:4])
    F.add(f"Most frequent validator checks: {top}.", q["source"])
    lat = model["week2_siem_trigger_to_triage_seconds"]
    F.add(f'OpenObserve trigger to AI-triage record: mean {lat["mean"]} s over {len(lat["values"])} alerts (historical replay).',
          "Week-2/Evidence/SIEM-OpenObserve/")
    w3 = [t for c in model["cases"] for t in c["tickets"]]
    F.add(f'Week-3: {len(w3)} tickets created automatically; {sum(1 for t in w3 if t["review_status"] == "Pending Review")} '
          f'still Pending Review; Tier-2 actions are hard-blocked in the dispatcher.', "Week-3/SOAR/tickets/")
    for g in life["open_gates"]["week2"]:
        F.add(f"Week-2 open gate: {g}", "Week-2/Week-2-Final-Report.md")
    for g in life["open_gates"]["week3"]:
        F.add(f"Week-3 open gate: {g}", "Week-3/Week-3-Final-Report.md")
    for o in model["cross_case_overlaps"]:
        F.add(f'Cross-dataset overlap found by Week-4 correlation: {o["value"]} in {", ".join(o["cases"])}.', "Week-4/Output/observables.csv")
    chk = [i for i in life["items"] if i.get("check")]
    F.add(f'Week-4 read-only checks: {sum(1 for i in chk if i["check"]["completed_from_repo"])} of {len(chk)} T0 checks could be '
          f'answered from repository data; the rest need systems or records that are not in the lab data.', "Week-4/Output/t0_checks.json")
    F.add("No live threat-intelligence feed: every indicator reputation is 'not checked'.", "Week-3/SOAR/enrichment/stub.py")
    return F


def all_fact_sheets(model, life):
    sheets = {"incident_report": facts_incident(model, life), "exec_briefing": facts_exec(model, life),
              "lessons_learned": facts_lessons(model, life)}
    for st in model["scenario"]["stages"]:
        sheets[f'stage_{st["stage_id"]}'] = facts_stage(model, life, st)
    return sheets


def spec(draft_id):
    return DRAFTS.get(draft_id, STAGE_DRAFT)


def render_prompt(draft_id, facts):
    tpl_path = spec(draft_id)["prompt"]
    tpl = tpl_path.read_text(encoding="utf-8")
    return tpl.replace("{{INPUT}}", "\n".join(facts.lines())), tpl_path, hashlib.sha256(tpl.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------------------------
def run(only=None, dry_run=False, model_name=None, num_ctx=6144, num_predict=1500, timeout=1800):
    model = load_json(OUTPUT_DIR / "incident.json")
    life = load_json(OUTPUT_DIR / "ir_lifecycle.json")
    sheets = all_fact_sheets(model, life)
    ids = [d for d in sheets if not only or d in only]
    if not ids:
        raise SystemExit(f"Unknown draft id(s): {only}. Available: {', '.join(sheets)}")

    if not dry_run:
        env = ollama_client.check_environment()
        if not env["server_up"]:
            raise SystemExit(f"Ollama is not reachable on 127.0.0.1:11434 ({env['error']}). Start it with: ollama serve")
        want = model_name or w2config.PRIMARY_MODEL
        # Ollama on Windows can list the same model with different capitalisation
        # (e.g. "Mistral:7b-instruct-v0.3-q4_K_S"); match case-insensitively, then use the exact installed name.
        resolved = ollama_client.resolve_model(want, env["installed"]) or next(
            (m for m in env["installed"] if m.lower() in (want.lower(), want.lower() + ":latest")), None)
        if not resolved:
            raise SystemExit(f"Model {want} not installed (installed: {', '.join(env['installed']) or 'none'}). "
                             f"Run: ollama pull {w2config.PRIMARY_MODEL}")
        model_name = resolved
        print(f"Using local model: {model_name}", flush=True)

    AI_DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = []
    for did in ids:
        F = sheets[did]
        prompt, tpl_path, tpl_sha = render_prompt(did, F)
        if dry_run:
            p = OUTPUT_DIR / "ai_prompts" / f"{did}.txt"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(prompt, encoding="utf-8")
            summary.append((did, "prompt written", len(F.rows), len(prompt)))
            continue
        print(f"[{did}] {len(F.rows)} facts, {len(prompt)} chars -> local model ...", flush=True)
        rec = {"draft_id": did, "created_utc": utcnow_iso(), "generator": "Week-4/IR/ai_report_drafter.py",
               "prompt_file": rel(tpl_path), "prompt_sha256": tpl_sha, "facts": F.rows}
        try:
            res = ollama_client.generate(prompt, model=model_name, timeout=timeout,
                                         options={"num_ctx": num_ctx, "num_predict": num_predict})
        except ollama_client.OllamaError as e:
            rec.update(status="generation_failed", error=str(e), attempts=getattr(e, "attempts", None))
            write_json(AI_DRAFTS_DIR / f"{did}.json", rec)
            summary.append((did, "FAILED", str(e)[:80], ""))
            print(f"   FAILED: {str(e)[:160]}  -> re-run later with: ir_cli.py draft --only {did}", flush=True)
            continue
        sections, flags = validate_text(res.text, did, F.rows, res.truncated)
        rec.update(status="generated", model=res.model, options=res.options_used, attempts=res.attempts,
                   done_reason=res.done_reason, truncated=res.truncated, tokens_per_second=res.tokens_per_second,
                   wall_seconds=res.wall_seconds, eval_count=res.eval_count, text=res.text, sections=sections,
                   validation={"flags": flags, "severity_counts": summarize_flags(flags),
                               "disclaimer": "Flags request human review; they are not proof of hallucination. "
                                             "Passing all checks does not prove correctness."},
                   review={"status": "Pending Review"})
        write_json(AI_DRAFTS_DIR / f"{did}.json", rec)
        summary.append((did, "ok", f"{res.wall_seconds}s", f"{len(flags)} flags"))
        print(f"   done in {res.wall_seconds}s, {res.tokens_per_second} tok/s, {len(flags)} validator flags", flush=True)
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description="Week-4 local-AI report drafting (Ollama + Week-2 validator)")
    ap.add_argument("--only", nargs="*", help="draft ids (incident_report exec_briefing lessons_learned stage_S1..stage_S9)")
    ap.add_argument("--dry-run", action="store_true", help="write prompts to Output/ai_prompts, do not call the model")
    ap.add_argument("--model", default=None, help=f"default {w2config.PRIMARY_MODEL}")
    ap.add_argument("--num-ctx", type=int, default=6144)
    ap.add_argument("--num-predict", type=int, default=1500)
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per draft (CPU-only machines are slow)")
    a = ap.parse_args(argv)
    for row in run(a.only, a.dry_run, a.model, a.num_ctx, a.num_predict, a.timeout):
        print(" | ".join(str(x) for x in row))


if __name__ == "__main__":
    sys.exit(main())
