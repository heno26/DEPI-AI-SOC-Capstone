"""Save results, record analyst review, maintain the validation log, export markdown deliverables."""
import csv
import json
from pathlib import Path

import config
from Core.analysis import utc_now

LOG_COLUMNS = ["timestamp_utc", "analysis_id", "task", "input_file", "input_sha256", "evidence_class", "model", "prompt_version",
               "event", "flag_id", "check", "severity", "section", "value", "message", "analyst_disposition",
               "review_status", "final_classification", "analyst", "notes"]


def _log_path(results_dir=None):
    base = Path(results_dir) if results_dir else config.VALIDATION_DIR
    base.mkdir(parents=True, exist_ok=True)
    return base / "validation_log.csv"


def _append_log(rows, log_dir=None):
    p = _log_path(log_dir)
    new = not p.exists()
    with open(p, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=LOG_COLUMNS)
        if new:
            w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in LOG_COLUMNS})


def _base_row(rec):
    return {"timestamp_utc": utc_now(), "analysis_id": rec["analysis_id"], "task": rec["task"], "input_file": rec["input"]["filename"],
            "input_sha256": rec["input"]["sha256"], "evidence_class": rec["input"]["evidence_class"], "model": rec["model"]["name"],
            "prompt_version": rec["prompt"]["version"]}


def report_markdown(rec):
    L = []
    L.append(f"# {rec['task'].replace('_', ' ').title()} - {rec['analysis_id']}")
    L.append("\n> **AI-GENERATED DRAFT. Not verified. The human analyst makes the final decision.**\n")
    i, m, r = rec["input"], rec["model"], rec["review"]
    L.append("## Run metadata\n")
    L.append(f"| Item | Value |\n|---|---|\n| Input file | `{i['filename']}` |\n| SHA-256 | `{i['sha256']}` |\n| Source type | {i['source_type']} |\n"
             f"| Evidence class | {i['evidence_class']} |\n| Events (analysed/total) | {len(i['events_analysed'])}/{i['event_count']} |\n"
             f"| Created (UTC) | {rec['created_utc']} |\n| Model | `{m['name']}` |\n| Settings | `{json.dumps(m['options'])}` |\n"
             f"| Retry used | {m['retry_used']} |\n| Output finished normally | {not rec['ai_output']['truncated']} |\n"
             f"| Speed | {m['tokens_per_second']} tok/s, {m['wall_seconds']} s |\n| Prompt | {rec['prompt']['file']} ({rec['prompt']['version']}) |\n"
             f"| Review status | **{r['status']}** |")
    if i["warnings"]:
        L.append("\n**Input warnings:** " + "; ".join(i["warnings"]))
    if rec["task"] == "alert_triage":
        t = rec["triage"]
        L.append("\n## Triage summary\n")
        L.append(f"| Field | Value |\n|---|---|\n| Alert ID | {t['alert_id']} ({t['alert_id_source']}) |\n| Description | {t['description']} |\n"
                 f"| **Original SIEM severity** | {t['original_severity']['value']} (`{t['original_severity']['source_field']}`) |\n"
                 f"| **AI-recommended priority** | {t['recommended_priority']} |\n| AI-recommended classification | {t['recommended_classification']} |\n"
                 f"| Escalation (AI recommendation) | {t['escalation']['recommended']} |\n| Human review status | **{r['status']}** |")
    L.append("\n## AI output (verbatim)\n")
    L.append(rec["ai_output"]["raw_text"])
    if rec["task"] == "detection_improvement" and rec.get("suggestions"):
        L.append("\n## Parsed suggestions (human review requirement added by software)\n")
        for s in rec["suggestions"]:
            L.append(f"- Suggestion {s['number']}: {s['observed_detection_gap']}  \n  Human review: {s['human_review_requirement']}")
    L.append("\n## Evidence-based timeline (built by code from the input, not by AI)\n")
    L.append("| Timestamp (as in source) | Event | Source | Host/User | Ref |\n|---|---|---|---|---|")
    for t in rec["evidence_timeline"][:200]:
        L.append(f"| {t['timestamp']} | {t['event'].replace('|', '/')} | {t['source']} | {t['host_user']} | {t['evidence_ref']} |")
    L.append("\n## IOC context (extracted by code; external reputation not checked)\n")
    L.append("| Type | Exact value | Scope | Refs | Reputation |\n|---|---|---|---|---|")
    for o in rec["ioc_context"][:150]:
        L.append(f"| {o['type']} | `{o['value']}` | {o['scope']} | {', '.join(o['refs'][:6])} | {o['reputation']} |")
    if rec["facts"]:
        L.append("\n## Code-computed facts\n" + "\n".join("- " + f for f in rec["facts"]))
    L.append("\n## Automated validation flags (review requests, not proof)\n")
    fl = rec["validation"]["flags"]
    if not fl:
        L.append("No automated flags. This does NOT prove the analysis is correct.")
    else:
        L.append("| ID | Severity | Check | Section | Exact value | Message | Analyst disposition |\n|---|---|---|---|---|---|---|")
        for f in fl:
            L.append(f"| {f['id']} | {f['severity']} | {f['check']} | {f['section']} | `{str(f['value']).replace('|', '/')}` | {f['message']} | {f['analyst_disposition']} |")
    L.append("\n## Analyst review\n")
    L.append(f"Status: **{r['status']}**  \nAnalyst: {r['analyst']}  \nFinal classification: {r['final_classification']}  \nFinal priority: {r['final_priority']}  \n"
             f"Correct findings: {r['correct_findings']}  \nIncorrect findings: {r['incorrect_findings']}  \nMissing evidence: {r['missing_evidence']}  \n"
             f"Hallucinations noted: {r['hallucinations']}  \nNotes: {r['notes']}")
    return "\n".join(L) + "\n"


def save_result(rec, results_dir=None, log_dir=None):
    base = Path(results_dir or config.RESULTS_DIR) / rec["analysis_id"]
    base.mkdir(parents=True, exist_ok=True)
    (base / "raw_ai_output.txt").write_text(rec["ai_output"]["raw_text"], encoding="utf-8")
    rows = []
    for f in rec["validation"]["flags"]:
        row = _base_row(rec)
        row.update(event="automated_flag", flag_id=f["id"], check=f["check"], severity=f["severity"], section=f["section"],
                   value=f["value"], message=f["message"], analyst_disposition="Unreviewed", review_status="Pending Review")
        rows.append(row)
    if not rows:
        row = _base_row(rec)
        row.update(event="automated_run_no_flags", message="No automated flags (does not prove correctness).", review_status="Pending Review")
        rows.append(row)
    _append_log(rows, log_dir)
    write_files(rec, base)
    return base


def write_files(rec, base):
    (base / "analysis.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    (base / "report.md").write_text(report_markdown(rec), encoding="utf-8")


def list_results(results_dir=None):
    base = Path(results_dir or config.RESULTS_DIR)
    out = []
    for p in sorted(base.glob("AN-*/analysis.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append(d)
        except (OSError, json.JSONDecodeError):
            continue
    return out


def load_result(analysis_id, results_dir=None):
    p = Path(results_dir or config.RESULTS_DIR) / analysis_id / "analysis.json"
    if not p.is_file():
        raise FileNotFoundError(f"No saved result '{analysis_id}'.")
    return json.loads(p.read_text(encoding="utf-8"))


def apply_review(rec, review, dispositions=None, results_dir=None, log_dir=None):
    """Record the analyst's decision. `review` keys: status, analyst, final_classification, final_priority,
    correct_findings, incorrect_findings, missing_evidence, hallucinations, notes."""
    if review.get("status") not in config.REVIEW_STATUSES:
        raise ValueError(f"Invalid review status: {review.get('status')}")
    for fl in rec["validation"]["flags"]:
        if dispositions and fl["id"] in dispositions:
            fl["analyst_disposition"] = dispositions[fl["id"]]
    prev = dict(rec["review"])
    prev_hist = prev.pop("history", [])
    new = dict(rec["review"])
    for k in ("status", "analyst", "final_classification", "final_priority", "correct_findings", "incorrect_findings",
              "missing_evidence", "hallucinations", "notes"):
        if k in review:
            new[k] = review[k]
    new["reviewed_utc"] = utc_now()
    new["history"] = prev_hist + [prev]
    rec["review"] = new
    if rec["task"] == "alert_triage":
        rec["triage"]["human_review_status"] = new["status"]
    base = Path(results_dir or config.RESULTS_DIR) / rec["analysis_id"]
    write_files(rec, base)
    rows = []
    for fl in rec["validation"]["flags"]:
        if dispositions and fl["id"] in dispositions:
            r = _base_row(rec)
            r.update(event="analyst_disposition", flag_id=fl["id"], check=fl["check"], severity=fl["severity"], section=fl["section"],
                     value=fl["value"], analyst_disposition=fl["analyst_disposition"], review_status=new["status"], analyst=new["analyst"])
            rows.append(r)
    r = _base_row(rec)
    r.update(event="analyst_review", review_status=new["status"], final_classification=new["final_classification"], analyst=new["analyst"],
             notes=json.dumps({k: new[k] for k in ("correct_findings", "incorrect_findings", "missing_evidence", "hallucinations", "notes")}, ensure_ascii=False))
    rows.append(r)
    _append_log(rows, log_dir)
    return rec


def export_markdown(results_dir=None, validation_dir=None, detection_dir=None):
    """Regenerate the two *.generated.md deliverable files from saved results. Hand-written files are not touched."""
    recs = list_results(results_dir)
    vdir = Path(validation_dir or config.VALIDATION_DIR)
    ddir = Path(detection_dir or config.DETECTION_DIR)
    vdir.mkdir(parents=True, exist_ok=True)
    ddir.mkdir(parents=True, exist_ok=True)
    V = ["# Hallucination / Validation Log - generated from saved results\n",
         f"Generated (UTC): {utc_now()}  \nResults included: {len(recs)}\n",
         "Flags are requests for human review. A disposition of *Confirmed hallucination* or *False alarm* is the analyst's decision.\n",
         "| Analysis | Task | Input | Evidence class | Model | Review status | Flags (H/M/L) | Confirmed hallucinations | False alarms | Unreviewed |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for r in recs:
        fl = r["validation"]["flags"]
        c = r["validation"]["severity_counts"]
        n_conf = sum(1 for f in fl if f["analyst_disposition"] == "Confirmed hallucination")
        n_fa = sum(1 for f in fl if f["analyst_disposition"] == "False alarm")
        n_un = sum(1 for f in fl if f["analyst_disposition"] == "Unreviewed")
        V.append(f"| {r['analysis_id']} | {r['task']} | {r['input']['filename']} | {r['input']['evidence_class']} | {r['model']['name']} | "
                 f"{r['review']['status']} | {c.get('high', 0)}/{c.get('medium', 0)}/{c.get('low', 0)} | {n_conf} | {n_fa} | {n_un} |")
    V.append("\n## Flag detail\n")
    for r in recs:
        if not r["validation"]["flags"]:
            continue
        V.append(f"### {r['analysis_id']} ({r['input']['filename']})\n")
        V.append("| Flag | Severity | Check | Section | Exact value | Analyst disposition |\n|---|---|---|---|---|---|")
        for f in r["validation"]["flags"]:
            V.append(f"| {f['id']} | {f['severity']} | {f['check']} | {f['section']} | `{str(f['value']).replace('|', '/')}` | {f['analyst_disposition']} |")
        rv = r["review"]
        V.append(f"\nReview: **{rv['status']}** by {rv['analyst']}. Incorrect findings: {rv['incorrect_findings']}. Missing evidence: {rv['missing_evidence']}. "
                 f"Hallucinations noted: {rv['hallucinations']}. Notes: {rv['notes']}\n")
    (vdir / "Hallucination-Validation-Log.generated.md").write_text("\n".join(V) + "\n", encoding="utf-8")
    D = ["# Detection Improvement Notes - generated from saved results\n",
         "AI-generated suggestions. Status shows the analyst review outcome. Nothing here has been deployed.\n"]
    n = 0
    for r in recs:
        if r["task"] != "detection_improvement":
            continue
        D.append(f"## {r['analysis_id']} - input `{r['input']['filename']}` - review status: {r['review']['status']}\n")
        for s in r.get("suggestions", []):
            n += 1
            D.append(f"### Suggestion {s['number']}\n- **Observed detection gap:** {s['observed_detection_gap']}\n- **Supporting evidence:** {s['supporting_evidence']}\n"
                     f"- **Suggested improvement:** {s['suggested_improvement']}\n- **Expected benefit:** {s['expected_benefit']}\n"
                     f"- **Potential false-positive risk:** {s['potential_false_positive_risk']}\n- **Human review requirement:** {s['human_review_requirement']}\n")
    if n == 0:
        D.append("No detection-improvement results saved yet. PENDING LOCAL EXECUTION.\n")
    (ddir / "Detection-Improvement-Notes.generated.md").write_text("\n".join(D) + "\n", encoding="utf-8")
    return vdir / "Hallucination-Validation-Log.generated.md", ddir / "Detection-Improvement-Notes.generated.md"
