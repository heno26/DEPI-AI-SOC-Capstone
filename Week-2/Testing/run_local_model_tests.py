"""Run the fixture set through the REAL local Ollama model and write a CSV for manual scoring.

Run this on YOUR machine (needs Ollama + the model). Results stay 'Pending Review'; nothing is auto-approved.
Usage (from Week-2/):   python Testing\\run_local_model_tests.py [--only TC-02 TC-12] [--model llama3.2:3b]
The CSV has empty manual columns - the analyst fills them. Automatic columns are NOT accuracy.
"""
import argparse
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import config
from Core import alert_triage, analysis, log_parser, ollama_client, store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="substring filters on fixture file names, e.g. TC-02 W2-01")
    ap.add_argument("--model", default=config.PRIMARY_MODEL)
    ap.add_argument("--tasks", nargs="*", default=["auto"], help="auto = log_analysis for logs, alert_triage for alerts/Wazuh")
    ap.add_argument("--temperature", type=float)
    ap.add_argument("--repeat-penalty", dest="repeat_penalty", type=float)
    ap.add_argument("--num-ctx", dest="num_ctx", type=int)
    ap.add_argument("--num-predict", dest="num_predict", type=int)
    a = ap.parse_args()

    st = ollama_client.check_environment()
    if not st["server_up"] or not ollama_client.resolve_model(a.model, st["installed"]):
        print("[ERROR]", st["error"] or f"Model {a.model} not installed (ollama pull {a.model})")
        return 1
    manifest = json.load(open(config.DATA_DIR / "fixtures_manifest.json", encoding="utf-8"))["fixtures"]
    rows = []
    for fx in manifest:
        if a.only and not any(s.lower() in fx["file"].lower() for s in a.only):
            continue
        parsed = log_parser.load_file(config.DATA_DIR / fx["file"])
        if "auto" in a.tasks:
            is_alert = parsed["format"] == "alert_text" or all(e["source_kind"] == "wazuh" for e in parsed["events"])
            tasks = ["alert_triage" if is_alert else "log_analysis"]
        else:
            tasks = a.tasks
        for task in tasks:
            units = alert_triage.alert_units(parsed)[:1] if task == "alert_triage" else [(None, None)]
            for _, evs in units:
                print(f"== {fx['file']}  [{task}]  model={a.model} ...", flush=True)
                t0 = time.time()
                try:
                    rec = analysis.run_task(task, parsed, {e["ref"] for e in evs} if evs else None, model=a.model,
                                            options={"temperature": a.temperature, "repeat_penalty": a.repeat_penalty,
                                                     "num_ctx": a.num_ctx, "num_predict": a.num_predict})
                except ollama_client.OllamaError as e:
                    print("   FAILED:", e)
                    rows.append({"fixture": fx["file"], "task": task, "model": a.model, "result": f"FAILED: {str(e)[:150]}"})
                    continue
                store.save_result(rec)
                c = rec["validation"]["severity_counts"]
                t = rec.get("triage", {})
                rows.append({"fixture": fx["file"], "task": task, "model": rec["model"]["name"], "analysis_id": rec["analysis_id"],
                             "result": "completed", "seconds": round(time.time() - t0, 1), "tokens_per_s": rec["model"]["tokens_per_second"],
                             "retry_used": rec["model"]["retry_used"], "truncated": rec["ai_output"]["truncated"],
                             "sections_found": len(rec["ai_output"]["sections"]), "flags_high": c["high"], "flags_medium": c["medium"],
                             "flags_low": c["low"], "ai_verdict": t.get("recommended_classification"), "ai_priority": t.get("recommended_priority"),
                             "week1_ground_truth": fx.get("week1_ground_truth"), "manual_quality_1to5": "", "manual_notes": ""})
    out = ROOT / "Testing" / "test_results" / f"local_llm_run_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    fields = ["fixture", "task", "model", "analysis_id", "result", "seconds", "tokens_per_s", "retry_used", "truncated", "sections_found",
              "flags_high", "flags_medium", "flags_low", "ai_verdict", "ai_priority", "week1_ground_truth", "manual_quality_1to5", "manual_notes"]
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print("\nWrote", out, "- now fill manual_quality_1to5 / manual_notes by reading each Results\\<id>\\report.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
