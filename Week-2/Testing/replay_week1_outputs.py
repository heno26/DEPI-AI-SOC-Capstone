"""Replay REAL Week 1 raw model outputs through the Week 2 validator (offline, no model is run).

Purpose: measure whether the deterministic validator would have flagged the corruptions that the
Week 1 manual review found. This is NOT a Week 2 model execution and NOT an accuracy benchmark.

Usage (from Week-2/):  python Testing/replay_week1_outputs.py --week1 ..\\Week-1 [--out Testing\\test_results\\week1_replay_validation.md]
"""
import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from Core import log_parser, validator


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--week1", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    w1 = Path(a.week1)
    cases = {c["id"]: c for c in json.load(open(w1 / "Testing" / "Test-Cases.json", encoding="utf-8-sig"))["cases"]}
    rows, seen = [], set()
    tmp = Path(tempfile.mkdtemp())
    for raw in sorted((w1 / "Benchmarks" / "results").glob("run_*/raw/*.txt")):
        model, tc = raw.stem.split("__")
        run = raw.parent.parent.name
        text = raw.read_text(encoding="utf-8", errors="replace")
        f = tmp / f"{tc}.log"
        f.write_text("\n".join(cases[tc]["input_lines"]) + "\n", encoding="utf-8")
        p = log_parser.load_file(f)
        flags = validator.validate_output(text, {}, p["events"], log_parser.auth_stats(p["events"]), [])
        flags = [x for x in flags if x["check"] not in ("nonexistent_evidence_ref",)]  # Week 1 prompts had no E### refs
        rows.append((run, model, tc, flags))
    out = ["# Week 1 raw outputs replayed through the Week 2 validator\n",
           "**Replay of existing Week 1 outputs. No model was run. Not an accuracy benchmark.** Flags are review requests.\n",
           "| Run | Model | Case | High | Medium | Low | High/medium flagged values (exact) |", "|---|---|---|---|---|---|---|"]
    for run, model, tc, fl in rows:
        c = {"high": 0, "medium": 0, "low": 0}
        for x in fl:
            c[x["severity"]] += 1
        vals = "; ".join(f"{x['check']}: `{str(x['value'])[:40]}`" for x in fl if x["severity"] in ("high", "medium"))[:300]
        out.append(f"| {run} | {model} | {tc} | {c['high']} | {c['medium']} | {c['low']} | {vals} |")
    text = "\n".join(out) + "\n"
    print(text)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
