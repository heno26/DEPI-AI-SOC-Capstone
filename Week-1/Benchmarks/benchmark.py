#!/usr/bin/env python3
"""
Week 1 - Local Model Benchmark for SOC prompts (Ollama)

What it does
  1. Loads the 4 SOC prompts (SOC-Prompts/*.txt) and the synthetic test cases (Testing/Test-Cases.json).
  2. Sends each test case to each local model through the Ollama REST API (localhost only).
  3. Measures response time, tokens/second, model memory (RAM/VRAM) and GPU offload.
  4. Runs a simple automatic first-pass check (expected findings found, unsupported
     IPs/CVEs/hashes, forbidden claims).
  5. Saves everything to Benchmarks/results/run_<date>/ (raw answers, CSV, JSON).

Requirements: Python 3.8+ and a running Ollama. No extra packages are needed.

Usage (from the Week-1 folder):
  python Benchmarks\\benchmark.py
  python Benchmarks\\benchmark.py --models llama3.2:3b phi3:mini
  python Benchmarks\\benchmark.py --models llama3.2:3b --cases TC-03

IMPORTANT: the automatic score is only a rough screen. The analyst must review the
raw answers and fill in the manual columns / AI-Accuracy-Review.md.
"""
import argparse
import csv
import json
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

WEEK1_DIR = Path(__file__).resolve().parent.parent
PROMPT_DIR = WEEK1_DIR / "SOC-Prompts"
CASES_FILE = WEEK1_DIR / "Testing" / "Test-Cases.json"
RESULTS_DIR = WEEK1_DIR / "Benchmarks" / "results"
OLLAMA_URL = "http://localhost:11434"

DEFAULT_MODELS = ["llama3.2:3b", "mistral:7b", "phi3:mini"]
PROMPT_FILES = {
    "log_analysis": "Log-Analysis.txt",
    "alert_triage": "Alert-Triage.txt",
    "threat_intel": "Threat-Intelligence.txt",
    "incident_report": "Incident-Report.txt",
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


# ----------------------------------------------------------------- Ollama API
def http_json(path, payload=None, timeout=60):
    """GET (no payload) or POST (payload) JSON to the local Ollama server."""
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(OLLAMA_URL + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Ollama usually returns a JSON error body that explains HTTP 500.
        # Keep the original status code and the actual server message.
        error_body = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            "Ollama HTTP %s: %s" % (exc.code, error_body[:1500] or exc.reason)
        ) from exc


def installed_models():
    """Return the list of installed model names, or None if Ollama is not reachable."""
    try:
        data = http_json("/api/tags", timeout=10)
    except (urllib.error.URLError, OSError):
        return None
    return [m["name"] for m in data.get("models", [])]


def resolve_model(model, installed):
    if model in installed:
        return model
    if ":" not in model and model + ":latest" in installed:
        return model + ":latest"
    return None


def generate(model, prompt, num_ctx, max_tokens, timeout):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "10m",
        "options": {
            "temperature": 0,      # deterministic, comparable results
            "seed": 42,
            "num_ctx": num_ctx,
            "num_predict": max_tokens,
        },
    }
    start = time.perf_counter()
    data = http_json("/api/generate", payload, timeout=timeout)
    return data, time.perf_counter() - start


def unload(model):
    """Unload the model from memory so models never run at the same time."""
    try:
        http_json("/api/generate", {"model": model, "keep_alive": 0}, timeout=30)
    except Exception:
        pass


def memory_info(model):
    """Return (total_size_bytes, vram_bytes) of the loaded model from /api/ps."""
    try:
        data = http_json("/api/ps", timeout=10)
    except Exception:
        return None, None
    for m in data.get("models", []):
        if model in (m.get("name"), m.get("model")):
            return m.get("size"), m.get("size_vram")
    return None, None


def gpu_used_mb():
    """Whole-GPU memory in use (MB) via nvidia-smi, or None if unavailable."""
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return int(out.stdout.strip().splitlines()[0])
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ test data
def load_cases(selected_ids):
    with open(CASES_FILE, encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    if selected_ids:
        wanted = {c.upper() for c in selected_ids}
        cases = [c for c in cases if c["id"].upper() in wanted]
    return cases


def case_input(case):
    return "\n".join(case["input_lines"])


def build_prompt(case):
    template = (PROMPT_DIR / PROMPT_FILES[case["task"]]).read_text(encoding="utf-8")
    return template.replace("{{INPUT}}", case_input(case))


# -------------------------------------------------------------- auto scoring
def score_case(case, response, input_text):
    """First-pass automatic checks. NOT a replacement for human review."""
    low = response.lower()
    found, missed = [], []
    for f in case["expected_findings"]:
        kws = [k.lower() for k in f["keywords"]]
        ok = all(k in low for k in kws) if f.get("match", "any") == "all" else any(k in low for k in kws)
        (found if ok else missed).append(f["id"])

    flagged = [k for k in case.get("must_not_claim", [])
               if re.search(r"\b" + re.escape(k.lower()) + r"\b", low)]

    bad_ips = sorted(set(IPV4_RE.findall(response)) - set(IPV4_RE.findall(input_text)))
    bad_cves = sorted({c.upper() for c in CVE_RE.findall(response)} -
                      {c.upper() for c in CVE_RE.findall(input_text)})
    bad_hashes = sorted(set(HASH_RE.findall(response)) - set(HASH_RE.findall(input_text)))
    unsupported = bad_ips + bad_cves + bad_hashes

    total = len(case["expected_findings"])
    return {
        "expected_found": len(found),
        "expected_total": total,
        "recall": round(len(found) / total, 2) if total else None,
        "missed_ids": ",".join(missed),
        "flagged_claims": ",".join(flagged),
        "unsupported_indicators": ",".join(unsupported),
    }


# ----------------------------------------------------------------------- main
def rnd(x, n=2):
    return round(x, n) if isinstance(x, (int, float)) else None


def main():
    ap = argparse.ArgumentParser(description="Benchmark local Ollama models on SOC test cases.")
    ap.add_argument("--models", nargs="+", default=DEFAULT_MODELS, help="model tags to test")
    ap.add_argument("--cases", nargs="+", default=None, help="test case IDs, e.g. TC-01 TC-03")
    ap.add_argument("--num-ctx", type=int, default=4096, help="context window (default 4096)")
    ap.add_argument("--max-tokens", type=int, default=800, help="max output tokens (default 800)")
    ap.add_argument("--timeout", type=int, default=600, help="seconds per request (default 600)")
    args = ap.parse_args()

    installed = installed_models()
    if installed is None:
        print("ERROR: cannot reach Ollama at " + OLLAMA_URL)
        print("Start Ollama (open the Ollama app or run: ollama serve) and try again.")
        sys.exit(1)

    cases = load_cases(args.cases)
    if not cases:
        print("ERROR: no matching test cases found.")
        sys.exit(1)

    run_dir = RESULTS_DIR / datetime.now().strftime("run_%Y%m%d_%H%M%S")
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    skipped = []
    for requested in args.models:
        model = resolve_model(requested, installed)
        if model is None:
            print("SKIP %s : not installed (run: ollama pull %s)" % (requested, requested))
            skipped.append(requested)
            continue

        print("\n=== Model: %s ===" % model)
        # Warm-up: loads the model so load time does not pollute test 1.
        try:
            warm, _ = generate(model, "Reply with the single word: OK", args.num_ctx, 5, args.timeout)
            load_s = rnd((warm.get("load_duration") or 0) / 1e9)
        except Exception as exc:
            print("  Warm-up failed: %s" % exc)
            skipped.append(requested)
            continue
        print("  Model load time: %s s" % load_s)

        for case in cases:
            row = {"model": model, "case_id": case["id"], "task": case["task"], "model_load_s": load_s}
            try:
                data, wall = generate(model, build_prompt(case), args.num_ctx, args.max_tokens, args.timeout)
                text = data.get("response", "")
                (raw_dir / ("%s__%s.txt" % (model.replace(":", "_").replace("/", "_"), case["id"]))
                 ).write_text(text, encoding="utf-8")

                eval_s = (data.get("eval_duration") or 0) / 1e9
                out_tokens = data.get("eval_count")
                size, vram = memory_info(model)
                row.update({
                    "wall_time_s": rnd(wall),
                    "total_time_s": rnd((data.get("total_duration") or 0) / 1e9),
                    "prompt_tokens": data.get("prompt_eval_count"),
                    "output_tokens": out_tokens,
                    "tokens_per_sec": rnd(out_tokens / eval_s) if eval_s and out_tokens else None,
                    "done_reason": data.get("done_reason"),
                    "model_size_gb": rnd(size / 1e9) if size else None,
                    "vram_gb": rnd(vram / 1e9) if vram is not None else None,
                    "gpu_offload_pct": rnd(100.0 * vram / size, 0) if size and vram is not None else None,
                    "gpu_mem_used_mb": gpu_used_mb(),
                })
                row.update(score_case(case, text, case_input(case)))
                print("  %s  %6.1fs  %5s tok/s  found %s/%s  flagged=[%s]  unsupported=[%s]" % (
                    case["id"], wall, row["tokens_per_sec"], row["expected_found"], row["expected_total"],
                    row["flagged_claims"], row["unsupported_indicators"]))
            except Exception as exc:
                row["error"] = str(exc)
                print("  %s  ERROR: %s" % (case["id"], exc))
            # Fields the analyst fills in by hand after reading the raw answers:
            row.update({"manual_quality_1to5": "", "manual_hallucination_0to3": "", "manual_notes": ""})
            rows.append(row)

        unload(model)  # free memory before the next model

    if not rows:
        print("Nothing was run.")
        sys.exit(1)

    # ---- write results.csv / results.json
    fields = ["model", "case_id", "task", "model_load_s", "wall_time_s", "total_time_s", "prompt_tokens",
              "output_tokens", "tokens_per_sec", "done_reason", "model_size_gb", "vram_gb", "gpu_offload_pct",
              "gpu_mem_used_mb", "expected_found", "expected_total", "recall", "missed_ids", "flagged_claims",
              "unsupported_indicators", "manual_quality_1to5", "manual_hallucination_0to3", "manual_notes", "error"]
    with open(run_dir / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # ---- per-model summary
    summary = []
    for m in sorted({r["model"] for r in rows}):
        ok = [r for r in rows if r["model"] == m and not r.get("error")]
        if not ok:
            continue
        def avg(key):
            vals = [r[key] for r in ok if isinstance(r.get(key), (int, float))]
            return rnd(sum(vals) / len(vals)) if vals else None
        summary.append({
            "model": m,
            "runs": len(ok),
            "avg_wall_time_s": avg("wall_time_s"),
            "avg_tokens_per_sec": avg("tokens_per_sec"),
            "avg_auto_recall": avg("recall"),
            "total_flagged_claims": sum(1 for r in ok for _ in filter(None, r["flagged_claims"].split(","))),
            "total_unsupported_indicators": sum(1 for r in ok for _ in filter(None, r["unsupported_indicators"].split(","))),
            "model_size_gb": avg("model_size_gb"),
            "vram_gb": avg("vram_gb"),
            "gpu_offload_pct": avg("gpu_offload_pct"),
        })
    summary_fields = [
        "model", "runs", "avg_wall_time_s", "avg_tokens_per_sec", "avg_auto_recall",
        "total_flagged_claims", "total_unsupported_indicators", "model_size_gb",
        "vram_gb", "gpu_offload_pct",
    ]
    with open(run_dir / "summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=summary_fields)
        w.writeheader()
        w.writerows(summary)
    if not summary:
        print("No successful model responses in this run; details are in results.csv and results.json.")

    meta = {
        "date": datetime.now().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "os": platform.platform(),
        "options": {"temperature": 0, "seed": 42, "num_ctx": args.num_ctx, "num_predict": args.max_tokens},
        "skipped_models": skipped,
    }
    with open(run_dir / "results.json", "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "summary": summary, "runs": rows}, f, indent=2)

    print("\n=== SUMMARY (automatic metrics only) ===")
    for s in summary:
        print(json.dumps(s))
    print("\nSaved to: %s" % run_dir)
    print("Next: read the raw answers in %s and fill the manual columns / AI-Accuracy-Review.md." % raw_dir)


if __name__ == "__main__":
    main()
