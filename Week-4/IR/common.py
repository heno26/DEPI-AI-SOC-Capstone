"""Week 4 shared helpers: repository paths, safe file loading, hashing, Week-2 module access.

Design rules (inherited from Weeks 1-3):
  * Read-only on Week 1-3 artifacts. Week 4 never modifies earlier weeks.
  * Standard library only.
  * Every derived value keeps a pointer to the repository file it came from.
"""
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

WEEK4_DIR = Path(__file__).resolve().parent.parent          # .../Week-4
REPO_ROOT = WEEK4_DIR.parent                                # .../DEPI-AI-SOC-Capstone
WEEK1 = REPO_ROOT / "Week-1"
WEEK2 = REPO_ROOT / "Week-2"
WEEK3 = REPO_ROOT / "Week-3"

CONFIG_DIR = WEEK4_DIR / "Config"
PROMPTS_DIR = WEEK4_DIR / "Prompts"
OUTPUT_DIR = WEEK4_DIR / "Output"
AI_DRAFTS_DIR = OUTPUT_DIR / "ai_drafts"
REPORTS_DIR = WEEK4_DIR / "Reports"
DASHBOARD_DIR = WEEK4_DIR / "Dashboard"
DECISIONS_LOG = WEEK4_DIR / "Simulation" / "analyst_decisions.jsonl"
DRAFT_REVIEWS_LOG = WEEK4_DIR / "Simulation" / "ai_draft_reviews.jsonl"


def utcnow_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def rel(path):
    """Repository-relative POSIX path (stable across Windows/Linux)."""
    try:
        return Path(path).resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def load_json(path):
    # Several Week-2 files were written on Windows with a UTF-8 BOM.
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def load_jsonl(path):
    rows = []
    p = Path(path)
    if not p.exists():
        return rows
    text = p.read_text(encoding="utf-8-sig")
    # Week-3 audit files concatenate JSON objects without newlines; decode sequentially.
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \r\n\t":
            i += 1
        if i >= n:
            break
        obj, j = dec.raw_decode(text, i)
        rows.append(obj)
        i = j
    return rows


def append_jsonl(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def load_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def write_json(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path, rows, fieldnames):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_config(name):
    return load_json(CONFIG_DIR / name)


REQUIRED = [
    "Week-1/Benchmarks/results/run_20261016_061045/summary.csv",
    "Week-2/config.py", "Week-2/Core/validator.py", "Week-2/Core/ollama_client.py", "Week-2/Core/analysis.py",
    "Week-2/Evidence/SIEM-OpenObserve", "Week-2/Results", "Week-2/Data/Real-Datasets",
    "Week-2/Week-2-Final-Report.md", "Week-3/SOAR/tickets", "Week-3/SOAR/audit", "Week-3/Week-3-Final-Report.md",
]


def preflight():
    missing = [p for p in REQUIRED if not (REPO_ROOT / p).exists()]
    if missing:
        raise SystemExit(
            "\nWeek-4 must sit inside a copy of the GitHub repo heno26/DEPI-AI-SOC-Capstone.\n"
            f"Repo root detected: {REPO_ROOT}\nMissing:\n  - " + "\n  - ".join(missing) +
            "\nFix: git clone https://github.com/heno26/DEPI-AI-SOC-Capstone.git and put the Week-4 folder inside it.\n")


def import_week2():
    """Make Week-2 `config` and `Core.*` importable (Week-2 modules import `config` top-level)."""
    preflight()
    w2 = str(WEEK2)
    if w2 not in sys.path:
        sys.path.insert(0, w2)


def import_week3():
    w3 = str(WEEK3 / "SOAR")
    if w3 not in sys.path:
        sys.path.insert(0, w3)


def micros_to_iso(us):
    try:
        return datetime.fromtimestamp(int(us) / 1e6, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def parse_iso(s):
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    # Trim >6 fractional digits (Windows 7-digit ticks)
    if "." in s:
        head, tail = s.split(".", 1)
        frac = ""
        rest = ""
        for k, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                rest = tail[k:]
                break
        s = head + "." + frac[:6] + rest
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
