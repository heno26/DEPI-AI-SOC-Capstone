import json
import csv
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import urlopen

from flask import Flask, jsonify, abort, send_from_directory

V2_DIR = Path(__file__).resolve().parent.parent
WEEK4_DIR = V2_DIR.parent
ROOT_DIR = WEEK4_DIR.parent

OUTPUT_DIR = WEEK4_DIR / "Output"
REPORTS_DIR = WEEK4_DIR / "Reports"
SIMULATION_DIR = WEEK4_DIR / "Simulation"
FRONTEND_DIR = V2_DIR / "Frontend"

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.json.sort_keys = False


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]


def ollama_status():
    try:
        with urlopen(
            "http://127.0.0.1:11434/api/tags",
            timeout=3
        ) as response:
            data = json.loads(response.read())

        return {
            "connected": True,
            "models": [
                model.get("name")
                for model in data.get("models", [])
            ]
        }

    except Exception:
        return {
            "connected": False,
            "models": []
        }


@app.before_request
def local_access_only():
    from flask import request

    if request.remote_addr not in (
        "127.0.0.1", "::1"
    ):
        abort(403)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home():
    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.get("/css/<path:filename>")
def frontend_css(filename):
    return send_from_directory(
        FRONTEND_DIR / "css",
        filename
    )


@app.get("/js/<path:filename>")
def frontend_js(filename):
    return send_from_directory(
        FRONTEND_DIR / "js",
        filename
    )


@app.get("/assets/<path:filename>")
def frontend_assets(filename):
    return send_from_directory(
        FRONTEND_DIR / "assets",
        filename
    )



@app.get("/api/health")
def health():
    required = {
        "incident_data": OUTPUT_DIR / "incident.json",
        "lifecycle_data": OUTPUT_DIR / "ir_lifecycle.json",
        "analyst_decisions":
            SIMULATION_DIR / "analyst_decisions.jsonl",
        "ai_reviews":
            SIMULATION_DIR / "ai_draft_reviews.jsonl"
    }

    files = {
        name: path.is_file()
        for name, path in required.items()
    }

    return jsonify({
        "backend": "ONLINE",
        "timestamp_utc": utc_now(),
        "mode": "SIMULATION_ONLY",
        "weeks": {
            f"Week-{i}": (
                ROOT_DIR / f"Week-{i}"
            ).is_dir()
            for i in range(1, 5)
        },
        "data_files": files,
        "data_ready": all(files.values()),
        "ollama": ollama_status(),
        "real_response_execution": False
    })


@app.get("/api/incidents")
def incidents():
    return jsonify(
        read_json(OUTPUT_DIR / "incident.json")
    )




@app.get("/api/timeline")
def timeline_api():
    timeline_file = OUTPUT_DIR / "incident_timeline.csv"

    if not timeline_file.is_file():
        return jsonify({
            "error": "Timeline source file is missing"
        }), 503

    required_fields = [
        "seq", "stage_id", "stage", "domain", "case_id",
        "ts_original", "ts_quality", "summary", "ref", "source"
    ]

    try:
        with timeline_file.open(
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as file:
            reader = csv.DictReader(file)

            if reader.fieldnames != required_fields:
                return jsonify({
                    "error": "Unexpected timeline CSV schema",
                    "expected_fields": required_fields,
                    "actual_fields": reader.fieldnames
                }), 503

            events = list(reader)

            if any(
                None in event or
                any(value is None for value in event.values())
                for event in events
            ):
                return jsonify({
                    "error": "Malformed timeline CSV row"
                }), 503

        def distribution(field):
            counts = {}
            for event in events:
                value = event[field]
                counts[value] = counts.get(value, 0) + 1
            return counts

        return jsonify({
            "count": len(events),
            "source": "incident_timeline.csv",
            "read_only": True,
            "timestamp_policy": "Original timestamps preserved; no timezone assumptions",
            "statistics": {
                "domains": distribution("domain"),
                "cases": distribution("case_id"),
                "stages": distribution("stage_id"),
                "timestamp_quality": distribution("ts_quality")
            },
            "events": events
        })

    except (OSError, csv.Error, UnicodeError) as error:
        return jsonify({
            "error": "Unable to read timeline source",
            "details": str(error)
        }), 503

@app.get("/api/lifecycle")
def lifecycle():
    return jsonify(
        read_json(OUTPUT_DIR / "ir_lifecycle.json")
    )


@app.get("/api/decisions")
def decisions():
    records = read_jsonl(
        SIMULATION_DIR / "analyst_decisions.jsonl"
    )

    return jsonify({
        "count": len(records),
        "records": records
    })


@app.get("/api/ai-reviews")
def ai_reviews():
    records = read_jsonl(
        SIMULATION_DIR / "ai_draft_reviews.jsonl"
    )

    return jsonify({
        "count": len(records),
        "records": records
    })


@app.get("/api/reports")
def reports():
    files = sorted(REPORTS_DIR.glob("*.md"))

    return jsonify({
        "count": len(files),
        "reports": [
            {
                "filename": file.name,
                "size_bytes": file.stat().st_size,
                "modified_utc": datetime.fromtimestamp(
                    file.stat().st_mtime,
                    timezone.utc
                ).isoformat()
            }
            for file in files
        ]
    })


@app.get("/api/reports/<filename>")
def report_content(filename):
    allowed = {
        file.name
        for file in REPORTS_DIR.glob("*.md")
    }

    if filename not in allowed:
        abort(404)

    return jsonify({
        "filename": filename,
        "content": (
            REPORTS_DIR / filename
        ).read_text(encoding="utf-8-sig")
    })


@app.get("/api/reports/<filename>/download")
def download_report(filename):
    allowed = {
        file.name
        for file in REPORTS_DIR.glob("*.md")
    }

    if filename not in allowed:
        abort(404)

    return send_from_directory(
        REPORTS_DIR,
        filename,
        as_attachment=True
    )


@app.errorhandler(FileNotFoundError)
def missing_data(error):
    return jsonify({
        "error": "Required data file is missing"
    }), 503


@app.errorhandler(json.JSONDecodeError)
def invalid_data(error):
    return jsonify({
        "error": "Invalid project JSON data"
    }), 503



# =====================================================

# =====================================================
# DEPI_P5_UNIFIED_REPORTS_V1
# Read-only unified reporting API
# =====================================================

REPORT_CENTER_SOURCES = {
    "final_reports": REPORTS_DIR,
    "ai_assessments": OUTPUT_DIR / "ai_assessments",
    "ai_drafts": OUTPUT_DIR / "ai_drafts"
}

REPORT_CENTER_EXTENSIONS = {
    ".md", ".json", ".jsonl"
}


def report_center_catalog():

    records = []

    for category, directory in REPORT_CENTER_SOURCES.items():

        if not directory.is_dir():
            continue

        for path in sorted(directory.iterdir()):

            if not path.is_file():
                continue

            if path.suffix.lower() not in REPORT_CENTER_EXTENSIONS:
                continue

            records.append({
                "category": category,
                "filename": path.name,
                "size_bytes": path.stat().st_size,
                "modified_utc": datetime.fromtimestamp(
                    path.stat().st_mtime,
                    timezone.utc
                ).isoformat(),
                "preview_url": (
                    "/api/report-center/"
                    + category + "/" + path.name
                ),
                "download_url": (
                    "/api/report-center/"
                    + category + "/" + path.name
                    + "?download=1"
                )
            })

    review_file = SIMULATION_DIR / "ai_draft_reviews.jsonl"

    if review_file.is_file():

        records.append({
            "category": "review_history",
            "filename": review_file.name,
            "size_bytes": review_file.stat().st_size,
            "modified_utc": datetime.fromtimestamp(
                review_file.stat().st_mtime,
                timezone.utc
            ).isoformat(),
            "preview_url": (
                "/api/report-center/review_history/"
                + review_file.name
            ),
            "download_url": (
                "/api/report-center/review_history/"
                + review_file.name + "?download=1"
            )
        })

    records.sort(
        key=lambda item: item["modified_utc"],
        reverse=True
    )

    return records


@app.get("/api/report-center")
def unified_report_center():

    records = report_center_catalog()

    categories = {}

    for record in records:
        category = record["category"]
        categories[category] = categories.get(category, 0) + 1

    return jsonify({
        "count": len(records),
        "categories": categories,
        "records": records,
        "read_only": True
    })


@app.get("/api/report-center/<category>/<path:filename>")
def unified_report_content(category, filename):

    from flask import request, send_file

    if category == "review_history":

        directory = SIMULATION_DIR

    elif category in REPORT_CENTER_SOURCES:

        directory = REPORT_CENTER_SOURCES[category]

    else:

        abort(404)

    directory = directory.resolve()

    path = (directory / filename).resolve()

    if not path.is_relative_to(directory):
        abort(403)

    if not path.is_file():
        abort(404)

    if path.suffix.lower() not in REPORT_CENTER_EXTENSIONS:
        abort(404)

    if category == "review_history":
        if path.name != "ai_draft_reviews.jsonl":
            abort(404)

    if request.args.get("download") == "1":

        return send_file(
            path,
            as_attachment=True,
            download_name=path.name
        )

    if path.stat().st_size > 5 * 1024 * 1024:

        return jsonify({
            "error": "File exceeds preview size limit. Download it instead."
        }), 413

    content = path.read_text(
        encoding="utf-8-sig"
    )

    return jsonify({
        "category": category,
        "filename": path.name,
        "content": content,
        "size_bytes": path.stat().st_size,
        "read_only": True
    })


# DEPI_P5_AI_ENGINE_V1
# =====================================================

@app.get("/api/ai/status")
def ai_engine_status():

    from ai_engine import engine_status

    try:
        return jsonify(engine_status())

    except Exception as error:

        return jsonify({
            "connected": False,
            "error": str(error)
        }), 503


@app.post("/api/ai/analyze")
def ai_engine_analyze():

    from flask import request
    from ai_engine import analyze_case

    payload = request.get_json(silent=True) or {}

    case_id = payload.get("case_id")

    if not isinstance(case_id, str) or not case_id.strip():

        return jsonify({
            "error": "A valid case_id is required"
        }), 400

    try:

        result = analyze_case(case_id.strip())

        return jsonify({
            "success": True,
            "result": result
        })

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 400

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 503


@app.get("/api/ai/assessments")
def ai_engine_assessments():

    from ai_engine import ASSESSMENT_DIR

    ASSESSMENT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    records = []

    for path in sorted(
        ASSESSMENT_DIR.glob("*.json"),
        reverse=True
    ):

        try:

            records.append(
                json.loads(
                    path.read_text(encoding="utf-8-sig")
                )
            )

        except (OSError, json.JSONDecodeError):
            continue

    return jsonify({
        "count": len(records),
        "assessments": records
    })



# =====================================================
# DEPI_P5_DECISION_CENTER_V1
# Human-approved simulated response decisions
# =====================================================

@app.post("/api/decisions")
def create_analyst_decision():

    from flask import request
    from datetime import datetime, timezone
    import os

    payload = request.get_json(silent=True) or {}

    item_id = payload.get("item_id")
    decision = payload.get("decision")
    analyst = payload.get("analyst")
    note = payload.get("note", "")

    if not all(isinstance(x, str) for x in
               [item_id, decision, analyst, note]):
        return jsonify({"error": "Invalid input types"}), 400

    item_id = item_id.strip()
    analyst = analyst.strip()
    note = note.strip()

    if not item_id or not analyst:
        return jsonify({
            "error": "Item ID and analyst are required"
        }), 400

    if decision not in ("approved", "rejected", "deferred"):
        return jsonify({
            "error": "Invalid decision"
        }), 400

    if len(analyst) > 100 or len(note) > 2000:
        return jsonify({
            "error": "Input exceeds permitted length"
        }), 400

    lifecycle_path = OUTPUT_DIR / "ir_lifecycle.json"
    decision_path = SIMULATION_DIR / "analyst_decisions.jsonl"

    try:

        lifecycle = read_json(lifecycle_path)
        items = lifecycle.get("items", [])

        target = next(
            (item for item in items
             if item.get("item_id") == item_id),
            None
        )

        if target is None:
            return jsonify({
                "error": "Unknown response item"
            }), 404

        if (
            target.get("decision") == "prohibited_by_design"
            or target.get("phase") == "prohibited"
        ):
            return jsonify({
                "error": "This action is prohibited by design"
            }), 403

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        record = {
            "ts_utc": timestamp,
            "item_id": item_id,
            "decision": decision,
            "analyst": analyst,
            "note": note,
            "tier": target.get("tier", "Unknown"),
            "via": "V2_DECISION_CENTER"
        }

        SIMULATION_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        decision_path.touch(exist_ok=True)

        # Preserve previous audit records.
        with decision_path.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write(json.dumps(
                record,
                ensure_ascii=False
            ) + "\n")

        target["decision"] = decision
        target["decided_by"] = analyst
        target["decided_utc"] = timestamp
        target["decision_note"] = note
        target["decision_via"] = "V2_DECISION_CENTER"

        temp_path = lifecycle_path.with_suffix(".tmp")

        temp_path.write_text(
            json.dumps(
                lifecycle,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

        os.replace(temp_path, lifecycle_path)

        return jsonify({
            "success": True,
            "record": record,
            "message": "Decision recorded successfully",
            "execution": False
        })

    except (OSError, ValueError, KeyError) as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


if __name__ == "__main__":
    print("=" * 55)
    print("DEPI-P5 | AI-SOC COMMAND CENTER V2")
    print("Local Backend: http://127.0.0.1:5050")
    print("Mode: SIMULATION_ONLY")
    print("Original evidence: READ ONLY")
    print("=" * 55)

    app.run(
        host="127.0.0.1",
        port=5050,
        debug=False,
        use_reloader=False
    )
