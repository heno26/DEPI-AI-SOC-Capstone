import argparse
import json
import time
import urllib.request
import urllib.error

from datetime import datetime, timezone
from pathlib import Path


MODEL_DEFAULT = "mistral:7b-instruct-v0.3-q4_K_S"
OLLAMA_URL = "http://localhost:11434/api/chat"
SEVERITIES = {"Low", "Medium", "High", "Critical"}
CONFIDENCES = {"Low", "Moderate", "High"}


def load_dataset(path):
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data.get("records"), list):
        raise ValueError("Invalid normalized evidence dataset")

    return data


def find_record(data, internal_id):
    matches = [
        record for record in data["records"]
        if record.get("identity", {}).get("internal_id") == internal_id
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one record for internal_id, found {len(matches)}"
        )

    return matches[0]


def build_prompt(record):
    classification = record["classification"]
    evidence_block = record["evidence"]
    alert_type = classification["alert_type"]

    evidence = evidence_block.get("original_evidence")
    if evidence is None:
        evidence = evidence_block.get("correlation")

    if evidence is None:
        raise ValueError("No original evidence available")

    system_prompt = """
You are a SOC Tier 1 incident triage analyst.

Analyze ONLY the supplied verified evidence.

Rules:
1. Never invent events, indicators, timestamps, counts, or facts.
2. Separate confirmed observations from hypotheses.
3. Do not claim compromise or successful exploitation without supporting evidence.
4. Explicitly identify missing evidence and evidence limitations.
5. Consider plausible false-positive explanations.
6. Treat IP reputation as unknown unless reputation evidence is supplied.
7. Do not execute or authorize response actions.
8. Never recommend automatic account disabling, host isolation, or evidence deletion.
9. Recommendations must require human approval.
10. Return one complete, valid JSON object only. No Markdown fences or commentary.
11. Include every required field. If a field cannot be supported, use a cautious explanation or an empty array/object of the required type.
"""

    if alert_type == "EXCHANGE":
        output_schema = {
            "executive_summary": "string",
            "confirmed_observations": ["string"],
            "suspicious_indicators": ["string"],
            "unverified_hypotheses": ["string"],
            "missing_evidence": ["string"],
            "recommended_actions": ["string"],
            "severity": "Low/Medium/High/Critical",
            "confidence": "Low/Moderate/High"
        }
    else:
        output_schema = {
            "summary": "string",
            "severity": "Low/Medium/High/Critical",
            "potential_threat": "string",
            "indicators": {},
            "false_positive_possibility": "string",
            "recommended_actions": ["string"],
            "evidence_limitations": "string",
            "confidence": "Low/Moderate/High"
        }

    user_payload = {
        "task": "Independent SOC alert re-analysis",
        "alert_type": alert_type,
        "alert_rule": classification.get("alert_rule"),
        "evidence": evidence,
        "required_output_schema": output_schema
    }

    return system_prompt, json.dumps(user_payload, ensure_ascii=False, indent=2)


def call_ollama(system_prompt, user_prompt, model, timeout):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_predict": 1600
        }
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        response_doc = json.loads(response.read().decode("utf-8"))

    raw_content = response_doc.get("message", {}).get("content")
    if not isinstance(raw_content, str) or not raw_content.strip():
        raise ValueError("Ollama returned an empty response body")

    return {
        "raw_response": raw_content,
        "actual_model": response_doc.get("model"),
        "ollama_total_duration_ns": response_doc.get("total_duration")
    }


def validate_analysis(analysis, alert_type):
    if not isinstance(analysis, dict):
        raise ValueError("AI response must be a JSON object")

    if alert_type == "EXCHANGE":
        required_strings = [
            "executive_summary", "severity", "confidence"
        ]
        required_lists = [
            "confirmed_observations", "suspicious_indicators",
            "unverified_hypotheses", "missing_evidence",
            "recommended_actions"
        ]
        required_objects = []
    else:
        required_strings = [
            "summary", "severity", "potential_threat",
            "false_positive_possibility", "evidence_limitations",
            "confidence"
        ]
        required_lists = ["recommended_actions"]
        required_objects = ["indicators"]

    missing = [key for key in (
        required_strings + required_lists + required_objects
    ) if key not in analysis]

    if missing:
        raise ValueError("Missing AI fields: " + ", ".join(missing))

    invalid = []
    for key in required_strings:
        if not isinstance(analysis[key], str) or not analysis[key].strip():
            invalid.append(f"{key} must be a non-empty string")

    for key in required_lists:
        if not isinstance(analysis[key], list):
            invalid.append(f"{key} must be an array")
        elif not all(isinstance(item, str) for item in analysis[key]):
            invalid.append(f"{key} must contain strings only")

    for key in required_objects:
        if not isinstance(analysis[key], dict):
            invalid.append(f"{key} must be an object")

    if analysis.get("severity") not in SEVERITIES:
        invalid.append("severity must be Low, Medium, High, or Critical")

    if analysis.get("confidence") not in CONFIDENCES:
        invalid.append("confidence must be Low, Moderate, or High")

    if invalid:
        raise ValueError("; ".join(invalid))

    return True


def build_repair_prompt(original_user_prompt, first_raw_response, validation_error):
    repair_payload = {
        "task": "Repair the previous AI response so it satisfies the required JSON schema.",
        "original_analysis_request": json.loads(original_user_prompt),
        "previous_response": first_raw_response,
        "validation_error": validation_error,
        "repair_rules": [
            "Use only facts in the original analysis request evidence.",
            "Do not invent missing evidence or claim successful compromise.",
            "Return every required field with the correct JSON type.",
            "For recommended_actions, return an array of strings; an empty array is acceptable only if no safe recommendation is supported.",
            "Return valid JSON only, without Markdown or commentary."
        ]
    }

    return json.dumps(repair_payload, ensure_ascii=False, indent=2)


def write_json(path, document):
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def execute_attempt(attempt_number, system_prompt, user_prompt, model, timeout,
                    attempt_dir, alert_type):
    started = time.perf_counter()
    attempt = {
        "attempt": attempt_number,
        "request": user_prompt,
        "raw_response": None,
        "parsed_analysis": None,
        "actual_model": None,
        "ollama_total_duration_ns": None,
        "validation_error": None,
        "transport_or_runtime_error": None,
        "elapsed_seconds": None
    }

    try:
        response = call_ollama(system_prompt, user_prompt, model, timeout)
        attempt["raw_response"] = response["raw_response"]
        attempt["actual_model"] = response["actual_model"]
        attempt["ollama_total_duration_ns"] = response["ollama_total_duration_ns"]

        try:
            analysis = json.loads(response["raw_response"])
            validate_analysis(analysis, alert_type)
            attempt["parsed_analysis"] = analysis
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            attempt["validation_error"] = (
                f"{type(exc).__name__}: {str(exc)}"
            )

    except Exception as exc:
        attempt["transport_or_runtime_error"] = (
            f"{type(exc).__name__}: {str(exc)}"
        )

    attempt["elapsed_seconds"] = round(time.perf_counter() - started, 2)
    write_json(attempt_dir / f"attempt_{attempt_number}.json", attempt)

    return attempt


def run(args):
    project = Path(args.project)
    dataset_path = (
        project / "Runs" / "Normalized" / "normalized_evidence.json"
    )

    data = load_dataset(dataset_path)
    record = find_record(data, args.event_id)
    alert_type = record["classification"]["alert_type"]

    system_prompt, original_user_prompt = build_prompt(record)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"RPR-{timestamp}-{args.event_id[:12]}"
    output_dir = project / "Runs" / "Reprocessing" / run_id
    attempts_dir = output_dir / "attempts"
    attempts_dir.mkdir(parents=True, exist_ok=False)

    print(f"Alert: {alert_type}")
    print(f"Internal ID: {args.event_id}")
    print(f"Model: {args.model}")
    print("Attempt 1: sending original verified evidence to Ollama...")

    (output_dir / "request.json").write_text(
        original_user_prompt, encoding="utf-8"
    )

    attempt_1 = execute_attempt(
        1, system_prompt, original_user_prompt, args.model,
        args.timeout, attempts_dir, alert_type
    )

    attempts = [attempt_1]
    final_analysis = attempt_1["parsed_analysis"]
    retry_attempted = False
    final_error = None

    if final_analysis is None:
        first_error = (
            attempt_1["validation_error"]
            or attempt_1["transport_or_runtime_error"]
            or "Unknown first-attempt failure"
        )

        # Retry only when Ollama returned content that failed JSON/schema validation.
        # Transport/runtime failures are preserved and are not blindly retried.
        if attempt_1["raw_response"] is not None:
            retry_attempted = True
            retry_prompt = build_repair_prompt(
                original_user_prompt,
                attempt_1["raw_response"],
                first_error
            )
            (output_dir / "retry_request.json").write_text(
                retry_prompt, encoding="utf-8"
            )

            print("Attempt 1 did not pass validation. Running one schema-repair retry...")
            attempt_2 = execute_attempt(
                2, system_prompt, retry_prompt, args.model,
                args.timeout, attempts_dir, alert_type
            )
            attempts.append(attempt_2)
            final_analysis = attempt_2["parsed_analysis"]

            if final_analysis is None:
                final_error = (
                    attempt_2["validation_error"]
                    or attempt_2["transport_or_runtime_error"]
                    or "Retry failed without a detailed error"
                )
        else:
            final_error = first_error

    successful_attempt = next(
        (item for item in reversed(attempts)
         if item["parsed_analysis"] is not None),
        None
    )

    if successful_attempt:
        status = "PASS_SCHEMA_HUMAN_REVIEW_REQUIRED"
        actual_model = successful_attempt["actual_model"] or args.model
        ollama_duration = successful_attempt["ollama_total_duration_ns"]
    else:
        status = "FAILED"
        actual_model = next(
            (item["actual_model"] for item in reversed(attempts)
             if item["actual_model"]),
            args.model
        )
        ollama_duration = next(
            (item["ollama_total_duration_ns"] for item in reversed(attempts)
             if item["ollama_total_duration_ns"] is not None),
            None
        )

    raw_response_path = output_dir / "final_raw_response.txt"
    last_raw = next(
        (item["raw_response"] for item in reversed(attempts)
         if item["raw_response"] is not None),
        None
    )
    if last_raw is not None:
        raw_response_path.write_text(last_raw, encoding="utf-8")

    total_elapsed = round(
        sum(item["elapsed_seconds"] or 0 for item in attempts), 2
    )

    result = {
        "project": "DEPI-P5",
        "component": "Scenario Orchestrator",
        "stage": "AI_REPROCESSING",
        "run_id": run_id,
        "internal_id": args.event_id,
        "source_filename": record["identity"]["source_filename"],
        "source_sha256": record["identity"]["source_sha256"],
        "alert_type": alert_type,
        "model": actual_model,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "processing_status": status,
        "qa_status": status,
        "human_validation_required": True,
        "analysis": final_analysis,
        "retry_attempted": retry_attempted,
        "attempt_count": len(attempts),
        "attempt_files": [
            f"attempts/attempt_{item['attempt']}.json"
            for item in attempts
        ],
        "final_raw_response_file": (
            raw_response_path.name if last_raw is not None else None
        ),
        "error": final_error,
        "processing_time_seconds": total_elapsed,
        "ollama_total_duration_ns": ollama_duration
    }

    write_json(output_dir / "result.json", result)

    print("\n===== REPROCESSING RESULT =====")
    print(f"Status: {status}")
    print(f"Alert: {alert_type}")
    print(f"Attempts: {len(attempts)}")
    print(f"Retry attempted: {retry_attempted}")
    print(f"Processing time: {total_elapsed}s")
    print(f"Output: {output_dir / 'result.json'}")

    if final_error:
        print(f"Error: {final_error}")

    if status == "FAILED":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(
        description="DEPI P5 Scenario Orchestrator - AI Reprocessor V2"
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--model", default=MODEL_DEFAULT)
    parser.add_argument("--timeout", type=int, default=300)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
