import json
import re
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR.parent / "Output"
INCIDENT_FILE = OUTPUT_DIR / "incident.json"

ASSESSMENT_DIR = OUTPUT_DIR / "ai_assessments"

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"

PRIMARY_MODEL = "mistral:7b-instruct-v0.3-q4_K_S"


SYSTEM_PROMPT = """
You are the primary AI analysis engine of DEPI P5 AI-assisted SOC.

Your role is evidence-grounded cybersecurity incident analysis.

STRICT RULES:

1. Never invent events, timestamps, IOCs, IP addresses or evidence.
2. Distinguish observed facts from hypotheses.
3. Do not assume separate datasets represent one real attack.
4. Preserve original evidence references.
5. Never claim successful compromise without supporting evidence.
6. Never claim malware execution or persistence without sufficient evidence.
7. Do not execute remediation.
8. All consequential recommendations require human approval.
9. Explicitly identify missing information.
10. Never modify source evidence.

Return ONLY valid JSON using this structure:

{
  "case_id": "",
  "assessment_type": "NEW_AI_ASSESSMENT",
  "severity": "Informational",
  "confidence": "Low",
  "verdict": "",
  "executive_summary": "",
  "observed_facts": [],
  "analytical_findings": [],
  "hypotheses": [],
  "mitre_mapping": [],
  "evidence_references": [],
  "evidence_gaps": [],
  "recommended_actions": [],
  "prohibited_assumptions": [],
  "human_validation_required": true
}

Severity must be one of:
Critical, High, Medium, Low, Informational.

Confidence must be one of:
High, Moderate, Low.

Recommendations must be proposals only.
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_incident():
    if not INCIDENT_FILE.is_file():
        raise FileNotFoundError("incident.json not found")

    return json.loads(
        INCIDENT_FILE.read_text(encoding="utf-8-sig")
    )


def find_case(case_id):

    incident = load_incident()

    for case in incident.get("cases", []):

        if case.get("case_id") == case_id:
            return incident, case

    raise ValueError("Unknown case_id")


def verify_evidence_files(case):

    results = []

    for item in case.get("evidence_files", []):

        relative = Path(item["path"])

        if ".." in relative.parts:
            raise ValueError("Unsafe evidence path")

        path = BASE_DIR.parent.parent / relative

        result = {
            "path": item["path"],
            "expected_sha256": item.get("sha256"),
            "exists": False,
            "hash_verified": False
        }

        if path.is_file():

            result["exists"] = True

            digest = hashlib.sha256()

            with path.open("rb") as file:

                for chunk in iter(
                    lambda: file.read(1024 * 1024),
                    b""
                ):
                    digest.update(chunk)

            actual = digest.hexdigest()

            result["actual_sha256"] = actual

            result["hash_verified"] = (
                actual.lower() ==
                str(item.get("sha256", "")).lower()
            )

        results.append(result)

    return results


def build_context(case):

    return {
        "case_id": case.get("case_id"),
        "title": case.get("title"),
        "domain": case.get("domain"),
        "detection_rule": case.get("detection_rule"),
        "dataset": case.get("dataset"),
        "facts": case.get("facts", {}),
        "events": case.get("events", []),
        "ai_historical_result": case.get("ai", {}),
        "attack_mapping": case.get("attack", []),
        "evidence_files": case.get("evidence_files", []),
        "evidence_integrity": verify_evidence_files(case),
        "limitations": case.get("limitations", []),
        "human_review": case.get("human_review", {}),
        "existing_tickets": case.get("tickets", []),
        "stage_id": case.get("stage_id")
    }


def call_ollama(context):

    payload = {

        "model": PRIMARY_MODEL,

        "stream": False,

        "format": "json",

        "options": {
            "temperature": 0.1,
            "num_ctx": 8192
        },

        "messages": [

            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },

            {
                "role": "user",
                "content": (
                    "Analyze this case using only the "
                    "provided evidence.\n\n"
                    + json.dumps(
                        context,
                        ensure_ascii=False,
                        indent=2
                    )
                )
            }

        ]

    }

    request = Request(

        OLLAMA_URL,

        data=json.dumps(payload).encode("utf-8"),

        headers={
            "Content-Type": "application/json"
        },

        method="POST"

    )

    with urlopen(request, timeout=300) as response:

        result = json.loads(response.read())

    return result


def validate_assessment(data, case_id):

    required = [
        "case_id",
        "assessment_type",
        "severity",
        "confidence",
        "verdict",
        "executive_summary",
        "observed_facts",
        "analytical_findings",
        "hypotheses",
        "mitre_mapping",
        "evidence_references",
        "evidence_gaps",
        "recommended_actions",
        "prohibited_assumptions",
        "human_validation_required"
    ]

    missing = [
        field for field in required
        if field not in data
    ]

    if missing:
        raise ValueError(
            "Missing fields: " + ", ".join(missing)
        )

    if data["case_id"] != case_id:
        raise ValueError("Case ID mismatch")

    if data["severity"] not in [
        "Critical", "High", "Medium",
        "Low", "Informational"
    ]:
        raise ValueError("Invalid severity")

    # Normalize common Mistral confidence variations.
    confidence = data.get("confidence")

    if isinstance(confidence, str):

        confidence_aliases = {
            "high": "High",
            "high confidence": "High",
            "moderate": "Moderate",
            "medium": "Moderate",
            "medium confidence": "Moderate",
            "moderate confidence": "Moderate",
            "observed_pattern": "Moderate",
            "low": "Low",
            "low confidence": "Low"
        }

        normalized = confidence.strip().lower()

        if normalized in confidence_aliases:
            data["confidence"] = confidence_aliases[normalized]

    if data["confidence"] not in [
        "High", "Moderate", "Low"
    ]:
        raise ValueError("Invalid confidence")

    for field in [
        "observed_facts",
        "analytical_findings",
        "hypotheses",
        "mitre_mapping",
        "evidence_references",
        "evidence_gaps",
        "recommended_actions",
        "prohibited_assumptions"
    ]:

        if not isinstance(data[field], list):
            raise ValueError(
                field + " must be a list"
            )

    if data["human_validation_required"] is not True:
        raise ValueError(
            "Human validation cannot be disabled"
        )

    return True


def analyze_case(case_id):

    incident, case = find_case(case_id)

    context = build_context(case)

    response = call_ollama(context)

    raw = response.get(
        "message", {}
    ).get("content", "")

    assessment = json.loads(raw)

    validate_assessment(
        assessment,
        case_id
    )

    ASSESSMENT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    filename = (
        case_id + "_" + timestamp + ".json"
    )

    output = {

        "generated_at_utc": utc_now(),

        "generator": "DEPI-P5 Interactive AI Engine",

        "assessment_id": filename,

        "model": PRIMARY_MODEL,

        "scenario_id": incident.get(
            "scenario", {}
        ).get("scenario_id"),

        "case_id": case_id,

        "assessment_type": "NEW_AI_ASSESSMENT",

        "source_evidence_preserved": True,

        "evidence_integrity": context[
            "evidence_integrity"
        ],

        "human_validation_required": True,

        "qa_status": "SCHEMA_PASS_HUMAN_REVIEW_REQUIRED",

        "response_execution": False,

        "assessment": assessment,

        "raw_model_response": raw

    }

    destination = ASSESSMENT_DIR / filename

    destination.write_text(
        json.dumps(
            output,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    return output


def engine_status():

    request = Request(
        "http://127.0.0.1:11434/api/tags"
    )

    with urlopen(request, timeout=5) as response:

        data = json.loads(response.read())

    models = [
        item.get("name")
        for item in data.get("models", [])
    ]

    return {

        "connected": True,

        "primary_model": PRIMARY_MODEL,

        "primary_model_available": (
            PRIMARY_MODEL in models
        ),

        "available_models": models

    }
