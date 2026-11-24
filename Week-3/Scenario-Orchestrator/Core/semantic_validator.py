import argparse
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path


VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_CONFIDENCE = {"Low", "Moderate", "High"}

STANDARD_REQUIRED = {
    "summary", "severity", "potential_threat", "indicators",
    "false_positive_possibility", "recommended_actions",
    "evidence_limitations", "confidence"
}
EXCHANGE_REQUIRED = {
    "executive_summary", "confirmed_observations", "suspicious_indicators",
    "unverified_hypotheses", "missing_evidence", "recommended_actions",
    "severity", "confidence"
}

# These phrases imply a completed outcome that must be backed by explicit evidence.
UNSUPPORTED_OUTCOME_PATTERNS = {
    "CONFIRMED_COMPROMISE_CLAIM": (
        r"\b(host|system|server|account|mailbox)\s+(is|was)\s+compromised\b",
        r"\bconfirmed\s+(compromise|breach|intrusion)\b",
    ),
    "CONFIRMED_C2_CLAIM": (
        r"\b(command[- ]and[- ]control|c2)\s+(server|communication|connection)\s+(is|was)\s+confirmed\b",
    ),
    "CONFIRMED_EXFILTRATION_CLAIM": (
        r"\b(data|mailbox|files?)\s+(was|were)\s+(successfully\s+)?(exfiltrated|exported)\b",
    ),
    "CONFIRMED_WEBSHELL_CLAIM": (
        r"\b(web[- ]shell|webshell)\s+(was|has been)\s+(deployed|executed|confirmed)\b",
    ),
    "SUCCESSFUL_XSS_EXECUTION_CLAIM": (
        r"\b(xss|cross[- ]site scripting)\s+(was|has been)\s+(successfully\s+)?(executed|exploited)\b",
    ),
}


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize(value):
    return str(value).strip().lower() if value is not None else ""


def add_finding(findings, level, code, message):
    findings.append({"level": level, "code": code, "message": message})


def find_original_record(dataset, internal_id):
    matches = [
        r for r in dataset.get("records", [])
        if r.get("identity", {}).get("internal_id") == internal_id
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one original record, found {len(matches)}")
    return matches[0]


def get_original_evidence(record):
    block = record.get("evidence") or {}
    evidence = block.get("original_evidence")
    if evidence is None:
        evidence = block.get("correlation")
    if not isinstance(evidence, dict):
        raise ValueError("Original evidence/correlation object is missing")
    return evidence


def get_analysis_text(analysis, alert_type):
    if alert_type == "EXCHANGE":
        fields = (
            "executive_summary", "confirmed_observations",
            "suspicious_indicators", "unverified_hypotheses",
            "missing_evidence", "recommended_actions"
        )
    else:
        fields = (
            "summary", "potential_threat", "indicators",
            "false_positive_possibility", "recommended_actions",
            "evidence_limitations"
        )
    return " ".join(
        json.dumps(analysis.get(k, ""), ensure_ascii=False)
        for k in fields
    ).lower()


def flatten_values(value):
    """Return normalized scalar values from nested indicator structures."""
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            found.extend(flatten_values(k))
            found.extend(flatten_values(v))
    elif isinstance(value, list):
        for item in value:
            found.extend(flatten_values(item))
    elif value is not None and not isinstance(value, bool):
        found.append(str(value).strip())
    return found


def validate_identity(record, result, findings):
    identity = record["identity"]
    checks = (
        ("internal_id", "IDENTITY_MISMATCH",
         "Reprocessing result does not match original internal ID."),
        ("source_filename", "SOURCE_FILENAME_MISMATCH",
         "Source filename does not match original evidence."),
        ("source_sha256", "SOURCE_HASH_MISMATCH",
         "Original evidence SHA256 does not match."),
    )
    for field, code, message in checks:
        if result.get(field) != identity.get(field):
            add_finding(findings, "ERROR", code, message)

    # Independently verify the normalized source hash recorded in the dataset.
    source_hash = identity.get("source_sha256")
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", source_hash):
        add_finding(findings, "WARNING", "SOURCE_HASH_FORMAT",
                    "Dataset source SHA256 is absent or is not a 64-character hexadecimal digest.")


def validate_human_gate(result, findings):
    if result.get("human_validation_required") is not True:
        add_finding(findings, "ERROR", "HUMAN_GATE_MISSING",
                    "Human validation is not explicitly required.")


def validate_analysis_schema(analysis, alert_type, findings):
    if not isinstance(analysis, dict):
        add_finding(findings, "ERROR", "INVALID_ANALYSIS",
                    "AI analysis is not a JSON object.")
        return False

    required = EXCHANGE_REQUIRED if alert_type == "EXCHANGE" else STANDARD_REQUIRED
    missing = sorted(required - set(analysis))
    if missing:
        add_finding(findings, "ERROR", "MISSING_ANALYSIS_FIELDS",
                    "Missing fields: " + ", ".join(missing))

    if analysis.get("severity") not in VALID_SEVERITIES:
        add_finding(findings, "ERROR", "INVALID_SEVERITY",
                    "Unrecognized severity value.")

    if analysis.get("confidence") not in VALID_CONFIDENCE:
        add_finding(findings, "ERROR", "INVALID_CONFIDENCE",
                    "Unrecognized confidence value.")

    list_fields = ["recommended_actions"]
    if alert_type == "EXCHANGE":
        list_fields += [
            "confirmed_observations", "suspicious_indicators",
            "unverified_hypotheses", "missing_evidence"
        ]
    else:
        if not isinstance(analysis.get("indicators"), dict):
            add_finding(findings, "ERROR", "INVALID_INDICATORS",
                        "Indicators must be a JSON object.")

    for field in list_fields:
        if field in analysis and not isinstance(analysis[field], list):
            add_finding(findings, "ERROR", "INVALID_LIST_FIELD",
                        f"{field} must be a JSON array.")

    if alert_type != "EXCHANGE":
        for field in (
            "summary", "potential_threat", "false_positive_possibility",
            "evidence_limitations"
        ):
            if field in analysis and (
                not isinstance(analysis[field], str) or not analysis[field].strip()
            ):
                add_finding(findings, "WARNING", "EMPTY_ANALYSIS_FIELD",
                            f"Field {field} is empty or invalid.")
    else:
        if "executive_summary" in analysis and (
            not isinstance(analysis["executive_summary"], str)
            or not analysis["executive_summary"].strip()
        ):
            add_finding(findings, "WARNING", "EMPTY_ANALYSIS_FIELD",
                        "Field executive_summary is empty or invalid.")

    return not missing


def validate_reported_value(analysis, expected, label, findings, *,
                            severity="WARNING", code_prefix="EVIDENCE"):
    """Check a value only when the model explicitly reports it."""
    if expected is None or expected == "":
        return
    values = flatten_values(analysis)
    expected_text = str(expected).strip().lower()
    if expected_text in values:
        add_finding(findings, "INFO", f"{code_prefix}_{label}_VERIFIED",
                    f"Reported {label.lower()} matches original evidence: {expected}.")
    else:
        # Do not call absence a mismatch: some valid summaries omit individual fields.
        add_finding(findings, severity, f"{code_prefix}_{label}_NOT_REPORTED",
                    f"AI output does not explicitly repeat the verified {label.lower()}: {expected}.")


def validate_ip_quality(evidence, analysis, findings):
    expected_ip = evidence.get("source_ip")
    if not expected_ip:
        return
    try:
        ip_obj = ipaddress.ip_address(expected_ip)
    except ValueError:
        add_finding(findings, "ERROR", "INVALID_SOURCE_IP_IN_EVIDENCE",
                    f"Original evidence contains an invalid source IP: {expected_ip}.")
        return

    quality = evidence.get("source_ip_quality") or {}
    declared_global = quality.get("is_global")
    declared_reserved = quality.get("is_reserved")

    if declared_global is not None and bool(declared_global) != ip_obj.is_global:
        add_finding(findings, "WARNING", "SOURCE_IP_QUALITY_METADATA_CONFLICT",
                    "Stored source_ip_quality metadata conflicts with Python IP classification.")

    text = get_analysis_text(analysis, "STANDARD")
    if ip_obj.is_global and re.search(r"\b(internal|private|lan)\s+ip\b", text):
        add_finding(findings, "WARNING", "SOURCE_IP_SCOPE_MISCHARACTERIZED",
                    f"AI appears to describe globally routable address {expected_ip} as internal/private.")
    if not ip_obj.is_global and re.search(r"\b(public|globally routable)\s+ip\b", text):
        add_finding(findings, "WARNING", "SOURCE_IP_SCOPE_MISCHARACTERIZED",
                    f"AI appears to describe non-global address {expected_ip} as public/global.")

    validate_reported_value(
        analysis, expected_ip, "SOURCE_IP", findings,
        severity="WARNING", code_prefix="IOC"
    )


def validate_ssh_evidence(evidence, analysis, findings):
    indicators = analysis.get("indicators", {})
    if not isinstance(indicators, dict):
        return

    expected_ip = evidence.get("source_ip")
    actual_ip = indicators.get("source_ip")
    if expected_ip and actual_ip:
        if normalize(actual_ip) != normalize(expected_ip):
            add_finding(findings, "ERROR", "SOURCE_IP_MISMATCH",
                        f"Expected {expected_ip}; AI reported {actual_ip}.")
        else:
            add_finding(findings, "INFO", "SOURCE_IP_VERIFIED",
                        f"Source IP matches original evidence: {expected_ip}.")
    elif expected_ip:
        add_finding(findings, "WARNING", "SOURCE_IP_NOT_REPORTED",
                    f"AI did not explicitly report verified source IP {expected_ip}.")

    expected_users = {
        normalize(item.get("username")): item.get("failed_attempts")
        for item in evidence.get("top_usernames", [])
        if isinstance(item, dict) and item.get("username") is not None
    }
    reported_users = indicators.get("top_usernames")
    if isinstance(reported_users, dict):
        actual_users = {normalize(k): v for k, v in reported_users.items()}
    elif isinstance(reported_users, list):
        actual_users = {
            normalize(item.get("username")): item.get("failed_attempts")
            for item in reported_users if isinstance(item, dict)
        }
    else:
        actual_users = {}

    if not actual_users:
        add_finding(findings, "WARNING", "USERNAME_EVIDENCE_NOT_REPORTED",
                    "AI did not provide structured username/count indicators.")
    else:
        for username, expected_count in expected_users.items():
            actual_count = actual_users.get(username)
            if actual_count != expected_count:
                add_finding(findings, "ERROR", "USERNAME_COUNT_MISMATCH",
                            f"{username}: expected {expected_count}, AI reported {actual_count}.")
            else:
                add_finding(findings, "INFO", "USERNAME_COUNT_VERIFIED",
                            f"{username}: {expected_count} failed attempts verified.")
        unexpected = set(actual_users) - set(expected_users)
        if unexpected:
            add_finding(findings, "WARNING", "UNSUPPORTED_USERNAME",
                        "AI reported usernames absent from verified top-user evidence: "
                        + ", ".join(sorted(unexpected)))

    expected_total = evidence.get("verified_failed_password_count")
    if expected_total is not None:
        numeric = [
            v for v in actual_users.values()
            if isinstance(v, int) and not isinstance(v, bool)
        ]
        if numeric and sum(numeric) != expected_total:
            add_finding(findings, "ERROR", "TOTAL_COUNT_MISMATCH",
                        f"Expected {expected_total} verified failures; AI indicators account for {sum(numeric)}.")
        elif numeric:
            add_finding(findings, "INFO", "TOTAL_COUNT_VERIFIED",
                        f"Verified failed-password count: {expected_total}.")
        else:
            add_finding(findings, "WARNING", "TOTAL_COUNT_NOT_REPORTED",
                        f"AI did not provide a structured count to compare with {expected_total}.")

    threshold = evidence.get("failure_threshold")
    if isinstance(expected_total, int) and isinstance(threshold, int):
        if expected_total >= threshold:
            add_finding(findings, "INFO", "SSH_THRESHOLD_CONFIRMED",
                        f"Verified failures ({expected_total}) meet/exceed threshold ({threshold}).")


def validate_web_evidence(evidence, analysis, findings):
    validate_ip_quality(evidence, analysis, findings)
    expected_count = evidence.get("verified_request_count")
    if expected_count is not None:
        validate_reported_value(analysis, expected_count, "VERIFIED_REQUEST_COUNT",
                                findings, code_prefix="WEB")
    # Preserve the fact that request/path samples are evidence, not proof of exploitation.
    text = get_analysis_text(analysis, "STANDARD")
    if re.search(r"\b(successfully exploited|confirmed web compromise|server compromised)\b", text):
        add_finding(findings, "WARNING", "WEB_OUTCOME_OVERCLAIM",
                    "AI states a successful compromise/exploitation outcome; verify that the supplied HTTP evidence proves it.")
    if evidence.get("correlation_limitations"):
        limitation = str(evidence["correlation_limitations"])
        ai_limits = str(analysis.get("evidence_limitations", "")).lower()
        key_terms = [t for t in ("correlation", "sample", "log", "minute") if t in limitation.lower()]
        missing = [t for t in key_terms if t not in ai_limits]
        if missing:
            add_finding(findings, "WARNING", "WEB_LIMITATIONS_NOT_PRESERVED",
                        "AI evidence_limitations may omit original correlation constraints: "
                        + ", ".join(missing))


def validate_malware_evidence(evidence, analysis, findings):
    indicators = analysis.get("indicators", {})
    if not isinstance(indicators, dict):
        return
    for field, label in (
        ("process_guid", "PROCESS_GUID"),
        ("process_image", "PROCESS_IMAGE"),
        ("destination_ip", "DESTINATION_IP"),
        ("destination_port", "DESTINATION_PORT"),
    ):
        expected = evidence.get(field)
        actual = indicators.get(field)
        if expected is not None and actual is not None and str(actual).lower() != str(expected).lower():
            add_finding(findings, "ERROR", f"MALWARE_{label}_MISMATCH",
                        f"Expected {expected}; AI reported {actual}.")
        elif expected is not None and actual is not None:
            add_finding(findings, "INFO", f"MALWARE_{label}_VERIFIED",
                        f"{label.replace('_', ' ').title()} matches original evidence.")
    expected_counts = evidence.get("verified_counts") or {}
    reported_counts = indicators.get("verified_counts") or indicators.get("counts") or {}
    if isinstance(reported_counts, dict):
        for key, expected in expected_counts.items():
            if key in reported_counts:
                if reported_counts[key] != expected:
                    add_finding(findings, "ERROR", "MALWARE_EVENT_COUNT_MISMATCH",
                                f"{key}: expected {expected}; AI reported {reported_counts[key]}.")
                else:
                    add_finding(findings, "INFO", "MALWARE_EVENT_COUNT_VERIFIED",
                                f"{key}: {expected} verified events.")
    text = get_analysis_text(analysis, "STANDARD")
    if re.search(r"\bconfirmed\s+(c2|command[- ]and[- ]control)\b|\bknown c2 server\b", text):
        add_finding(findings, "WARNING", "MALWARE_C2_OVERCLAIM",
                    "AI appears to state confirmed C2 without a verified threat-intelligence verdict.")
    if evidence.get("destination_ip") and evidence.get("destination_ip_quality", {}).get("is_global") is False:
        if "public" in text and "destination" in text:
            add_finding(findings, "WARNING", "MALWARE_DESTINATION_SCOPE_REVIEW",
                        "Review AI characterization of destination IP scope against original IP-quality metadata.")


def validate_xss_evidence(evidence, analysis, findings):
    indicators = analysis.get("indicators", {})
    if not isinstance(indicators, dict):
        return
    expected_ip = evidence.get("source_ip")
    actual_ip = indicators.get("source_ip")
    if expected_ip and actual_ip and normalize(expected_ip) != normalize(actual_ip):
        add_finding(findings, "ERROR", "XSS_SOURCE_IP_MISMATCH",
                    f"Expected source IP {expected_ip}; AI reported {actual_ip}.")
    expected_count = evidence.get("verified_count")
    if expected_count is not None:
        for field in ("verified_count", "request_count", "event_count"):
            if field in indicators and indicators[field] != expected_count:
                add_finding(findings, "ERROR", "XSS_VERIFIED_COUNT_MISMATCH",
                            f"Expected {expected_count}; AI reported {indicators[field]} in {field}.")
    expected_tx = evidence.get("transaction_id")
    if expected_tx and indicators.get("transaction_id"):
        if str(indicators["transaction_id"]) != str(expected_tx):
            add_finding(findings, "ERROR", "XSS_TRANSACTION_ID_MISMATCH",
                        "AI transaction ID differs from verified evidence.")
    text = get_analysis_text(analysis, "STANDARD")
    if re.search(r"\b(successfully executed|successful xss|victim browser executed)\b", text):
        add_finding(findings, "WARNING", "XSS_EXECUTION_OVERCLAIM",
                    "HTTP evidence alone may not establish successful browser-side XSS execution.")
    if evidence.get("limitations"):
        ai_limits = str(analysis.get("evidence_limitations", "")).lower()
        if not ai_limits.strip():
            add_finding(findings, "WARNING", "XSS_LIMITATIONS_NOT_PRESERVED",
                        "Original XSS evidence limitations were not restated in AI evidence_limitations.")


def validate_exchange_evidence(evidence, analysis, findings):
    verified = evidence.get("verified_evidence", [])
    if not isinstance(verified, list):
        add_finding(findings, "ERROR", "EXCHANGE_VERIFIED_EVIDENCE_INVALID",
                    "correlation.verified_evidence must be a list.")
        return
    unique_events = evidence.get("unique_events")
    if unique_events is not None and unique_events != len(verified):
        add_finding(findings, "WARNING", "EXCHANGE_EVENT_COUNT_REVIEW",
                    f"unique_events={unique_events}, but verified_evidence contains {len(verified)} records.")
    # Check only explicitly reported values; do not require every field in the narrative.
    ai_text = get_analysis_text(analysis, "EXCHANGE")
    for event in verified:
        if not isinstance(event, dict):
            continue
        for key in ("host", "record_number", "mailbox", "command", "transaction_id"):
            value = event.get(key)
            if value and str(value).lower() not in ai_text:
                # Omission is a warning, not a factual contradiction.
                add_finding(findings, "INFO", "EXCHANGE_DETAIL_NOT_REPEATED",
                            f"Verified Exchange detail {key}={value} is not explicitly repeated in AI output.")
    if analysis.get("confirmed_observations") and not verified:
        add_finding(findings, "WARNING", "EXCHANGE_CONFIRMATIONS_WITHOUT_EVENTS",
                    "AI supplied confirmed observations but the original correlation has no verified evidence rows.")
    text = ai_text
    if re.search(r"\b(export(s|ed)?|exfiltrat(ed|ion))\s+(completed|successfully)\b", text):
        add_finding(findings, "WARNING", "EXCHANGE_EXPORT_COMPLETION_OVERCLAIM",
                    "AI appears to claim completed export/exfiltration; verify filesystem or Exchange completion evidence.")
    if re.search(r"\b(web[- ]shell|webshell)\s+(was|has been)\s+(deployed|executed)\b", text):
        add_finding(findings, "WARNING", "EXCHANGE_WEBSHELL_OVERCLAIM",
                    "AI appears to claim Web Shell deployment/execution without independent completion evidence.")


def validate_unsupported_claims(analysis, alert_type, evidence, findings):
    text = get_analysis_text(analysis, alert_type)
    for code, patterns in UNSUPPORTED_OUTCOME_PATTERNS.items():
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
            add_finding(findings, "WARNING", code,
                        "AI wording may assert a completed security outcome; confirm that original evidence directly supports it.")
    # Explicitly guard against invented reputation verdicts.
    evidence_json = json.dumps(evidence, ensure_ascii=False).lower()
    if re.search(r"\b(malicious|known malicious|blacklisted)\s+(ip|address)\b", text):
        if not any(term in evidence_json for term in ("reputation", "threat_intelligence", "malicious_verdict")):
            add_finding(findings, "WARNING", "UNVERIFIED_IP_REPUTATION",
                        "AI labels an IP as malicious without a reputation verdict in the supplied evidence.")


def compare_original_ai(record, analysis, alert_type, findings):
    original = record.get("original_ai", {}).get("analysis", {})
    if not isinstance(original, dict) or not original:
        return
    fields = ("severity", "confidence")
    for field in fields:
        old, new = original.get(field), analysis.get(field)
        if old != new:
            add_finding(findings, "INFO", "AI_COMPARISON_DIFFERENCE",
                        f"{field}: Week-2={old}; Week-3={new}. Difference requires analyst review, not automatic rejection.")

    old_actions = original.get("recommended_actions")
    new_actions = analysis.get("recommended_actions")
    if isinstance(old_actions, list) and isinstance(new_actions, list) and old_actions != new_actions:
        add_finding(findings, "INFO", "AI_RECOMMENDATIONS_CHANGED",
                    "Week-2 and Week-3 recommended actions differ; analyst should review safety and evidence alignment.")


def validate_generic_quality(analysis, alert_type, findings):
    if alert_type == "EXCHANGE":
        if not analysis.get("executive_summary"):
            add_finding(findings, "WARNING", "NO_EXECUTIVE_SUMMARY",
                        "No executive summary was provided.")
    else:
        for field in ("summary", "potential_threat", "false_positive_possibility", "evidence_limitations"):
            value = analysis.get(field)
            if not isinstance(value, str) or not value.strip():
                add_finding(findings, "WARNING", "EMPTY_ANALYSIS_FIELD",
                            f"Field {field} is empty or invalid.")
    if not analysis.get("recommended_actions"):
        add_finding(findings, "WARNING", "NO_RECOMMENDATIONS",
                    "No investigation recommendations were provided.")


def validate(dataset_path, result_path, output_dir):
    dataset = load_json(dataset_path)
    result = load_json(result_path)
    internal_id = result.get("internal_id")
    if not internal_id:
        raise ValueError("Missing internal ID in reprocessing result")

    record = find_original_record(dataset, internal_id)
    alert_type = record.get("classification", {}).get("alert_type", "UNKNOWN")
    evidence = get_original_evidence(record)
    analysis = result.get("analysis")
    findings = []

    validate_identity(record, result, findings)
    validate_human_gate(result, findings)
    schema_valid = validate_analysis_schema(analysis, alert_type, findings)

    if schema_valid:
        if alert_type == "SSH_BRUTE_FORCE":
            validate_ssh_evidence(evidence, analysis, findings)
        elif alert_type == "WEB_HIGH_RATE":
            validate_web_evidence(evidence, analysis, findings)
        elif alert_type == "MALWARE":
            validate_malware_evidence(evidence, analysis, findings)
        elif alert_type == "XSS":
            validate_xss_evidence(evidence, analysis, findings)
        elif alert_type == "EXCHANGE":
            validate_exchange_evidence(evidence, analysis, findings)
        else:
            add_finding(findings, "WARNING", "NO_SPECIALIZED_VALIDATOR",
                        f"No specialized semantic validator is registered for {alert_type}.")

        validate_unsupported_claims(analysis, alert_type, evidence, findings)
        validate_generic_quality(analysis, alert_type, findings)
        compare_original_ai(record, analysis, alert_type, findings)

    errors = sum(f["level"] == "ERROR" for f in findings)
    warnings = sum(f["level"] == "WARNING" for f in findings)
    infos = sum(f["level"] == "INFO" for f in findings)

    status = "FAIL" if errors else ("PASS_WITH_WARNINGS" if warnings else "PASS")
    report = {
        "project": "DEPI-P5",
        "component": "Scenario Orchestrator",
        "stage": "SEMANTIC_VALIDATION",
        "validator_version": "2.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "internal_id": internal_id,
        "alert_type": alert_type,
        "source_file": record["identity"]["source_filename"],
        "source_sha256": record["identity"].get("source_sha256"),
        "source_files_modified": False,
        "ai_reexecution_performed": False,
        "human_validation_required": True,
        "validation_status": status,
        "summary": {
            "total_checks": len(findings),
            "errors": errors,
            "warnings": warnings,
            "informational": infos
        },
        "findings": findings
    }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{internal_id[:16]}_semantic_validation.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n===== SEMANTIC VALIDATION v2.0 =====")
    print(f"Alert: {alert_type}")
    print(f"Status: {status}")
    print(f"Errors: {errors}")
    print(f"Warnings: {warnings}")
    print(f"Informational: {infos}")
    print("\n===== FINDINGS =====")
    for item in findings:
        print(f"[{item['level']}] {item['code']}: {item['message']}")
    print(f"\nReport: {report_path}")

    if errors:
        raise SystemExit(2)


def main():
    parser = argparse.ArgumentParser(description="DEPI P5 Semantic Evidence Validator v2.0")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    validate(Path(args.dataset), Path(args.result), Path(args.out))


if __name__ == "__main__":
    main()
