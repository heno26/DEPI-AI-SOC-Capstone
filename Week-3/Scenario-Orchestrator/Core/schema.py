SCHEMA_VERSION = "1.0"

ALLOWED_ALERT_TYPES = {
    "WEB_HIGH_RATE",
    "SSH_BRUTE_FORCE",
    "MALWARE",
    "XSS",
    "EXCHANGE"
}

def create_normalized_record(
    internal_id,
    original_event_id,
    source_filename,
    source_sha256,
    alert_type,
    alert_rule,
    source_document
):
    evidence = (
        source_document.get("evidence")
        or source_document.get("correlation")
        or {}
    )

    ai = source_document.get("ai_triage") or {}

    return {
        "schema_version": SCHEMA_VERSION,
        "project": source_document.get("project", "DEPI-P5"),

        "identity": {
            "internal_id": internal_id,
            "original_event_id": original_event_id,
            "source_filename": source_filename,
            "source_sha256": source_sha256
        },

        "classification": {
            "alert_type": alert_type,
            "alert_rule": alert_rule,
            "stream": (
                evidence.get("stream")
                or source_document.get("stream")
            ),
            "source_phase": source_document.get("phase")
        },

        "source": {
            "generated_at_utc": source_document.get(
                "generated_at_utc"
            ),
            "original_model": source_document.get("model"),
            "original_mode": source_document.get("mode")
        },

        "evidence": {
            "evidence_type": (
                "correlation"
                if "correlation" in source_document
                else "standard_evidence"
            ),
            "original_evidence": evidence,
            "source_trigger": source_document.get(
                "source_trigger"
            ),
            "correlation": (
                source_document.get("correlation")
                if "correlation" in source_document
                else None
            )
        },

        "original_ai": {
            "analysis": ai,
            "qa_status": source_document.get("qa_status"),
            "missing_fields": source_document.get(
                "missing_fields", []
            ),
            "human_validation_required":
                source_document.get(
                    "human_validation_required"
                )
        },

        "reprocessing": {
            "status": "NOT_STARTED",
            "model": None,
            "analysis": None,
            "qa_status": None
        },

        "provenance": {
            "source_read_only": True,
            "source_integrity_verified": False,
            "processing_history": []
        },

        "source_snapshot": source_document
    }
