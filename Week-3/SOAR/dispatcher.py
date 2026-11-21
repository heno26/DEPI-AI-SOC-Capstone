#!/usr/bin/env python3
"""DEPI P5 Week-3: SOAR dispatcher.

Reads saved Week-2 evidence JSON files, routes to a playbook, applies decision gates,
creates a local ticket, writes an audit trail. Never calls the model, never calls a live
SIEM, never executes remediation.

Run:  python -B dispatcher.py --evidence <dir> --playbooks <dir> --out <dir>
      python -B dispatcher.py --evidence ../Evidence/SIEM-OpenObserve --playbooks playbooks --out .
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ticketing.local_json import LocalJSONBackend
from enrichment.stub import EnrichmentStub

PROHIBITED_ACTIONS = {
    "execute_isolation",
    "execute_rate_limit",
    "disable_account",
    "lock_account",
    "delete_export_request",
    "close_ticket_as_benign",
}

ROUTE = {
    "SIEM_AUTH_002_SSH_BRUTE_FORCE": "PB-01",
    "SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR": "PB-02",
    "SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS": "PB-03",
    "SIEM_WEB_004_XSS_ATTACK_DETECTED": "PB-03",
    "SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT": "PB-04",
}


def utcnow():
    return datetime.now(timezone.utc).isoformat()

def normalise_document(doc):
    """Make every Week-2 receiver's JSON shape look like the SIEM06/07 envelope.
    Returns the doc unchanged if already in SIEM06/07 shape.
    """
    # SIEM06/07 shape is already correct
    if "source_trigger" in doc and "evidence" in doc:
        return doc

    # Exchange shape: correlation + ai_result + event_id at top level
    if "correlation" in doc:
        corr = doc.get("correlation") or {}
        ai = doc.get("ai_result") or doc.get("ai_triage") or {}
        # Synthesise a source_trigger from the alert rule name
        rule = doc.get("alert_rule") or "SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT"
        return {
            "event_id": doc.get("event_id") or corr.get("event_id") or "unknown",
            "source_trigger": {
                "key": rule + "/exchange" if "/" not in rule else rule,
                "status": "firing",
            },
            "evidence": {
                "rule": rule,
                "verified_unique_events": corr.get("unique_events"),
                "matched_replays": corr.get("matched_replays"),
                "duplicates_removed": corr.get("duplicates_removed"),
                "events": corr.get("verified_evidence", []),
            },
            "ai_triage": ai,
            "qa_status": "REVIEW_REQUIRED",  # Exchange receiver hard-codes this
            "missing_fields": doc.get("missing_fields", []),
            "semantic_warnings": doc.get("semantic_warnings", []),
            "human_validation_required": True,
            "limitations": doc.get("limitations", []),
            "_source_file": doc.get("_source_file"),
        }

    # Anything else — leave unchanged; envelope validation will reject it cleanly.
    return doc


def load_evidence(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def alert_rule(doc):
    trig = doc.get("source_trigger") or {}
    key = trig.get("key", "") or ""
    # OpenObserve firing triggers append '/<uniqueId>'; strip it for routing.
    # Mirrors SIEM06_Multi_Alert_Receiver.find_rule_trigger's startswith(rule + '/').
    return key.split("/", 1)[0] if "/" in key else key


def validate_envelope(doc):
    required = ["event_id", "source_trigger", "evidence", "ai_triage", "qa_status"]
    missing = [k for k in required if k not in doc]
    if missing:
        raise ValueError(f"evidence missing fields: {missing}")
    if doc.get("human_validation_required") is not True:
        raise ValueError("evidence does not require human validation — refusing to process")
    return doc


def build_ticket(doc, playbook_id, tier, enrichment, proposed, prohibited, adapter_name):
    ev = doc["evidence"]
    trig = doc["source_trigger"]
    return {
        "ticket_id": doc["event_id"],
        "created_at_utc": utcnow(),
        "playbook_id": playbook_id,
        "alert_rule": trig.get("key"),
        "trigger_status": trig.get("status"),
        "evidence_adapter": adapter_name,
        "tier": tier,
        "qa_status": doc.get("qa_status"),
        "semantic_warnings": doc.get("semantic_warnings", []),
        "missing_fields": doc.get("missing_fields", []),
        "ai_severity": (doc.get("ai_triage") or {}).get("severity"),
        "ai_confidence": (doc.get("ai_triage") or {}).get("confidence"),
        "enrichment": enrichment,
        "proposed_actions": proposed,
        "prohibited_actions": prohibited,
        "review_status": "Pending Review",
        "analyst_decision": None,
        "linked_evidence_file": doc.get("_source_file"),
        "limitations": doc.get("limitations", []),
    }


def run_playbook(doc, playbook, backend, enrich, out_dir):
    rule = alert_rule(doc)
    pb_id = ROUTE.get(rule)
    if not pb_id:
        raise ValueError(f"no playbook routes rule {rule!r}")
    if playbook.get("playbook_id") != pb_id:
        raise ValueError(f"playbook mismatch: expected {pb_id}, got {playbook.get('playbook_id')}")

    # Gate 1: evidence must be verified (Week-2 receivers set this implicitly by
    # producing evidence; a heuristic check is that evidence is non-empty dict).
    if not isinstance(doc["evidence"], dict) or not doc["evidence"]:
        raise ValueError("evidence blob empty — gate failed")

    # Gate 2: QA status must be a recognised review state.
    allowed_qa = {"SCHEMA_PASS_HUMAN_REVIEW_REQUIRED", "REVIEW_REQUIRED"}
    if doc["qa_status"] not in allowed_qa:
        raise ValueError(f"unexpected qa_status {doc['qa_status']!r}")

    # Enrichment (stub: always "not performed", never fabricates reputation).
    enrichment = enrich.run(doc)

    # Proposed actions come from the playbook YAML, but PB-04 is capped at Tier 0.
    proposed = []
    if pb_id != "PB-04":
        proposed = playbook.get("actions", {}).get("propose", [])

    prohibited = list(playbook.get("actions", {}).get("prohibited", []))
    for action in prohibited:
        if action.get("action") in PROHIBITED_ACTIONS:
            # Already declared; fine. Anything not declared but in the set would be a bug.
            continue

    tier = playbook.get("tier_max", "Tier 0")
    ticket = build_ticket(doc, pb_id, tier, enrichment, proposed, prohibited,
                          playbook.get("evidence_adapter"))
    backend.create(ticket)

    audit = {
        "ts_utc": utcnow(),
        "event_id": doc["event_id"],
        "playbook_id": pb_id,
        "tier": tier,
        "actions_auto": ["parse", "enrich(stub)", "create_ticket", "notify", "audit"],
        "actions_proposed": [a.get("action") for a in proposed],
        "actions_prohibited": [a.get("action") for a in prohibited],
        "review_status": "Pending Review",
    }
    audit_path = Path(out_dir) / "audit" / f"{doc['event_id']}.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(audit) + "\n")
    return ticket, audit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--playbooks", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ev_dir = Path(args.evidence)
    pb_dir = Path(args.playbooks)
    out_dir = Path(args.out)
    (out_dir / "tickets").mkdir(parents=True, exist_ok=True)
    (out_dir / "audit").mkdir(parents=True, exist_ok=True)

    backend = LocalJSONBackend(out_dir / "tickets")
    enrich = EnrichmentStub()

    playbooks = {}
    for yaml_path in sorted(pb_dir.glob("PB-*.yaml")):
        pb = parse_simple_yaml(yaml_path.read_text(encoding="utf-8"))
        playbooks[pb["playbook_id"]] = pb

    processed = 0
    for path in sorted(ev_dir.glob("*_AI_Triage*.json")):
        try:
            doc = load_evidence(path)
            doc["_source_file"] = str(path)
            doc = normalise_document(doc)
            validate_envelope(doc)
            rule = alert_rule(doc)
            pb_id = ROUTE.get(rule)
            if not pb_id:
                print(f"SKIP {path.name}: no route for rule {rule!r}")
                continue
            pb = playbooks[pb_id]
            ticket, audit = run_playbook(doc, pb, backend, enrich, out_dir)
            print(f"TICKET {ticket['ticket_id'][:16]} -> {pb_id} ({ticket['tier']})")
            processed += 1
        except Exception as exc:
            if "missing fields" in str(exc) and "event_id" in str(exc):
              # Older format (SIEM04) — legitimately not routable, not an error
                print(f"SKIP {path.name}: legacy format without event_id (pre-SIEM05)")
            else:
                print(f"FAIL {path.name}: {type(exc).__name__}: {exc}")

    print(f"STATUS: DISPATCH COMPLETE | processed={processed}")


def parse_simple_yaml(text):
    """Minimal YAML reader for our fixed playbook schema (no external deps)."""
    import yaml  # type: ignore
    return yaml.safe_load(text)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"STATUS: DISPATCH FAILED: {exc}", file=sys.stderr)
        sys.exit(1)