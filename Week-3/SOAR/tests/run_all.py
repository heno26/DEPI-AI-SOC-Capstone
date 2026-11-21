#!/usr/bin/env python3
"""Runs unit + simulated end-to-end + negative tests. No network. No model. ~2s."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dispatcher import ROUTE, PROHIBITED_ACTIONS, alert_rule, validate_envelope, run_playbook
from ticketing.local_json import LocalJSONBackend
from enrichment.stub import EnrichmentStub


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _pb():
    import yaml
    out = {}
    for p in sorted((ROOT / "playbooks").glob("PB-*.yaml")):
        out[yaml.safe_load(p.read_text(encoding="utf-8"))["playbook_id"]] = yaml.safe_load(
            p.read_text(encoding="utf-8"))
    return out


def test_unit_route_table():
    assert ROUTE["SIEM_AUTH_002_SSH_BRUTE_FORCE"] == "PB-01"
    assert ROUTE["SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR"] == "PB-02"
    assert ROUTE["SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT"] == "PB-04"
    print("PASS test_unit_route_table")


def test_unit_prohibited_set():
    must = {"execute_isolation", "execute_rate_limit", "disable_account",
            "lock_account", "delete_export_request", "close_ticket_as_benign"}
    assert must.issubset(PROHIBITED_ACTIONS)
    print("PASS test_unit_prohibited_set")


def test_unit_envelope_rejects_no_human_validation():
    doc = json.loads((FIXTURES / "ssh_valid.json").read_text(encoding="utf-8"))
    doc["human_validation_required"] = False
    try:
        validate_envelope(doc)
    except ValueError:
        print("PASS test_unit_envelope_rejects_no_human_validation")
        return
    raise AssertionError("envelope with human_validation_required=False was accepted")


def test_unit_alert_rule_extraction():
    doc = json.loads((FIXTURES / "mal_valid.json").read_text(encoding="utf-8"))
    assert alert_rule(doc) == "SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR"
    print("PASS test_unit_alert_rule_extraction")


def _run_one(fixture_name, expected_pb, tmpdir):
    playbooks = _pb()
    doc = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    doc["_source_file"] = f"fixtures/{fixture_name}"
    validate_envelope(doc)
    backend = LocalJSONBackend(tmpdir / "tickets")
    ticket, _ = run_playbook(doc, playbooks[expected_pb], backend, EnrichmentStub(), tmpdir)
    assert ticket["playbook_id"] == expected_pb
    assert ticket["tier"] in ("Tier 0", "Tier 1")
    assert ticket["review_status"] == "Pending Review"
    return ticket


def test_e2e_ssh():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        t = _run_one("ssh_valid.json", "PB-01", Path(d))
        assert any(p.get("action") == "rate_limit_source_ip" for p in t["proposed_actions"])
        assert not any(p.get("action") == "execute_rate_limit" for p in t["proposed_actions"])
    print("PASS test_e2e_ssh")


def test_e2e_malware():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        t = _run_one("mal_valid.json", "PB-02", Path(d))
        assert any(p.get("action") == "propose_host_isolation" for p in t["proposed_actions"])
        assert not any(p.get("action") == "execute_isolation" for p in t["proposed_actions"])
    print("PASS test_e2e_malware")


def test_e2e_xss():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        t = _run_one("xss_valid.json", "PB-03", Path(d))
        assert any(p.get("action") == "propose_waf_rule_review" for p in t["proposed_actions"])
    print("PASS test_e2e_xss")


def test_e2e_exchange_tier0_only():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        t = _run_one("exchange_valid.json", "PB-04", Path(d))
        assert t["tier"] == "Tier 0"
        assert t["proposed_actions"] == [], f"PB-04 emitted propose actions: {t['proposed_actions']}"
    print("PASS test_e2e_exchange_tier0_only")


def test_negative_bad_qa():
    import tempfile
    doc = json.loads((FIXTURES / "ssh_valid.json").read_text(encoding="utf-8"))
    doc["qa_status"] = "WEIRD_STATUS"
    try:
        with tempfile.TemporaryDirectory() as d:
            playbooks = _pb()
            run_playbook(doc, playbooks["PB-01"], LocalJSONBackend(Path(d) / "t"),
                         EnrichmentStub(), Path(d))
    except ValueError:
        print("PASS test_negative_bad_qa")
        return
    raise AssertionError("unknown qa_status was accepted")


def test_negative_missing_evidence():
    import tempfile
    doc = json.loads((FIXTURES / "ssh_valid.json").read_text(encoding="utf-8"))
    doc["evidence"] = {}
    try:
        validate_envelope(doc) if False else None
        with tempfile.TemporaryDirectory() as d:
            playbooks = _pb()
            run_playbook(doc, playbooks["PB-01"], LocalJSONBackend(Path(d) / "t"),
                         EnrichmentStub(), Path(d))
    except ValueError:
        print("PASS test_negative_missing_evidence")
        return
    raise AssertionError("empty evidence blob was accepted")


def main():
    tests = [
        test_unit_route_table, test_unit_prohibited_set,
        test_unit_envelope_rejects_no_human_validation,
        test_unit_alert_rule_extraction,
        test_e2e_ssh, test_e2e_malware, test_e2e_xss, test_e2e_exchange_tier0_only,
        test_negative_bad_qa, test_negative_missing_evidence,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:
            print(f"FAIL {t.__name__}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"SUMMARY: {len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()