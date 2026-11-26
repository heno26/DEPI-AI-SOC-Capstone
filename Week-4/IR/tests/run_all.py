"""Week 4 test suite (standard library only).

Run from the repository root:   python -B Week-4/IR/tests/run_all.py

Taxonomy (same as Weeks 2-3):
  * Integrity / anti-fabrication - real repository data: every timestamp and IP the pipeline shows
    must appear verbatim in the source file it cites; evidence hashes must re-verify.
  * Unit - real code, temporary decision/draft logs.
  * Simulated model - the Ollama call is replaced by a fake response to prove the validator catches
    an invented IP. This is NOT a test of Mistral quality; real drafts must be run locally.
"""
import hashlib
import json
import re
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import common  # noqa: E402
import correlate  # noqa: E402
import ir_lifecycle  # noqa: E402

RESULTS = []


def test(fn):
    RESULTS.append(fn)
    return fn


def _repo_hashes():
    out = {}
    for wk in ("Week-1", "Week-2", "Week-3"):
        for p in (common.REPO_ROOT / wk).rglob("*"):
            if p.is_file() and "__pycache__" not in p.parts:
                out[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


MODEL = None


def model():
    global MODEL
    if MODEL is None:
        MODEL = correlate.build()
    return MODEL


@test
def test_weeks_1_to_3_are_read_only():
    before = _repo_hashes()
    m = correlate.build()
    ir_lifecycle.build(m)
    after = _repo_hashes()
    changed = [k for k in before if before[k] != after.get(k)]
    assert not changed, f"Week 1-3 files changed: {changed[:3]}"


@test
def test_case_count_and_stage_mapping():
    m = model()
    ids = {c["case_id"] for c in m["cases"]}
    assert len(ids) == 19, len(ids)
    for st in m["scenario"]["stages"]:
        for cid in st["case_ids"]:
            assert cid in ids, cid
    assert all(c["stage_id"] for c in m["cases"]), "case without stage"


@test
def test_evidence_hashes_reverify():
    for c in model()["cases"]:
        for f in c["evidence_files"]:
            p = common.REPO_ROOT / f["path"]
            assert p.exists(), f["path"]
            assert common.sha256_file(p) == f["sha256"], f["path"]


@test
def test_every_timestamp_is_verbatim_in_its_source():
    """No timestamp is invented, shifted or reformatted."""
    cache = {}
    for c in model()["cases"]:
        for e in c["events"]:
            src = e["source"]
            if src not in cache:
                cache[src] = (common.REPO_ROOT / src).read_text(encoding="utf-8-sig")
            ts = e["ts_original"]
            assert ts in cache[src], f'{c["case_id"]} {ts} not in {src}'


@test
def test_every_fact_ip_is_in_case_evidence():
    ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    for c in model()["cases"]:
        text = "".join((common.REPO_ROOT / f["path"]).read_text(encoding="utf-8-sig", errors="replace")
                       for f in c["evidence_files"])
        for ip in ip_re.findall(json.dumps(c["facts"])):
            assert ip in text, f'{c["case_id"]}: {ip} not found in its evidence files'


@test
def test_observables_trace_to_cases():
    m = model()
    blob = {c["case_id"]: json.dumps(c["events"]) + json.dumps(c["facts"]) for c in m["cases"]}
    for o in m["observables"]:
        assert o["cases"], o
        assert any(o["value"].lower() in blob[cid].lower() for cid in o["cases"]), o["value"]
        assert "not checked" in o["reputation"], "reputation must never be fabricated"


@test
def test_known_cross_dataset_overlap():
    vals = {o["value"] for o in model()["cross_case_overlaps"]}
    assert "183.62.140.253" in vals, "SSH source shared by LT-01 and SIEM-AUTH-002 should correlate"


@test
def test_response_items_fully_resolved_and_nothing_executed():
    life = ir_lifecycle.build(model())
    for i in life["items"]:
        if i["tier"] != "T2":
            assert not re.search(r"\{\w+\}", i["action"]), i["action"]
        assert "executed" not in i["decision"], i
    assert any(i["tier"] == "T2" for i in life["items"]), "Week-3 prohibited actions must be carried over"


@test
def test_week3_gates_parsed():
    life = ir_lifecycle.build(model())
    assert len(life["open_gates"]["week2"]) == 6 and len(life["open_gates"]["week3"]) == 6


@test
def test_decision_log_flow_and_t2_block():
    tmp = Path(tempfile.mkdtemp())
    orig = ir_lifecycle.DECISIONS_LOG
    try:
        ir_lifecycle.DECISIONS_LOG = tmp / "d.jsonl"
        life = ir_lifecycle.build(model())
        t1 = next(i for i in life["items"] if i["tier"] == "T1")
        common.append_jsonl(ir_lifecycle.DECISIONS_LOG, {"ts_utc": "x", "item_id": t1["item_id"], "decision": "approved",
                                                         "analyst": "test"})
        life2 = ir_lifecycle.build(model())
        got = next(i for i in life2["items"] if i["item_id"] == t1["item_id"])
        assert got["decision"] == "approved" and got["decided_by"] == "test"
        t2 = next(i for i in life2["items"] if i["tier"] == "T2")
        assert t2["decision"] == "prohibited_by_design"
    finally:
        ir_lifecycle.DECISIONS_LOG = orig
        ir_lifecycle.build(model())           # restore real output
        shutil.rmtree(tmp, ignore_errors=True)


@test
def test_cli_refuses_t2_decision():
    import ir_cli
    life = common.load_json(common.OUTPUT_DIR / "ir_lifecycle.json")
    t2 = next(i for i in life["items"] if i["tier"] == "T2")
    try:
        ir_cli.main(["decide", "--item", t2["item_id"], "--decision", "approved", "--analyst", "test"])
    except SystemExit as e:
        assert "prohibited" in str(e)
        return
    raise AssertionError("T2 decision was accepted")


@test
def test_fact_sheets_have_refs_and_sources():
    import ai_report_drafter as d
    life = common.load_json(common.OUTPUT_DIR / "ir_lifecycle.json")
    sheets = d.all_fact_sheets(model(), life)
    assert {"incident_report", "exec_briefing", "lessons_learned"} <= set(sheets)
    assert len([k for k in sheets if k.startswith("stage_")]) == 9
    for name, F in sheets.items():
        assert F.rows, name
        for r in F.rows:
            assert re.fullmatch(r"E\d{3}", r["ref"]) and r["source"], (name, r)


@test
def test_simulated_model_invented_ip_is_flagged():
    """Fake model output with an invented IP -> Week-2 validator must flag it."""
    import ai_report_drafter as d
    from Core import ollama_client as oc
    tmp = Path(tempfile.mkdtemp())
    saved = (oc.check_environment, oc.generate, d.AI_DRAFTS_DIR)
    fake_text = ("1. STAGE SUMMARY\nPort scan observed [E002].\n2. EVIDENCE OBSERVED\n- Scanner 10.99.99.99 probed the host [E002]\n"
                 "3. ATTACK TECHNIQUES\n- T1046 candidate [E003]\n4. WHAT IS NOT ESTABLISHED\n- Intent [E004]\n"
                 "5. ANALYST QUESTION\nIs the scan authorised?\n6. REVIEW STATUS\n" + d.REVIEW_LINE)
    try:
        # Windows Ollama listed the model with a capital M on the analyst laptop - must still resolve
        oc.check_environment = lambda url=None: {"server_up": True, "installed": ["Mistral:7b-instruct-v0.3-q4_K_S"], "error": None}
        def fake_generate(prompt, model=None, options=None, **k):
            assert model == "Mistral:7b-instruct-v0.3-q4_K_S", model
            return oc.GenerationResult(
            text=fake_text, model="SIMULATED", options_used=options or {}, attempts=[{"attempt": 1, "outcome": "simulated"}],
            done_reason="stop", eval_count=100, eval_duration_ns=10**9, wall_seconds=0.01)
        oc.generate = fake_generate
        d.AI_DRAFTS_DIR = tmp
        d.run(only=["stage_S1"])
        rec = json.loads((tmp / "stage_S1.json").read_text(encoding="utf-8"))
        assert rec["status"] == "generated" and rec["review"]["status"] == "Pending Review"
        assert any("10.99.99.99" in (f.get("value") or "") for f in rec["validation"]["flags"]), rec["validation"]["flags"]
    finally:
        oc.check_environment, oc.generate, d.AI_DRAFTS_DIR = saved
        shutil.rmtree(tmp, ignore_errors=True)


@test
def test_t0_checks_read_repo_data():
    life = ir_lifecycle.build(model())
    ch = {i["item_id"]: i.get("check") for i in life["items"] if i["tier"] == "T0"}
    ssh = next(v for k, v in ch.items() if k.startswith("SIEM-AUTH-002:recovery:2-"))
    assert ssh["completed_from_repo"] and "'Accepted' logins from 183.62.140.253: 0" in ssh["result"], ssh
    ex = next(v for k, v in ch.items() if k.startswith("SIEM-EXCH-005:containment:1-"))
    assert "Remove-MailboxExportRequest" in ex["result"] and "dYbLTCleBT" in ex["result"] and "OnmrPW8m8Uv" in ex["result"]
    for v in ch.values():
        assert v and v["result"], "every T0 item has a check result or a stated reason"
        if v["completed_from_repo"]:
            assert (common.REPO_ROOT / v["source"]).exists(), v["source"]


@test
def test_decisions_csv_roundtrip_all_or_nothing():
    import csv as _csv
    import ir_cli
    tmp = Path(tempfile.mkdtemp())
    saved = (ir_cli.DECISIONS_LOG, ir_lifecycle.DECISIONS_LOG)
    try:
        ir_cli.DECISIONS_LOG = ir_lifecycle.DECISIONS_LOG = tmp / "d.jsonl"
        ir_lifecycle.build(model())
        f = tmp / "dec.csv"
        ir_cli.main(["export-decisions", "--file", str(f)])
        rows = list(_csv.DictReader(open(f, encoding="utf-8-sig")))
        t1 = next(r for r in rows if r["tier"] == "T1")
        t0 = next(r for r in rows if r["tier"] == "T0")
        t1.update(decision="done", analyst="tester")                 # invalid for T1 -> whole import refused
        t0.update(decision="done", analyst="tester", note="checked")
        with open(f, "w", encoding="utf-8-sig", newline="") as fh:
            w = _csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader(); w.writerows(rows)
        try:
            ir_cli.main(["import-decisions", str(f)])
            raise AssertionError("invalid row accepted")
        except SystemExit:
            pass
        assert not (tmp / "d.jsonl").exists(), "nothing may be recorded when any row is invalid"
        t1.update(decision="approved")
        with open(f, "w", encoding="utf-8-sig", newline="") as fh:
            w = _csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader(); w.writerows(rows)
        ir_cli.main(["import-decisions", str(f)])
        rec = common.load_jsonl(tmp / "d.jsonl")
        assert {r["item_id"] for r in rec} == {t1["item_id"], t0["item_id"]} and all(r["analyst"] == "tester" for r in rec)
    finally:
        ir_cli.DECISIONS_LOG, ir_lifecycle.DECISIONS_LOG = saved
        ir_cli.cmd_build()                                            # restore real outputs
        shutil.rmtree(tmp, ignore_errors=True)


@test
def test_suggestions_are_rule_based_and_accept_is_logged():
    import ir_cli
    life = ir_lifecycle.build(model())
    for i in life["items"]:
        if i["tier"] == "T2":
            assert i["suggested_decision"] is None
        elif i["tier"] == "T0":
            assert i["suggested_decision"] == ("done" if i["check"]["completed_from_repo"] else "deferred"), i["item_id"]
        else:
            assert i["suggested_decision"] in ("approved", "deferred") and i["suggestion_basis"], i["item_id"]
            if i["action"].lower().startswith("if "):
                assert i["suggested_decision"] == "deferred", i["action"]
    tmp = Path(tempfile.mkdtemp())
    saved = (ir_cli.DECISIONS_LOG, ir_lifecycle.DECISIONS_LOG)
    try:
        ir_cli.DECISIONS_LOG = ir_lifecycle.DECISIONS_LOG = tmp / "d.jsonl"
        ir_lifecycle.build(model())
        ir_cli.main(["accept-suggestions", "--analyst", "tester", "--yes"])
        rec = common.load_jsonl(tmp / "d.jsonl")
        assert len(rec) == sum(1 for i in life["items"] if i["tier"] != "T2")
        assert all(r["via"] == "accepted_rule_suggestion" and r["analyst"] == "tester" for r in rec)
        life2 = common.load_json(common.OUTPUT_DIR / "ir_lifecycle.json")
        assert not [i for i in life2["items"] if i["decision"].startswith("pending")]
    finally:
        ir_cli.DECISIONS_LOG, ir_lifecycle.DECISIONS_LOG = saved
        ir_cli.cmd_build()
        shutil.rmtree(tmp, ignore_errors=True)


@test
def test_inline_headings_are_not_false_missing_sections():
    import ai_report_drafter as d
    txt = ("1. STAGE SUMMARY: Scan seen [E001].\n2. EVIDENCE OBSERVED:\n- x [E001]\n3. ATT&CK TECHNIQUES:\n- T1046 [E001]\n"
           "4. WHAT IS NOT ESTABLISHED:\n- intent\n5. ANALYST QUESTION: Is it authorised?\n6. REVIEW STATUS: " + d.REVIEW_LINE)
    facts = [{"ref": "E001", "raw": "[E001] Scan seen.", "text": "Scan seen.", "source": "x"}]
    sections, flags = d.validate_text(txt, "stage_S1", facts)
    assert set(sections) == set(d.STAGE_DRAFT["headings"]), sections
    assert not [f for f in flags if f["check"] == "missing_section"], flags


@test
def test_dashboard_data_complete():
    import build_dashboard
    build_dashboard.build()
    s = (common.DASHBOARD_DIR / "dashboard_data.js").read_text(encoding="utf-8")
    data = json.loads(s[s.index("=") + 1:].rstrip().rstrip(";"))
    assert {c["id"] for c in data["cases"]} == {c["case_id"] for c in model()["cases"]}
    for k in data["kpis"]:
        assert k["source"], k
    html = (common.DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    assert "http://" not in html and "https://" not in html, "dashboard must work offline (no external URLs)"
    assert "const esc" in html, "dashboard must escape data (XSS payloads are in the evidence)"


if __name__ == "__main__":
    passed = 0
    for fn in RESULTS:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {fn.__name__}: {e}")
            traceback.print_exc(limit=2)
    print(f"SUMMARY: {passed}/{len(RESULTS)} passed")
    sys.exit(0 if passed == len(RESULTS) else 1)
