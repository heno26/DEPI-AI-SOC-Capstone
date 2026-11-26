"""Week 4 correlation engine.

Reads the saved Week 1-3 artifacts from the repository and builds ONE incident model for the
composite tabletop scenario (Config/scenario.json):

  Output/incident.json        full model (cases, stages, observables, overlaps, metrics)
  Output/incident_timeline.csv  every source event, in scenario-stage order
  Output/observables.csv      IOCs / observables with case references and scope

Nothing here calls an AI model, a SIEM or the network. Every value is read from a repository
file; each case keeps the list of files (with SHA-256) it was derived from.
"""
import glob
import re
from collections import Counter, defaultdict

from common import (WEEK1, WEEK2, WEEK3, OUTPUT_DIR, load_config, load_csv, load_json, load_jsonl,
                    micros_to_iso, parse_iso, rel, sha256_file, utcnow_iso, write_csv, write_json,
                    import_week2)

import_week2()
from Core.validator import extract_iocs, ip_scope  # noqa: E402  (Week-2 code reused, not copied)

RD = WEEK2 / "Data" / "Real-Datasets"
EVID = WEEK2 / "Evidence" / "SIEM-OpenObserve"

DATASET_CASE_DIRS = {
    "LT-01": RD / "Linux-Attacks" / "LT-01-SSH-Brute-Force",
    "LT-02": RD / "Linux-Attacks" / "LT-02-Privilege-Escalation",
    "LT-03": RD / "Linux-Attacks" / "LT-03-Suspicious-Execution",
    "LT-04": RD / "Linux-Benign" / "LT-04-Normal-Operations",
    "NT-01": RD / "Network-Attacks" / "NT-01-Port-Scanning",
    "NT-02": RD / "Network-Attacks" / "NT-02-DNS-Anomaly",
    "NT-03": RD / "Network-Attacks" / "NT-03-C2-Beaconing",
    "RT-01": RD / "Windows-Attacks" / "RT-01-C2",
    "RT-02": RD / "Windows-Attacks" / "RT-02-Discovery",
    "RT-03": RD / "Windows-Attacks" / "RT-03-Lateral-Movement",
    "RT-04": RD / "Windows-Attacks" / "RT-04-Persistence",
    "BT-01": RD / "Windows-Benign" / "BT-01",
    "BT-02": RD / "Windows-Benign" / "BT-02",
    "BT-03": RD / "Windows-Benign" / "BT-03",
}

# Week-2 AN-* analyses are matched to a case by their input filename prefix.
AN_INPUT_PREFIX = {k: k + "-" for k in DATASET_CASE_DIRS}

TITLES = {
    "SIEM-WEB-001": "High-rate HTTP requests from a single source",
    "SIEM-AUTH-002": "SSH brute force against root",
    "SIEM-MAL-003": "Suspicious executable with DNS + outbound connection",
    "SIEM-WEB-004": "Cross-site scripting (XSS) payloads",
    "SIEM-EXCH-005": "Exchange mailbox export to OWA .aspx path",
    "LT-01": "SSH password guessing (verified timeline)",
    "LT-02": "Privilege-sensitive sudo commands",
    "LT-03": "Bash reverse-shell command pattern",
    "LT-04": "Linux start-up (benign candidate)",
    "NT-01": "Vertical TCP port scan",
    "NT-02": "DNS chunk-style query burst",
    "NT-03": "Periodic HTTP connections to external host",
    "RT-01": "plink.exe RDP tunnel",
    "RT-02": "Security log cleared + share access checks",
    "RT-03": "WinRM remote command execution on DC",
    "RT-04": "Winlogon Shell persistence",
    "BT-01": ".NET native-image optimisation (benign candidate)",
    "BT-02": "SYSTEM service logons (benign candidate)",
    "BT-03": "Service start/stop transitions (benign candidate)",
}

DOMAINS = {
    "SIEM-WEB-001": "web", "SIEM-WEB-004": "web", "SIEM-AUTH-002": "auth", "SIEM-MAL-003": "endpoint",
    "SIEM-EXCH-005": "email", "LT-01": "auth", "LT-02": "endpoint", "LT-03": "endpoint", "LT-04": "endpoint",
    "NT-01": "network", "NT-02": "network", "NT-03": "network", "RT-01": "network", "RT-02": "endpoint",
    "RT-03": "endpoint", "RT-04": "endpoint", "BT-01": "endpoint", "BT-02": "endpoint", "BT-03": "endpoint",
}

PLAYBOOK_BY_RULE = {
    "SIEM_AUTH_002_SSH_BRUTE_FORCE": "PB-01",
    "SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR": "PB-02",
    "SIEM_WEB_004_XSS_ATTACK_DETECTED": "PB-03",
    "SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS": "PB-03",
    "SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT": "PB-04",
}


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
def _file_ref(path):
    return {"path": rel(path), "sha256": sha256_file(path)}


def _event(ts, quality, summary, ref, source):
    return {"ts_original": ts, "ts_quality": quality, "summary": summary, "ref": ref, "source": rel(source)}


def _first_ts_col(row):
    for k in row:
        if k and "timestamp" in k.lower():
            return k
    return None


def _ticket_index():
    idx = defaultdict(list)
    for f in sorted((WEEK3 / "SOAR" / "tickets").glob("*.json")):
        t = load_json(f)
        rule = t.get("alert_rule", "").split("/")[0]
        t["_file"] = rel(f)
        idx[rule].append(t)
    return idx


def _audit_index():
    out = {}
    for f in sorted((WEEK3 / "SOAR" / "audit").glob("*.jsonl")):
        out[f.stem] = {"file": rel(f), "lines": load_jsonl(f)}
    return out


def _siem_ai(doc, ev_path):
    ai = doc.get("ai_triage") or {}
    trig = doc.get("source_trigger") or {}
    trig_iso = micros_to_iso(trig.get("_timestamp")) if trig.get("_timestamp") else None
    gen = doc.get("generated_at_utc")
    latency = None
    if trig_iso and gen:
        a, b = parse_iso(trig_iso), parse_iso(gen)
        if a and b:
            latency = round((b - a).total_seconds(), 1)
    return {
        "model": doc.get("model"),
        "severity": ai.get("severity"),
        "confidence": ai.get("confidence"),
        "summary": ai.get("summary") or ai.get("executive_summary"),
        "qa_status": doc.get("qa_status"),
        "human_validation_required": doc.get("human_validation_required"),
        "semantic_warnings": doc.get("semantic_warnings") or [],
        "generated_at_utc": gen,
        "trigger_fired_utc": trig_iso,
        "trigger_to_ai_triage_seconds": latency,
        "trigger_key": trig.get("key"),
        "source": rel(ev_path),
    }


def _an_runs():
    runs = []
    for f in sorted(glob.glob(str(WEEK2 / "Results" / "AN-*" / "analysis.json"))):
        d = load_json(f)
        v = d.get("validation") or {}
        r = d.get("review") or {}
        m = d.get("model") or {}
        runs.append({
            "analysis_id": d.get("analysis_id"),
            "created_utc": d.get("created_utc"),
            "input_file": (d.get("input") or {}).get("filename"),
            "model": m.get("name"),
            "tokens_per_second": m.get("tokens_per_second"),
            "wall_seconds": m.get("wall_seconds"),
            "done_reason": m.get("done_reason"),
            "flags": len(v.get("flags") or []),
            "flag_checks": [fl.get("check") for fl in (v.get("flags") or [])],
            "severity_counts": v.get("severity_counts") or {},
            "review_status": r.get("status"),
            "analyst": r.get("analyst"),
            "correct_findings": len(r.get("correct_findings") or []),
            "incorrect_findings": len(r.get("incorrect_findings") or []),
            "missing_evidence": len(r.get("missing_evidence") or []),
            "hallucinations": r.get("hallucinations") or [],
            "source": rel(f),
        })
    return runs


def _case_ai_from_runs(case_id, runs):
    mine = [r for r in runs if (r["input_file"] or "").startswith(AN_INPUT_PREFIX[case_id])]
    if not mine:
        return None
    reviewed = [r for r in mine if r["review_status"] in ("Approved", "Corrected", "Rejected")]
    final = (reviewed or mine)[-1]
    return {
        "selection_rule": "latest Week-2 analysis with a recorded human review (else latest run)",
        "runs_total": len(mine),
        "runs_reviewed": len(reviewed),
        "final_analysis_id": final["analysis_id"],
        "model": final["model"],
        "tokens_per_second": final["tokens_per_second"],
        "wall_seconds": final["wall_seconds"],
        "validator_flags": final["flags"],
        "validator_severity_counts": final["severity_counts"],
        "review_status": final["review_status"],
        "analyst": final["analyst"],
        "correct_findings": final["correct_findings"],
        "incorrect_findings": final["incorrect_findings"],
        "hallucinations_recorded": len(final["hallucinations"]),
        "source": final["source"],
        "all_runs": [r["analysis_id"] for r in mine],
    }


EXCH_MGMT_LOG = WEEK2 / "Data" / "Exchange" / "msexchangemanagement.log"


def exchange_mgmt_records(names):
    """Records of the Exchange cmdlet audit log related to the given export names (read-only)."""
    text = EXCH_MGMT_LOG.read_text(encoding="utf-8-sig", errors="replace")
    recs = []
    for block in re.split(r"\n(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M\n)", text):
        ts = block.split("\n", 1)[0].strip()
        rn = re.search(r"RecordNumber=(\d+)", block)
        msg = re.search(r"Message=(.*)", block)
        host = re.search(r"ComputerName=(\S+)", block)
        if rn and msg:
            recs.append({"record": int(rn.group(1)), "ts": ts, "message": msg.group(1).strip(),
                         "host": host.group(1) if host else None,
                         "cmdlet": (re.search(r"Cmdlet ([A-Za-z]+-[A-Za-z]+)", msg.group(1)) or [None, "?"])[1]})
    recs.sort(key=lambda r: r["record"])
    return [r for r in recs if any(n in r["message"] for n in names) or "Mailbox Import Export" in r["message"]
            or (r["cmdlet"] == "Search-Mailbox" and "Administrator@attackrange.local" in r["message"])]


# --------------------------------------------------------------------------------------------
# SIEM alert cases (Week-2 OpenObserve evidence + Week-3 tickets)
# --------------------------------------------------------------------------------------------
def build_siem_cases(tickets, audits):
    cases = []

    # ---- HTTP 001 (primary evidence per Week-2 final report: SIEM05 auto alert)
    p = EVID / "SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json"
    reanalysis = EVID / "SIEM05_Controlled_AI_Reanalysis_20261023.json"
    d, ra = load_json(p), load_json(reanalysis)
    ev = d["evidence"]
    methods = ", ".join(f'{m["http_method"]} {m["http_status"]} x{m["request_count"]}' for m in ev["methods_and_statuses"])
    facts = {"source_ip": ev["source_ip"], "request_count": ev["verified_request_count"],
             "threshold": ra["detection_threshold"], "minute_utc": ev["original_minute_utc"],
             "top_path": ev["top_http_paths"][0]["http_path"],
             "request_uri": ", ".join(t["http_path"] for t in ev["top_http_paths"][:3]) + " (top paths)"}
    cases.append(_siem_case(
        "SIEM-WEB-001", d, p, [p, reanalysis], facts,
        [_event(ev["original_minute_utc"], "original_utc_minute",
                f'{ev["verified_request_count"]} HTTP requests from {ev["source_ip"]} in one minute '
                f'(threshold {ra["detection_threshold"]}); {methods}', "W001", p)],
        ev["verified_request_count"], tickets, audits,
        ["Source IP is in reserved address space (source_ip_quality.is_reserved=true)."] + list(d.get("limitations") or [])))

    # ---- SSH 002
    p = EVID / "SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json"
    d = load_json(p)
    ev = d["evidence"]
    facts = {"source_ip": ev["source_ip"], "failed_count": ev["verified_failed_password_count"],
             "threshold": ev["failure_threshold"], "username": ev["top_usernames"][0]["username"],
             "minute": ev["original_minute_no_year"], "dataset": ev["source_dataset"]}
    events = [_event(ev["original_minute_no_year"], "no_year_no_timezone",
                     f'{ev["verified_failed_password_count"]} failed passwords for {facts["username"]} from {ev["source_ip"]} '
                     f'within one minute (threshold {ev["failure_threshold"]})', "A001", p)]
    for i, s in enumerate(ev["sampled_source_lines"], 2):
        events.append(_event(s["original_datetime_no_year"], "no_year_no_timezone",
                             f'Failed password for {s["username"]} from {ev["source_ip"]} port {s["src_port"]} '
                             f'(source line {s["source_line"]})', f"A{i:03d}", p))
    cases.append(_siem_case("SIEM-AUTH-002", d, p, [p], facts, events, ev["verified_failed_password_count"],
                            tickets, audits, list(d.get("limitations") or [])))

    # ---- Malware 003
    p = EVID / "SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json"
    d = load_json(p)
    ev = d["evidence"]
    sha = imphash = None
    domains = []
    events = []
    for i, s in enumerate(ev["source_events"], 1):
        if s.get("hashes"):
            for part in s["hashes"].split(","):
                k, _, v = part.partition("=")
                if k.strip().upper() == "SHA256":
                    sha = v.strip()
                if k.strip().upper() == "IMPHASH":
                    imphash = v.strip()
        if s["event_id"] == 1:
            summ = f'Sysmon 1 process create {s["image"]} (parent {s["parent_image"]})'
        elif s["event_id"] == 22:
            summ = f'Sysmon 22 DNS query {s["query_name"]}'
            domains.append(s["query_name"])
        elif s["event_id"] == 3:
            summ = f'Sysmon 3 network connection to {s.get("destination_ip")}:{s.get("destination_port")}'
        else:
            summ = f'Sysmon {s["event_id"]} record {s["record_id"]}'
        events.append(_event(s["original_event_time_local"], "original_with_offset", summ, s["source_evidence_id"], p))
    facts = {"process_image": ev["process_image"], "parent_process": ev["parent_process"], "sha256": sha,
             "imphash": imphash, "destination_ip": ev["destination_ip"], "destination_port": ev["destination_port"],
             "dns_query_count": ev["verified_counts"]["dns_queries"], "domains": domains,
             "dataset": ev["source_dataset"]}
    cases.append(_siem_case("SIEM-MAL-003", d, p, [p], facts, events, len(ev["source_events"]),
                            tickets, audits, list(d.get("limitations") or [])))

    # ---- XSS 004 (three alert instances / three tickets)
    xs = sorted(EVID.glob("SIEM07_XSS_004_AI_Triage_*.json"))
    docs = [load_json(x) for x in xs]
    events, uris, txids = [], [], []
    for x, dd in zip(xs, docs):
        for rec in dd["evidence"]["verified_records"]:
            uris.append(rec["request_uri"])
            txids.append(rec["transaction_id"])
            events.append(_event(rec["original_event_time"], "original_with_offset",
                                 f'HTTP {rec["response_status"]} for XSS payload {rec["request_uri"]} from {rec["source_ip"]} '
                                 f'(tx {rec["transaction_id"]})', rec["transaction_id"], x))
    path_only = sorted({u.split("?")[0] for u in uris})
    facts = {"source_ip": docs[0]["evidence"]["source_ip"], "instances": len(docs), "transaction_ids": txids,
             "request_path": ", ".join(path_only), "request_uri": ", ".join(path_only)}
    cases.append(_siem_case("SIEM-WEB-004", docs[0], xs[0], xs, facts, events, len(events), tickets, audits,
                            list(docs[0]["evidence"].get("limitations") or [])))

    # ---- Exchange 005
    p = EVID / "SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json"
    hr = WEEK2 / "Results" / "SIEM_EXCHANGE_005_Human_Reviewed.json"
    d, h = load_json(p), load_json(hr)
    events, aspx, names = [], [], []
    for rec in sorted(d["correlation"]["verified_evidence"], key=lambda r: r["timestamp_source"]):
        fp = re.search(r'-FilePath "([^"]+)"', rec["message"])
        nm = re.search(r'-Name "([^"]+)"', rec["message"])
        mb = re.search(r'-Mailbox "([^"]+)"', rec["message"])
        if fp:
            aspx.append(fp.group(1))
        if nm:
            names.append(nm.group(1))
        events.append(_event(rec["timestamp_source"], "original_no_timezone",
                             f'{rec["command"]} on {rec["host"]} for {mb.group(1) if mb else "?"} '
                             f'to {fp.group(1) if fp else "?"} (record {rec["record_number"]})',
                             f'EXCH-R{rec["record_number"]}', p))
    # Related records from the full cmdlet audit log already in Week-2/Data/Exchange (not used by the Week-2 alert):
    # role assignment before each export, and removal + mailbox content deletion after it.
    mg = exchange_mgmt_records(names)
    for r in mg:
        if r["cmdlet"] == "New-MailboxExportRequest":
            continue                                    # already represented by the SIEM evidence events
        events.append(_event(r["ts"], "original_no_timezone",
                             f'[cmdlet audit log] {r["cmdlet"]} on {r["host"]} (record {r["record"]}): {r["message"][:200]}',
                             f'EXCH-R{r["record"]}', EXCH_MGMT_LOG))
    events.sort(key=lambda e: int(e["ref"].split("R")[-1]))
    facts = {"host": d["correlation"]["verified_evidence"][0]["host"], "aspx_paths": aspx, "export_names": names,
             "mailbox": "Administrator@attackrange.local" if any("Administrator@attackrange.local" in e["summary"] for e in events) else None,
             "unique_events": d["correlation"]["unique_events"],
             "removed_exports": [n for n in names if any(r["cmdlet"] == "Remove-MailboxExportRequest" and n in r["message"] for r in mg)],
             "role_assignments": sum(1 for r in mg if r["cmdlet"] == "New-ManagementRoleAssignment"),
             "content_deletions": sum(1 for r in mg if r["cmdlet"] == "Search-Mailbox" and "-DeleteContent" in r["message"])}
    c = _siem_case("SIEM-EXCH-005", d, p, [p, hr, EXCH_MGMT_LOG], facts, events, len(events), tickets, audits,
                   h.get("unverified_hypotheses", []) +
                   ["Cmdlet audit log shows the export requests were removed and Search-Mailbox -DeleteContent ran after each export; "
                    "export file creation on disk is still not shown by any log in the repository."])
    c["human_review"] = {"status": h.get("analyst_approval_status"), "disposition": h.get("disposition"),
                         "severity": h.get("severity"), "semantic_warnings": h.get("semantic_warnings", []),
                         "source": rel(hr)}
    cases.append(c)
    return cases


def _siem_case(case_id, doc, ev_path, files, facts, events, total, tickets, audits, limitations):
    rule = (doc.get("evidence") or {}).get("rule") or (doc.get("evidence") or {}).get("alert_rule") or doc.get("alert_rule")
    my_tickets = tickets.get(rule, [])
    if case_id == "SIEM-WEB-001":
        # Week-3 dispatched both SIEM04 and SIEM05 HTTP evidence; only SIEM05 has an event_id ticket.
        my_tickets = [t for t in my_tickets if t["ticket_id"].startswith("469dc3de")]
    tk = []
    for t in my_tickets:
        a = audits.get(t["ticket_id"], {})
        tk.append({
            "ticket_id": t["ticket_id"], "playbook_id": t["playbook_id"], "tier": t["tier"],
            "qa_status": t["qa_status"], "review_status": t["review_status"],
            "analyst_decision": t.get("analyst_decision"),
            "proposed_actions": [pa["action"] for pa in t.get("proposed_actions", [])],
            "proposed_detail": t.get("proposed_actions", []),
            "prohibited_actions": [pa["action"] for pa in t.get("prohibited_actions", [])],
            "prohibited_detail": t.get("prohibited_actions", []),
            "auto_actions": (a.get("lines") or [{}])[-1].get("actions_auto", []),
            "audit_lines": len(a.get("lines") or []),
            "file": t["_file"], "audit_file": a.get("file"),
        })
    ai = _siem_ai(doc, ev_path)
    return {
        "case_id": case_id, "title": TITLES[case_id], "domain": DOMAINS[case_id], "source_kind": "siem_alert",
        "detection_rule": rule, "playbook": PLAYBOOK_BY_RULE.get(rule),
        "dataset": facts.get("dataset") or (doc.get("evidence") or {}).get("stream") or doc.get("stream"),
        "evidence_files": [_file_ref(f) for f in files],
        "facts": facts, "events": events, "event_count_total": total,
        "ai": ai, "human_review": {"status": "PENDING (Week-2 REVIEW_REQUIRED; Week-3 tickets Pending Review)",
                                   "source": ai["source"]},
        "tickets": tk, "benign_control": False, "limitations": limitations,
    }


# --------------------------------------------------------------------------------------------
# Dataset cases (Week-2 real datasets + AN analyses)
# --------------------------------------------------------------------------------------------
def _timeline_rows(case_id, d):
    tl = list(d.glob(f"{case_id}-Verified-Timeline.csv"))
    if tl:
        return tl[0], load_csv(tl[0])
    return None, []


def build_dataset_case(case_id, runs):
    d = DATASET_CASE_DIRS[case_id]
    files, events, facts, total, limitations = [], [], {}, 0, []
    tl_path, rows = _timeline_rows(case_id, d)
    case_study = next(iter(d.glob(f"{case_id}-Case-Study.md")), None)
    if tl_path:
        files.append(tl_path)
    if case_study:
        files.append(case_study)

    def add(ts, q, summ, ref, src):
        events.append(_event(ts, q, summ, ref, src))

    if case_id == "LT-01":
        ips, users, kinds = Counter(), Counter(), Counter()
        for r in rows:
            kinds[r["event_type"]] += 1
            if r["source_ip_if_explicit"]:
                ips[r["source_ip_if_explicit"]] += 1
            if r["username_if_explicit"]:
                users[r["username_if_explicit"]] += 1
            add(r["timestamp_as_recorded"], "no_year_no_timezone",
                f'{r["event_type"]}' + (f' user={r["username_if_explicit"]}' if r["username_if_explicit"] else "")
                + (f' from {r["source_ip_if_explicit"]}' if r["source_ip_if_explicit"] else ""), r["evidence_id"], tl_path)
        facts = {"host": rows[0]["host"], "source_ip": ips.most_common(1)[0][0], "usernames": sorted(users),
                 "event_types": dict(kinds)}
    elif case_id == "LT-02":
        cmds = Counter()
        for r in rows:
            argv = " ".join(__import__("json").loads(r["command_argv_json"]))
            cmds[argv] += 1
            add(r["timestamp_utc"], "original_utc", f'{r["audit_record_type"]}: {argv} ({r["command_category"]})',
                r["evidence_id"], tl_path)
        facts = {"distinct_commands": len(cmds), "commands": dict(cmds)}
        limitations.append("PROCTITLE-only evidence: execution outcome, authorisation and successful escalation not established.")
    elif case_id == "LT-03":
        r = rows[0]
        add(r["timestamp_utc"], "original_utc", f'{r["image"]} (parent {r["parent_image"]}) user={r["user"]}: {r["command_line"]}',
            r["evidence_ref"], tl_path)
        facts = {"host": r["host"], "user": r["user"], "target_ip": r["command_target_ip"],
                 "target_port": r["command_target_port"], "command_line": r["command_line"], "process_guid": r["process_guid"]}
        limitations.append("Network success, interactive access and intent are unconfirmed (network_outcome=unknown).")
    elif case_id == "LT-04":
        progs = Counter()
        for r in rows:
            progs[r["program"]] += 1
            add(r["timestamp_as_recorded_year_and_timezone_unknown"], "no_year_no_timezone",
                f'{r["program"]}: {r["event_message"].strip()}', r["evidence_ref"], tl_path)
        facts = {"host": rows[0]["host"], "programs": dict(progs)}
    elif case_id in ("NT-01", "NT-02", "NT-03"):
        stats_path = d / f"{case_id}-Verified-Full-Source-Statistics.json"
        st = load_json(stats_path)
        files.append(stats_path)
        if case_id == "NT-01":
            for r in rows:
                add(r["Timestamp UTC"], "original_utc",
                    f'{r["Protocol"]} {r["Source IP"]}:{r["Source Port"]} -> {r["Destination IP"]}:{r["Destination Port"]} {r["Connection State"]}',
                    r["Evidence Ref"], tl_path)
            facts = {"scanner_ip": st["scan_src_ip"], "target_ip": st["scan_dst_ip"],
                     "distinct_ports": st["scan_pair_distinct_destination_ports"],
                     "tcp_records": st["scan_pair_tcp_records"], "rej": st["scan_pair_connection_states"].get("REJ"),
                     "start_utc": st["scan_pair_utc_start"], "end_utc": st["scan_pair_utc_end"]}
            total = st["source_connections"]
        elif case_id == "NT-02":
            for r in rows:
                add(r["Timestamp UTC"], "original_utc",
                    f'DNS {r["Query Type"]} {r["DNS Query"]} {r["Client IP"]} -> {r["Resolver IP"]} rcode={r["Response Code"]}',
                    r["Evidence Ref"], tl_path)
            facts = {"client_ip": st["cluster_src"], "resolver_ip": st["cluster_dst"], "pattern": st["cluster_query_pattern"],
                     "burst_count": st["cluster_record_count"], "burst_seconds": st["cluster_duration_seconds"],
                     "zone": st["cluster_query_pattern"].split(".", 1)[1],
                     "context_values": sorted({pair.split("->")[1].strip() for pair in st["source_client_resolver_pairs"]}
                                              - {st["cluster_dst"]})}
            total = st["source_total_dns_records"]
            limitations += st.get("uncertainties", [])
        else:
            for r in rows:
                add(r["timestamp_utc"], "original_utc",
                    f'{r["protocol"]} {r["src_ip"]}:{r["src_port"]} -> {r["dst_ip"]}:{r["dst_port"]} {r["conn_state"]} '
                    f'bytes {r["orig_bytes"]}/{r["resp_bytes"]}', r["evidence_ref"], tl_path)
            facts = {"src_ip": st["target_src_ip"], "dst_ip": st["target_dst_ip"], "dst_port": st["target_dst_port"],
                     "connection_records": st["target_connection_records"],
                     "port_reuse_groups": st["target_source_port_reuse_group_count"]}
            total = st["total_original_connection_records"]
    elif case_id in ("RT-01", "RT-02"):
        for r in rows:
            add(r["timestamp_utc"], "original_utc", f'Event {r["event_id"]} on {r["host"]}: {r["event_summary"]}',
                r["original_ref"], tl_path)
        facts = {"host": rows[0]["host"]}
        if case_id == "RT-01":
            m = re.search(r"process creation: (\S+plink\.exe)", " ".join(r["event_summary"] for r in rows), re.I)
            facts["tool_path"] = m.group(1) if m else None
            facts["destinations"] = sorted({x for x in re.findall(r"destination (\S+)", " ".join(r["event_summary"] for r in rows))})
        else:
            m = re.search(r"account: (\S+)", rows[0]["event_summary"])
            facts["account"] = m.group(1) if m else None
            facts["source_ip"] = sorted(set(re.findall(r"source (\d+\.\d+\.\d+\.\d+)", " ".join(r["event_summary"] for r in rows))))[0]
            facts["shares"] = [re.search(r"\): (\w+),", r["event_summary"]).group(1) for r in rows if r["event_id"] == "5145"]
    elif case_id == "RT-03":
        for r in rows:
            add(r["Timestamp (original UTC)"], "original_utc", f'Sysmon {r["Event ID"]} on {r["Host"]}: {r["Image"]}',
                r["Evidence"], tl_path)
        facts = {"host": rows[0]["Host"], "images": [r["Image"] for r in rows]}
    elif case_id == "RT-04":
        payload = regkey = dropper = None
        for r in rows:
            sid = r["Sysmon Event ID"]
            if sid == "1":
                s = f'Sysmon 1 process create {r["Image"]} (parent {r["ParentImage"]})'
                if dropper is None:
                    dropper = r["Image"]
            elif sid == "11":
                s = f'Sysmon 11 file create {r["TargetFilename"]} by {r["Image"]}'
                payload = r["TargetFilename"]
            elif sid == "13":
                s = f'Sysmon 13 registry set {r["TargetObject"]} = {r["Details"]}'
                regkey = r["TargetObject"]
            else:
                s = f'Sysmon {sid}'
            add(r["Timestamp (original UTC)"], "original_utc", s, r["Original Evidence"], tl_path)
        facts = {"host": rows[0]["Host"], "payload_path": payload, "registry_key": regkey, "dropper": dropper}
    elif case_id.startswith("BT-"):
        fj = d / f"{case_id}-focused.json"
        files.append(fj)
        data = load_json(fj)
        imgs = Counter()
        for i, e in enumerate(data, 1):
            ed = e.get("event_data") or {}
            what = ed.get("Image") or ed.get("param1") or ed.get("TargetUserName") or ""
            if ed.get("Image"):
                imgs[ed["Image"]] += 1
            add(e["timestamp"], "original_utc", f'{e.get("provider", "")} Event {e["event_id"]} on {e["computer"]} {what}'.strip(),
                f"E{i:03d}", fj)
        facts = {"host": data[0]["computer"], "event_ids": sorted({str(e["event_id"]) for e in data}), "images": dict(imgs)}
        limitations.append("Benign candidate only: approved/benign operation is not independently proven.")

    total = total or len(events)
    ai = _case_ai_from_runs(case_id, runs)
    return {
        "case_id": case_id, "title": TITLES[case_id], "domain": DOMAINS[case_id], "source_kind": "dataset_case",
        "detection_rule": None, "playbook": None, "dataset": rel(d),
        "evidence_files": [_file_ref(f) for f in files],
        "facts": facts, "events": events, "event_count_total": total,
        "ai": ai,
        "human_review": {"status": ai["review_status"] if ai else "NO ANALYSIS FOUND", "analyst": ai["analyst"] if ai else None,
                         "source": ai["source"] if ai else None},
        "tickets": [], "benign_control": case_id.startswith("BT-") or case_id == "LT-04",
        "limitations": limitations,
    }


# --------------------------------------------------------------------------------------------
# Observables & cross-case overlaps
# --------------------------------------------------------------------------------------------
WINDOWS_BUILTIN = {"cmd.exe", "explorer.exe", "userinit.exe", "winlogon.exe", "ipconfig.exe", "winrshost.exe",
                   "mscorsvw.exe", "svchost.exe", "services.exe", "lsass.exe", "powershell.exe"}


def build_observables(cases):
    """Extract observables from verified event summaries + facts using the Week-2 IOC extractor.

    role = "indicator"  -> value that is specific to the suspicious activity (IP, domain, hash, payload file)
    role = "context"    -> lab asset hostnames, OS built-in binaries, benign-control values
    """
    obs = {}
    for c in cases:
        text = "\n".join(e["summary"] for e in c["events"])
        fx = c["facts"]
        extra = []
        for k in ("sha256", "imphash"):
            if fx.get(k):
                extra.append(fx[k])
        for k in ("domains", "aspx_paths"):
            extra += fx.get(k) or []
        blob = text + "\n" + "\n".join(map(str, extra))
        found = extract_iocs(blob)
        for kind, vals in found.items():
            for v in vals:
                if kind == "domain" and not _keep_domain(v, blob):
                    continue
                t = kind
                if kind == "hash":
                    t = "sha256" if len(v) == 64 else ("imphash" if fx.get("imphash", "").lower() == v.lower() else "md5/imphash")
                key = (t, v.lower())
                o = obs.setdefault(key, {"type": t, "value": v, "cases": set(), "scope": None, "role": None,
                                         "reputation": "not checked (no live threat-intelligence feed in lab)"})
                o["cases"].add(c["case_id"])
                if t == "ipv4":
                    o["scope"] = _scope(v)
    benign = {c["case_id"] for c in cases if c["benign_control"]}
    hosts = set()
    for c in cases:
        if c["facts"].get("host"):
            hosts.add(str(c["facts"]["host"]).lower())
        hosts.update(str(x).lower() for x in c["facts"].get("context_values", []))
    out = []
    for o in obs.values():
        o["cases"] = sorted(o["cases"])
        v = o["value"].lower()
        if set(o["cases"]) <= benign or v in WINDOWS_BUILTIN or v in hosts or v.endswith((".local", ".corp")) \
                or (o["type"] == "domain" and v.endswith(".ubuntu.com")):
            o["role"] = "context"
        else:
            o["role"] = "indicator"
        out.append(o)
    out.sort(key=lambda o: (o["role"] != "indicator", -len(o["cases"]), o["type"], o["value"]))
    return out


def _scope(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if a.is_reserved:
        return "reserved (240.0.0.0/4) - not routable"
    return ip_scope(ip)


def _keep_domain(v, blob):
    low = v.lower()
    if low.endswith((".service", ".socket", ".target")):
        return False                       # systemd unit names, not domains
    if re.search(r"\\" + re.escape(low), blob.lower()):
        return False                       # part of a Windows path (e.g. Microsoft.NET\Framework)
    return not re.fullmatch(r"[\w-]+\.(php|gif|css|js|ico)", v, re.I)


def overlaps(observables):
    return [o for o in observables if len(o["cases"]) > 1]


# --------------------------------------------------------------------------------------------
# Week-1 / Week-2 quality summaries (for the dashboard + lessons learned)
# --------------------------------------------------------------------------------------------
def week1_benchmark():
    base = WEEK1 / "Benchmarks" / "results"
    baseline = base / "run_20261016_061045"
    summ = load_csv(baseline / "summary.csv")
    rows = load_csv(baseline / "results.csv")
    extra_rows = load_csv(WEEK1 / "Testing" / "Additional-6-Manual-Review.csv")
    retry_runs = {"mistral": base / "run_20261016_063533", "phi3": base / "run_20261016_063843"}
    for name, rd in retry_runs.items():
        for r in load_csv(rd / "results.csv"):
            rows.append(r)
    models = {}
    for s in summ:
        models[s["model"]] = {
            "model": s["model"], "baseline_runs": int(s["runs"]), "avg_wall_time_s": float(s["avg_wall_time_s"]),
            "avg_tokens_per_sec": float(s["avg_tokens_per_sec"]), "avg_auto_recall": float(s["avg_auto_recall"]),
            "vram_gb": float(s["vram_gb"]), "gpu_offload_pct": float(s["gpu_offload_pct"]),
            "manual_quality": [], "manual_unsupported_severity": [],
        }
    for r in rows:
        m = models.get(r["model"])
        if m is None:
            continue
        if r.get("manual_quality_1to5"):
            m["manual_quality"].append(float(r["manual_quality_1to5"]))
        if r.get("manual_hallucination_0to3"):
            m["manual_unsupported_severity"].append(float(r["manual_hallucination_0to3"]))
    for r in extra_rows:
        m = models.get(r["model"])
        if m is None:
            continue
        m["manual_quality"].append(float(r["manual_quality_1to5"]))
        m["manual_unsupported_severity"].append(float(r["unsupported_fact_severity_0to3"]))
    for m in models.values():
        q, h = m.pop("manual_quality"), m.pop("manual_unsupported_severity")
        m["manual_reviews"] = len(q)
        m["manual_quality_mean"] = round(sum(q) / len(q), 2) if q else None
        m["manual_unsupported_severity_mean"] = round(sum(h) / len(h), 2) if h else None
    return {"models": list(models.values()), "selected_model": "mistral:7b-instruct-v0.3-q4_K_S",
            "sources": [rel(baseline / "summary.csv"), rel(baseline / "results.csv"),
                        rel(WEEK1 / "Testing" / "Additional-6-Manual-Review.csv")] + [rel(p / "results.csv") for p in retry_runs.values()],
            "note": "Manual quality = human review score (1-5). Automatic recall is a keyword check and is NOT accuracy (Week-1 finding)."}


def week2_quality(runs):
    status = Counter(r["review_status"] for r in runs)
    sev = Counter()
    checks = Counter()
    for r in runs:
        for k, v in (r["severity_counts"] or {}).items():
            sev[k] += v
        checks.update(r["flag_checks"])
    reviewed = [r for r in runs if r["review_status"] in ("Approved", "Corrected", "Rejected")]
    tps = [r["tokens_per_second"] for r in runs if r["tokens_per_second"]]
    wall = [r["wall_seconds"] for r in runs if r["wall_seconds"]]
    return {
        "analysis_runs": len(runs),
        "review_status_counts": dict(status),
        "validator_flags_total": sum(r["flags"] for r in runs),
        "validator_flags_by_severity": dict(sev),
        "top_flag_checks": checks.most_common(8),
        "reviewed_runs": len(reviewed),
        "analyst_correct_findings": sum(r["correct_findings"] for r in reviewed),
        "analyst_incorrect_findings": sum(r["incorrect_findings"] for r in reviewed),
        "analyst_missing_evidence_items": sum(r["missing_evidence"] for r in reviewed),
        "reviewed_runs_corrected": status.get("Corrected", 0),
        "reviewed_runs_approved": status.get("Approved", 0),
        "mean_tokens_per_second": round(sum(tps) / len(tps), 2) if tps else None,
        "mean_wall_seconds": round(sum(wall) / len(wall), 1) if wall else None,
        "source": "Week-2/Results/AN-*/analysis.json",
    }


# --------------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------------
def build():
    scenario = load_config("scenario.json")
    mapping = load_config("attack_mapping.json")["mapping"]
    tickets, audits = _ticket_index(), _audit_index()
    runs = _an_runs()

    cases = build_siem_cases(tickets, audits)
    for cid in DATASET_CASE_DIRS:
        cases.append(build_dataset_case(cid, runs))
    by_id = {c["case_id"]: c for c in cases}

    for c in cases:
        c["attack"] = mapping.get(c["case_id"], [])

    stage_of = {}
    for st in scenario["stages"]:
        for cid in st["case_ids"]:
            if cid not in by_id:
                raise SystemExit(f"scenario.json references unknown case {cid}")
            stage_of[cid] = st["stage_id"]
    for cid in scenario["false_positive_controls"]["case_ids"]:
        stage_of[cid] = "FP"
    for c in cases:
        c["stage_id"] = stage_of.get(c["case_id"])

    observables = build_observables(cases)

    # Scenario timeline: stage order, then case order inside the stage, then source order.
    timeline = []
    seq = 0
    for st in sorted(scenario["stages"], key=lambda s: s["order"]):
        for cid in st["case_ids"]:
            for e in by_id[cid]["events"]:
                seq += 1
                timeline.append({"seq": seq, "stage_id": st["stage_id"], "stage": st["name"], "domain": st["domain"],
                                 "case_id": cid, **e})

    latencies = [c["ai"]["trigger_to_ai_triage_seconds"] for c in cases
                 if c["source_kind"] == "siem_alert" and c["ai"].get("trigger_to_ai_triage_seconds") is not None]
    model = {
        "generated_at_utc": utcnow_iso(),
        "generator": "Week-4/IR/correlate.py",
        "scenario": scenario,
        "cases": cases,
        "observables": observables,
        "cross_case_overlaps": overlaps(observables),
        "timeline_events": len(timeline),
        "week1_benchmark": week1_benchmark(),
        "week2_quality": week2_quality(runs),
        "week2_siem_trigger_to_triage_seconds": {
            "values": latencies,
            "mean": round(sum(latencies) / len(latencies), 1) if latencies else None,
            "note": "OpenObserve trigger _timestamp -> receiver generated_at_utc, read from Week-2 evidence JSON (historical replay)."},
    }
    write_json(OUTPUT_DIR / "incident.json", model)
    write_csv(OUTPUT_DIR / "incident_timeline.csv", timeline,
              ["seq", "stage_id", "stage", "domain", "case_id", "ts_original", "ts_quality", "summary", "ref", "source"])
    write_csv(OUTPUT_DIR / "observables.csv",
              [{**o, "cases": ";".join(o["cases"])} for o in observables],
              ["type", "value", "cases", "scope", "reputation"])
    return model


if __name__ == "__main__":
    m = build()
    print(f"cases={len(m['cases'])} timeline_events={m['timeline_events']} observables={len(m['observables'])} "
          f"overlaps={len(m['cross_case_overlaps'])}")
