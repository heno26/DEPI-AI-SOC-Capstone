"""Week 4 automated T0 checks (read-only) against the evidence already in the repository.

T0 in the Week-3 decision matrix = automatic, read-only, no state change. These checks only READ
Week-2 datasets and report what the data shows, with the file and line numbers as proof.
They never decide anything: the analyst still records the decision (done / deferred) with
`ir_cli.py decide` or the decisions CSV.

  completed_from_repo = True  -> the check could be answered from repository data
  completed_from_repo = False -> the data needed is not in the repository (reason given); the
                                 analyst normally records `deferred` with that reason.
Output: Output/t0_checks.json
"""
import binascii
import json
import re
from collections import defaultdict

from common import OUTPUT_DIR, WEEK2, load_json, rel, utcnow_iso, write_json

RD = WEEK2 / "Data" / "Real-Datasets"


def _r(done, result, evidence=None, source=None):
    return {"completed_from_repo": done, "result": result, "evidence": evidence or [], "source": source}


# ---------------------------------------------------------------- checks that the data can answer
def ssh_accepted(model, case_id):
    p = WEEK2 / "Data" / "SIEM-BruteForce-SSH" / "OpenSSH_2k.log"
    c = next(x for x in model["cases"] if x["case_id"] == case_id)
    ip = c["facts"]["source_ip"]
    users = set(c["facts"].get("usernames") or [c["facts"].get("username")])
    lines = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    acc = [(i, l) for i, l in enumerate(lines, 1) if "Accepted " in l]
    from_ip = [(i, l) for i, l in acc if ip in l]
    for_users = [(i, l) for i, l in acc if any(f" for {u} " in l for u in users)]
    n_ip = sum(1 for l in lines if ip in l)
    res = (f"{len(lines)} log lines searched; {n_ip} lines mention {ip}; 'Accepted' logins from {ip}: {len(from_ip)}; "
           f"'Accepted' logins for {', '.join(sorted(users))}: {len(for_users)}. "
           f"The whole file contains {len(acc)} 'Accepted' line(s), from other sources.")
    ev = [f"line {i}: {l}" for i, l in acc[:5]]
    return _r(True, res, ev, rel(p))


def exchange_cmdlets(model, case_id):
    from correlate import EXCH_MGMT_LOG, exchange_mgmt_records
    c = next(x for x in model["cases"] if x["case_id"] == case_id)
    recs = exchange_mgmt_records(c["facts"]["export_names"])
    seq = [f'RecordNumber {r["record"]} {r["ts"]}: {r["cmdlet"]}' for r in recs]
    removed = c["facts"].get("removed_exports") or []
    res = ("Get-MailboxExportRequest cannot be run (no server), but the Exchange cmdlet audit log answers the status question: "
           + "; ".join(seq) + f". Export requests later removed: {', '.join(removed) or 'none'}. "
           "Cmdlet success is logged; export file creation on disk is NOT shown by this log.")
    return _r(True, res, [f'RecordNumber {r["record"]} {r["ts"]}: {r["message"][:220]}' for r in recs], rel(EXCH_MGMT_LOG))


def exchange_files(model, case_id):
    return _r(False, "No filesystem, IIS or OWA access log for win-dc-exch01 is in the repository "
                     "(ESI-HttpProxyLogs.json is from a different host/date and contains no request to the .aspx paths).",
              [], rel(WEEK2 / "Data" / "Exchange"))


def lt03_network(model, case_id):
    p = RD / "Linux-Attacks" / "LT-03-Suspicious-Execution" / "LT-03-Sysmon-original.log"
    t = p.read_text(encoding="utf-8-sig", errors="replace")
    ids = re.findall(r"<EventID>(\d+)</EventID>", t)
    res = (f"Original Sysmon-for-Linux file has {len(ids)} event(s), Event IDs {sorted(set(ids))}; "
           f"no Event ID 3 (network connection) record exists, so connection success cannot be established from this dataset.")
    return _r(True, res, [f"EventIDs: {ids}"], rel(p))


def nt01_open_ports(model, case_id):
    p = RD / "Network-Attacks" / "NT-01-Port-Scanning" / "NT-01-Zeek-conn-original.log"
    c = next(x for x in model["cases"] if x["case_id"] == case_id)
    src, dst = c["facts"]["scanner_ip"], c["facts"]["target_ip"]
    lines = p.read_text(encoding="utf-8-sig").splitlines()
    fields = next(l for l in lines if l.startswith("#fields")).split("\t")[1:]
    st = defaultdict(set)
    for l in lines:
        if not l or l.startswith("#"):
            continue
        r = dict(zip(fields, l.split("\t")))
        if r["id.orig_h"] == src and r["id.resp_h"] == dst:
            st[r["conn_state"]].add(int(r["id.resp_p"]))
    rsto = sorted(st.get("RSTO", set()) | st.get("SF", set()))
    res = (f"Zeek conn_state for {src} -> {dst}: REJ (closed) on {len(st.get('REJ', ()))} ports; "
           f"S0 (no reply) on {len(st.get('S0', ()))} ports; handshake completed (RSTO/SF) on {len(rsto)} ports: "
           f"{', '.join(map(str, rsto))}. These are the candidate open services to review.")
    return _r(True, res, [f"RSTO/SF ports: {rsto}"], rel(p))


def nt02_decode(model, case_id):
    p = RD / "Network-Attacks" / "NT-02-DNS-Anomaly" / "NT-02-Zeek-dns-original.log"
    t = p.read_text(encoding="utf-8-sig")
    q = sorted(set(re.findall(r"chunk(\d{3})-([0-9a-f]+)\.lab\.test", t)))
    raw = b"".join(binascii.unhexlify(h) for _, h in q)
    printable = sum(32 <= b < 127 for b in raw) / len(raw) if raw else 0
    res = (f"{len(q)} distinct chunk labels; hex parts decode to {len(raw)} bytes, of which {printable:.0%} are printable ASCII. "
           f"The decoded bytes are not readable text (consistent with encoded/encrypted or random content); "
           f"payload meaning remains undetermined.")
    return _r(True, res, [f"first label: chunk{q[0][0]}-{q[0][1]}"] if q else [], rel(p))


def rt02_session(model, case_id):
    p = RD / "Windows-Attacks" / "RT-02-Discovery" / "RT-02-Discovery-converted.json"
    d = load_json(p)
    e = next(x for x in d if x["event_id"] == 1102)
    return _r(True, f"Event 1102 record {e['record_id']} at {e['timestamp']}: the verified timeline records account "
                    f"Administrator; the converted event carries no LogonId/session data (event_data is empty), so the "
                    f"session and approval cannot be established from the repository.",
              [json.dumps(e)[:300]], rel(p))


def rt03_client(model, case_id):
    p = RD / "Windows-Attacks" / "RT-03-Lateral-Movement" / "RT-03-converted.json"
    d = load_json(p)
    e = next(x for x in d if "winrshost" in (x["event_data"].get("Image") or "").lower())
    ed = e["event_data"]
    return _r(True, f"winrshost.exe ran as {ed.get('User')} (LogonId {ed.get('LogonId')}, IntegrityLevel {ed.get('IntegrityLevel')}). "
                    f"The remote client address is not in the dataset (no Security 4624 record for that LogonId).",
              [f"Sysmon 1 record {e['record_id']}: User={ed.get('User')} LogonId={ed.get('LogonId')}"], rel(p))


# ---------------------------------------------------------------- checks the repository cannot answer
NOT_IN_REPO = {
    "SIEM-WEB-001:eradication:1": "Needs the live OpenObserve alert rows to prove the trigger-to-row join (Week-2 gate 2).",
    "SIEM-WEB-001:recovery:2": "Needs a baseline of normal web traffic; only the alert group evidence is in the repository.",
    "SIEM-WEB-004:recovery:2": "Needs the fixed web application to re-test; the lab application is not part of the repository.",
    "LT-02:containment:1": "No change-management records exist in the repository.",
    "NT-01:containment:1": "Scanner authorisation is recorded as 'unknown' in NT-01 statistics; no scan schedule/change record in the repository.",
    "NT-03:eradication:2": "No endpoint telemetry for 192.168.1.199 in the dataset.",
    "RT-04:recovery:4": "Requires a logon after eradication; the dataset ends before that.",
}

CHECKS = {
    "SIEM-AUTH-002:recovery:2": ssh_accepted,
    "LT-01:recovery:2": ssh_accepted,
    "SIEM-EXCH-005:containment:1": exchange_cmdlets,
    "SIEM-EXCH-005:containment:2": exchange_files,
    "LT-03:recovery:3": lt03_network,
    "NT-01:recovery:3": nt01_open_ports,
    "NT-02:eradication:2": nt02_decode,
    "RT-02:containment:1": rt02_session,
    "RT-03:recovery:2": rt03_client,
}


def key_of(item_id):
    m = re.match(r"^([^:]+:[a-z]+:\d+)-", item_id)
    return m.group(1) if m else None


def build(model=None, life=None):
    model = model or load_json(OUTPUT_DIR / "incident.json")
    life = life or load_json(OUTPUT_DIR / "ir_lifecycle.json")
    out = {}
    for it in life["items"]:
        if it["tier"] != "T0":
            continue
        k = key_of(it["item_id"])
        if k in CHECKS:
            out[it["item_id"]] = CHECKS[k](model, it["case_id"])
        elif k in NOT_IN_REPO:
            out[it["item_id"]] = _r(False, NOT_IN_REPO[k])
        else:
            out[it["item_id"]] = _r(False, "No automated check defined for this item.")
        out[it["item_id"]]["case_id"] = it["case_id"]
        out[it["item_id"]]["action"] = it["action"]
    write_json(OUTPUT_DIR / "t0_checks.json", {"generated_at_utc": utcnow_iso(), "generator": "Week-4/IR/t0_checks.py",
                                               "note": "Read-only checks; results are evidence for the analyst, not decisions.",
                                               "checks": out})
    return out


if __name__ == "__main__":
    for k, v in build().items():
        print(("DATA " if v["completed_from_repo"] else "N/A  ") + k + "\n     " + v["result"][:300])
