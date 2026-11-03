"""Alert triage helpers: select alert units, describe them deterministically, parse the AI triage
sections into a structured record, and run consistency checks. The AI only RECOMMENDS."""
import hashlib
import re

from Core import validator

CLASSIFICATIONS = ["Likely True Positive", "Likely False Positive", "Needs Investigation"]
PRIORITIES = ["P1 Critical", "P2 High", "P3 Medium", "P4 Low"]


def alert_units(parsed):
    """Return a list of (label, [events]). Alerts are individual units; plain logs are one unit."""
    evs = parsed["events"]
    if parsed["format"] == "alert_text" or all(e["source_kind"] == "wazuh" for e in evs):
        return [(describe_alert([e])["description"], [e]) for e in evs]
    if any(e["source_kind"] == "wazuh" for e in evs):
        return [(describe_alert([e])["description"], [e]) for e in evs if e["source_kind"] == "wazuh"]
    return [(f"Whole file: {parsed['name']} ({len(evs)} events)", evs)]


def describe_alert(events):
    """Deterministic alert metadata taken from the data (never from the AI)."""
    e = events[0]
    m = e.get("meta", {})
    if e["source_kind"] == "wazuh":
        aid = m.get("alert_id")
        sev = {"value": m.get("rule_level"), "source_field": "rule.level"} if m.get("rule_level") is not None else {"value": None, "source_field": None}
        desc = m.get("rule_description") or "Not provided"
    elif m.get("alert_title") is not None:
        aid = None
        sev = {"value": m.get("original_severity"), "source_field": "Severity (SIEM)"}
        desc = m.get("alert_title")
    else:
        aid, sev, desc = None, {"value": None, "source_field": None}, f"{len(events)} log event(s), no SIEM alert wrapper"
    if len(events) > 1:
        id_value, id_source = "DERIVED-" + hashlib.sha256("".join(x["raw"] for x in events).encode()).hexdigest()[:10], "derived_sha256_of_raw"
    elif aid:
        id_value, id_source = str(aid), "wazuh_alert_id_field"
    else:
        id_value, id_source = "DERIVED-" + hashlib.sha256(e["raw"].encode()).hexdigest()[:10], "derived_sha256_of_raw"
    return {"alert_id": id_value, "alert_id_source": id_source, "description": desc,
            "original_severity": sev, "event_refs": [x["ref"] for x in events]}


def _bullets(text):
    out = []
    for ln in text.splitlines():
        s = re.sub(r'^\s*(?:[-*\u2022]|\d+[.)])\s*', '', ln).strip()
        if s:
            out.append(s)
    return out


def parse_triage(sections, events):
    t = describe_alert(events)
    warnings = []

    def one_of(section, allowed):
        body = sections.get(section, "")
        found = [a for a in allowed if re.search(re.escape(a), body, re.I)]
        if len(found) == 1:
            return found[0]
        warnings.append(f"{section}: expected exactly one of {allowed}; found {len(found)}. Analyst must set it.")
        return None

    t["recommended_classification"] = one_of("VERDICT", CLASSIFICATIONS)
    pri_body = sections.get("PRIORITY", "")
    codes = sorted(set(re.findall(r'\bP[1-4]\b', pri_body)))
    if len(codes) == 1:
        t["recommended_priority"] = next(p for p in PRIORITIES if p.startswith(codes[0]))
    else:
        t["recommended_priority"] = None
        warnings.append(f"PRIORITY: expected exactly one of P1-P4; found {len(codes)}. Analyst must set it.")
    t["confidence"] = sections.get("CONFIDENCE", "").strip().splitlines()[0] if sections.get("CONFIDENCE", "").strip() else None
    t["summary"] = sections.get("ALERT SUMMARY", "").strip()
    t["evidence_malicious"] = _bullets(sections.get("EVIDENCE SUPPORTING MALICIOUS ACTIVITY", ""))
    t["evidence_benign"] = _bullets(sections.get("EVIDENCE SUPPORTING BENIGN ACTIVITY", ""))
    t["ai_listed_iocs"] = _bullets(sections.get("RELEVANT IOCS", ""))
    t["missing_information"] = _bullets(sections.get("MISSING INFORMATION", ""))
    esc = sections.get("ESCALATION", "").strip()
    m = re.match(r'\W*(yes|no)\b', esc, re.I)
    t["escalation"] = {"recommended": m.group(1).capitalize() if m else None, "reason": esc}
    if not m:
        warnings.append("ESCALATION: could not read Yes/No. Analyst must decide.")
    t["analyst_actions"] = _bullets(sections.get("ANALYST ACTIONS", ""))
    t["human_review_status"] = "Pending Review"
    t["parse_warnings"] = warnings
    return t


def triage_flags(triage, events):
    flags = []
    sig = validator.risk_signals(events)
    ben = validator.benign_context(events)
    cls, pri = triage.get("recommended_classification"), triage.get("recommended_priority")

    def add(check, sev, value, msg):
        flags.append({"check": check, "severity": sev, "section": "TRIAGE", "value": value, "message": msg, "analyst_disposition": "Unreviewed"})

    for w in triage.get("parse_warnings", []):
        add("triage_unparsed_field", "medium", w[:100], w)
    if cls == "Likely False Positive" and sig:
        add("fp_verdict_vs_signals", "high", "; ".join(sorted({s['label'] for s in sig})[:4]),
            "Verdict is Likely False Positive but code detected risk signals in the data. Analyst must verify.")
    if cls == "Likely False Positive" and pri in ("P1 Critical", "P2 High"):
        add("verdict_priority_inconsistent", "medium", f"{cls} / {pri}", "False-positive verdict with high priority is inconsistent.")
    if cls == "Likely True Positive" and pri == "P4 Low":
        add("verdict_priority_inconsistent", "medium", f"{cls} / {pri}", "True-positive verdict with lowest priority is inconsistent.")
    if ben and not [b for b in triage.get("evidence_benign", []) if b.lower() not in ("none", "none.")]:
        add("benign_context_not_acknowledged", "medium", "; ".join(sorted({b['label'] for b in ben})[:3]),
            "Data contains approved/authorized/maintenance context but the benign-evidence section is empty.")
    sev = triage["original_severity"]["value"]
    try:
        if sev is not None and int(sev) >= 12 and pri == "P4 Low":
            add("priority_far_below_siem_severity", "low", f"rule.level {sev} vs {pri}", "AI priority is far below the original SIEM level; the analyst should confirm the reasoning.")
    except (TypeError, ValueError):
        pass
    return flags
