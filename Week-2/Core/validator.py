"""Deterministic validation of AI output against the original evidence.

IMPORTANT: every flag is a REQUEST FOR HUMAN REVIEW, not proof of hallucination, and passing all
checks is NOT proof the analysis is correct. Keyword/string checks cannot verify semantics.
"""
import json
import ipaddress
import re

IP_CAND_RE = re.compile(r'(?<![\w.])\d{1,6}(?:\.\d{1,6}){2,3}(?![\w]|\.\d)')
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b', re.I)
URL_RE = re.compile(r'(?:https?|hxxps?|ftp)://[^\s<>"\'`)\]]+', re.I)
HASH_RE = re.compile(r'\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b')
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
FILE_RE = re.compile(r'\b[\w][\w.\-]*\.(?:exe|dll|ps1|bat|cmd|sh|msi|html?|js|vbs|zip|docm|xlsm|docx?|xlsx?|py|jar|lnk|iso|scr|sys)\b', re.I)
REF_RE = re.compile(r'\bE\d{3,5}\b')
DATE_RE = re.compile(r'\b\d{4,5}-\d{1,3}-\d{1,3}\b')
TIME_RE = re.compile(r'\b\d{1,2}:\d{2}:\d{2}\b')
FILE_EXTS = {"sh", "exe", "dll", "msi", "html", "htm", "txt", "log", "json", "csv", "ps1", "bat", "cmd", "py", "js", "doc",
             "docx", "xls", "xlsx", "pdf", "zip", "gz", "conf", "cfg", "xml", "yaml", "yml", "ini", "tmp", "dat", "bin",
             "so", "sys", "lnk", "vbs", "jar", "png", "jpg", "md", "sql", "php", "asp", "aspx", "pl", "rb", "go", "iso", "scr"}
ATTRIBUTION_RE = re.compile(r'\b(apt\s?-?\d+|lazarus|fin\d+|cobalt strike|mimikatz|metasploit|emotet|qakbot|trickbot|mirai|'
                            r'ransomware|scattered spider|lockbit|conti|ryuk|sandworm|turla|kimsuky|darkside|revil|agent tesla)\b', re.I)
CERTAINTY_RE = re.compile(r'(confirmed (?:breach|compromise|exfiltration|data (?:theft|loss|breach)|credential theft|lateral movement|malware)|'
                          r'successfully exploited|was exfiltrated|data was stolen|attacker (?:gained|successfully)|'
                          r'(?:script|payload|file) (?:was |has been )?executed|downloads? and (?:runs?|executes?)|downloaded and (?:run|executed)|'
                          r'malware (?:was )?(?:installed|executed))', re.I)
NEGATION_RE = re.compile(r'\b(no|not|without|cannot|can\'t|unconfirmed|no evidence|if|may|might|could|possible|potential|'
                         r'suspected|verify|whether|unknown|would)\b', re.I)
NONE_CLAIM_RE = re.compile(r'(none identified|no suspicious|nothing suspicious|no evidence of (?:malicious|suspicious)|not suspicious)', re.I)
INJECTION_RE = re.compile(r'(ignore (?:all |any )?(?:previous|prior|above) (?:instructions|rules)|disregard (?:the )?(?:above|previous|system)|'
                          r'you are now|new instructions:|system prompt|act as|respond only with|do not (?:flag|report|escalate))', re.I)
HOST_TOKEN_RE = re.compile(r'\b(?:[A-Za-z]+-)*[A-Za-z]{2,}\d{1,3}\b')
HOST_ALLOW = {"ssh2", "sha1", "sha256", "sha512", "md5", "http2", "tls1", "base64", "x509", "win32", "win64", "ipv4", "ipv6",
              "p1", "p2", "p3", "p4", "utf8", "sha384", "tcp443", "udp53", "port22", "t1566"}

PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def refang(text):
    t = text
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@"), ("[at]", "@")):
        t = t.replace(a, b)
    t = re.sub(r'\bhxxp(s?)', r'http\1', t, flags=re.I)
    return t


def defanged_tokens(text):
    """Defanged indicators and their host part (e.g. hxxps://a[.]b/c -> also a[.]b)."""
    t = re.sub(r'[="\'<>,;]', ' ', text)
    out = set()
    for tok in re.findall(r'\S*(?:\[\.\]|\(\.\)|\{\.\}|hxxp)\S*', t, flags=re.I):
        tok = tok.strip('.:`()')
        out.add(tok)
        host = re.sub(r'^[a-z]+://', '', tok, flags=re.I).split('/')[0]
        if host and host != tok:
            out.add(host)
    return out


def _valid_ipv4(s):
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def ip_scope(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if any(a in n for n in PRIVATE_NETS):
        return "private (RFC 1918)"
    if any(a in n for n in DOC_NETS):
        return "documentation range (RFC 5737)"
    if a.is_loopback:
        return "loopback"
    return "public/other"


def extract_iocs(text):
    """Return {kind: sorted unique values} found in text (values refanged for comparison)."""
    t = refang(text)
    ips = {m for m in IP_CAND_RE.findall(t) if _valid_ipv4(m)}
    urls = {u.rstrip('.,;:') for u in URL_RE.findall(t)}
    emails = set(EMAIL_RE.findall(t))
    doms = set()
    for d in DOMAIN_RE.findall(t):
        last = d.rsplit(".", 1)[-1].lower()
        if last in FILE_EXTS or _valid_ipv4(d):
            continue
        doms.add(d.lower())
    return {"ipv4": sorted(ips), "url": sorted(urls), "domain": sorted(doms), "hash": sorted({h.lower() for h in HASH_RE.findall(t)}),
            "cve": sorted({c.upper() for c in CVE_RE.findall(t)}), "email": sorted(emails), "filename": sorted(set(FILE_RE.findall(t)))}


def ioc_context(events):
    """Indicators present in the supplied data, with refs. NO reputation is looked up or invented."""
    rows = []
    index = {}
    for ev in events:
        found = extract_iocs(ev["raw"])
        defang_src = defanged_tokens(ev["raw"])
        for kind, vals in found.items():
            if kind == "domain":
                vals = [v for v in vals if not any(v in u for u in found["url"])]
                from Core import feedback_semantics
                vals = [v for v in vals if not feedback_semantics.is_service_unit_domain(v, ev["raw"])]
            for v in vals:
                key = (kind, v)
                e = index.setdefault(key, {"type": kind, "value": v, "refs": [], "count": 0})
                e["count"] += 1
                if ev["ref"] not in e["refs"]:
                    e["refs"].append(ev["ref"])
        for fld, kind in (("user", "username"), ("host", "hostname")):
            if ev.get(fld):
                e = index.setdefault((kind, ev[fld]), {"type": kind, "value": ev[fld], "refs": [], "count": 0})
                e["count"] += 1
                if ev["ref"] not in e["refs"]:
                    e["refs"].append(ev["ref"])
        _ = defang_src
    for (kind, v), e in index.items():
        e["scope"] = ip_scope(v) if kind == "ipv4" else ""
        e["reputation"] = "External reputation not checked."
        rows.append(e)
    order = {"ipv4": 0, "domain": 1, "url": 2, "hash": 3, "email": 4, "filename": 5, "username": 6, "hostname": 7, "cve": 8}
    rows.sort(key=lambda r: (order.get(r["type"], 9), r["value"]))
    return rows


RISK_PATTERNS = [
    (re.compile(r"action=BLOCK|outcome=Prevented|EDR alert=", re.I), "security control blocked/prevented or raised an alert"),
    (re.compile(r"severity=High|severity=Critical", re.I), "source reports High/Critical severity"),
    (re.compile(r"MFAUsed=No", re.I), "console login without MFA"),
    (re.compile(r"EventID=4732|AddUserToGroup|MemberAdded=", re.I), "group membership change"),
    (re.compile(r"lsass", re.I), "LSASS referenced"),
    (re.compile(r"-enc\b|-EncodedCommand|UNION%20SELECT|UNION SELECT|OR%201%3D1|category=SQLi", re.I), "encoded command or injection pattern"),
    (re.compile(r"SeDebugPrivilege", re.I), "SeDebugPrivilege assigned"),
    (re.compile(r"CreateAccessKey", re.I), "access key created"),
    (re.compile(r"qtype=TXT", re.I), "DNS TXT query (check frequency/entropy)"),
    (re.compile(r"COMMAND=.*(?:wget|curl)\s", re.I), "download command run with sudo"),
]
BENIGN_PATTERNS = [
    (re.compile(r"\bapproved\b|\bauthori[sz]ed\b", re.I), "approved/authorized wording"),
    (re.compile(r"change[_ ]?(?:ticket|calendar|window)|CHG-\d+|maintenance|scheduled", re.I), "change/maintenance/schedule context"),
    (re.compile(r"SignatureValid=True|registered as", re.I), "valid signature / registered asset"),
]


def risk_signals(events):
    out = []
    for ev in events:
        if ev["source_kind"] == "wazuh":
            try:
                lvl = int(ev["meta"].get("rule_level"))
                if lvl >= 10:
                    out.append({"ref": ev["ref"], "label": f"Wazuh rule.level {lvl} (original SIEM severity)"})
            except (TypeError, ValueError):
                pass
        for rx, label in RISK_PATTERNS:
            if rx.search(ev["raw"]):
                out.append({"ref": ev["ref"], "label": label})
    # Source-derived investigation signals; not evidence of proven attack success.
    from Core import feedback_semantics
    out.extend(feedback_semantics.additional_risk_signals(events))
    return out


def benign_context(events):
    out = []
    for ev in events:
        for rx, label in BENIGN_PATTERNS:
            if rx.search(ev["raw"]):
                out.append({"ref": ev["ref"], "label": label})
    return out


def injection_scan(events):
    return [{"ref": e["ref"], "value": m.group(0)} for e in events for m in INJECTION_RE.finditer(e["raw"])]


def _sentences(text):
    return [s.strip() for s in re.split(r'(?<=[.!?])\s+|\n', text) if s.strip()]


def _supported(value, hay_lower):
    return re.search(r'(?<![\w.])' + re.escape(value.lower()) + r'(?![\w]|\.\d)', hay_lower) is not None


class _Flags:
    def __init__(self, sections):
        self.items = []
        self.sections = sections

    def add(self, check, severity, value, message, section=None):
        if section is None:
            section = "(whole output)"
            for name, body in self.sections.items():
                if value and value in body:
                    section = name
                    break
        self.items.append({"check": check, "severity": severity, "section": section, "value": value, "message": message,
                           "analyst_disposition": "Unreviewed"})


def validate_output(ai_text, sections, events, facts_lines, expected_headings, truncated=False, cap=12):
    """Run all automated checks. Returns list of flag dicts (ids F001...)."""
    F = _Flags(sections)
    src_raw = "\n".join(e["raw"] for e in events) + "\n" + "\n".join(facts_lines)
    src_ref = refang(src_raw)
    src_low = src_ref.lower()
    ref_ids = {e["ref"] for e in events}
    ai_ref = refang(ai_text)

    # --- structure
    if truncated:
        F.add("output_truncated", "high", "done_reason=length", "Model output hit the token limit and is incomplete; do not rely on missing sections.")
    for h in expected_headings:
        if h not in sections:
            F.add("missing_section", "medium", h, f"Expected section '{h}' not found in the model output.")

    # --- IOC consistency
    counts = {}

    def capped(check):
        counts[check] = counts.get(check, 0) + 1
        return counts[check] <= cap

    seen = set()
    for cand in IP_CAND_RE.findall(ai_ref):
        if cand in seen or _supported(cand, src_low):
            continue
        seen.add(cand)
        if not capped("ip"):
            continue
        if _valid_ipv4(cand):
            near = next((s for s in extract_iocs(src_raw)["ipv4"] if s.replace(".", "").lstrip("0") == cand.replace(".", "").lstrip("0") or
                         re.sub(r"\.0+(\d)", r".\1", cand) == s), None)
            msg = "IPv4 address not present in the source evidence."
            if near:
                msg += f" It resembles source value {near} (possible character-level alteration)."
            F.add("unsupported_ip", "high", cand, msg)
        else:
            F.add("malformed_ip_like", "medium", cand, "Number sequence resembles an IP address but is malformed and not in the source (could also be a version number).")
    for u in set(URL_RE.findall(ai_ref)):
        u = u.rstrip('.,;:')
        if not _supported(u, src_low) and capped("url"):
            F.add("unsupported_url", "high", u, "URL not present in the source evidence.")
    for d in extract_iocs(ai_ref)["domain"]:
        if not _supported(d, src_low) and not any(d in u.lower() for u in URL_RE.findall(ai_ref)) and capped("domain"):
            F.add("unsupported_domain", "medium", d, "Domain-like value not present in the source (may be ordinary text containing a dot).")
    for h in {x.lower() for x in HASH_RE.findall(ai_ref)}:
        if h not in src_low:
            F.add("unsupported_hash", "high", h, "File hash not present in the source evidence.")
    for c in {x.upper() for x in CVE_RE.findall(ai_ref)}:
        if c.lower() not in src_low:
            F.add("unsupported_cve", "high", c, "CVE identifier not present in the source evidence.")
    for e in set(EMAIL_RE.findall(ai_ref)):
        if not _supported(e, src_low):
            F.add("unsupported_email", "medium", e, "Email address not present in the source evidence.")
    for fn in {x for x in FILE_RE.findall(ai_ref)}:
        if fn.lower() not in src_low and capped("file"):
            F.add("unsupported_filename", "medium", fn, "File name not present in the source evidence.")
    ai_low = ai_text.lower()
    for tok in defanged_tokens(src_raw):
        rf = refang(tok)
        if rf != tok and rf.lower() in ai_ref.lower() and tok.lower() not in ai_low:
            F.add("ioc_format_altered", "low", tok, f"Source indicator is defanged; the output shows it re-fanged ('{rf}'). Exact IOC format was not preserved.")

    # --- timestamps (exact-string)
    for d in set(DATE_RE.findall(ai_text)):
        if d not in src_raw and capped("ts"):
            F.add("unsupported_timestamp", "high", d, "Date value not found in the source evidence (possible invented/corrupted timestamp).")
    for t in set(TIME_RE.findall(ai_text)):
        if t not in src_raw and capped("ts"):
            F.add("unsupported_timestamp", "medium", t, "Time value not found in the source evidence.")

    # --- entities
    for k, v in re.findall(r'\b(Account|User|user|Host|host|hostname|WorkstationName|SourceIP|src_ip|SourceImage|Image)=("[^"]+"|[^\s,;)]+)', ai_text):
        v = v.strip('"`\'.')
        if v and not _supported(v, src_low) and capped("ent"):
            F.add("unsupported_entity", "medium", f"{k}={v}", "Field value quoted in the output is not present in the source evidence.")
    for tok in set(re.findall(r'`([^`\s]{3,60})`', ai_text)):
        if not _supported(tok, src_low) and not REF_RE.fullmatch(tok) and not re.fullmatch(r'P[1-4]', tok) and capped("ent"):
            low = tok.lower()
            if any(ch.isdigit() for ch in tok) or "-" in tok or "\\" in tok or "." in tok:
                F.add("unsupported_entity", "low", tok, "Backtick-quoted value not present in the source evidence.")
    for tok in set(HOST_TOKEN_RE.findall(ai_text)):
        low = tok.lower()
        if low in HOST_ALLOW or REF_RE.fullmatch(tok) or re.fullmatch(r'(?:T|P|E)\d+', tok):
            continue
        if not _supported(tok, src_low) and capped("host"):
            F.add("possible_unsupported_hostname", "low", tok, "Host-like token not found in the source (heuristic; may be ordinary text such as 'ssh2').")

    # --- evidence references
    for r in sorted(set(REF_RE.findall(ai_text)) - ref_ids):
        F.add("nonexistent_evidence_ref", "high", r, "Evidence reference does not exist in the input.")
    for name in ("SIGNIFICANT SECURITY EVENTS", "SUSPICIOUS ACTIVITIES", "POTENTIAL ATTACK INDICATORS"):
        body = sections.get(name, "")
        for ln in body.splitlines():
            s = ln.strip()
            body_ = re.sub(r'^([-*\u2022]|\d+[.)])\s+', '', s)
            exempt = re.match(r'^\W*(none\b|not provided|insufficient|no (?:suspicious|evidence|significant|attack|additional|indicators|events))', body_, re.I)
            if re.match(r'^([-*\u2022]|\d+[.)])\s+', s) and not REF_RE.search(s) and not exempt and capped("uncited"):
                F.add("finding_without_evidence_ref", "medium", s[:140], "Finding has no [E###] evidence reference.", section=name)

    # --- fabricated SIEM identifiers
    for m in re.finditer(r'rule(?:\s*id)?\s*[:=#]?\s*(\d{3,7})\b', ai_text, re.I):
        if m.group(1) not in src_raw:
            F.add("possible_fabricated_rule_id", "high", m.group(1), "Rule ID not present in the source evidence.")
    for m in re.finditer(r'agent(?:\s*id)?\s*[:=#]?\s*(\d{3})\b', ai_text, re.I):
        if m.group(1) not in src_raw:
            F.add("possible_fabricated_agent_id", "high", m.group(1), "Agent ID not present in the source evidence.")

    # --- semantics / unsupported conclusions
    for s in _sentences(ai_text):
        low = s.lower()
        if "4625" in s and re.search(r'success|succeeded', low) and not re.search(r'fail|unsuccess|denied|not success|followed|after|then|later|before', low):
            F.add("eventid_semantic_mismatch", "medium", s[:160], "EventID 4625 is a FAILED logon; sentence describes success (heuristic).")
        if "4624" in s and re.search(r'fail|unsuccess', low) and not re.search(r'success|after|following|before|then|subsequent|followed', low):
            F.add("eventid_semantic_mismatch", "medium", s[:160], "EventID 4624 is a SUCCESSFUL logon; sentence describes failure (heuristic).")
        if "4732" in s and "removed" in low:
            F.add("eventid_semantic_mismatch", "medium", s[:160], "EventID 4732 is a member ADDED event; sentence says removed (heuristic).")
        m = CERTAINTY_RE.search(s)
        if m and not NEGATION_RE.search(s) and m.group(0).lower() not in src_low:
            F.add("unsupported_conclusion", "medium", m.group(0), "Definitive claim without confirming text in the source; the evidence may only show an attempt or a possibility.")
    for m in ATTRIBUTION_RE.finditer(ai_text):
        sent = next((s for s in _sentences(ai_text) if m.group(0) in s), "")
        if m.group(0).lower() not in src_low and not re.search(r'\b(no|not|without|cannot|unknown)\b', sent, re.I):
            F.add("unsupported_attribution", "medium", m.group(0), "Threat actor / malware name not present in the source evidence.")

    # --- 'nothing suspicious' vs code-detected signals (and the reverse is left to the analyst)
    susp = sections.get("SUSPICIOUS ACTIVITIES", "") + " " + sections.get("EVIDENCE SUPPORTING MALICIOUS ACTIVITY", "")
    if NONE_CLAIM_RE.search(sections.get("SUSPICIOUS ACTIVITIES", "")) or (sections.get("EVIDENCE SUPPORTING MALICIOUS ACTIVITY", "").strip().lower().startswith("none")):
        sig = risk_signals(events)
        if sig:
            labels = sorted({s["label"] for s in sig})[:4]
            F.add("none_claim_vs_signals", "high", "; ".join(labels), "Output reports no suspicious/malicious evidence but code detected these risk signals (" +
                  ", ".join(sorted({s['ref'] for s in sig})[:6]) + "). Analyst must verify.")
    _ = susp

    _windows_semantic_flags(ai_text, sections, events, F)
    _rt03_authorization_claim_flags(sections, events, F)
    _rt04_persistence_claim_flags(sections, events, F)

    # BT baseline guardrails: analyst review requests, not verdicts.
    from Core import benign_semantics
    benign_semantics.add_review_requests(F, sections, events)
    # Human-review requests for Linux command/IP/outcome contradictions.
    from Core import feedback_semantics
    feedback_semantics.add_review_requests(F, sections, events)
    for i, f in enumerate(F.items, 1):
        f["id"] = f"F{i:03d}"
    return F.items




# Narrow, evidence-gated Windows checks. Each result is a REVIEW FLAG, not a verdict.
# Only interpret numeric Event IDs when those IDs are present in supplied events.
_RT02_LOGIN_RE = re.compile(
    r"\b(?:logged\s+(?:on|in)|log(?:on|in)\s+(?:succeeded|successful)|"
    r"successful\s+log(?:on|in)|signed\s+in|administrator\s+log(?:on|in))\b", re.I)
_RT02_CREATED_RE = re.compile(
    r"\b(?:windows\s+)?(?:security\s+|audit\s+|event\s+)?log\s+(?:was\s+)?(?:created|creation)\b", re.I)
_RT02_FILE_ACCESS_RE = re.compile(
    r"\b(?:accessed|opened|read|modified|wrote)\s+(?:(?:multiple|several|the|some|system)\s+){0,4}files?\b|"
    r"\bfiles?\s+(?:were\s+|was\s+)?(?:accessed|opened|read|modified|written)\b", re.I)
_RT02_NEGATED_RE = re.compile(r"\b(?:not|never|incorrect(?:ly)?|wrong(?:ly)?|does\s+not|without|rather\s+than|instead\s+of|no\s+evidence)\b", re.I)
_RT02_EVENT_1102_RE = re.compile(r"\b(?:event\s*id|eventid|id)\s*[:=#-]?\s*1102\b", re.I)
_RT02_UNAUTHORIZED_RE = re.compile(r"\b(?:unauthori[sz]ed|unapproved)\s+(?:access|activity|use|file|changes?)\b", re.I)
_RT02_MAINTENANCE_RE = re.compile(r"\boutside\s+(?:of\s+)?(?:an?\s+)?(?:approved\s+)?maintenance\s+windows?\b", re.I)


def _windows_semantic_flags(ai_text, sections, events, F):
    """Detect contradicted Windows event descriptions without inferring attack intent.

    Rules are conservative, gated on original event_id AND (where applicable)
    evidence refs. The assistant's narrative is not used as a source of truth.
    """
    windows = [e for e in events if e.get("source_kind") == "windows"]
    if not windows:
        return
    ids = {str(e.get("event_id")) for e in windows}
    refs_1102 = {e["ref"] for e in windows if str(e.get("event_id")) == "1102"}
    refs_5145_pipe = {
        e["ref"] for e in windows
        if str(e.get("event_id")) == "5145" and "IPC$" in str(e.get("raw", "")).upper()
    }
    # Restrict to descriptive findings, not questions, recommendations or
    # the analyst's own uncertainty statements in MISSING INFORMATION.
    eligible = ("EXECUTIVE SUMMARY", "SIGNIFICANT SECURITY EVENTS",
                "EVIDENCE REFERENCES", "INCIDENT TIMELINE",
                "SUSPICIOUS ACTIVITIES", "POTENTIAL ATTACK INDICATORS")
    if sections:
        claim_lines = [(name, ln.strip()) for name in eligible
                       for ln in sections.get(name, "").splitlines() if ln.strip()]
    else:
        claim_lines = [("(whole output)", ln.strip()) for ln in ai_text.splitlines() if ln.strip()]
    counts = {}

    def add_once(check, severity, value, message, section, limit=3):
        if counts.get(check, 0) < limit:
            F.add(check, severity, value[:180], message, section=section)
            counts[check] = counts.get(check, 0) + 1

    only_1102_5145 = ids.issubset({"1102", "5145"})
    raw_source = " ".join(str(e.get("raw", "")) for e in windows).lower()
    for name, line in claim_lines:
        line_refs = set(REF_RE.findall(line))
        negated = bool(_RT02_NEGATED_RE.search(line))
        is_1102 = bool(refs_1102 & line_refs or (_RT02_EVENT_1102_RE.search(line) and refs_1102))
        if is_1102 and not negated and (_RT02_LOGIN_RE.search(line) or _RT02_CREATED_RE.search(line)):
            add_once("eventid_semantic_mismatch", "high", line,
                     "Windows Security Event ID 1102 denotes Security Audit Log Cleared, NOT a logon or log creation. Check cited evidence and UserData.", name)

        relevant_pipes = bool(refs_5145_pipe & line_refs) or (name == "EXECUTIVE SUMMARY" and only_1102_5145 and refs_5145_pipe)
        if relevant_pipes and not negated and _RT02_FILE_ACCESS_RE.search(line):
            add_once("possible_5145_access_overclaim", "medium", line,
                     "Event ID 5145 is a detailed file-share access check; IPC$ named-pipe records alone do not prove system-file reads or modifications.", name)

        if not negated and _RT02_MAINTENANCE_RE.search(line) and not _RT02_MAINTENANCE_RE.search(raw_source):
            add_once("unsupported_maintenance_window", "medium", line,
                     "The supplied events do not establish that activity occurred outside an approved maintenance window.", name, limit=2)
        if not negated and _RT02_UNAUTHORIZED_RE.search(line) and not _RT02_UNAUTHORIZED_RE.search(raw_source):
            add_once("unsupported_authorization_status", "medium", line,
                     "The source events do not independently establish that the activity was unauthorized; verify approval and context.", name, limit=2)


# RT-03: narrowly target positive claims of *verified authorization* in recorded
# Windows telemetry. A Sysmon process User/IntegrityLevel is execution identity,
# not evidence of organizational approval. These are analyst-review flags.
_RT03_AUTHORIZED_ACTOR_RE = re.compile(
    r"\b(?:initiated|performed|executed|run|carried\s+out|conducted|started|launched|issued)\s+"
    r"(?:by\s+)?(?:an?\s+|the\s+)?(?:approved|authori[sz]ed)\s+"
    r"(?:user|administrator|admin|operator|account|actor|team|tools?)\b|"
    r"\b(?:approved|authori[sz]ed)\s+(?:user|administrator|admin|operator|account|team|tools?)"
    r"\s+(?:initiated|performed|executed|ran|started|launched)\b", re.I)
_RT03_APPROVED_SCOPE_RE = re.compile(
    r"\b(?:within|inside|under|in)\s+(?:the\s+|an?\s+)?"
    r"(?:approved|authori[sz]ed)\s+(?:scope|change|maintenance\s+window|"
    r"procedure|operations?|activity|process)\b|"
    r"\b(?:aligns?|aligned)\s+with\s+(?:an?\s+|the\s+)?"
    r"(?:approved|authori[sz]ed)\s+(?:scope|change|maintenance\s+window)\b", re.I)
_RT03_NEGATED_OR_HYPOTHETICAL_RE = re.compile(
    r"\b(?:not|never|without|no\s+evidence|cannot|can't|unknown|unconfirmed|"
    r"possibly|possible|potential|might|may|could|whether|if|verify|"
    r"investigate|check|determine|to\s+confirm|to\s+ensure|"
    r"needs?\s+verification|should\s+be\s+checked)\b", re.I)
# Only an explicit source field indicating organizational approval can suppress
# this *heuristic review request*. Account names, integrity levels, and process
# execution do NOT constitute independent authorization evidence.
_RT03_APPROVAL_EVIDENCE_RE = re.compile(
    r"[\"']?(?:AuthorizationStatus|ApprovalStatus|ChangeApproval|AuthorizedActivity)"
    r"[\"']?\s*[:=]\s*[\"']?(?:approved|authorized|true|yes)\b", re.I)


def _rt03_authorization_claim_flags(sections, events, F):
    windows = [e for e in events if e.get("source_kind") == "windows"]
    if not windows:
        return
    if _RT03_APPROVAL_EVIDENCE_RE.search(" ".join(e.get("raw", "") for e in windows)):
        return
    # Findings and assessment, never recommendations or missing-evidence fields.
    eligible = ("EXECUTIVE SUMMARY", "SIGNIFICANT SECURITY EVENTS",
                "EVIDENCE REFERENCES", "INCIDENT TIMELINE",
                "SUSPICIOUS ACTIVITIES", "POTENTIAL ATTACK INDICATORS",
                "CONFIDENCE AND UNCERTAINTY")
    counts = {}
    for section in eligible:
        for line in sections.get(section, "").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Only qualifiers PRECEDING the claim affect the claim. For example,
            # "it was authorized, but further review is needed" still asserts
            # authorization; "verify whether it was authorized" does not.
            for check, pattern, severity, message, limit in (
                ("unsupported_authorization_status", _RT03_AUTHORIZED_ACTOR_RE, "medium",
                 "Windows process ownership or Administrator identity does not verify organizational authorization.", 3),
                ("unsupported_approved_scope", _RT03_APPROVED_SCOPE_RE, "medium",
                 "No source approval or change record establishes an approved scope.", 2),
            ):
                for claim in pattern.finditer(stripped):
                    before = stripped[:claim.start()]
                    before = re.split(r"(?<=[.!?])\s+|;\s*", before)[-1]
                    if _RT03_NEGATED_OR_HYPOTHETICAL_RE.search(before):
                        continue
                    counts[check] = counts.get(check, 0) + 1
                    if counts[check] <= limit:
                        excerpt = stripped[max(0, claim.start() - 55): min(len(stripped), claim.end() + 85)]
                        F.add(check, severity, excerpt, message, section=section)
                    break


# RT-04: Evidence-gated, conservative review flags for Winlogon Shell scenarios.
# These are not verdicts: exact causal conclusions require independent validation.
_RT04_DOWNLOAD_RE = re.compile(r"\b(?:downloaded|downloading)\b", re.I)
_RT04_DOWNLOAD_PROOF = re.compile(
    r"(?:https?://|Zone\.Identifier|HostUrl|SourceUrl|DownloadUrl|ReferrerUrl|BrowserDownload)", re.I)
_RT04_HEDGE = re.compile(
    r"\b(?:may|might|could|potential(?:ly)?|possible|hypothes(?:is|ized)|"
    r"unknown|unconfirmed|not|no\s+evidence|without|cannot|"
    r"whether|if|check|verify|investigate|determine)\b", re.I)
_RT04_CREATE_PROCESS_RE = re.compile(
    r"\b(?:process|file|executable|binary|payload)\b.{0,110}\b(?:was\s+)?creat(?:ed|ion)\b|"
    r"\bcreat(?:ed|ion)\b.{0,55}\b(?:process|file|executable|binary|payload)\b", re.I)
_RT04_SESSIONS_RE = re.compile(
    r"\b(?:across|in|over)\s+(?:multiple|different|separate|distinct)\s+"
    r"(?:(?:user|logon|login|terminal)\s+)?sessions?\b|"
    r"\b(?:multiple|different|separate|distinct)\s+"
    r"(?:(?:user|logon|login|terminal)\s+)?sessions?\b", re.I)


def _rt04_has_distinct_payload_logons(windows):
    """Require two Sysmon process-create events for the SAME image with distinct Logon IDs."""
    by_image = {}
    for ev in windows:
        if str(ev.get("event_id")) != "1":
            continue
        fields = ev.get("fields") or {}
        try:
            raw_data = json.loads(ev.get("raw", "{}")).get("event_data", {})
        except (ValueError, TypeError, AttributeError):
            raw_data = {}
        if not isinstance(raw_data, dict):
            raw_data = {}
        image = str(fields.get("event_data.Image") or raw_data.get("Image") or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
        logon = str(fields.get("event_data.LogonId") or raw_data.get("LogonId") or "").strip().lower()
        if image and logon and logon not in ("0", "0x0", "-", "unknown"):
            by_image.setdefault(image, set()).add(logon)
    return any(len(logons) >= 2 for logons in by_image.values())


def _rt04_persistence_claim_flags(sections, events, F):
    """Flag unsupported positive statements in recorded Winlogon Shell samples.

    Scope: Windows Sysmon 13 modifying Winlogon\\Shell. Do not infer criminal
    intent, download origin or different logon sessions from mere process activity.
    """
    windows = [e for e in events if e.get("source_kind") == "windows"]
    reg = [e for e in windows if str(e.get("event_id")) == "13" and
           "\\winlogon\\shell" in str(e.get("raw", "")).lower().replace("\\\\", "\\")]
    if not reg or not sections:
        return
    registry_refs = {e.get("ref") for e in reg}
    file_refs = {e.get("ref") for e in windows if str(e.get("event_id")) == "11"}
    src_blob = " ".join(str(e.get("raw", "")) for e in windows)
    has_download_proof = bool(_RT04_DOWNLOAD_PROOF.search(src_blob))
    has_sessions_proof = _rt04_has_distinct_payload_logons(windows)
    eligible = ("EXECUTIVE SUMMARY", "SIGNIFICANT SECURITY EVENTS", "SUSPICIOUS ACTIVITIES",
                "EVIDENCE REFERENCES", "INCIDENT TIMELINE", "POTENTIAL ATTACK INDICATORS",
                "CONFIDENCE AND UNCERTAINTY")
    counts = {}

    def add(check, severity, snippet, why, section, limit=3):
        if counts.get(check, 0) < limit:
            F.add(check, severity, snippet[:200], why, section=section)
            counts[check] = counts.get(check, 0) + 1

    for section in eligible:
        for line in sections.get(section, "").splitlines():
            line = line.strip()
            if not line or line.startswith("|---"):
                continue
            # Skip declarations of uncertainty and counterfactual examples, not
            # claims followed by a later caveat.
            dl = _RT04_DOWNLOAD_RE.search(line)
            if dl and not has_download_proof:
                before = re.split(r"(?<=[.!?])\s+|;\s*", line[:dl.start()])[-1]
                if not _RT04_HEDGE.search(before):
                    add("unsupported_download_origin", "medium", line,
                        "An executable path under Downloads is not download evidence; no URL/Zone.Identifier/browser-origin record is present.", section)

            refs = set(REF_RE.findall(line))
            if refs & registry_refs and not refs & file_refs:
                cm = _RT04_CREATE_PROCESS_RE.search(line)
                if cm:
                    before = re.split(r"(?<=[.!?])\s+|;\s*", line[:cm.start()])[-1]
                    if not _RT04_HEDGE.search(before):
                        add("sysmon_13_semantic_mismatch", "high", line,
                            "Cited Sysmon Event ID 13 records Registry Value Set, not process/file creation; verify Event ID 11/1 evidence.", section)

            sm = _RT04_SESSIONS_RE.search(line)
            if sm and not has_sessions_proof:
                before = re.split(r"(?<=[.!?])\s+|;\s*", line[:sm.start()])[-1]
                if not _RT04_HEDGE.search(before):
                    add("unsupported_multiple_sessions", "medium", line,
                        "Repeated process execution does not establish distinct logon sessions without distinct LogonIds for the same image.", section)


def summarize_flags(flags):
    sev = {"high": 0, "medium": 0, "low": 0}
    for f in flags:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    return sev
