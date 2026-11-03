"""Load and normalise security input without ever modifying the original evidence.

Supported inputs:
  * Plain-text logs (Windows key=value, Linux syslog/auth.log, network/firewall/DNS/IDS key=value)
  * Generic SIEM alert text blocks that start with "ALERT:"
  * Wazuh alert JSON: single object, JSON array, wrapper objects (hits.hits[]._source / alerts[]),
    JSON Lines / NDJSON, and any of these gzip-compressed (.gz)
Every event keeps its ORIGINAL text (`raw`) and gets an evidence reference (E001, E002 ...).
Normalised fields are additive; missing fields are None, never invented.
"""
import gzip
import hashlib
import io
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import config


class InputError(Exception):
    """Raised for invalid, empty or unsafe input files (message is analyst-readable)."""


KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("[^"]*"|\S+)')
SYSLOG_RE = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w./\-]+)(?:\[(\d+)\])?:\s*(.*)$')
ISO_PREFIX_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s*(.*)$')
IPV4_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]|\.\d)')
TZ_RE = re.compile(r'(?:Z|[+-]\d{2}:?\d{2})$')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _read_text(path):
    p = Path(path)
    if not p.is_file():
        raise InputError(f"File not found: {path}")
    size = p.stat().st_size
    if size == 0:
        raise InputError(f"Input file is empty: {p.name}")
    if size > config.MAX_FILE_BYTES:
        raise InputError(f"File is larger than {config.MAX_FILE_BYTES // (1024*1024)} MB limit: {p.name}")
    raw = p.read_bytes()
    compressed = raw[:2] == b"\x1f\x8b"
    if compressed:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                raw = gz.read(config.MAX_FILE_BYTES * 2 + 1)
        except (OSError, EOFError) as e:
            raise InputError(f"Corrupt gzip file {p.name}: {e}")
        if len(raw) > config.MAX_FILE_BYTES * 2:
            raise InputError("Decompressed content exceeds the safety limit.")
    if b"\x00" in raw[:4096]:
        raise InputError(f"{p.name} looks like a binary file, not a text/JSON log.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return text, compressed


def flatten(obj, prefix="", out=None):
    """Flatten nested dict/list into {'a.b.0.c': value}."""
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                flatten(v, f"{prefix}{k}.", out)
            else:
                out[f"{prefix}{k}"] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                flatten(v, f"{prefix}{i}.", out)
            else:
                out[f"{prefix}{i}"] = v
    return out


def _first(flat, keys):
    for k in keys:
        v = flat.get(k)
        if v not in (None, "", []):
            return str(v)
    return None


def iso_utc_if_safe(ts):
    """Return an ISO-8601 UTC string ONLY when the raw timestamp carries a year and timezone."""
    if not ts or not TZ_RE.search(ts.strip()) or not re.match(r"\d{4}-\d{2}-\d{2}", ts.strip()):
        return None
    s = ts.strip().replace(",", ".")
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def _blank_event(ref, line_no, raw):
    return {"ref": ref, "line_no": line_no, "raw": raw, "timestamp_raw": None, "timestamp_utc": None,
            "host": None, "user": None, "src_ip": None, "dst_ip": None, "event_id": None,
            "source_kind": "generic", "meta": {}, "fields": {}}


# --------------------------------------------------------------------------- text lines
def _event_from_line(line, ref, line_no):
    ev = _blank_event(ref, line_no, line)
    body = line
    m = ISO_PREFIX_RE.match(line)
    s = SYSLOG_RE.match(line)
    if m:
        ev["timestamp_raw"], ev["host"], body = m.group(1), m.group(2), m.group(3)
    elif s:
        ev["timestamp_raw"], ev["host"] = s.group(1), s.group(2)
        ev["fields"]["program"] = s.group(3)
        body = s.group(5)
        ev["source_kind"] = "linux"
    ev["timestamp_utc"] = iso_utc_if_safe(ev["timestamp_raw"])
    kv = {k: v.strip('"') for k, v in KV_RE.findall(body)}
    ev["fields"].update(kv)
    low = {k.lower(): v for k, v in kv.items()}
    ev["event_id"] = low.get("eventid") or low.get("event_id")
    ev["user"] = next((low[k] for k in ("account", "user", "username", "user_name", "useridentity.username") if k in low), None)
    ev["src_ip"] = next((low[k] for k in ("sourceip", "src_ip", "src", "client", "sourceipaddress") if k in low), None)
    ev["dst_ip"] = next((low[k] for k in ("dst_ip", "dest_ip", "dst", "destinationip") if k in low), None)
    if ev["event_id"]:
        ev["source_kind"] = "windows"
    elif ev["source_kind"] != "linux" and re.search(r"\b(sshd|sudo|CRON|pam_unix|su)\b", body):
        ev["source_kind"] = "linux"
    if ev["source_kind"] == "linux":
        mu = re.search(r"(?:for|user)\s+(?:invalid user\s+)?([\w.\-$]+)\s+(?:from|by)", body) or \
             re.search(r"^\s*([\w.\-]+)\s*:\s*TTY=", body) or re.search(r"session (?:opened|closed) for user ([\w.\-]+)", body)
        if mu:
            ev["user"] = mu.group(1)
        ip = IPV4_RE.search(body)
        if ip and "from" in body:
            ev["src_ip"] = ip.group(0)
    if ev["source_kind"] == "generic" and any(k in low for k in ("action", "qname", "qtype", "src_ip", "dst_ip", "proto", "signature", "category")):
        ev["source_kind"] = "network"
    return ev


def _parse_alert_blocks(lines):
    blocks, cur = [], []
    for ln in lines:
        if ln.upper().startswith("ALERT:") and cur:
            blocks.append(cur)
            cur = []
        cur.append(ln)
    if cur:
        blocks.append(cur)
    return blocks


def _event_from_alert_block(block, ref, line_no):
    raw = "\n".join(block)
    ev = _blank_event(ref, line_no, raw)
    ev["source_kind"] = "generic"
    f = {}
    for ln in block:
        if ":" in ln:
            k, v = ln.split(":", 1)
            f[k.strip()] = v.strip()
    ev["fields"] = f
    low = {k.lower(): v for k, v in f.items()}
    ev["timestamp_raw"] = low.get("time")
    ev["host"] = low.get("host") or low.get("source")
    ev["user"] = low.get("user")
    m = IPV4_RE.search(low.get("source", ""))
    ev["src_ip"] = m.group(0) if m else None
    ev["meta"] = {"alert_title": low.get("alert"), "original_severity": next((v for k, v in f.items() if k.lower().startswith("severity")), None)}
    return ev


# --------------------------------------------------------------------------- JSON
def _event_from_json(obj, ref, line_no, raw=None):
    raw = raw if raw is not None else json.dumps(obj, ensure_ascii=False)
    ev = _blank_event(ref, line_no, raw)
    flat = flatten(obj)
    ev["fields"] = {k: v for k, v in flat.items() if k != "full_log"}
    rule = obj.get("rule") if isinstance(obj.get("rule"), dict) else None
    is_wazuh = bool(rule) or ("agent" in obj and "decoder" in obj)
    # Converted Windows Event Log / Sysmon records keep the original XML fields
    # under event_data. Recognise those records without affecting Wazuh parsing.
    provider = str(obj.get("provider") or "").lower()
    is_win_evtx = (
        not is_wazuh
        and isinstance(obj.get("event_data"), dict)
        and obj.get("event_id") is not None
        and ("microsoft-windows-" in provider or "sysmon" in provider or provider == "service control manager")
    )
    ev["source_kind"] = "wazuh" if is_wazuh else ("windows" if is_win_evtx else "generic")
    ev["timestamp_raw"] = _first(flat, ["timestamp", "@timestamp", "time", "eventTime"])
    ev["timestamp_utc"] = iso_utc_if_safe(ev["timestamp_raw"])
    ev["host"] = _first(flat, ["agent.name", "data.win.system.computer", "host.name", "hostname", "host", "computer"])
    ev["user"] = _first(flat, ["data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
                               "data.dstuser", "data.srcuser", "data.user", "user.name", "user", "event_data.User"])
    ev["src_ip"] = _first(flat, ["data.srcip", "data.win.eventdata.ipAddress", "data.src_ip", "src_ip", "source.ip",
                                "event_data.SourceIp", "event_data.SourceIP"])
    ev["dst_ip"] = _first(flat, ["data.dstip", "data.dest_ip", "dst_ip", "destination.ip",
                                "event_data.DestinationIp", "event_data.DestinationIP"])
    ev["event_id"] = _first(flat, ["data.win.system.eventID", "data.id", "event_id"])
    if is_wazuh:
        ev["meta"] = {
            "alert_id": obj.get("id"),
            "rule_id": _first(flat, ["rule.id"]), "rule_level": _first(flat, ["rule.level"]),
            "rule_description": _first(flat, ["rule.description"]),
            "rule_groups": rule.get("groups") if rule else None,
            "agent_id": _first(flat, ["agent.id"]), "agent_name": _first(flat, ["agent.name"]),
            "location": obj.get("location"), "decoder": _first(flat, ["decoder.name"]),
            "full_log": obj.get("full_log"),
        }
    if "_synthetic_fixture" in obj:
        ev["meta"]["synthetic_notice"] = obj["_synthetic_fixture"]
    return ev


def _extract_items(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        hits = obj.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
            return [h.get("_source", h) if isinstance(h, dict) else h for h in hits["hits"]]
        for key in ("alerts", "events", "records"):
            if isinstance(obj.get(key), list):
                return obj[key]
    return [obj]


# --------------------------------------------------------------------------- public API
def load_file(path, source_hint="auto", origin=None):
    """Parse a file into a dict: {path,name,sha256,format,source_type,evidence_class,events,warnings,...}."""
    p = Path(path)
    text, compressed = _read_text(p)
    if not text.strip():
        raise InputError(f"Input file contains no content: {p.name}")
    warnings, events = [], []
    stripped = text.lstrip()
    fmt = "text"

    if stripped[:1] in "{[":
        docs = None
        try:
            docs = json.loads(text)
            fmt = "json"
        except json.JSONDecodeError as whole_err:
            good, bad = [], []
            for i, ln in enumerate(text.splitlines(), 1):
                if not ln.strip():
                    continue
                try:
                    good.append((i, ln, json.loads(ln)))
                except json.JSONDecodeError:
                    bad.append(i)
            if not good:
                raise InputError(f"Invalid JSON in {p.name}: {whole_err}")
            fmt = "ndjson"
            if bad:
                warnings.append(f"Skipped {len(bad)} line(s) that are not valid JSON (line numbers: {bad[:10]}).")
            for i, ln, obj in good:
                if isinstance(obj, dict):
                    events.append(_event_from_json(obj, "", i, raw=ln))
                else:
                    warnings.append(f"Line {i}: JSON value is not an object; skipped.")
        if docs is not None:
            items = _extract_items(docs)
            for idx, item in enumerate(items, 1):
                if isinstance(item, dict):
                    events.append(_event_from_json(item, "", idx))
                elif isinstance(item, str) and item.strip():
                    events.append(_event_from_line(item.strip(), "", idx))
                else:
                    warnings.append(f"Item {idx}: unsupported JSON value type; skipped.")
    else:
        lines = [ln.rstrip("\r") for ln in text.splitlines()]
        comment_lines = [ln for ln in lines if ln.lstrip().startswith("#")]
        content = [(i, ln) for i, ln in enumerate(lines, 1) if ln.strip() and not ln.lstrip().startswith("#")]
        if not content:
            raise InputError(f"{p.name} contains only comments/blank lines.")
        if any(ln.upper().startswith("ALERT:") for _, ln in content):
            fmt = "alert_text"
            for n, block in enumerate(_parse_alert_blocks([ln for _, ln in content]), 1):
                events.append(_event_from_alert_block(block, "", n))
        else:
            for i, ln in content:
                events.append(_event_from_line(ln.strip(), "", i))
        if any("SYNTHETIC" in c.upper() for c in comment_lines):
            warnings.append("File header marks this as a SYNTHETIC fixture.")

    if not events:
        raise InputError(f"No usable events found in {p.name}.")
    if len(events) > config.MAX_EVENTS:
        warnings.append(f"File has {len(events)} events; only the first {config.MAX_EVENTS} were loaded.")
        events = events[:config.MAX_EVENTS]
    width = max(3, len(str(len(events))))
    for n, ev in enumerate(events, 1):
        ev["ref"] = f"E{n:0{width}d}"

    synthetic = p.name.upper().startswith("SYNTHETIC") or any("SYNTHETIC" in w for w in warnings) or \
        any("synthetic_notice" in e["meta"] for e in events)
    if synthetic:
        evidence_class = "synthetic_fixture"
    elif origin == "genuine_wazuh":
        evidence_class = "analyst_declared_genuine_wazuh_export"
    else:
        evidence_class = "user_supplied_unverified"

    return {
        "path": str(p), "name": p.name, "sha256": sha256_file(p), "size_bytes": p.stat().st_size,
        "compressed": compressed, "format": fmt,
        "source_type": detect_source_type(events, source_hint, p),
        "evidence_class": evidence_class, "events": events, "warnings": warnings,
    }


def detect_source_type(events, hint, path):
    if hint and hint != "auto":
        return hint
    parts = {x.lower() for x in Path(path).parts}
    for key in ("windows", "linux", "network", "wazuh"):
        if key in parts:
            return key
    counts = defaultdict(int)
    for e in events:
        counts[e["source_kind"]] += 1
    return max(counts, key=counts.get) if counts else "generic"


# --------------------------------------------------------------------------- prompt rendering
def render_event(ev, max_chars=None):
    """Compact single-line(ish) rendering with the evidence reference. Original text is preserved."""
    max_chars = max_chars or config.MAX_EVENT_CHARS_IN_PROMPT
    if ev["source_kind"] == "wazuh":
        m = ev["meta"]
        parts = [f"timestamp={ev['timestamp_raw']}", f"rule.id={m.get('rule_id')}", f"rule.level={m.get('rule_level')}",
                 f"rule.description=\"{m.get('rule_description')}\"", f"agent.id={m.get('agent_id')}",
                 f"agent.name={m.get('agent_name')}", f"location={m.get('location')}", f"decoder={m.get('decoder')}"]
        skip = ("rule.", "agent.", "decoder.", "manager.", "timestamp", "location", "id", "previous_output", "full_log")
        data = [f"{k}={v}" for k, v in ev["fields"].items() if not k.startswith(skip) and v not in (None, "")]
        line = "WAZUH_ALERT " + " ".join(parts)
        if data:
            line += " | " + " ".join(data)
        if m.get("full_log"):
            line += f" | full_log={m['full_log']}"
        line = line.replace("\n", " ")
    else:
        line = ev["raw"].replace("\n", " ; ")
    if len(line) > max_chars:
        line = line[:max_chars] + f" ...[truncated {len(line) - max_chars} chars]"
    return f"[{ev['ref']}] {line}"


def reference_notes(events):
    """Fixed, factual reference semantics for the event types present (not evidence about this case)."""
    blob = " ".join(e["raw"] for e in events)
    notes = []
    ids = {str(e["event_id"]) for e in events if e["event_id"]} | set(re.findall(r"(?:EventID|eventID)[\"=: ]+(\d+)", blob))

    if "1102" in ids:
        notes.append("Windows Security EventID 1102 = THE SECURITY AUDIT LOG WAS CLEARED; NOT a logon, and NOT log creation. UserData SubjectUserName identifies the account associated with clearing; log clearing alone does not prove an attacker.")
    if "5145" in ids:
        notes.append("Windows Security EventID 5145 = a detailed NETWORK SHARE ACCESS CHECK. For IPC$ with RelativeTargetName winreg/lsarpc/srvsvc, these are named-pipe paths, NOT ordinary system files; this event alone does NOT prove successful file reads, file changes or malicious intent.")
    if ("13" in ids and "\\winlogon\\shell" in blob.lower().replace("\\\\", "\\")):
        notes.append("Sysmon EventID 13 = REGISTRY VALUE SET; TargetObject Winlogon\\Shell with Details referencing an executable may establish a persistence CONFIGURATION CHANGE. EventID 13 does NOT mean a process or a file was created. EventID 11 = FILE CREATION, EventID 1 = PROCESS CREATION. For payload execution verify parent ProcessGuid and subsequent EventID 1, then distinguish observed logon execution from proven repeated persistence across multiple logons.")
        notes.append("The path C:\\Users\\...\\Downloads alone does NOT establish that a user downloaded a file, any source URL, or a suspicious domain. Multiple executions alone do NOT establish different logon sessions; compare LogonId across the same payload image. Never fabricate network origin or timestamp; use exact source timestamp with each evidence reference.")
    if "4624" in ids:
        notes.append("EventID 4624 = successful logon. LogonType 2=interactive, 3=network, 10=RemoteInteractive (RDP).")
    if "4625" in ids:
        notes.append("EventID 4625 = FAILED logon (not a success). Status 0xC000006D=logon failure (bad user or credentials), 0xC000006A=wrong password for a valid account. One failure alone is not an attack.")
    if "4672" in ids:
        notes.append("EventID 4672 = special privileges assigned to a new logon; common for administrative accounts and not malicious by itself.")
    if "4688" in ids:
        notes.append("EventID 4688 = a process was created (check parent, command line, user).")
    if "4732" in ids:
        notes.append("EventID 4732 = a member was ADDED to a security-enabled local group.")
    if "10" in ids or "TargetImage" in blob:
        notes.append("Sysmon EventID 10 = one process accessed another process; EventID 1 = process creation.")
    if re.search(r"Failed password|Accepted (?:password|publickey)|sudo:", blob):
        notes.append("sshd 'Failed password' = failed login; 'Accepted ...' = successful login. sudo COMMAND= shows a command run with elevated rights; a download command is not proof the file was executed.")
    if re.search(r"action=BLOCK|Prevented|http_status=403|status=403|DENY|DROP", blob, re.I):
        notes.append("A BLOCK/403/Prevented/DENY outcome means the attempt was stopped; it is not evidence of a successful compromise by itself.")
    if "1" in ids and re.search(r"\bwinrshost\.exe\b", blob, flags=re.I):
        notes.append("Sysmon EventID 1 records PROCESS CREATION. A process chain winrshost.exe -> cmd.exe -> ipconfig.exe can be consistent with WinRM-related command execution, but alone does NOT prove a remote client, malicious lateral movement, or a successful compromise. Administrator as a process user is an IDENTITY, not proof of authorization, approved scope, or a maintenance window.")
    notes.append("Approved changes, registered authorized tools and maintenance windows in the data are legitimate context and must be weighed; missing approval must be stated as missing, not assumed.")
    # BT baseline factual reference notes.
    from Core import benign_semantics
    notes.extend(benign_semantics.extra_reference_notes(events))
    return notes


def auth_stats(events):
    """Code-computed authentication facts (Windows 4625/4624 and sshd failed/accepted)."""
    fails = defaultdict(list)
    succ = []
    for e in events:
        raw = e["raw"]
        is_fail = str(e["event_id"]) == "4625" or "Failed password" in raw
        is_ok = str(e["event_id"]) == "4624" or re.search(r"Accepted (?:password|publickey)", raw)
        if is_fail and e["src_ip"]:
            fails[e["src_ip"]].append(e)
        elif is_ok:
            succ.append(e)
    lines = []
    for ip, evs in fails.items():
        if len(evs) < 3:
            continue
        users = sorted({x["user"] for x in evs if x["user"]})
        lines.append(f"{len(evs)} failed logons from source {ip} against {len(users)} distinct account(s) "
                     f"[{evs[0]['ref']}..{evs[-1]['ref']}], first at {evs[0]['timestamp_raw']}, last at {evs[-1]['timestamp_raw']}.")
        later = [s for s in succ if s["src_ip"] == ip and s["line_no"] > evs[-1]["line_no"]]
        for s in later:
            lines.append(f"A successful logon for account {s['user']} from the same source {ip} follows the failures [{s['ref']}] at {s['timestamp_raw']}.")
    return lines


# --------------------------------------------------------------------------- sanitisation (copy only)
SANITIZE_RULES = [
    (re.compile(r'(?i)("(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)"\s*:\s*)"[^"]*"'), r'\1"[REDACTED]"'),
    (re.compile(r'''(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s"',;}\]\\]+'''), r"\1=[REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer [REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
]
EMAIL_RULE = (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "[REDACTED_EMAIL]")


def sanitize_file(path, mask_emails=False, out_dir=None):
    """Write a sanitised COPY next to Data/_sanitized; the original is never touched."""
    text, _ = _read_text(path)
    rules = SANITIZE_RULES + ([EMAIL_RULE] if mask_emails else [])
    counts = {}
    for rx, repl in rules:
        text, n = rx.subn(repl, text)
        if n:
            counts[rx.pattern[:30]] = n
    out_dir = Path(out_dir or config.SANITIZED_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    p = Path(path)
    name = p.name[:-3] if p.name.endswith(".gz") else p.name
    out = out_dir / (Path(name).stem + ".sanitized" + Path(name).suffix)
    out.write_text(text, encoding="utf-8")
    return out, sum(counts.values())
