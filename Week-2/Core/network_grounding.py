"""Network evidence grounding for Zeek summaries and source-row samples.

E001-style aggregates are DERIVED records, never individual connections.
The module only reads parsed event dictionaries; full-source provenance must be
verified separately. Detection of a traffic pattern is not attribution, a
maliciousness verdict, or evidence of compromise.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address
from Core import dns_grounding, network_semantics, tcp_retry_grounding
import re

RULE = "NETWORK_VERTICAL_PORT_SCAN"
AGGREGATE_KIND = "VERIFIED_FULL_SOURCE_AGGREGATE_NOT_RAW_ZEEK_EVENT"
RAW_KIND = "ZEEK_CONN_ORIGINAL_SOURCE_ROW"
REF = re.compile(r"E\d{3,5}\Z")


def _field(ev, key):
    # Core.log_parser flattens event JSON into fields; support both its output
    # and the original dict for deterministic fixture testing.
    fields = ev.get("fields") if isinstance(ev.get("fields"), dict) else ev
    return fields.get(key)


def _int(value):
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
        if str(value).strip() != str(n):
            return None
        return n
    except (TypeError, ValueError, OverflowError):
        return None


def _ip(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _key(ev):
    return _field(ev, "record_kind")


def _refs(events):
    seen = set()
    for ev in events:
        ref = ev.get("ref")
        if isinstance(ref, str) and REF.fullmatch(ref) and ref not in seen:
            seen.add(ref)
            yield ev


def _state_counts(ev):
    counts = {}
    flat = ev.get("fields") if isinstance(ev.get("fields"), dict) else ev
    prefix = "scan_pair_conn_states."
    for key, value in flat.items():
        if key.startswith(prefix):
            count = _int(value)
            if count is None or count < 0:
                return None
            counts[key[len(prefix):]] = count
    nested = flat.get("scan_pair_conn_states")
    if not counts and isinstance(nested, dict):
        for key, value in nested.items():
            count = _int(value)
            if count is None or count < 0:
                return None
            counts[str(key)] = count
    return counts


def _duration(ev):
    a = _field(ev, "scan_pair_first_utc")
    b = _field(ev, "scan_pair_last_utc")
    if not isinstance(a, str) or not isinstance(b, str):
        return None
    try:
        start = datetime.fromisoformat(a.replace("Z", "+00:00"))
        end = datetime.fromisoformat(b.replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None:
            return None
        diff = (end - start).total_seconds()
        return round(diff, 3) if 0 <= diff <= 31536000 else None
    except ValueError:
        return None


def detect_network(events):
    """Report strongly supported vertical port-scan patterns in supplied input.

    Does not fetch, re-hash or validate the original capture. A declared full-
    source aggregate is assessed as supplied and its provenance remains pending
    unless the external NT01 verify-case step has succeeded.
    """
    items = list(_refs(events))
    aggregates = [e for e in items if _key(e) == AGGREGATE_KIND]
    raw = [e for e in items if _key(e) == RAW_KIND]
    findings = []
    context = []
    for agg in aggregates:
        src, dst = _ip(_field(agg, "src_ip")), _ip(_field(agg, "dst_ip"))
        flows = _int(_field(agg, "scan_pair_tcp_records"))
        ports = _int(_field(agg, "scan_pair_distinct_destination_ports"))
        states = _state_counts(agg)
        duration = _duration(agg)
        sourcehash = _field(agg, "source_sha256")
        if (not src or not dst or src == dst or flows is None or ports is None or
                flows < 100 or ports < 100 or ports > 65536 or ports > flows or
                duration is None or not isinstance(sourcehash, str) or
                not re.fullmatch(r"[a-fA-F0-9]{64}", sourcehash) or states is None or
                (states and sum(states.values()) != flows)):
            continue
        # Cross-check full-source aggregate against several selected original rows;
        # do not count the aggregate as an independent connection.
        witnesses = []
        witness_ports = set()
        for ev in raw:
            if (_field(ev, "proto") == "tcp" and
                _ip(_field(ev, "src_ip")) == src and
                _ip(_field(ev, "dst_ip")) == dst and
                _int(_field(ev, "dst_port")) is not None):
                port = _int(_field(ev, "dst_port"))
                if 0 <= port <= 65535:
                    witnesses.append(ev["ref"])
                    witness_ports.add(port)
        if len(witness_ports) < 5 or len(witness_ports) > ports:
            continue
        refs = [agg["ref"]] + witnesses
        high = flows >= 500 and ports >= 200 and (duration <= 3600)
        findings.append({
            "rule_id": RULE,
            "label": "Vertical TCP destination-port sweep pattern",
            "confidence_in_observed_pattern": "high" if high else "medium",
            "evidence_refs": sorted(set(refs)),
            "observation": (f"Supplied aggregate reports {flows} TCP flow records from {src} "
                            f"to {dst} across {ports} distinct destination ports "
                            f"in {duration:.3f}s; sampled Zeek rows corroborate endpoints."),
            "outcome": ("Pattern is consistent with vertical TCP port scanning; authorization, "
                        "attacker intent, port openness and successful compromise NOT established."),
            "details": {
                "source_ip": src, "destination_ip": dst,
                "tcp_records": flows, "distinct_destination_ports": ports,
                "connection_state_counts": states, "duration_seconds": duration,
                "aggregate_ref": agg["ref"], "sample_source_refs": sorted(set(witnesses)),
                "aggregate_is_raw_connection": False,
                "full_source_integrity_checked_in_this_function": False,
                "source_sha256_claimed_by_aggregate": sourcehash,
            },
            "status": "investigation_indicator_not_incident_verdict",
        })
    if aggregates:
        context.append({
            "rule_id": "NETWORK_COMPUTED_AGGREGATE_CONTEXT",
            "evidence_refs": [e["ref"] for e in aggregates],
            "observation": "Full-source aggregate supplied; it is NOT a raw Zeek connection.",
            "security_limit": "Re-verify original capture SHA256 and the aggregate derivation separately.",
        })
    dns = dns_grounding.detect_dns(events)
    findings.extend(dns["behavioral_findings"])
    context.extend(dns["context_observations"])
    retry = tcp_retry_grounding.detect_tcp_retry_sequences(items)
    findings.extend(retry["behavioral_findings"])
    context.extend(retry["context_observations"])
    return {"behavioral_findings": findings, "context_observations": context}


def prompt_notes(events):
    result = detect_network(events)
    # A DNS finding is NOT a vertical TCP scan. Only give the model port-scan
    # instructions when an independently grounded TCP scan finding exists.
    tcp_scan = any(f.get("rule_id") == RULE for f in result["behavioral_findings"])
    if not tcp_scan:
        return dns_grounding.prompt_notes(events) + tcp_retry_grounding.prompt_notes(events)
    return [
        "NETWORK GROUNDING: Source-provided full-file metrics and separate Zeek source rows "
        "support a vertical TCP port scan PATTERN. Explicitly name vertical port scanning, "
        "its source and target and the distinction between targeted ports and open ports.",
        "NETWORK EVIDENCE BOUNDARY: Computed aggregate E001 is NOT an individual flow, "
        "packet, connection attempt or open port. E002+ are original sampled flows. "
        "Connection REJ alone does not prove firewall action. Authorization and compromise "
        "are unknown; do not assert a malicious actor or successful intrusion.",
        "NETWORK REPORT: Use [E###] references in every finding and complete timeline rows. "
        "Use source (id.orig_h) -> destination (id.resp_h) direction. Do not classify "
        "source-line SHA-256 evidence integrity hashes as malware IOCs.",
    ] + dns_grounding.prompt_notes(events) + tcp_retry_grounding.prompt_notes(events)


def review_requests(sections, events):
    result = detect_network(events)
    tcp_scan = any(f.get("rule_id") == RULE for f in result["behavioral_findings"])
    # Presence of DNS grounding cannot activate TCP-specific review checks.
    tcp_aggregates = [e for e in _refs(events) if _key(e) == AGGREGATE_KIND]
    flags = []
    relevant = "\n".join(str(sections.get(k, "")) for k in (
        "EXECUTIVE SUMMARY", "SIGNIFICANT SECURITY EVENTS", "SUSPICIOUS ACTIVITIES", "POTENTIAL ATTACK INDICATORS"))
    if tcp_scan and relevant.strip() and not re.search(r"\b(?:port[ -]?scan(?:ning)?|vertical[ -]?(?:scan|sweep)|port[ -]?sweep)\b", relevant, re.I):
        flags.append({"check": "network_vertical_scan_not_identified", "severity": "high",
                      "section": "SUSPICIOUS ACTIVITIES", "value": relevant[:160],
                      "message": "Verified-in-input aggregate and sampled conn.log rows support a vertical TCP port sweep; report does not identify the pattern.",
                      "analyst_disposition": "Unreviewed"})
    # E001 can refer to an aggregate in more than one dataset: only apply the
    # connection-specific E001 rule when the input actually contains conn.log
    # aggregate evidence. DNS aggregates are handled by dns_grounding.
    for section, body in sections.items() if tcp_aggregates else ():
        if section not in ("EXECUTIVE SUMMARY", "SIGNIFICANT SECURITY EVENTS", "SUSPICIOUS ACTIVITIES", "EVIDENCE REFERENCES", "INCIDENT TIMELINE"):
            continue
        # Conservative: review when a single-connection description explicitly cites E001.
        for line in str(body).splitlines():
            if re.search(r"\bE001\b", line) and re.search(r"\b(?:connection attempt|single (?:connection|flow)|on port \d+)\b", line, re.I):
                if not re.search(r"\b(?:not|isn['’]t|never)\s+(?:an?\s+)?(?:individual|single|raw)\b", line, re.I):
                    flags.append({"check": "network_aggregate_misread_as_raw_event", "severity": "high",
                                  "section": section, "value": line[:160],
                                  "message": "E001 is a computed full-source aggregate, not an individual Zeek connection.",
                                  "analyst_disposition": "Unreviewed"})
                    break
        if any(f["check"] == "network_aggregate_misread_as_raw_event" for f in flags):
            break
    flags.extend(network_semantics.review_requests(sections, events))
    flags.extend(dns_grounding.review_requests(sections, events))
    flags.extend(tcp_retry_grounding.review_requests(sections, events))
    return flags
