"""Orchestrates one analysis run: prompt -> local Ollama -> parse -> validate -> record.
The result is always created with review status 'Pending Review'; this code never approves anything."""
import hashlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import config
from Core import alert_triage, log_parser, ollama_client, validator

HEADINGS = {
    "log_analysis": ["EXECUTIVE SUMMARY", "LOG SOURCE", "SIGNIFICANT SECURITY EVENTS", "SUSPICIOUS ACTIVITIES",
                     "EVIDENCE REFERENCES", "INCIDENT TIMELINE", "EXTRACTED IOCS", "POTENTIAL ATTACK INDICATORS",
                     "CONFIDENCE AND UNCERTAINTY", "MISSING INFORMATION", "RECOMMENDED INVESTIGATION STEPS"],
    "alert_triage": ["ALERT SUMMARY", "VERDICT", "CONFIDENCE", "PRIORITY", "EVIDENCE SUPPORTING MALICIOUS ACTIVITY",
                     "EVIDENCE SUPPORTING BENIGN ACTIVITY", "RELEVANT IOCS", "MISSING INFORMATION", "ESCALATION", "ANALYST ACTIONS"],
    "detection_improvement": [],
}
SUGGESTION_FIELDS = [("Detection Gap", "observed_detection_gap"), ("Supporting Evidence", "supporting_evidence"),
                     ("Suggested Improvement", "suggested_improvement"), ("Expected Benefit", "expected_benefit"),
                     ("False-Positive Risk", "potential_false_positive_risk")]
HUMAN_REVIEW_TEXT = ("Required. An analyst must validate this note against the evidence. No Wazuh rule is modified "
                     "or deployed by this application.")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_prompt(task):
    path = config.PROMPTS_DIR / config.PROMPT_FILES[task]
    text = path.read_text(encoding="utf-8")
    version = (re.search(r'#\s*prompt_version:\s*(\S+)', text) or [None, "unknown"])[1]
    body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("# ")).strip("\n")
    return body, version, hashlib.sha256(text.encode()).hexdigest(), path.name


def _norm(s):
    return re.sub(r'[^A-Z ]', '', s.upper()).strip()


def parse_sections(text, headings):
    keys = {_norm(h): h for h in headings}
    # Equivalent report headings are normalized deliberately, not treated as
    # extra paragraphs in the preceding evidence section.
    aliases = {
        "EXTRACTED IOCS INDICATORS OF COMPROMISE": "EXTRACTED IOCS",
        "RECOMMENDATIONS": "RECOMMENDED INVESTIGATION STEPS",
        "SUSPICIOUS ACTIVITY": "SUSPICIOUS ACTIVITIES",
    }
    sections, cur, buf = {}, None, []
    for ln in text.splitlines():
        trimmed = ln.strip()
        is_markdown_heading = bool(re.match(r'^#{1,6}\s+\S', trimmed))
        cand = _norm(re.sub(r'^\s*(?:#{1,6}|\*\*|\d+[.)])\s*', '', ln).replace("**", "").rstrip(":"))
        hit = next((keys[k] for k in keys if cand == k or (cand.startswith(k) and len(cand) <= len(k) + 3)), None)
        if not hit and cand in aliases and aliases[cand] in headings:
            hit = aliases[cand]
        if hit and len(trimmed) < 100:
            if cur:
                sections[cur] = "\n".join(buf).strip()
            cur, buf = hit, []
        elif is_markdown_heading:
            # Unknown Markdown headings must close the previous known section.
            # Otherwise RECOMMENDATIONS / IOC bullets get falsely attributed
            # to SIGNIFICANT SECURITY EVENTS (NT-02 F009-F013).
            if cur:
                sections[cur] = "\n".join(buf).strip()
            cur, buf = None, []
        elif cur:
            buf.append(ln)
    if cur:
        sections[cur] = "\n".join(buf).strip()
    return sections


def parse_timeline(section_text):
    rows = []
    for ln in section_text.splitlines():
        s = ln.strip()
        if not s.startswith("|") or re.match(r'^\|[\s:\-|]+\|?$', s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if cells and cells[0].lower().startswith("timestamp"):
            continue
        if len(cells) >= 2:
            rows.append({"timestamp": cells[0], "event": cells[1], "source": cells[2] if len(cells) > 2 else "",
                         "host_user": cells[3] if len(cells) > 3 else "", "evidence_ref": cells[4] if len(cells) > 4 else "",
                         "refs_found": validator.REF_RE.findall(s)})
    return rows



def _timestamp_matches_event(ts, event):
    """Match timestamps while allowing sub-millisecond precision differences."""

    # Preserve existing exact-text matching behavior.
    if ts in (event.get("raw") or ""):
        return True

    from datetime import datetime, timedelta, timezone

    def parse_utc(value):
        if not isinstance(value, str) or not value.strip():
            return None

        value = value.strip()

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(value)

            if dt.utcoffset() is None:
                return None

            return dt.astimezone(timezone.utc)

        except (ValueError, TypeError, OverflowError):
            return None

    reported = parse_utc(ts)

    if reported is None:
        return False

    tolerance = timedelta(milliseconds=1)

    for field in ("timestamp_raw", "timestamp_utc"):
        actual = parse_utc(event.get(field))

        if actual is not None and abs(reported - actual) < tolerance:
            return True

    return False


def timeline_flags(rows, events):
    by_ref = {e["ref"]: e for e in events}
    flags = []

    def add(check, sev, value, msg):
        flags.append({"check": check, "severity": sev, "section": "INCIDENT TIMELINE", "value": value, "message": msg, "analyst_disposition": "Unreviewed"})

    for r in rows:
        refs = [x for x in r["refs_found"] if x in by_ref]
        if not r["refs_found"]:
            add("timeline_row_without_ref", "medium", r["event"][:100], "Timeline row has no evidence reference.")
            continue
        ts = r["timestamp"].strip()
        if ts and ts.lower() not in ("not provided", "unknown", "n/a") and refs:
            if not any(_timestamp_matches_event(ts, by_ref[x]) for x in refs):
                add("timeline_timestamp_mismatch", "high", ts, f"Timestamp does not appear in the cited event(s) {', '.join(refs)}.")
    return flags


def evidence_timeline(events):
    rows = []
    for e in events:
        who = " / ".join(x for x in (e.get("host"), e.get("user")) if x)
        rows.append({"timestamp": e["timestamp_raw"] or "Not provided", "timestamp_utc": e.get("timestamp_utc"),
                     "event": log_parser.render_event(e, 160).split("] ", 1)[1], "source": e["source_kind"],
                     "host_user": who or "Not provided", "evidence_ref": e["ref"]})
    return rows


def build_input(events, fixed_chars, num_ctx, num_predict):
    budget = int((num_ctx - num_predict - config.CONTEXT_MARGIN_TOKENS) * config.CHARS_PER_TOKEN) - fixed_chars
    budget = max(budget, 600)
    for cap in (config.MAX_EVENT_CHARS_IN_PROMPT, 400, 220):
        lines = [log_parser.render_event(e, cap) for e in events]
        if sum(len(x) + 1 for x in lines) <= budget:
            return events, "\n".join(lines), cap, budget
    keep, used = [], 0
    for e in events:
        ln = log_parser.render_event(e, 220)
        if used + len(ln) + 1 > budget:
            break
        keep.append(ln)
        used += len(ln) + 1
    return events[:len(keep)], "\n".join(keep), 220, budget


def parsed_from_record(record):
    """Reload the original input of a saved result and confirm its hash is unchanged."""
    p = Path(record["input"]["path"])
    if not p.is_file():
        raise log_parser.InputError(f"Original input file no longer exists: {p}")
    parsed = log_parser.load_file(p, source_hint=record["input"]["source_type"])
    if parsed["sha256"] != record["input"]["sha256"]:
        parsed["warnings"].append("WARNING: file hash differs from the hash recorded in the saved result (file changed).")
    return parsed


def run_task(task, parsed, selected_refs=None, model=None, options=None, origin_note=None, url=None, progress=None):
    """Execute one task. Raises ollama_client.OllamaError on generation failure (no silent fallback)."""
    say = progress or (lambda m: None)
    model = model or config.PRIMARY_MODEL
    opts = dict(config.GENERATION)
    opts.update({k: v for k, v in (options or {}).items() if v is not None})
    events_all = parsed["events"]
    events = [e for e in events_all if not selected_refs or e["ref"] in selected_refs]

    template, pversion, psha, pfile = load_prompt(task)
    reference = log_parser.reference_notes(events)
    # Curated, case-matched rules; never raw analyst feedback.
    from Core import feedback_learning
    if task in ("log_analysis", "alert_triage"):
        reference.extend(feedback_learning.prompt_guidance(events))
    # Source-derived, bounded instructions independent of the model.
    from Core import grounded_detection
    if task in ("log_analysis", "alert_triage"):
        reference.extend(grounded_detection.prompt_notes(events))
    facts = log_parser.auth_stats(events)
    facts_text = "\n".join("- " + f for f in facts) or "None"
    ref_text = "\n".join("- " + r for r in reference)
    head, tail = template.split("{{INPUT}}", 1)
    nonce = uuid.uuid4().hex[:10]
    head = head.replace("{{NONCE}}", nonce).replace("{{REFERENCE}}", ref_text).replace("{{FACTS}}", facts_text)
    tail = tail.replace("{{NONCE}}", nonce)
    sent, input_text, cap, budget = build_input(events, len(head) + len(tail), opts["num_ctx"], opts["num_predict"])
    prompt = head + input_text + tail

    extra_flags = []
    inj = validator.injection_scan(events)
    for i in inj:
        extra_flags.append({"check": "prompt_injection_in_input", "severity": "medium", "section": "INPUT", "value": i["value"],
                            "message": f"Input event {i['ref']} contains instruction-like text. It was treated as data, not instructions.",
                            "analyst_disposition": "Unreviewed"})
    if len(sent) < len(events):
        extra_flags.append({"check": "input_truncated", "severity": "high", "section": "INPUT", "value": f"{len(sent)} of {len(events)} events sent",
                            "message": f"Only {sent[0]['ref']}..{sent[-1]['ref']} fit the context budget. Split the file or raise num_ctx (check GPU offload).",
                            "analyst_disposition": "Unreviewed"})
    say(f"Sending {len(sent)} event(s) to local model {model} (prompt ~{len(prompt)} chars, num_ctx={opts['num_ctx']}). This can take 30-120 s ...")
    gen = ollama_client.generate(prompt, model=model, options=opts, url=url)

    headings = HEADINGS[task]
    sections = parse_sections(gen.text, headings) if headings else {}
    record = {
        "analysis_id": f"AN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}",
        "schema_version": "week2-1", "task": task, "created_utc": utc_now(),
        "references": {"alert_id": None, "incident_ref": None, "note": "incident_ref is reserved for Week 3/4 correlation"},
        "input": {"filename": parsed["name"], "path": parsed["path"], "sha256": parsed["sha256"], "format": parsed["format"],
                  "compressed": parsed["compressed"], "source_type": parsed["source_type"], "evidence_class": parsed["evidence_class"],
                  "event_count": len(events_all), "events_analysed": [e["ref"] for e in sent], "warnings": parsed["warnings"]},
        "model": {"name": gen.model, "options": gen.options_used, "attempts": gen.attempts, "retry_used": gen.retry_used,
                  "done_reason": gen.done_reason, "tokens_per_second": gen.tokens_per_second, "wall_seconds": gen.wall_seconds},
        "prompt": {"file": pfile, "version": pversion, "sha256": psha, "nonce_delimiter_used": True},
        "events": events, "facts": facts, "ioc_context": validator.ioc_context(events),
        "risk_signals": validator.risk_signals(events), "benign_context": validator.benign_context(events),
        "evidence_timeline": evidence_timeline(events),
        "ai_output": {"raw_text": gen.text, "sections": sections, "truncated": gen.truncated},
    }

    # Prompt provenance records the reviewed feedback KB fingerprint.
    record["prompt"]["feedback"] = feedback_learning.feedback_audit(events)
    # Record deterministic observations alongside the AI draft. No verdict or action.
    if task in ("log_analysis", "alert_triage"):
        record["grounding"] = grounded_detection.detect(sent)
    flags = list(extra_flags)
    if task == "detection_improvement":
        blocks = re.split(r'(?im)^\s*#{0,4}\s*SUGGESTION\s*\d+\s*:?\s*$', gen.text)[1:]
        suggestions = []
        for n, b in enumerate(blocks, 1):
            item = {"number": n}
            for label, key in SUGGESTION_FIELDS:
                m = re.search(rf'(?is){re.escape(label)}\s*:\s*(.*?)(?=\n\s*(?:{"|".join(re.escape(l) for l, _ in SUGGESTION_FIELDS)})\s*:|\Z)', b)
                item[key] = m.group(1).strip() if m else None
            item["human_review_requirement"] = HUMAN_REVIEW_TEXT
            suggestions.append(item)
        record["suggestions"] = suggestions
        sections = {f"SUGGESTION {s['number']}": b for s, b in zip(suggestions, blocks)}
        if not suggestions:
            flags.append({"check": "missing_section", "severity": "high", "section": "(whole output)", "value": "SUGGESTION blocks",
                          "message": "No '### SUGGESTION n' blocks could be parsed.", "analyst_disposition": "Unreviewed"})
        for s in suggestions:
            for _, key in SUGGESTION_FIELDS:
                if not s[key]:
                    flags.append({"check": "missing_section", "severity": "low", "section": f"SUGGESTION {s['number']}", "value": key,
                                  "message": f"Suggestion {s['number']} lacks field '{key}'.", "analyst_disposition": "Unreviewed"})
    flags += validator.validate_output(gen.text, sections, sent, facts, headings, truncated=gen.truncated)
    # Additional evidence-grounding requests; all still require human review.
    if task in ("log_analysis", "alert_triage"):
        flags.extend(grounded_detection.review_requests(sections, sent))
    if task == "log_analysis":
        rows = parse_timeline(sections.get("INCIDENT TIMELINE", ""))
        record["ai_output"]["timeline_rows"] = rows
        flags += timeline_flags(rows, sent)
    if task == "alert_triage":
        record["triage"] = alert_triage.parse_triage(sections, sent)
        record["references"]["alert_id"] = record["triage"]["alert_id"]
        flags += alert_triage.triage_flags(record["triage"], sent)

    for i, f in enumerate(flags, 1):
        f["id"] = f"F{i:03d}"
    record["validation"] = {
        "flags": flags, "severity_counts": validator.summarize_flags(flags),
        "automated_checks": ["structure/truncation", "IP/URL/domain/hash/CVE/email/file exact-string support", "defang preservation",
                             "timestamp source-text check; timeline timestamp <1ms tolerance", "entity (key=value, backtick, host-token) support",
                             "evidence-reference existence and presence", "fabricated rule/agent ID", "Event ID semantics (heuristic: Windows 1102/5145/4624/4625/4732)",
                             "unsupported certainty / attribution", "none-claim vs code-detected risk signals", "timeline timestamp vs cited event",
                             "input prompt-injection scan"] + (["triage consistency"] if task == "alert_triage" else []),
        "disclaimer": "Flags request human review; they are not proof of hallucination. Passing all checks does not prove correctness.",
    }
    record["review"] = {"status": "Pending Review", "analyst": None, "final_classification": None, "final_priority": None,
                        "correct_findings": [], "incorrect_findings": [], "missing_evidence": [], "hallucinations": [],
                        "notes": "", "reviewed_utc": None, "history": []}
    return record
