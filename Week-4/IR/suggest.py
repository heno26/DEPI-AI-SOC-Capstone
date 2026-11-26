"""Week 4 rule-based decision suggestions (deterministic, documented, reviewable).

A suggestion is NOT a decision. It is what the playbook rules below would recommend from the
evidence; an analyst accepts it (ir_cli.py accept-suggestions --analyst NAME) or overrides it in the
decisions CSV. The decision log records which decisions came from accepted suggestions.

Rules (applied in order):
  T0 check answered from repository data      -> done      (note = check result + source)
  T0 check not answerable from repository     -> deferred  (note = why)
  T1 proposal that is conditional ("If ...", "Only after ...", "... if ...")
                                               -> deferred  (condition not established in lab data)
  T1 disruptive action (block, isolate, remove, terminate, re-image, reset, blocklist, sinkhole, delete, rate-limit)
       case has an ATT&CK technique labelled observed_pattern -> approved
       otherwise (candidate / hypothesis only)                -> deferred
  T1 other (review, fix, forward logs, restrict, disable password auth, inspect)
                                               -> approved  (low-impact, no service disruption)
"""
import re

CONDITIONAL = re.compile(r"^(if |only after)|\bif (unauthorised|unapproved|the|misuse)\b", re.I)
DISRUPTIVE = re.compile(r"\b(block|blocklist|blocklisting|isolate|isolation|remove|terminate|re-image|reset|sinkhole|delete|"
                        r"edge rate-limit)\b", re.I)


def suggest(item, case):
    tier, action = item["tier"], item["action"]
    if tier == "T2":
        return None, "prohibited automation (Week-3 Tier 2)"
    if tier == "T0":
        ch = item.get("check") or {}
        if ch.get("completed_from_repo"):
            return "done", f"Checked against {ch.get('source')}: {ch.get('result')}"
        return "deferred", f"Not checkable in lab data: {ch.get('result', 'no check defined')}"
    observed = [a for a in case["attack"] if a["confidence"] == "observed_pattern"]
    if CONDITIONAL.search(action):
        return "deferred", "Conditional proposal; its condition is not established by the lab evidence (see case limitations / T0 checks)."
    if DISRUPTIVE.search(action):
        if observed:
            a = observed[0]
            return "approved", f"Behaviour directly visible in evidence: {a['technique']} {a['name']} ({a['basis'][:120]})."
        labels = ", ".join(sorted({a["confidence"] for a in case["attack"]})) or "none"
        return "deferred", f"Disruptive action but evidence is only {labels}; confirm before acting."
    return "approved", "Low-impact review/hardening step with no service disruption; supported by the case evidence."


def annotate(items, cases):
    by = {c["case_id"]: c for c in cases}
    for it in items:
        s, why = suggest(it, by[it["case_id"]])
        it["suggested_decision"] = s
        it["suggestion_basis"] = why
    return items
