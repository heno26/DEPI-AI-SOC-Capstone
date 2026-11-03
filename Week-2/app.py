#!/usr/bin/env python3
"""Week 2 - AI-Assisted SOC Analysis (local only). Run `python app.py` for the menu.

The AI recommends; the human analyst decides. Nothing is blocked, isolated, deployed or approved automatically.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from Core import alert_triage, analysis, log_parser, ollama_client, store

BANNER = """
==============================================================
 Week 2 - AI-Assisted SOC Analysis (LOCAL ONLY, no cloud AI)
 AI output is an UNVERIFIED DRAFT. The analyst decides.
==============================================================
"""


def ask(prompt, default=""):
    try:
        v = input(prompt).strip()
    except EOFError:
        return default
    return v or default


def yes(prompt):
    return ask(prompt + " [y/N]: ").lower() in ("y", "yes")


# ------------------------------------------------------------------ file selection
def list_data_files():
    files = []
    for sub in ("Windows", "Linux", "Network", "Wazuh", "Generic"):
        d = config.DATA_DIR / sub
        if d.is_dir():
            files += [p for p in sorted(d.iterdir()) if p.is_file() and not p.name.startswith(".")]
    return files


def choose_file():
    files = list_data_files()
    print("\nSample / collected inputs (Data/):")
    for i, p in enumerate(files, 1):
        print(f"  {i:2d}. {p.parent.name}/{p.name}")
    print("   p. Enter a path to another file")
    c = ask("Select: ")
    if c.lower() == "p":
        return Path(ask("Path: ").strip('"'))
    if c.isdigit() and 1 <= int(c) <= len(files):
        return files[int(c) - 1]
    print("Invalid selection.")
    return None


# ------------------------------------------------------------------ model handling
def gen_options(args):
    return {"temperature": getattr(args, "temperature", None), "repeat_penalty": getattr(args, "repeat_penalty", None),
            "num_ctx": getattr(args, "num_ctx", None), "num_predict": getattr(args, "num_predict", None)}


def check_ready(model, interactive):
    """Return the model to use, or None. Never switches model without the analyst's explicit yes."""
    st = ollama_client.check_environment()
    if not st["server_up"]:
        print(f"\n[ERROR] {st['error']}")
        return None
    if ollama_client.resolve_model(model, st["installed"]):
        return model
    print(f"\n[ERROR] Model '{model}' is not installed. Run: ollama pull {model}")
    backup = st["backup"]
    if (
    interactive
    and sys.stdout.isatty()
    and backup
    and model != backup
    and yes(f"Use backup model {backup} instead?")
):
        return backup

    return None


# ------------------------------------------------------------------ display
def show_input_summary(parsed):
    print(f"\nLoaded: {parsed['name']}  format={parsed['format']}  source_type={parsed['source_type']}  events={len(parsed['events'])}")
    print(f"SHA-256: {parsed['sha256']}")
    print(f"Evidence class: {parsed['evidence_class']}")
    for w in parsed["warnings"]:
        print(f"  [warning] {w}")


def show_result(rec):
    print("\n" + "=" * 62)
    print(f"{rec['analysis_id']}  task={rec['task']}  model={rec['model']['name']}")
    print(f"settings={rec['model']['options']}  retry_used={rec['model']['retry_used']}  {rec['model']['tokens_per_second']} tok/s")
    print("=" * 62)
    if rec["task"] == "alert_triage":
        t = rec["triage"]
        print(f"Alert ID: {t['alert_id']} ({t['alert_id_source']})\nDescription: {t['description']}")
        print(f"ORIGINAL SIEM severity: {t['original_severity']['value']}   |   AI-RECOMMENDED priority: {t['recommended_priority']}")
        print(f"AI classification: {t['recommended_classification']}   Escalation: {t['escalation']['recommended']}   Review: {t['human_review_status']}")
        print("-" * 62)
    print(rec["ai_output"]["raw_text"])
    if rec["ai_output"]["truncated"]:
        print("\n[!] OUTPUT WAS TRUNCATED (token limit reached). Treat missing sections as unknown.")
    print("\n--- IOC context (extracted by code; External reputation not checked.) ---")
    for o in rec["ioc_context"][:25]:
        print(f"  {o['type']:9s} {o['value']}  {o['scope']}  refs={','.join(o['refs'][:4])}")
    fl = rec["validation"]["flags"]
    c = rec["validation"]["severity_counts"]
    print(f"\n--- Automated validation: {len(fl)} flag(s)  high={c.get('high',0)} medium={c.get('medium',0)} low={c.get('low',0)} ---")
    print("(Flags are review requests, not proof of hallucination. No flags does not prove correctness.)")
    for f in fl:
        print(f"  {f['id']} [{f['severity']}] {f['check']} | section={f['section']} | value={str(f['value'])[:70]}\n        {f['message']}")


# ------------------------------------------------------------------ review
def review_interactive(rec, results_dir=None):
    print("\n=== HUMAN ANALYST REVIEW (the application never approves its own conclusions) ===")
    disp = {}
    for f in rec["validation"]["flags"]:
        print(f"\n{f['id']} [{f['severity']}] {f['check']}  value={str(f['value'])[:80]}\n  {f['message']}")
        c = ask("  [h] confirmed hallucination  [f] false alarm  [n] needs follow-up  [Enter] skip: ").lower()
        disp[f["id"]] = {"h": "Confirmed hallucination", "f": "False alarm", "n": "Needs follow-up"}.get(c, "Unreviewed")
    unrev = [k for k, v in disp.items() if v == "Unreviewed"]
    s = ask("\nReview status - [a]pproved [c]orrected [r]ejected [p]ending: ", "p").lower()
    status = {"a": "Approved", "c": "Corrected", "r": "Rejected"}.get(s, "Pending Review")
    if status == "Approved" and unrev and ask(f"{len(unrev)} flag(s) not dispositioned. Type APPROVE to approve anyway: ") != "APPROVE":
        status = "Pending Review"
        print("Status kept as Pending Review.")
    rv = {"status": status, "analyst": ask("Analyst name: ") or None}
    if rec["task"] == "alert_triage":
        print("Final classification: 1) Likely True Positive 2) Likely False Positive 3) Needs Investigation  (Enter = none)")
        c = ask("> ")
        rv["final_classification"] = alert_triage.CLASSIFICATIONS[int(c) - 1] if c in ("1", "2", "3") else None
        print("Final priority: 1) P1 Critical 2) P2 High 3) P3 Medium 4) P4 Low  (Enter = none)")
        c = ask("> ")
        rv["final_priority"] = alert_triage.PRIORITIES[int(c) - 1] if c in ("1", "2", "3", "4") else None
    for key, label in (("correct_findings", "Correct findings"), ("incorrect_findings", "Incorrect findings"),
                       ("missing_evidence", "Missing evidence the AI ignored"), ("hallucinations", "Hallucinations (describe)")):
        v = ask(f"{label} (separate with ';'): ")
        rv[key] = [x.strip() for x in v.split(";") if x.strip()]
    rv["notes"] = ask("Review notes: ")
    store.apply_review(rec, rv, disp, results_dir=results_dir)
    print(f"Review saved. Status: {rec['review']['status']}")


# ------------------------------------------------------------------ workflows
def run_and_save(task, parsed, selected_refs, model, args, interactive, review=True):
    say = print
    while True:
        try:
            rec = analysis.run_task(task, parsed, selected_refs, model=model, options=gen_options(args), progress=say)
            break
        except ollama_client.OllamaNotRunning as e:
            print(f"\n[ERROR] Ollama is not running: {e}")
            return None
        except ollama_client.ModelNotInstalled as e:
            print(f"\n[ERROR] {e}")
            return None
        except ollama_client.OllamaError as e:
            print(f"\n[GENERATION FAILED] {e}")
            for a in e.attempts:
                print(f"   attempt {a['attempt']}: {a['outcome']} settings={a['options']} {a.get('error', '')}")
            st = ollama_client.check_environment()
            if interactive and model != config.BACKUP_MODEL and st.get("backup") and yes(f"Run again with the backup model {config.BACKUP_MODEL}? (your choice; recorded)"):
                model = config.BACKUP_MODEL
                continue
            return None
    show_result(rec)
    path = store.save_result(rec)
    print(f"\nSaved: {path}")
    if review and interactive:
        if yes("Review this result now?"):
            review_interactive(rec)
    else:
        print("Review status: Pending Review (use `python app.py review <analysis_id>`).")
    return rec


def load_input(path, args, interactive):
    hint = getattr(args, "source_type", "auto") or "auto"

    try:
        # Validate and parse the input before asking questions.
        parsed = log_parser.load_file(
            path,
            source_hint=hint,
            origin=None
        )

        # Ask for provenance confirmation only for Wazuh data.
        if (
            interactive
            and parsed.get("source_type") == "wazuh"
            and not Path(path).name.upper().startswith("SYNTHETIC")
        ):
            if yes(
                "Is this a genuine Wazuh export that you collected yourself?"
            ):
                parsed = log_parser.load_file(
                    path,
                    source_hint=hint,
                    origin="genuine_wazuh"
                )

    except log_parser.InputError as e:
        print(f"\n[INPUT ERROR] {e}")
        return None

    show_input_summary(parsed)
    return parsed


def do_task(task, path, args, interactive=True, alert=None, all_alerts=False):
    model = check_ready(getattr(args, "model", None) or config.PRIMARY_MODEL, interactive)
    if not model:
        return
    parsed = load_input(path, args, interactive)
    if not parsed:
        return
    if task == "alert_triage":
        units = alert_triage.alert_units(parsed)
        if len(units) > 1 and alert is None and not all_alerts:
            for i, (label, evs) in enumerate(units, 1):
                print(f"  {i}. [{evs[0]['ref']}] {label}")
            c = ask("Alert number (or 'a' for all): ")
            if c.lower() == "a":
                all_alerts = True
            elif c.isdigit() and 1 <= int(c) <= len(units):
                alert = int(c)
            else:
                print("Invalid selection.")
                return
        chosen = units if all_alerts else [units[(alert or 1) - 1]]
        for label, evs in chosen:
            run_and_save(task, parsed, {e["ref"] for e in evs}, model, args, interactive, review=not getattr(args, "no_review", False))
    else:
        run_and_save(task, parsed, None, model, args, interactive, review=not getattr(args, "no_review", False))


def do_detect(args, interactive=True, from_result=None):
    if from_result:
        try:
            rec = store.load_result(from_result)
            parsed = analysis.parsed_from_record(rec)
        except (FileNotFoundError, log_parser.InputError) as e:
            print(f"[ERROR] {e}")
            return
        show_input_summary(parsed)
        model = check_ready(getattr(args, "model", None) or config.PRIMARY_MODEL, interactive)
        if model:
            run_and_save("detection_improvement", parsed, None, model, args, interactive, review=not getattr(args, "no_review", False))
    else:
        path = args.file if getattr(args, "file", None) else choose_file()
        if path:
            do_task("detection_improvement", path, args, interactive)


def menu_review():
    recs = store.list_results()
    if not recs:
        print("No saved results yet.")
        return
    for i, r in enumerate(recs, 1):
        print(f"  {i:2d}. {r['analysis_id']}  {r['task']:22s} {r['input']['filename'][:34]:34s} {r['review']['status']}")
    c = ask("Open number (Enter = back): ")
    if c.isdigit() and 1 <= int(c) <= len(recs):
        rec = recs[int(c) - 1]
        show_result(rec)
        if yes("Record / update analyst review?"):
            review_interactive(rec)


def show_status():
    st = ollama_client.check_environment()
    if not st["server_up"]:
        print(f"[ERROR] {st['error']}")
        return
    print(f"Ollama up (version {st['version']}). Installed: {', '.join(st['installed']) or 'none'}")
    print(f"Primary {config.PRIMARY_MODEL}: {'OK' if st['primary'] else 'MISSING - ollama pull ' + config.PRIMARY_MODEL}")
    print(f"Backup  {config.BACKUP_MODEL}: {'OK' if st['backup'] else 'missing (optional)'}")
    print(f"Generation settings: {config.GENERATION}")


def menu(args):
    print(BANNER)
    while True:
        print("\n1. Analyze Security Logs\n2. Triage SIEM Alert\n3. Generate Detection Improvement Notes\n4. Review Previous Results\n"
              "5. Sanitize a copy of a log file\n6. Check Ollama / models\n7. Export validation log + detection notes (markdown)\n0. Exit")
        c = ask("Select: ")
        if c == "1":
            p = choose_file()
            if p:
                do_task("log_analysis", p, args)
        elif c == "2":
            p = choose_file()
            if p:
                do_task("alert_triage", p, args)
        elif c == "3":
            do_detect(args)
        elif c == "4":
            menu_review()
        elif c == "5":
            p = choose_file()
            if p:
                try:
                    out, n = log_parser.sanitize_file(p, mask_emails=yes("Also mask email addresses?"))
                    print(f"Sanitized COPY written: {out} ({n} redactions). Original untouched.")
                except log_parser.InputError as e:
                    print(f"[INPUT ERROR] {e}")
        elif c == "6":
            show_status()
        elif c == "7":
            for p in store.export_markdown():
                print("Wrote", p)
        elif c == "0":
            return


def build_parser():
    ap = argparse.ArgumentParser(description="Week 2 local AI-assisted SOC analysis")
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("--model", help=f"default {config.PRIMARY_MODEL}")
        p.add_argument("--temperature", type=float)
        p.add_argument("--repeat-penalty", dest="repeat_penalty", type=float)
        p.add_argument("--num-ctx", dest="num_ctx", type=int)
        p.add_argument("--num-predict", dest="num_predict", type=int)
        p.add_argument("--source-type", dest="source_type", default="auto", choices=["auto", "windows", "linux", "network", "wazuh", "generic"])
        p.add_argument("--no-review", dest="no_review", action="store_true", help="leave result as Pending Review")

    for name, helptext in (("analyze", "log analysis"), ("triage", "alert triage"), ("detect", "detection improvement notes")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("file", nargs="?")
        common(p)
        if name == "triage":
            p.add_argument("--alert", type=int, help="1-based alert number in the file")
            p.add_argument("--all", dest="all_alerts", action="store_true")
        if name == "detect":
            p.add_argument("--from-result", dest="from_result", help="re-use the input file of a saved analysis_id")
    p = sub.add_parser("review", help="record analyst review of a saved result")
    p.add_argument("analysis_id")
    sub.add_parser("list", help="list saved results")
    sub.add_parser("check", help="check Ollama and models")
    sub.add_parser("export", help="write generated validation log / detection notes markdown")
    p = sub.add_parser("sanitize", help="write a sanitised COPY of a file")
    p.add_argument("file")
    p.add_argument("--mask-emails", action="store_true")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.cmd:
        menu(args)
    elif args.cmd == "analyze":
        do_task("log_analysis", args.file or choose_file(), args, interactive=sys.stdin.isatty())
    elif args.cmd == "triage":
        do_task("alert_triage", args.file or choose_file(), args, interactive=sys.stdin.isatty(), alert=args.alert, all_alerts=args.all_alerts)
    elif args.cmd == "detect":
        do_detect(args, interactive=sys.stdin.isatty(), from_result=args.from_result)
    elif args.cmd == "review":
        try:
            rec = store.load_result(args.analysis_id)
        except FileNotFoundError as e:
            print(e)
            return 1
        show_result(rec)
        review_interactive(rec)
    elif args.cmd == "list":
        for r in store.list_results():
            print(f"{r['analysis_id']}  {r['task']:22s} {r['input']['filename']:45s} {r['model']['name']}  {r['review']['status']}")
    elif args.cmd == "check":
        show_status()
    elif args.cmd == "export":
        for p in store.export_markdown():
            print("Wrote", p)
    elif args.cmd == "sanitize":
        try:
            out, n = log_parser.sanitize_file(args.file, mask_emails=args.mask_emails)
            print(f"Sanitized COPY: {out} ({n} redactions). Original untouched.")
        except log_parser.InputError as e:
            print(f"[INPUT ERROR] {e}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
