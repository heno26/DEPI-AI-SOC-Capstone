# Dispatcher Runbook

Operational guide for running the Week-3 SOAR dispatcher. Written for a fresh Windows 11
/ PowerShell environment.

## 1. Prerequisites

```
- Python 3.9 or newer
- pyyaml  (pip install pyyaml)
- The repository cloned locally
- Week-2/Evidence/SIEM-OpenObserve/ present
```

No Ollama, no OpenObserve, no TheHive server, no network connection is required.

## 2. Folder layout

```
<repo>/
├── Week-2/
│   └── Evidence/
│       └── SIEM-OpenObserve/
│           ├── SIEM05_Auto_Alert_AI_Triage_*.json
│           ├── SIEM06_Auth_002_AI_Triage_*.json
│           ├── SIEM06_Mal_003_AI_Triage_*.json
│           ├── SIEM07_XSS_004_AI_Triage_*.json  (x3)
│           ├── SIEM_EXCHANGE_005_*_AI_Triage.json
│           └── SIEM04_Real_Alert_AI_Triage_*.json  (legacy, skipped)
└── Week-3/
    └── SOAR/
        ├── dispatcher.py
        ├── playbooks/
        │   ├── PB-01.yaml
        │   ├── PB-02.yaml
        │   ├── PB-03.yaml
        │   └── PB-04.yaml
        ├── enrichment/stub.py
        ├── ticketing/local_json.py
        ├── tickets/   (output)
        └── audit/     (output)
```

## 3. Running the dispatcher

From the repository root:

```powershell
python -B Week-3/SOAR/dispatcher.py --evidence Week-2/Evidence/SIEM-OpenObserve --playbooks Week-3/SOAR/playbooks --out Week-3/SOAR
```

That is the canonical command. Do not vary the paths unless the repository layout has
changed.

## 4. Expected output

```
SKIP SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json: legacy format without event_id (pre-SIEM05)
TICKET 469dc3deb13af639 -> PB-03 (Tier 1)
TICKET a823d14b61f061f7 -> PB-01 (Tier 1)
TICKET e05ccfe875e6a535 -> PB-02 (Tier 1)
TICKET 6ba5792eef667c9c -> PB-03 (Tier 1)
TICKET 843425fa737b11ef -> PB-03 (Tier 1)
TICKET fad10ea2b71bb2bc -> PB-03 (Tier 1)
TICKET 21c4515e439a0b3b -> PB-04 (Tier 0)
STATUS: DISPATCH COMPLETE | processed=7
```

The skip is expected. If any line shows `FAIL`, see §5.

## 5. What to do with the output

**To inspect a ticket:**

```powershell
Get-Content Week-3/SOAR/tickets/e05ccfe875e6a53524e7270675a6720d54c7ae95ab4353e906f32f04c14f14b9.json
```

Or open in VS Code:
```powershell
code Week-3/SOAR/tickets/e05ccfe875e6a53524e7270675a6720d54c7ae95ab4353e906f32f04c14f14b9.json
```

**To inspect an audit log:**

```powershell
Get-Content Week-3/SOAR/audit/a823d14b61f061f7954e2e3eb7f18d6af6280f53242fe8c711d5cd78bcefdbae.jsonl
```

## 6. Re-running after fixes

The dispatcher is **idempotent by `event_id`**:
- Re-running produces no duplicate tickets.
- Each run appends one audit line per event (append-only).
- To start fresh, delete `Week-3/SOAR/tickets/*.json` and `Week-3/SOAR/audit/*.jsonl` and
  re-run.

## 7. Adding a new playbook

1. Create `Week-3/SOAR/playbooks/PB-05.yaml` following the PB-01 schema.
2. Create `Week-3/SOAR/playbooks/PB-05.md` with a short narrative.
3. Add the rule name to `ROUTE` in `Week-3/SOAR/dispatcher.py`.
4. Add any prohibited actions to `PROHIBITED_ACTIONS` in the same file.
5. Add a test in `Week-3/SOAR/tests/run_all.py` following the existing patterns.
6. Run `python -B Week-3/SOAR/tests/run_all.py` and verify all tests still pass.

## 8. Adding a new evidence adapter

If a new Week-2 receiver produces a different envelope shape:

1. Add a normalisation branch to `normalise_document()` in `dispatcher.py`.
2. Add an entry to `ROUTE` for the rule name.
3. Add a fixture in `Week-3/SOAR/tests/fixtures/` mirroring the new shape.
4. Add a `test_e2e_<adapter>` test.
5. Document the adapter in `Integration-Workflow.md` §3.

## 9. Cleanup / reset

```powershell
Remove-Item Week-3/SOAR/tickets/*.json
Remove-Item Week-3/SOAR/audit/*.jsonl
python -B Week-3/SOAR/dispatcher.py --evidence Week-2/Evidence/SIEM-OpenObserve --playbooks Week-3/SOAR/playbooks --out Week-3/SOAR
```

The pre-generated demo tickets are lost by this. If you want them back, use `git checkout`
on the `Week-3/SOAR/tickets/` and `Week-3/SOAR/audit/` folders.

## 10. What NOT to do

- **Do not edit `Week-2/Evidence/SIEM-OpenObserve/*.json`.** They are the input; modifying
  them invalidates the evidence.
- **Do not edit tickets by hand.** Ticket updates go through
  `LocalJSONBackend.update_review()`.
- **Do not add remediation execution to any playbook.** Tier 2 actions are blocked in code;
  adding an execution path would break the constitutional rule (see `decision-matrix.md`
  row 18).
- **Do not rename or move evidence files** without updating `dispatcher.py` or the
  `--evidence` argument.
- **Do not re-run the dispatcher in an attempt to "test" remediation.** No remediation is
  ever executed by this package.

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'yaml'` | `pyyaml` not installed | `pip install pyyaml` |
| `FileNotFoundError: Week-3/SOAR/playbooks` | Wrong working directory | Run from repo root |
| All evidence files skipped (`no route for rule`) | Rule suffix not stripped | Ensure `dispatcher.py` is v0.2 or later (see `Dispatcher-Change-Log.md`) |
| Exchange file fails with `missing fields` | v0.1 dispatcher (no Exchange adapter) | Use v0.2 (see Fix 2) |
| SIEM04 file fails with `missing event_id` | v0.1 dispatcher (no legacy handling) | Use v0.2 (see Fix 3) |