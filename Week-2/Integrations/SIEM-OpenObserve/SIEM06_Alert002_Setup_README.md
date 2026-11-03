# DEPI P5 — SIEM Alert 002 (SSH Brute Force) — Safe Receiver Upgrade

## Scope
This is an add-on for Week 2, not a replacement of original code. It supports existing `SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS` and new `SIEM_AUTH_002_SSH_BRUTE_FORCE` using the same local `DEPI_SOC_Webhook` destination and Windows Credential Manager keys. It will **not** generate a report unless a recent real `firing` trigger exists and the webhook group's SSH failed-password count matches OpenObserve source logs. The source OpenSSH file is historical replay and has no original year or timezone.

## Copy
Put `SIEM06_Multi_Alert_Receiver.py` into:

`D:\Desktop\w\Week-2\Integrations\SIEM-OpenObserve\`

**Keep** `SIEM04_Real_Alert_Triage.py`, `SIEM05_Auto_Triage_Receiver.py` and existing reports unchanged. Neither the old rule nor the old destination template is edited. Keep original backups.

## PowerShell startup
From a second PowerShell window (leave OpenObserve running):

```powershell
Set-Location "D:\Desktop\w\Week-2\Integrations\SIEM-OpenObserve"
python -B .\SIEM06_Multi_Alert_Receiver.py --self-test
python -B .\SIEM06_Multi_Alert_Receiver.py --check
```

Only after both PASS, **stop any original SIEM05 listener on port 8765** (`Ctrl+C` in the SIEM05 terminal), then run:

```powershell
python -B .\SIEM06_Multi_Alert_Receiver.py
```

Expected: `STATUS: SIEM06 RECEIVER LISTENING http://127.0.0.1:8765/depi-alerts`.

Do not run two servers on the same port. No credential setup should be needed if SIEM05 was previously configured. If `--check` fails, do not proceed.

## OpenObserve Alert 002 edits (still in draft)
- Alert name: `SIEM_AUTH_002_SSH_BRUTE_FORCE`
- Stream: `depi_auth_logs`
- Existing SQL: change final line `LIMIT 20` to `LIMIT 1` (one top group/report).
- In **Advanced > Additional Settings > Row Template**, select **JSON** and enter:

```json
{"src_ip":"{src_ip}","original_minute_no_year":"{original_minute_no_year}","failed_attempts":{failed_attempts}}
```

- Destination: existing `DEPI_SOC_Webhook`.
- Existing destination template `DEPI_SOC_Structured` stays unchanged:

```json
{"alert_name":"{alert_name}","stream_name":"{stream_name}","rows":"{rows}"}
```

- Confirm preview and settings, then save while the new receiver is listening.
- Do not press the destination's generic **Test** button as proof of end-to-end success. The structured `rows` for Alert 002 come from its scheduled SQL query.

## End-to-end acceptance
1. Alert fires in OpenObserve (`triggers` has a recent `firing` event for the new rule).
2. Receiver terminal prints `STATUS: SIEM06 AI TRIAGE PASS` for the new rule, **not just HTTP 202**.
3. Check: `Week-2\Evidence\SIEM-OpenObserve\SIEM06_Auth_002_AI_Triage_*.json`.
4. Verify `verified_failed_password_count`, rule name, source event sample references, `qa_status`, and `human_validation_required=true`. Do not present any AI hypothesis as a confirmed compromise.

## Safe rollback
Stop SIEM06 with Ctrl+C. Start the original `SIEM05_Auto_Triage_Receiver.py` again; all original files and old evidence remain unchanged. Until Alert 002 uses a separate destination or is paused, its notifications will not be processed by the old receiver (which accepts web Alert 001 only).
