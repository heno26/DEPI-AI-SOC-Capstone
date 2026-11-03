# DEPI P5 — SIEM06 Alert 003 (Malware) Safe Upgrade

## What is included

- `SIEM06_Multi_Alert_Receiver.py` — drop-in update of the original SIEM06 for **Web 001**, **SSH 002**, and **Malware 003**. Existing `SIEM04_Real_Alert_Triage.py`, `SIEM05_Auto_Triage_Receiver.py`, OpenObserve alerts and prior evidence are not rewritten.
- Current Malware dataset assumed: `9c9aa5_campaign.evtx`, `replay_mode=historical_lab_replay`, searchable in `depi_malware_sysmon`.
- A fresh **firing** trigger, a structured authenticated webhook, verified counts, and matching original Sysmon source event records must be present before the local Ollama model is called.

## 1. Back up and install

Keep Alert 003 **paused** and stop a running receiver (Ctrl+C) before swapping the script. Leave OpenObserve and Ollama running.

1. Back up your original `D:\Desktop\w\Week-2\Integrations\SIEM-OpenObserve\SIEM06_Multi_Alert_Receiver.py`.
2. Copy the new `SIEM06_Multi_Alert_Receiver.py` to the same folder, replacing **only this file**. Keep SIEM04 and SIEM05 unchanged. No new libraries or external services are needed.
3. Open PowerShell:

```powershell
Set-Location "D:\Desktop\w\Week-2\Integrations\SIEM-OpenObserve"
python -B .\SIEM06_Multi_Alert_Receiver.py --self-test
python -B .\SIEM06_Multi_Alert_Receiver.py --check
```

Expected:

```text
STATUS: SIEM06 WEB+SSH+MALWARE LOCAL CONTRACT TESTS PASS (no SIEM writes / no AI calls)
STATUS: SIEM06 CREDENTIALS + WEB/SSH/MALWARE STREAMS + OLLAMA PASS
```

`--check` requires saved credentials, recent SSH + Malware logs, and accessible Ollama; it performs no model inference. A missing stream or unreachable local service is a failure, not an invitation to re-upload data.

## 2. Set **only the Malware Alert** row template (essential for avoiding HTTP 422)

Open OpenObserve `Reliability > Alerts` and edit `SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR`.

In **Advanced > Row Template**, select **JSON** and enter exactly:

```json
{"process_guid":"{process_guid}","suspicious_executions":{suspicious_executions},"dns_queries":{dns_queries},"network_connections":{network_connections}}
```

Why omit `process_image`/`parent_process` from the notification? Windows paths contain backslashes that can break simplistic JSON templating. The receiver independently queries authoritative source records for the paths, parent, DNS names and IP/port; never trust them in the webhook.

Preserve your **existing** destination template `DEPI_SOC_Structured`:

```json
{"alert_name":"{alert_name}","stream_name":"{stream_name}","rows":"{rows}"}
```

The Malware alert still uses `DEPI_SOC_Webhook` and its existing `X-DEPI-Webhook-Key`. The Scheduled SQL and detection settings remain unchanged. Save the edit and leave the alert paused until the receiver is running. Do not change the template on Web or SSH alerts.

## 3. Start receiver and do the real end-to-end test

Ensure only one listener uses port 8765. From the same PowerShell window, after both checks have passed:

```powershell
Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue
python -B .\SIEM06_Multi_Alert_Receiver.py
```

If the first command lists a listener, **do not** launch a second instance; stop the old receiver from its own console first. Expect:

```text
STATUS: SIEM06 RECEIVER LISTENING http://127.0.0.1:8765/depi-alerts
```

Now reactivate Alert 003. Trigger a real scheduled evaluation only after you have verified the SQL Preview still matches a replay event within the configured lookback. A destination's generic Test button does not prove valid structured alert-row delivery.

Acceptance requires **all** of the following:

1. OpenObserve `triggers` has a **new** `status='firing'` for `SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR` (within the receiver's recent trigger window).
2. Receiver shows `STATUS: SIEM06 AI TRIAGE PASS | rule=SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR` — `HTTP 202` means only queued, not analyzed.
3. A new file exists in `D:\Desktop\w\Week-2\Evidence\SIEM-OpenObserve\SIEM06_Mal_003_AI_Triage_*.json` containing `evidence`, `ai_triage`, `qa_status` and `human_validation_required=true`.
4. Verified counts should match the current lab case: suspicious executions=1, DNS=10, network=1, ProcessGuid for `2r8602.exe`, destination `104.80.2.104:443`.

The original event times are in June 2025; OpenObserve `_timestamp` represents the October 2026 replay ingest. This is a **historical lab detection**, not confirmation of current infection or C2 activity. AI output is always pending human review.

## Safe rollback

Stop the running SIEM06 receiver, restore the original backup of `SIEM06_Multi_Alert_Receiver.py`, and start it again. The original receives Web/SSH only. Pause Alert 003 or use a separate destination before rollback so you do not send Malware notifications to an unsupported receiver.

## Local development validation (not live proof)

The update was syntax checked, ran the `--self-test` with the legacy SIEM04/SIEM05 modules, and used offline simulated SIEM search results derived from the supplied 231-event Malware JSON to test the 12 correlated source records, count mismatches and report path (with a **mocked** LLM response). Live webhook/Ollama/Windows integration has **not yet** been demonstrated by this package alone.
