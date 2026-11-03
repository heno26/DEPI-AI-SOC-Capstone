# Wazuh Cloud - Future Alert Collection Guide

**Status: NOT EXECUTED. Wazuh Cloud has not been activated and nothing in this guide has been tested by the project.**
This guide was written from the official Wazuh documentation (`documentation.wazuh.com`, pages "Sign up for a trial",
"Archive data - Configuration", "Wazuh Cloud CLI", "Deploying Wazuh agents on Windows endpoints") read on 17 Oct 2026.
Documentation changes between versions: **always follow the live official page and the command the Wazuh dashboard generates for you.**
Do not copy version numbers from this file.

## Legend
| Label | Meaning |
|---|---|
| **DOCUMENTED** | Stated on an official Wazuh page (read on the date above). Still untested by us. |
| **REQUIRES PERMISSION** | Documented, but needs an account right / API key that we have not confirmed we will have in a trial. |
| **UNVERIFIED** | Not found in the documentation we read, or depends on our own environment. Must be checked on the day. |

## Facts that affect planning (DOCUMENTED)
- The Wazuh Cloud trial is **14 days** and needs **no credit card**.
- **If no agent is enrolled within 3 days of starting the trial, the environment is terminated for inactivity.** So do not start the trial until the Windows test endpoint is ready to enroll.
- Alert files (`alerts.json`) are sent to "archive data" **after rotation and compression, usually 10 to 30 minutes** after the event. Alerts will not be downloadable instantly.
- Files with a `.log` extension are never sent to archive data. `archives.json` (all events) only exists if `logall_json` is enabled; **we do not need it**.
- The oldest archive files are rotated according to the archive-data setting, so **download your alerts before the trial ends and keep them locally.**

## Privacy before you start (read this)
A cloud SIEM stores copies of endpoint security events on infrastructure you do not control. Events can contain
usernames, hostnames, IP addresses, process command lines and file paths.
- Use a **dedicated lab Windows machine or VM** that you own. Do not enrol a personal or work computer that holds real data.
- Do not log into personal accounts on that machine during the test.
- Nothing is sent to Wazuh Cloud by this project. Only the Wazuh agent you install sends data, and only after you enrol it.
- Keep the **raw** download untouched in `Data/Wazuh/_raw_do_not_edit/` and analyse a **sanitised copy** (step 8).
- Never put API keys, tokens or passwords in any project file or screenshot. Redact them before taking evidence screenshots.

## Step 1 - Create the trial account (DOCUMENTED)
1. Go to the Wazuh Cloud page on wazuh.com and choose **Start your free trial**.
2. Fill in the form, click **Start free trial**, and verify your email address.
3. Log in to the Wazuh Cloud Console, click **Create environment**, name it, fill in the use case, and start it.
4. Open the Wazuh dashboard of the environment when it is ready.
*Do this only when you are ready to enrol the agent the same day (3-day inactivity rule).*

## Step 2 - Enrol a Wazuh agent on an authorised Windows test machine (DOCUMENTED, exact command is generated for you)
1. In the Wazuh dashboard open the agents area (the docs call it **Agents management > Summary**; the exact menu names can differ by version: **UNVERIFIED**) and use the **Deploy new agent** wizard.
2. Choose **Windows** and give the agent a clear lab name (for example `LAB-WIN-01`).
3. The wizard shows a command. Run **that generated command** in an **Administrator PowerShell** on the test machine. Do not edit the manager address or token by hand.
4. Start the service if the wizard says so. The documentation shows `Start-Service wazuhsvc` (older instructions also show `NET START WazuhSvc`).

## Step 3 - Verify agent connectivity (DOCUMENTED)
```powershell
Get-Service wazuhsvc        # expect Status: Running
```
In the dashboard, **Agents management > Summary** should list the agent as **Active**. If it does not enrol within a few
minutes, read the agent log (`C:\Program Files (x86)\ossec-agent\ossec.log`, path from the official docs for 32/64-bit installs: **verify on your machine**).

## Step 4 - Confirm genuine events are arriving (UNVERIFIED in detail)
Open the dashboard's security-events / threat-hunting view for the agent. Menu names vary by version.
You are looking for events whose agent name is your lab machine. **Do not assume any activity creates an alert.**
An alert exists only if a Wazuh rule matched; check the actual `rule.id` and `rule.description` shown.

## Step 5 - Safe, authorised lab activities that *may* produce alerts (UNVERIFIED - depends on enabled rules/logging)
Do these only on your own lab machine. For each one, record what you did and the time (for the evidence log). If no alert appears, that is a valid, honest result.
| Activity | Why it might alert | Caveat |
|---|---|---|
| A few deliberate failed logons to a **lab-only** local account (lock-screen / `runas` with a wrong password) | Windows failed-logon events (4625) may match authentication rules | Needs Windows Security auditing and agent collection of the Security channel (default agent config normally collects it: **verify**). Do not attempt this against any account you do not own. |
| Create or modify a file in a folder monitored by File Integrity Monitoring | Syscheck alerts | Only monitored paths alert; syscheck by default scans periodically, so there can be a delay. Check `ossec.conf` on the agent. |
| Run a harmless admin action (open elevated PowerShell, add a **lab-only** test user to a local group and remove it) | Privilege / group change events may match rules | Whether a rule matches depends on rules and logging. Do not weaken real security settings. |
Do **not** run malware, exploit tools, or anything against systems you do not own.

## Step 6 - View the alerts (DOCUMENTED at concept level; exact UI UNVERIFIED)
Use the dashboard's events view filtered by your agent. Note `rule.id`, `rule.level`, `rule.description`, `agent.name`, timestamp.
Take screenshot 14 (see `Evidence/README.md`) **after redacting** tokens, emails and the Cloud ID if you prefer.

## Step 7 - Export / download alert data
There are two routes. Route A is the one with official documentation.

**Route A - Archive data via `wcloud-cli` (DOCUMENTED; REQUIRES PERMISSION; Windows support UNVERIFIED)**
- The documentation shows `wcloud-cli` being downloaded with `curl` and made executable with `chmod`, i.e. **Linux/macOS-style instructions**. Whether a Windows build exists is **not confirmed**. Options: use WSL (Windows Subsystem for Linux) on your laptop, or a small Linux VM.
- The CLI reads an **API key** from a local `credentials` file in the `.wazuh-cloud` folder of your home directory. **Where to create that API key in the console and whether the free trial allows it are UNVERIFIED.** Treat the key like a password: never put it in the project folder, never screenshot it.
- Documented commands (replace the placeholders with your own Cloud ID and dates; confirm syntax with `wcloud-cli --help`):
  ```bash
  wcloud-cli test-credentials --profile <PROFILE_NAME>
  wcloud-cli cold-storage list <CLOUD_ID> --start YYYY-MM-DD --end YYYY-MM-DD
  wcloud-cli cold-storage download <CLOUD_ID> <LOCAL_FOLDER> --start YYYY-MM-DD --end YYYY-MM-DD
  ```
- The downloaded files are **compressed JSON** (the documentation's example file names end in `.json.gz` under an `output/alerts/` path). **Our application reads `.json.gz` / NDJSON directly** (tested with synthetic gz fixtures only).
- Remember the 10-30 minute delivery delay after rotation.

**Route B - Copy individual alerts from the dashboard (UNVERIFIED)**
If the dashboard's event view lets you open an alert's JSON, you may copy it into a `.json` file. We have **not** confirmed this on a trial. A dashboard "export CSV" (if present) is not JSON and our parser does not read it.

**What we will NOT do:** use the Wazuh Server API or Indexer API (credentials and permissions are unconfirmed for the trial), or build any live connection. The application works only from files.

If neither route works on the day, record that in the final report as a limitation, use the synthetic Wazuh-format fixtures for the demonstration, and **label them as synthetic**.

## Step 8 - Store and sanitise locally
```powershell
# Raw evidence: store once, never edit
mkdir Data\Wazuh\_raw_do_not_edit
copy <download>\*.json.gz Data\Wazuh\_raw_do_not_edit\
Get-FileHash Data\Wazuh\_raw_do_not_edit\*.gz -Algorithm SHA256 | Tee-Object Evidence\wazuh_raw_hashes.txt

# Make a sanitised copy for analysis (the original stays untouched)
python app.py sanitize Data\Wazuh\_raw_do_not_edit\<file>.json.gz
# result: Data\_sanitized\<file>.sanitized.json
```
The built-in sanitiser redacts `password=`, `token=`, `secret=`, `api_key=` values, Bearer tokens, AWS key IDs, private-key blocks and (optionally) email addresses.
**It is not a guarantee.** Open the sanitised copy and check it yourself (usernames, hostnames and IPs are kept on purpose because analysis needs them; replace them manually if they are real).
Then copy the sanitised file you want to use into `Data\Wazuh\` with a **non-synthetic** name, for example `GENUINE_wazuh_alerts_2026-10-xx.json`.
Do **not** name genuine files `SYNTHETIC_*`, and do not name synthetic files like genuine ones.

## Step 9 - Import into the application
```powershell
python app.py triage Data\Wazuh\GENUINE_wazuh_alerts_2026-10-xx.json
```
When asked *"Is this a genuine Wazuh export that you collected yourself?"*, answer **y** only if you downloaded it from your own Wazuh Cloud environment.
The result records `evidence_class = analyst_declared_genuine_wazuh_export`. The program cannot verify authenticity; it records your declaration and the SHA-256 of the file.

## Step 10 - Preserve evidence for the presentation
- Screenshots 06 and 14 (checklist in `Evidence/README.md`), with secrets redacted.
- The SHA-256 list of raw files, the date/time you downloaded them, and your lab-activity log (what you did, when, on which machine).
- The saved `Results\AN-...\report.md` and `analysis.json` for each analysed alert.
- State in the presentation: **"This alert was collected earlier from Wazuh Cloud; the AI analysis is running live now, offline."** Never imply the SIEM alert is generated live.

## After the trial
The trial lasts 14 days. After it ends you will not be able to collect more alerts, but all downloaded files remain usable offline. Nothing in `app.py` contacts Wazuh.

## Checklist of claims this project may make
| Claim | Allowed now? |
|---|---|
| The application imports Wazuh-format JSON / NDJSON / gz files | **Yes** (tested on synthetic fixtures only) |
| The application analyses genuine Wazuh alerts | **No** - PENDING until real alerts are collected and analysed |
| Wazuh Cloud collection works for us | **No** - PENDING |
| Archive download via `wcloud-cli` works for us | **No** - PENDING / UNVERIFIED |
