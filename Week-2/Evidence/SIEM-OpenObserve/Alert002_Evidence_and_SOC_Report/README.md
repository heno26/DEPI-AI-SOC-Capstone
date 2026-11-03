# Alert 002 Evidence Pack — DEPI P5 Week 2

These are **actual screenshots previously supplied in the conversation**, copied without edits, along with the saved JSON and a human-readable report derived from it. No new SIEM queries or AI inference were run to create this bundle.

1. `01_OpenObserve_2000_SSH_Events.png` — 2,000 SSH records visible in `depi_auth_logs`.
2. `02_OpenObserve_SQL_Detection_Preview.png` — SQL query and `WOULD TRIGGER` with one group.
3. `03_Alert_002_Saved.png` — two configured alerts and successful save confirmation.
4. `04_SIEM06_AI_TRIAGE_PASS.png` — PowerShell `SIEM06 AI TRIAGE PASS` and JSON evidence path. (The earlier ZIP error at the top is unrelated to this completed run.)

- `SIEM06_Auth_002_AI_Triage_*.json` — original machine-readable AI/evidence output, unchanged.
- `Alert002_SSH_BruteForce_SOC_Report.md` — analyst-readable report based on JSON content; clearly labels caveats and human review.

**Still worth capturing:** a fresh screenshot of Alert 002 trigger history displaying `firing` or a successful webhook status, once delivery reliability is verified. A human review/sign-off has not been performed.
