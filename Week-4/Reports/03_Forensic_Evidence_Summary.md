# Forensic Evidence Summary

**Project:** DEPI Project 5 - AI-Assisted SOC Automation & Full Incident Response Capstone
**Week:** 4 - Full Capstone IR Simulation & Reporting
**Scenario:** W4-TT-01 - Composite multi-stage intrusion - tabletop simulation
**Generated:** 2026-11-26T02:47:58+00:00 by `Week-4/IR/build_reports.py` from `Week-4/Output/` (data generated 2026-11-26T02:47:58+00:00)
**Status:** DRAFT - acceptance pending human sign-off


## Simulation boundary

- Every stage is represented by real, hash-verifiable evidence that already exists in Week-2 (datasets, OpenObserve alert evidence, verified timelines) and Week-3 (tickets, audit logs).
- The datasets come from different public sources and different years. The chain that links the stages is a scenario construct for the tabletop exercise; causal links between stages are NOT observed in the data.
- Timeline order is the scenario stage order. Timestamps shown are the original dataset timestamps and are never shifted or invented.
- No live SIEM, no live TheHive, no live threat-intelligence feed, no remediation is executed. Containment/eradication/recovery items are proposals that require a recorded analyst decision.


## Chain of custody

- Week-4 reads Week-1..3 artifacts read-only; no evidence file is modified.
- SHA-256 below was computed by `correlate.py` at build time. Re-run `ir_cli.py build` and compare to detect change.
- Original raw datasets and their own manifests stay in `Week-2/Data/Real-Datasets/*/` (source manifests, final verification manifests).
- The large malware EVTX referenced by Week-2 is not in the repository; its derived ingest JSON and Sysmon evidence are.


## Evidence inventory

| Case | Stage | File | SHA-256 |
|---|---|---|---|
| SIEM-WEB-001 | S2 | Week-2/Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json | b264f37f246d18a5c3e4263d4ff39f78290879ac45efe1051ffa538f7fcbb9de |
| SIEM-WEB-001 | S2 | Week-2/Evidence/SIEM-OpenObserve/SIEM05_Controlled_AI_Reanalysis_20261023.json | 4a6258e99277b52e9bdaa7bcffe60520d1e19c4bcb6a0370b0ae68dcdc37aca2 |
| SIEM-AUTH-002 | S3 | Week-2/Evidence/SIEM-OpenObserve/SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json | cb1ea5fe6e96eb4d67f57fc8727599e638dd6a507e666d4668a29a87c56137db |
| SIEM-MAL-003 | S4 | Week-2/Evidence/SIEM-OpenObserve/SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json | 7146c223fec7c139b09da9c062e3d85ee0b8bd2e14476109d504b7e14194684d |
| SIEM-WEB-004 | S2 | Week-2/Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_6ba5792eef667c9cf8.json | 6eaa96bfc2ec8b81d3f27471afd03b15e6935fa4f66e755b9b93f21bb16bd47c |
| SIEM-WEB-004 | S2 | Week-2/Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_843425fa737b11ef71.json | ae56f8fbf252a894563c218b53b616f22444371b91bda6c0fbcb7e57d86e80f0 |
| SIEM-WEB-004 | S2 | Week-2/Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_fad10ea2b71bb2bc09.json | f6830ff7dda1276ff743adb22e814bec5ddf42df4f86dfd36cd7c312931b3bd6 |
| SIEM-EXCH-005 | S9 | Week-2/Evidence/SIEM-OpenObserve/SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json | c1a8ccc7d28eeb8d760afdcdda9ccb4d615e4da32818158d033e8e422c75dbad |
| SIEM-EXCH-005 | S9 | Week-2/Results/SIEM_EXCHANGE_005_Human_Reviewed.json | 6868368ed2b215b5e7084c6f9d35a2b05f65b868192d5f581a585edd3e68e64f |
| SIEM-EXCH-005 | S9 | Week-2/Data/Exchange/msexchangemanagement.log | 7250afa0f319471e29aed8a85c641ba5c4ebef127c88846b8ca30e59e5bdbf27 |
| LT-01 | S3 | Week-2/Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/LT-01-Verified-Timeline.csv | 9ed1c4217bdc4090092512e2c65553ed8d3cb70bb7aca24c08995a2529e7eabe |
| LT-01 | S3 | Week-2/Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/LT-01-Case-Study.md | 72bac9880d0a677f6f696909ec225632cdd3b5b09c96ec8ec697bab669ad2e33 |
| LT-02 | S5 | Week-2/Data/Real-Datasets/Linux-Attacks/LT-02-Privilege-Escalation/LT-02-Verified-Timeline.csv | d733d95d3d5533dfb6a1697ef2f47b7a34b632c0b3f6d573af4829eba63a2c23 |
| LT-02 | S5 | Week-2/Data/Real-Datasets/Linux-Attacks/LT-02-Privilege-Escalation/LT-02-Case-Study.md | 8445889a3618db3425faa7aff0b420fd78e856ff837d4cc2f9882358bf853d8d |
| LT-03 | S4 | Week-2/Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution/LT-03-Verified-Timeline.csv | 1ebfe1bb05a52ffeb6422f409d6a077ea80ab134286f7221095dcab237250ff2 |
| LT-03 | S4 | Week-2/Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution/LT-03-Case-Study.md | a29bbdee45be6f7a4f096c374d1261e308c9d5825e4981893db296e6586341bb |
| LT-04 | FP | Week-2/Data/Real-Datasets/Linux-Benign/LT-04-Normal-Operations/LT-04-Verified-Timeline.csv | 32a7d2870b3057d6c7efeb12bf9aa58af02706d11c9e77ffebe927e20791d482 |
| LT-04 | FP | Week-2/Data/Real-Datasets/Linux-Benign/LT-04-Normal-Operations/LT-04-Case-Study.md | d63f8eebb32dc01cea129af2f5969455f9b7678e4a2d2c007ced8528fcc36d3e |
| NT-01 | S1 | Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Verified-Timeline.csv | dfc6ba445b6e95612feaa093757f591f8c2badb17da2cd922895fbec817c2ce0 |
| NT-01 | S1 | Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Case-Study.md | 12c9ba90c21d75046d1f533f0554e64fe83fe4d83c134563f3d3d2a0e7c2874e |
| NT-01 | S1 | Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Verified-Full-Source-Statistics.json | eae152db9b57ff82382beb5e03373c76ad28b0756a71ba2605d1ea8cee1bf5eb |
| NT-02 | S8 | Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Verified-Timeline.csv | e1ecaa96fddb5d44ada967102cd2f3abf947305a21b0b7868255dde5b22dd783 |
| NT-02 | S8 | Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Case-Study.md | e65dfbd5902af22b8c4e6ed47cfb7b10c7222fc4362ed64229dcb293232eb5f7 |
| NT-02 | S8 | Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Verified-Full-Source-Statistics.json | d692dad937967d2a1f5484b40d0b64564dcbf4e1f5a3742118e3b7c8ae0be604 |
| NT-03 | S8 | Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/NT-03-Verified-Timeline.csv | 026ea56f226ba5e10a729e96ab62ffa6ed1fe82f914e5e561a5a0d96b8352d30 |
| NT-03 | S8 | Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/NT-03-Case-Study.md | 3371ecfe4d56b8e493a2872ece84d6a20a567fdbeac2095859cb62e91a18c735 |
| NT-03 | S8 | Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/NT-03-Verified-Full-Source-Statistics.json | 6b80909c7115870c61b947e4ec0fa50f45aaf6cf32f842473b7fb11ce63440a0 |
| RT-01 | S8 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-Verified-Timeline.csv | b68d1b22aeff7a2eb0c9e372670b65b0a0a472963019e6bb0a04fb1ab4250d7b |
| RT-01 | S8 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-Case-Study.md | b0f2bec328fd3aceb0abf14bb07f61c78cf8161fa2e10f57a01bfc31cd1c3c5b |
| RT-02 | S6 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Verified-Timeline.csv | db745c5366d57d704695d3e642afb8a1309db6756f862a07b320d23c462d8523 |
| RT-02 | S6 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Case-Study.md | a22768401b9dfe89112389aa738e68901dca19e31d3c69d7d07e0e3fcfbd5307 |
| RT-03 | S7 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-Verified-Timeline.csv | 68ab39716c3756da1e2a98a47e05049c8ef0a1510ff231d4020b6a543a314e94 |
| RT-03 | S7 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-Case-Study.md | d7e6fff23499e5c725b802adb5396eb2e8af689b8c255e807bed98470a4ee85b |
| RT-04 | S5 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-04-Persistence/RT-04-Verified-Timeline.csv | 3cb94bf61e2c258b1e8c8eecc1b765773a7c23bccbaf2f0d7d27c2f1a72e7f18 |
| RT-04 | S5 | Week-2/Data/Real-Datasets/Windows-Attacks/RT-04-Persistence/RT-04-Case-Study.md | 2103bea92ecc23e8436340d50c13c6dddb96cbdbd4cce96fbde004a35b8c72ed |
| BT-01 | FP | Week-2/Data/Real-Datasets/Windows-Benign/BT-01/BT-01-Case-Study.md | 207a480d3ce7ca9b8e0cbbfeeacd63922445e67382c1e8afa26ebefe680021ac |
| BT-01 | FP | Week-2/Data/Real-Datasets/Windows-Benign/BT-01/BT-01-focused.json | 923489eda20e1644e6dd4fb56292c98a32082f9c6e06dd04150ed4b1800d8312 |
| BT-02 | FP | Week-2/Data/Real-Datasets/Windows-Benign/BT-02/BT-02-Case-Study.md | 0c6ee319d32f63fea9a3794703e318871061b5ccdbb4c5721efe3704cfe5dfb7 |
| BT-02 | FP | Week-2/Data/Real-Datasets/Windows-Benign/BT-02/BT-02-focused.json | 847f9aba4e7ac7d5d383a89bb49c4e37c2f848297e8c46a62c36729f0b7f9207 |
| BT-03 | FP | Week-2/Data/Real-Datasets/Windows-Benign/BT-03/BT-03-Case-Study.md | 1a0bcf2281711a99105c1e6ec6a9cb7dcf41e33770909db7d49326e73416832c |
| BT-03 | FP | Week-2/Data/Real-Datasets/Windows-Benign/BT-03/BT-03-focused.json | 7d5df07e5ac203141a3f1d8325fa6bdcf06f0caebc1fa7a5c7bfe94dc999f4a8 |

## Case findings and evidentiary limits


### SIEM-WEB-001 - High-rate HTTP requests from a single source (S2)

- Source kind: siem_alert; dataset: `depi_web_access`; source records: 112
- Timestamp quality: original_utc_minute x1
- AI triage (local mistral:7b-instruct-v0.3-q4_K_S): severity Medium, confidence Moderate, QA REVIEW_REQUIRED; trigger->triage 31.3 s
- ATT&CK T1595 Active Scanning - *candidate*
- Limitation: Source IP is in reserved address space (source_ip_quality.is_reserved=true).
- Limitation: A firing trigger is checked within a recent interval but lacks a proven row-level ID join.
- Limitation: AI findings require human verification.
- Limitation: Replay dataset is not live production traffic.

### SIEM-AUTH-002 - SSH brute force against root (S3)

- Source kind: siem_alert; dataset: `OpenSSH_2k.log`; source records: 30
- Timestamp quality: no_year_no_timezone x9
- AI triage (local mistral:7b-instruct-v0.3-q4_K_S): severity Medium, confidence High, QA SCHEMA_PASS_HUMAN_REVIEW_REQUIRED; trigger->triage 28.6 s
- ATT&CK T1110.001 Brute Force: Password Guessing - *observed_pattern*
- Limitation: Repeated failed SSH password attempts are detected; successful intrusion is not established.
- Limitation: Original SSH event dates have no year/timezone.
- Limitation: Trigger-key correlation is rule-level, not proven exact alert-row linkage.
- Limitation: Historic replay data, not live production traffic.
- Limitation: AI schema validation does not prove semantic correctness; human review is required.

### SIEM-MAL-003 - Suspicious executable with DNS + outbound connection (S4)

- Source kind: siem_alert; dataset: `9c9aa5_campaign.evtx`; source records: 12
- Timestamp quality: original_with_offset x12
- AI triage (local mistral:7b-instruct-v0.3-q4_K_S): severity High, confidence Medium, QA SCHEMA_PASS_HUMAN_REVIEW_REQUIRED; trigger->triage 48.1 s
- ATT&CK T1204.002 User Execution: Malicious File - *candidate*
- ATT&CK T1071.001 Application Layer Protocol: Web Protocols - *candidate*
- Limitation: Behavioral correlation indicates suspicious activity; infection is not independently confirmed.
- Limitation: Original Sysmon events are from historical laboratory replay; _timestamp is ingestion time.
- Limitation: Trigger key verifies the alert rule, not exact alert-row provenance.
- Limitation: Network connection and DNS queries alone do not establish C2 or exfiltration.
- Limitation: AI schema/semantic checks do not replace analyst validation.

### SIEM-WEB-004 - Cross-site scripting (XSS) payloads (S2)

- Source kind: siem_alert; dataset: `depi_web_xss`; source records: 3
- Timestamp quality: original_with_offset x3
- AI triage (local mistral:7b-instruct-v0.3-q4_K_S): severity High, confidence High, QA SCHEMA_PASS_HUMAN_REVIEW_REQUIRED; trigger->triage 40.1 s
- ATT&CK T1190 Exploit Public-Facing Application - *candidate*
- Limitation: HTTP 200 does not prove successful XSS execution.
- Limitation: Original event timestamps represent historical laboratory data.
- Limitation: SIEM trigger does not independently prove browser-side execution.

### SIEM-EXCH-005 - Exchange mailbox export to OWA .aspx path (S9)

- Source kind: siem_alert; dataset: `depi_exchange_events`; source records: 8
- Timestamp quality: original_no_timezone x8
- AI triage (local mistral:7b-instruct-v0.3-q4_K_S): severity High, confidence Medium, QA REVIEW_REQUIRED; trigger->triage None s
- ATT&CK T1114.002 Email Collection: Remote Email Collection - *candidate*
- ATT&CK T1505.003 Server Software Component: Web Shell - *hypothesis*
- ATT&CK T1098 Account Manipulation - *observed_pattern*
- ATT&CK T1070.008 Indicator Removal: Clear Mailbox Data - *observed_pattern*
- Limitation: The export requests were unauthorized.
- Limitation: The ASPX destination paths were intended for web-shell staging.
- Limitation: The requested export operations resulted in actual files on disk.
- Limitation: Any web shell was deployed, accessed, or executed.
- Limitation: Any mailbox data was successfully exfiltrated.
- Limitation: Cmdlet audit log shows the export requests were removed and Search-Mailbox -DeleteContent ran after each export; export file creation on disk is still not shown by any log in the repository.

### LT-01 - SSH password guessing (verified timeline) (S3)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force`; source records: 42
- Timestamp quality: no_year_no_timezone x42
- Final Week-2 analysis AN-20261018-183730-901f (4 runs): 6 validator flags; human review **Corrected**; analyst-recorded hallucination entries 3
- ATT&CK T1110.001 Brute Force: Password Guessing - *observed_pattern*

### LT-02 - Privilege-sensitive sudo commands (S5)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Linux-Attacks/LT-02-Privilege-Escalation`; source records: 21
- Timestamp quality: original_utc x21
- Final Week-2 analysis AN-20261018-221905-552c (3 runs): 2 validator flags; human review **Corrected**; analyst-recorded hallucination entries 5
- ATT&CK T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching - *candidate*
- Limitation: PROCTITLE-only evidence: execution outcome, authorisation and successful escalation not established.

### LT-03 - Bash reverse-shell command pattern (S4)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution`; source records: 1
- Timestamp quality: original_utc x1
- Final Week-2 analysis AN-20261019-021336-409d (3 runs): 5 validator flags; human review **Corrected**; analyst-recorded hallucination entries 1
- ATT&CK T1059.004 Command and Scripting Interpreter: Unix Shell - *observed_pattern*
- Limitation: Network success, interactive access and intent are unconfirmed (network_outcome=unknown).

### LT-04 - Linux start-up (benign candidate) (benign control)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Linux-Benign/LT-04-Normal-Operations`; source records: 18
- Timestamp quality: no_year_no_timezone x18
- Final Week-2 analysis AN-20261019-014603-c434 (2 runs): 1 validator flags; human review **Corrected**; analyst-recorded hallucination entries 3

### NT-01 - Vertical TCP port scan (S1)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning`; source records: 65895
- Timestamp quality: original_utc x30
- Final Week-2 analysis AN-20261020-013537-8c86 (6 runs): 2 validator flags; human review **Corrected**; analyst-recorded hallucination entries 5
- ATT&CK T1046 Network Service Discovery - *observed_pattern*

### NT-02 - DNS chunk-style query burst (S8)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly`; source records: 581
- Timestamp quality: original_utc x24
- Final Week-2 analysis AN-20261020-033312-7c54 (2 runs): 6 validator flags; human review **Corrected**; analyst-recorded hallucination entries 1
- ATT&CK T1071.004 Application Layer Protocol: DNS - *candidate*
- Limitation: authorized lab/test activity unknown
- Limitation: DNS payload meaning unknown
- Limitation: NOERROR is not evidence of exfiltration
- Limitation: Zeek rcode - is not NXDOMAIN
- Limitation: lab.test is a test-style domain, not confirmed attacker infrastructure

### NT-03 - Periodic HTTP connections to external host (S8)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing`; source records: 237
- Timestamp quality: original_utc x23
- Final Week-2 analysis AN-20261021-132533-02e7 (4 runs): 7 validator flags; human review **Corrected**; analyst-recorded hallucination entries 1
- ATT&CK T1071.001 Application Layer Protocol: Web Protocols - *candidate*

### RT-01 - plink.exe RDP tunnel (S8)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-01-C2`; source records: 4
- Timestamp quality: original_utc x4
- Final Week-2 analysis AN-20261017-222659-f35b (3 runs): 6 validator flags; human review **Corrected**; analyst-recorded hallucination entries 4
- ATT&CK T1572 Protocol Tunneling - *observed_pattern*

### RT-02 - Security log cleared + share access checks (S6)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-02-Discovery`; source records: 4
- Timestamp quality: original_utc x4
- Final Week-2 analysis AN-20261018-002643-c097 (4 runs): 0 validator flags; human review **Approved**; analyst-recorded hallucination entries 1
- ATT&CK T1070.001 Indicator Removal: Clear Windows Event Logs - *observed_pattern*
- ATT&CK T1033 System Owner/User Discovery - *candidate*

### RT-03 - WinRM remote command execution on DC (S7)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement`; source records: 3
- Timestamp quality: original_utc x3
- Final Week-2 analysis AN-20261018-010933-ca14 (2 runs): 5 validator flags; human review **Corrected**; analyst-recorded hallucination entries 1
- ATT&CK T1021.006 Remote Services: Windows Remote Management - *observed_pattern*
- ATT&CK T1016 System Network Configuration Discovery - *observed_pattern*

### RT-04 - Winlogon Shell persistence (S5)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-04-Persistence`; source records: 7
- Timestamp quality: original_utc x7
- Final Week-2 analysis AN-20261018-022126-c65b (3 runs): 1 validator flags; human review **Corrected**; analyst-recorded hallucination entries 2
- ATT&CK T1547.004 Boot or Logon Autostart Execution: Winlogon Helper DLL - *observed_pattern*

### BT-01 - .NET native-image optimisation (benign candidate) (benign control)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Benign/BT-01`; source records: 6
- Timestamp quality: original_utc x6
- Final Week-2 analysis AN-20261018-160709-eabf (2 runs): 2 validator flags; human review **Corrected**; analyst-recorded hallucination entries 3
- Limitation: Benign candidate only: approved/benign operation is not independently proven.

### BT-02 - SYSTEM service logons (benign candidate) (benign control)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Benign/BT-02`; source records: 4
- Timestamp quality: original_utc x4
- Final Week-2 analysis AN-20261018-160835-f96a (2 runs): 1 validator flags; human review **Corrected**; analyst-recorded hallucination entries 4
- Limitation: Benign candidate only: approved/benign operation is not independently proven.

### BT-03 - Service start/stop transitions (benign candidate) (benign control)

- Source kind: dataset_case; dataset: `Week-2/Data/Real-Datasets/Windows-Benign/BT-03`; source records: 6
- Timestamp quality: original_utc x6
- Final Week-2 analysis AN-20261018-160932-6d1c (2 runs): 2 validator flags; human review **Corrected**; analyst-recorded hallucination entries 4
- Limitation: Benign candidate only: approved/benign operation is not independently proven.

## Observables (IOCs and context)

Reputation: not checked for any value (no live TI feed). Full list: `Week-4/Output/observables.csv`.

| Role | Type | Value | Cases | Scope |
|---|---|---|---|---|
| indicator | ipv4 | 183.62.140.253 | LT-01, SIEM-AUTH-002 | public/other |
| indicator | ipv4 | 192.168.16.132 | NT-01, NT-02 | private (RFC 1918) |
| indicator | domain | bloodyswif.lat | SIEM-MAL-003 |  |
| indicator | domain | chunk001-f137fa53a835cab9745e769d.lab.test | NT-02 |  |
| indicator | domain | chunk017-6814d168efb413495592a30a.lab.test | NT-02 |  |
| indicator | domain | chunk034-20ce2c76b69c7c9b9c46dbe9.lab.test | NT-02 |  |
| indicator | domain | chunk050-34794a1a92aba55a84b23ab2.lab.test | NT-02 |  |
| indicator | domain | chunk067-300a1a1d12c721a19915c978.lab.test | NT-02 |  |
| indicator | domain | chunk084-0cd8bb7ce828a50395bf5328.lab.test | NT-02 |  |
| indicator | domain | chunk100-79e128737488911d9a02ae78.lab.test | NT-02 |  |
| indicator | domain | chunk117-29ce0e62c46f6577e7cdd4cc.lab.test | NT-02 |  |
| indicator | domain | chunk133-b34657f154de097c7c1b01da.lab.test | NT-02 |  |
| indicator | domain | chunk150-abe40348a8dd0c1b937adb0c.lab.test | NT-02 |  |
| indicator | domain | chunk167-62871f01fd6e9380b53795fb.lab.test | NT-02 |  |
| indicator | domain | chunk183-f4df5747aa53924340bcd561.lab.test | NT-02 |  |
| indicator | domain | chunk200-859ef48e43462029ecd421ff.lab.test | NT-02 |  |
| indicator | domain | chunk216-cd05f608e727d855357a48bd.lab.test | NT-02 |  |
| indicator | domain | chunk233-f001b3344bc99da19a864543.lab.test | NT-02 |  |
| indicator | domain | chunk250-ef566286fc3a33e1c288d41c.lab.test | NT-02 |  |
| indicator | domain | finickypwk.lat | SIEM-MAL-003 |  |
| indicator | domain | kickykiduz.lat | SIEM-MAL-003 |  |
| indicator | domain | leggelatez.lat | SIEM-MAL-003 |  |
| indicator | domain | mail.lab.test | NT-02 |  |
| indicator | domain | miniatureyu.lat | SIEM-MAL-003 |  |
| indicator | domain | ntp.ubuntu.com.localdomain | NT-02 |  |
| indicator | domain | plodnittpw.lat | SIEM-MAL-003 |  |
| indicator | domain | portal.lab.test | NT-02 |  |
| indicator | domain | savorraiykj.lat | SIEM-MAL-003 |  |
| indicator | domain | shoefeatthe.lat | SIEM-MAL-003 |  |
| indicator | domain | steamcommunity.com | SIEM-MAL-003 |  |
| indicator | domain | update.lab.test | NT-02 |  |
| indicator | domain | washyceehsu.lat | SIEM-MAL-003 |  |
| indicator | filename | 2r8602.exe | SIEM-MAL-003 |  |
| indicator | filename | BRE6BgE2JubB.exe | RT-04 |  |
| indicator | filename | N1F90.exe | SIEM-MAL-003 |  |
| indicator | filename | a.exe | RT-04 |  |
| indicator | filename | plink.exe | RT-01 |  |
| indicator | imphash | 2eabe9054cad5152567f0699947a2c5b | SIEM-MAL-003 |  |
| indicator | ipv4 | 10.0.2.17 | RT-02 | private (RFC 1918) |
| indicator | ipv4 | 10.0.2.18 | RT-01 | private (RFC 1918) |
| indicator | ipv4 | 10.0.255.12 | LT-03 | private (RFC 1918) |
| indicator | ipv4 | 104.80.2.104 | SIEM-MAL-003 | public/other |
| indicator | ipv4 | 127.0.0.2 | RT-01 | loopback |
| indicator | ipv4 | 192.168.1.199 | NT-03 | private (RFC 1918) |
| indicator | ipv4 | 192.168.16.130 | NT-01 | private (RFC 1918) |
| indicator | ipv4 | 192.168.16.131 | NT-02 | private (RFC 1918) |
| indicator | ipv4 | 192.168.171.129 | SIEM-WEB-004 | private (RFC 1918) |
| indicator | ipv4 | 255.102.154.224 | SIEM-WEB-001 | reserved (240.0.0.0/4) - not routable |
| indicator | ipv4 | 46.101.251.172 | NT-03 | public/other |
| indicator | ipv4 | 81.2.248.189 | NT-03 | public/other |
| indicator | ipv4 | 94.124.107.190 | NT-03 | public/other |
| indicator | sha256 | a1a79febe636f6af95ca527bf37321a329f37bc2524414376f2727f4d9bd17c1 | SIEM-MAL-003 |  |
| context | ipv4 | 192.168.16.1 | NT-01, NT-02 | private (RFC 1918) |
| context | domain | attackrange.local | SIEM-EXCH-005 |  |
| context | domain | connectivity-check.ubuntu.com | NT-02 |  |
| context | domain | dc1.insecurebank.local | RT-03 |  |
| context | domain | pc01.example.corp | RT-01 |  |
| context | domain | win-77ltaphiq1r.example.corp | RT-02 |  |
| context | email | Administrator@attackrange.local | SIEM-EXCH-005 |  |
| context | filename | cmd.exe | RT-03 |  |
| context | filename | explorer.exe | RT-04 |  |
| context | filename | ipconfig.exe | RT-03 |  |
| context | filename | mscorsvw.exe | BT-01 |  |
| context | filename | userinit.exe | RT-04 |  |
| context | filename | winlogon.exe | RT-04 |  |
| context | filename | winrshost.exe | RT-03 |  |

## Cross-dataset overlaps found by correlation

| Value | Type | Role | Cases |
|---|---|---|---|
| 183.62.140.253 | ipv4 | indicator | LT-01, SIEM-AUTH-002 |
| 192.168.16.132 | ipv4 | indicator | NT-01, NT-02 |
| 192.168.16.1 | ipv4 | context | NT-01, NT-02 |
## Human sign-off

| Role | Name | Decision (Approved / Corrected / Rejected) | Date | Signature |
|---|---|---|---|---|
| SOC analyst |  |  |  |  |
| IR lead |  |  |  |  |
| Project supervisor |  |  |  |  |
