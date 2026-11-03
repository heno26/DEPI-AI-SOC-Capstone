# NT-03 — Repeated TCP Four-Tuple / Retry-Like Traffic: Evidence-Grounded SOC Case Study

> **Document status:** Draft based on the NT-03 PowerShell and model outputs provided during Week 2. The source file and manifests have **not** been independently opened in the document-authoring environment. Final publication should follow local artifact inventory, source-row/hash verification, and timeline generation.  
> **Scope:** NT-03 only. No NT-04 work is included.  
> **Assessment type:** Behavioral investigation and AI hallucination/semantic validation; **not** independent confirmation of an active C2 compromise.

## 1. Executive summary

NT-03 studies Zeek `conn.log` records from the Stratosphere IPS **IoT-23** dataset, capture **`CTU-IoT-Malware-Capture-44-1`**. A source-derived investigation identified **24 TCP connections** from `192.168.1.199` to `46.101.251.172:80`: **13** had Zeek state `S0` and **11** had state `SF`. Within the TCP/80 traffic, **four repeated same-four-tuple / source-port groups** contributed **17 source records** using source ports `59224`, `59228`, `59236`, and `59240`.

The repeated observations and their time intervals merit investigation for **retry-like connection behavior**. They do **not** alone prove that each row is a separate connection attempt, that a retry/backoff algorithm ran, that the flow is strictly periodic, or that C2, malicious intent, or compromise occurred. Source-provided `C&C` labels were kept as **evaluation metadata**, excluded from the AI-visible focused evidence and the behavioral selection criteria.

The case also demonstrates how a locally executed Mistral 7B model can omit material evidence and make assertions inconsistent with verified Zeek fields. Python-based grounding detected the repeated four-tuple pattern, while a later semantic validator patch identified three specific problems in the stored AI report during **read-only replay**.

## 2. Source provenance and integrity

| Item | Source-derived detail |
| --- | --- |
| Dataset | Stratosphere IPS IoT-23 |
| Capture | `CTU-IoT-Malware-Capture-44-1` |
| Original logical file | `bro/conn.log.labeled` |
| Retrieved from | `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled` |
| Local directory | `Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/` |
| Original bytes | `31,179` |
| Original SHA-256 | `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f` |
| Physical lines | `246` |
| Zeek connection records | `237` |
| Zeek fields | `23` |
| Original source acquisition | HTTPS certificate verification enabled; local integrity matched discovery-time SHA-256 |
| Source provenance limitation | URL and verified downloaded bytes; **not** an immutable pinned Git commit |

The source inspection reported **no malformed connection records** after the corrected parser was used. An initial parser attempt stopped at line 9 and was superseded by the successfully validated version. The original source was retained unchanged in the final acquisition step.

### Dataset-supplied labels — evaluation metadata only

| Label / detailed label | Records |
| --- | ---: |
| `Benign / -` | 211 |
| `Malicious / C&C` | 14 |
| `Malicious / C&C-FileDownload` | 11 |
| `Malicious / DDoS` | 1 |
| **Total** | **237** |

These labels are annotations supplied with the dataset; they were **not** used as proof of beaconing, payload content, or independent malicious attribution. The model-safe evidence explicitly withheld source labels.

## 3. Evidence preparation and audit boundaries

The focused input was created after checking the dataset and parser against the project's established `events` JSON schema.

- **Focused input:** `NT-03-focused.json` — **25** model-visible events: **E001–E002 computed aggregates** and **E003–E025 original Zeek source-row evidence**.
- **Focused SHA-256:** `ce7f1905335690eaea42f4d299824a057b36153d4747058a7405fbe6b04e67a6` (as reported by the CLI at analysis time).
- **Original-row selection:** **23 rows**; 17 repeated-four-tuple rows, three TCP/80 singleton context rows, one other TCP destination-port context row, and two UDP/123 comparison rows.
- **Provenance controls:** Original source-line numbers, timestamps, Zeek UIDs where available, and row-level SHA-256 mappings preserved; no replacement of actual rows by computed aggregates.
- **Companion artifacts reported as created:** `NT-03-evidence-mapping.csv`, `NT-03-Verified-Full-Source-Statistics.json`, and `NT-03-Selection-Manifest.json`.

**Important:** E001 and E002 summarize source-derived statistics and are **not** individual wire-level Zeek connection records. The reported 24 TCP/80 connections are a full-source count; the 17 mapped repeated rows are a selected model-visible subset, not the total number of source connections.

## 4. Observed network behavior

### 4.1 Focus flow

`192.168.1.199` → `46.101.251.172:80` over TCP:

| Field | Verified investigation output |
| --- | ---: |
| All target-flow records | 24 |
| `S0` records | 13 |
| `SF` records | 11 |
| Repeated same-source-port groups | 4 |
| Records in repeated groups | 17 |
| All adjacent inter-arrival intervals in target flow | 23 |
| Target-flow mean inter-arrival | approximately 7.7301 seconds |
| Target-flow median inter-arrival | approximately 7.2129 seconds |
| Target-flow coefficient of variation | approximately 0.979 |

`S0` means Zeek observed no reply for that connection record; it does not alone determine the remote endpoint's true state. `SF` and positive Zeek byte counts demonstrate **observed completed traffic and byte transfer for those records**, but do not reveal application payload content or establish C2 success.

### 4.2 Repeated source-port sequences

| Source port | Original source lines | Observed Zeek state sequence | Adjacent start-time intervals (seconds) |
| --- | --- | --- | --- |
| `59224` | 10, 11, 12, 13 | `S0, S0, S0, SF` | 7.161155; 8.240059; 16.640250 |
| `59228` | 15, 16, 17, 18 | `S0, S0, S0, SF` | 7.212885; 8.560111; 16.640009 |
| `59236` | 21, 23, 25, 26, 30 | `S0, S0, S0, S0, SF` | 7.235872; 8.320005; 16.640004; 32.640141 |
| `59240` | 32, 34, 36, 37 | `S0, S0, S0, SF` | 7.219131; 8.640072; 16.640003 |

These sequences support a **reviewable retry/backoff-like hypothesis**, not a confirmed TCP retransmission or a confirmed exponential-backoff implementation. The overall interval variation does not establish periodic beaconing.

### 4.3 Contrastive evidence: TCP/23 and UDP/123

- The original row at source line **242**, focused ref **E013**, shows `192.168.1.199:51834` → `46.101.251.172:23` (`tcp`, `S1`). Here `51834` is a **source** port and `23` is the **destination** port; this row is **not** part of the TCP/80 group.
- Two additional model-visible records were selected as UDP/123 comparison context (original source lines 22 and 243).

## 5. AI analysis and human review

### 5.1 Baseline before NT-03 grounded retry update

| Field | Result |
| --- | --- |
| Analysis ID | `AN-20261021-121055-9c32` |
| Model | `mistral:7b-instruct-v0.3-q4_K_S` |
| AI-visible events | 25 |
| Original automatic flags | 7 medium, all `missing_section` |
| Persisted NT-03 repeated-four-tuple grounded findings | 0 |
| Human analyst review | `Corrected` |

The baseline report noted TCP/80 activity but did not quantify the four repeated groups and had an evidence-reference attribution error (it described E008 as TCP/23 although the context row for TCP/23 was E013). Structural validation did not highlight the central behavioral gap.

### 5.2 After grounded retry installation

| Field | Result |
| --- | --- |
| Analysis ID | `AN-20261021-132533-02e7` |
| Model | `mistral:7b-instruct-v0.3-q4_K_S` |
| AI-visible events | 25 |
| Saved grounding rule | `NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE` |
| Grounding confidence | `high` **in the observed pattern**, not C2 attribution |
| Grounded evidence refs | 17 refs, covering the repeated groups |
| Saved automatic flags | 7 medium `missing_section` flags (historical, unchanged) |
| Human analyst review | `Corrected` |

The model acknowledged repeated TCP connections but described them as possibly scanning/probing, omitted the four-group quantification, and asserted there was *no evidence of successful connection or data transfer*. The latter conflicts with verified `SF` records and positive Zeek byte-count fields. It also listed source port `51834` in the context of the destination-port-80 flow, although the mapped E013 row targets port 23.

**Interpretation:** The grounded observation persisted successfully in `Results/<analysis_id>/analysis.json`, and the historical replay confirmed **four groups, 17 records, and source ports 59224/59228/59236/59240**. Model narrative quality did not automatically improve merely because grounded evidence was stored. A human analyst still adjudicated the report.

## 6. NT-03 validator upgrades and test results

| Milestone | Outcome |
| --- | --- |
| Grounded retry v1 install | `275 → 293` regression tests, **PASS** |
| Semantic validation v2 install | `293 → 317` regression tests, **PASS** |
| `SUSPICIOUS ACTIVITY` singular-heading alias | **Recognized** in post-fix replay |
| Historical report replay | Read-only, source SHA-256 **MATCH**, original result/review preserved |

The final post-fix semantic replay for analysis `AN-20261021-132533-02e7` returned **three targeted analyst review requests**:

| Severity | Rule | Supported issue |
| --- | --- | --- |
| **high** | `network_observed_tcp_data_contradiction` | Report broadly denied successful connection or data transfer despite source-observed `SF`/byte evidence. |
| **medium** | `network_source_port_group_mismatch` | Report listed source port `51834` with the TCP/80 flow, although the mapped context row is TCP/23. |
| **medium** | `network_tcp_retry_missing_quantification` | Report omitted supported quantities: repeated-group count, raw-row count, and a verified interval example. |

The replay confirmed: `Target check ... FOUND` for **all three**. These replay findings are **additional read-only review requests**; they did **not** overwrite the seven original stored flags, the model draft, the source evidence, or the human review.

A `ResourceWarning` referencing cleanup of an `HTTPError 500` object appeared during the regression suite but did not cause tests to fail; retain it as maintenance follow-up, not proof of a regression failure.

## 7. Conclusions and uncertainty

**Verified from the supplied execution outputs:**

1. Source acquisition and focused-evidence integrity checks passed against saved fingerprints.
2. Full-source inspection identified 24 TCP/80 rows, including 13 `S0` and 11 `SF` records.
3. Four same-four-tuple/source-port groups covering 17 mapped original rows were detected and persisted.
4. The AI's post-grounding narrative contained factual inaccuracies and omitted material quantification.
5. The updated semantic validator flagged all three target deficiencies on a read-only replay.
6. Regression tests passed after both patches, ending at **317 passing tests**.

**Not established by this case:** independently verified C2 attribution; true periodic beaconing; exponential-backoff implementation; distinct application-level retry attempts; file-download content or malware identity; data exfiltration; endpoint compromise; or that every possible hallucination is covered by the validator.

The dataset's original labels support **later evaluation against annotations**, not independent proof of any of the above.

## 8. Remaining documentation integrity gate

Before marking the NT-03 case *fully documented*, perform a **read-only local inventory** of `Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/` and `Evidence/Network/`, then:

1. Verify the original log, `NT-03-focused.json`, source/selection manifests, mapping CSV, and full-source statistics are present and internally consistent.
2. Generate or verify the **24/23-row evidence-linked timeline** from the **actual local original Zeek records**, not from copied console excerpts or AI-generated descriptions. Define precisely whether the timeline includes all focused original rows (23) or the full-source TCP/80 target flow (24), and do not label a subset as the full dataset.
3. Record actual SHA-256 digests of the **final documentation outputs** in a final verification manifest. Never predeclare output hashes before generating/verifying the files.
4. Confirm the evidence screenshot filenames and location; preserve original source, Results, saved reviews, and Core as they are.
5. Only then promote this draft to `NT-03-Case-Study.md` (without overwriting an existing document), and mark NT-03 documentation complete.

## 9. Known analysis and screenshot identifiers

- Baseline: `AN-20261021-121055-9c32` — Human Review `Corrected`.
- Post-grounding: `AN-20261021-132533-02e7` — Human Review `Corrected`.
- Installation screenshot naming convention: `NT03-Semantic-Validator-v2-Installation-317Tests-Final-Replay-PASS.png`.
- Final replay screenshot naming convention: `NT03-Semantic-Validator-v2-Final-Replay-3Flags-PASS.png`.

These screenshot names were **recommended** in the conversation; inspect the actual folder before claiming that the files exist.

---

**Draft prepared for the Week 2 NT-03 documentation stage. No NT-04 steps, code patches, or changes to the user's local project are included.**
