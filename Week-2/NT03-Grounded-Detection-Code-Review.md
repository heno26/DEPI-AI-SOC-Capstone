# NT-03 — Code review and minimal grounded-retry patch

## Review provenance and limits

**Input:** `NT03-Grounded-Detection-Code-Review.zip` (13 code/test files, 56,783 bytes); SHA-256 `58257a913832d1e452ac132e08e789f0eccfbfb64c0c8f72a4e7b9327e7348f5`.

This is a **review of the supplied code snapshot**, not proof that all 13 files match the current machine after packaging. The upload did **not** contain `NT-03-focused.json`, original `conn.log.labeled`, the complete 275-test repository, or saved `analysis.json`. Exact full-project regression and case replay therefore **must run on the user's machine**. Files were read without modifying user data.

## What the existing code already does

- `Core/log_parser.py` (`_event_from_json`, `load_file`, lines 190–327) maps top-level `events` into parsed records, flattens structured fields, and assigns `[E###]` references.
- `Core/analysis.py` (lines 196–309) builds the prompt, requests model inference, saves deterministic grounded observations and automated review flags, and initially marks all new runs `Pending Review`.
- `Core/grounded_detection.py` (lines 76–161, 164–231) contains Linux observation rules and delegates network handling to `Core/network_grounding.py`.
- `Core/network_grounding.py` (lines 99–228) covers verified-in-input **vertical TCP port sweep** patterns, calls `dns_grounding.py`, and delegates network attribution to `network_semantics.py`.
- `Core/dns_grounding.py` (lines 92–176, 202 onward) covers clustered DNS query patterns and safeguards their interpretation.
- `Core/network_semantics.py` (lines 99–157) checks directly cited raw Zeek references for direction mismatch, *source-versus-destination port swaps*, and a private-network-as-benign rationale.
- `Core/validator.py` (lines 207–355) handles report structure and broad IOC/reference checks, and keeps findings as *requests for human review*, not verdicts.
- Existing network and Linux tests cover earlier behavior. No project source file needs to be replaced wholesale.

## Confirmed NT-03 gaps

1. **No TCP retry/retransmission-like observation rule.** `network_grounding.detect_network` only adds vertical port-scan and DNS findings; grouped TCP/80 `S0 ... SF` source-port reuse is not analyzed.
2. **Port attribution gap:** `network_semantics.review_requests` flags `on port X` when `X` equals the actual **source** port rather than destination port. An invented third port, such as **[E008] TCP/80 incorrectly described as port 23**, was not compared at all. The new check is deliberately narrow: a *single explicitly bracket-cited original Zeek connection*, `from A to B`, and an unambiguous `on port P`/`destination port P` assertion.
3. **AI omissions are not the same as detections.** The seven baseline flags for `AN-20261021-121055-9c32` report missing headings but cannot establish that the network behavior was detected. A grounded finding needs independent references, counts, and caveats.
4. **`S0`/`SF` are not per se separate connection attempts.** Repeated same-four-tuple Zeek rows may be retransmission- or capture-related; `SF` means Zeek observed connection establishment and orderly closure, not automatically a confirmed file-download payload. Claims about a precise backoff algorithm, periodic beaconing, C2 intent, malicious authorization, or compromise remain unverified.

## Minimal patch package, not yet installed on the user's device

The accompanying `SOC_NT03_Grounded_Retry_v1.zip` contains:

| Action | Path | Scope |
|---|---|---|
| PATCH | `Core/network_grounding.py` | Compose new TCP findings alongside existing port-scan and DNS rules. |
| PATCH | `Core/network_semantics.py` | Add conservative `network_destination_port_mismatch` review for explicit single-ref attribution. |
| CREATE | `Core/tcp_retry_grounding.py` | Separate source-derived same-four-tuple pattern extraction without use of source labels. |
| CREATE | `Testing/test_nt03_retry_grounding.py` | 18 tests of positive findings, negative cases, labels, persistence, and attribution. |

**No modifications requested** to `Core/analysis.py`, `Core/validator.py`, `Core/log_parser.py`, Linux detection rules, DNS detection rules, existing tests, Data, Results, or saved analyst reviews.

**Rule constraints:** Accept only `record_kind == ZEEK_CONN_ORIGINAL_SOURCE_ROW` and `proto == tcp`; group by source/destination IP, destination port, and source port; require at least two repeated source-port groups for one endpoint pair, with at least three Zeek rows each and a minimum of two `S0` states before one later `SF`; preserve raw evidence references and observed intervals. Interpret as **repeated TCP same-four-tuple S0-before-SF pattern, potentially retry/retransmission/backoff-like**, not proof of periodic beaconing or C2. Computed aggregates do not count as raw connections. Ground truth `label` and `detailed-label` are not used.

**Replay behavior:** Re-compute findings on a *saved historical analysis* without changing that record. To persist new findings, run a **new analysis** after installation; historical results and reviews are retained unchanged.

## Local checks completed in isolated snapshot

- Uploaded ZIP SHA-256 verified against screenshot.
- New Python source syntax: **PASS**.
- Installer `--check` on extracted reviewed files: **PASS**.
- **109 relevant isolated unit tests PASS** in local temporary review workspace, including the 18 new tests and original network/Linux grounding test modules. (The full 275-test suite was not available here.)

## Guarded installation workflow

1. Extract the package into the Week-2 project root (do not overwrite the current source directly).
2. Run `python .\SOC_NT03_Grounded_Retry_v1\upgrade.py --check` — **read-only**, compares baseline SHA-256 of both patched files, verifies new paths do not already exist.
3. **Wait for and inspect the `--check` output.** If it passes, the next step is `--install`, which backs up original patched files, runs full test suite before and after, and attempts rollback on test failure.
4. Run the read-only `--replay` of `AN-20261021-121055-9c32`; inspect grounded groups, original refs and evidence-attribution flags.
5. Only then conduct a separate post-grounding AI analysis and human review, followed by final evidence mapping/documentation.

**Do not claim the patch is successfully installed or that 275→293 tests pass until the user's local command outputs confirm it.**
