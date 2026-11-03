# LT-04 — Linux Startup and Service Initialization: Verified Case Study

## Assessment

**Low-risk / benign candidate within the 18 selected records**, not verified benign ground truth for the entire host. Source events document ordinary-looking Linux startup messages. **No confirmed attack indicators were observed in this focused selection**. The 2,000-line original contains other potentially risky events; their exclusion must not be interpreted as a clean-host finding or a measured false-positive rate.

## Dataset and Evidence Provenance

- Source: Loghub `Linux/Linux_2k.log`, saved locally as `LT-04-Linux-original.log`.
- Source records: **2,000**; selected source-derived focused records: **18**.
- Host: **`combo`**, directly recorded in every selected syslog line. `localhost` in the original AI narrative is unsupported.
- Source SHA-256: `b3e20bc1afe732ab1bf3ed1de4bf9c809e4194e02f7dea911d918e5342e8e173`.
- Focused log SHA-256: `1eebd6b57e97b8ab72af8f0a109fb683cef99fe2cdb06990cc48c152dc458070`.
- Mapping CSV SHA-256: `0b9cf6172d8357e2f53ebde52e45265626c2e1540fa4200c0308314f9033ac3a`.
- `LT-04-evidence-mapping.csv` links `E001`–`E018` to original line numbers and raw line SHA-256 hashes.
- Focused file preserves the complete original selected syslog text, with line-ending normalization. Two documented parser-only trailing-whitespace differences **do not alter the source or focused file**; this script verified **2** such note(s) against the source.
- Source timestamps show `Jul 27` and clock times **without an explicit year or timezone**. Neither is inferred. The verified CSV timeline is sorted by **recorded local clock time**, not by assumed UTC. For equal timestamps, source selection order is retained.

## Source-Supported Observations

- [E001], [E004]: startup-success messages for `syslogd` and `klogd`.
- [E002], [E003], [E005]–[E012], [E017], [E018]: kernel initialization and device/memory/protocol information, including the **BIOS-e820 memory map** [E003].
- [E013], [E015]: Bluetooth-related service startup-success messages.
- [E014], [E016]: network parameter initialization and loopback interface startup-success messages.
- **BIOS-e820 reserved-memory description [E003] is not evidence of unauthorized BIOS changes, credential compromise, or privilege escalation.**
- The source is not sufficient to establish authorization of all activity, system integrity, or absence of attacks outside the selected window.

## Timeline

- Full **18-row** source-verified timeline: `LT-04-Verified-Timeline.csv`.
- Every row contains an `E###` evidence ref and original source line number; **no placeholder rows (`...`) or invented UTC timestamps**.
- Messages are provided as observed, not as reconstructed outcomes. Process/service message text and source order are both traceable.

## Local AI Analysis and Human Review

- AI analysis ID: `AN-20261019-003000-126d`; model: local Mistral.
- Model correctly recognized system initialization, but suggested unsupported unauthorized BIOS modification/privilege escalation based on [E003]. It also treated the actual host `combo` as a source name and invented `localhost` as hostname.
- The old automated validator detected **one medium flag**: a timeline placeholder row with no evidence reference. Other semantic errors were documented by the human analyst.
- CLI-observed analyst review disposition: **Corrected**. This script does **not** independently inspect the review-storage schema or modify the model output.
- An event labeled `Benign Candidate` in this report is **not a true-negative ground truth claim** or a statistical false-positive-rate estimate.

## Missing Evidence and Next Checks

1. Confirm service and kernel startup context against complete boot and process telemetry, if available.
2. Check authorizations, maintenance windows, host configuration, and adjacent source events before determining broader host posture.
3. When presenting AI results, distinguish *routine-looking observed events* from a general "host is secure" assertion.
4. Keep the original yearless and timezone-less timestamps intact; external corroboration is needed before assigning absolute calendar times.
5. Add feedback rules against unsupported privilege-escalation inferences from `BIOS-e820` information and incorrect syslog hostname attribution, then run regression tests.

## Conclusion

The 18 selected log lines support a **low-risk Linux initialization candidate**, with **no evidence of a confirmed security incident in those lines**. They do not establish an entirely benign host. Human review corrected the model's false-positive inference and attribution/timeline errors. All original inputs, AI results, and reviews remain unchanged.
