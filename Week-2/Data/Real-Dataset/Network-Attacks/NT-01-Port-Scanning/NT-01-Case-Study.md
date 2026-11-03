# NT-01 — Source-Verified Vertical TCP Port Scanning Case Study

**Track:** DEPI P5 — AI-Assisted SOC Analysis  
**Network source:** Zeek `conn.log`, pinned Git repository `dikshitdhawan/NTA-Zeek-Threat-Detection-Lab`  
**Original SHA-256:** `f9282d987047ef37a807a575a353ff601ddbb1b389aa76e92214c302de2fbda9`  
**Evidence scope:** 65,895 original Zeek connection records; 31 focused records (1 derived summary + 30 source rows).

## Evidence integrity and provenance

The original Zeek dataset and metadata were recomputed against the pinned-source evidence preparation logic. The saved focused JSON, mapping CSV, full-source statistics, and selection manifest match their source-derived bytes and SHA-256 values. All **30 selected original Zeek rows** were independently matched to the corresponding original source line, raw line SHA-256, Zeek UID, epoch timestamp, UTC rendering, source/destination IP, source/destination port, protocol and connection state. The project parser read 31 entries as network evidence with no warnings.

**Critical distinction:** `E001` is a *verified computed aggregate* of the complete source, **not a captured network connection**. `E002`–`E031` are sampled *original Zeek source records*; the source-derived timeline CSV contains those 30 connection rows, not a fictitious connection for `E001`.

## Verified network findings

| Metric | Source-derived result |
|---|---|
| Observed behavior | High-confidence **vertical TCP destination-port scan pattern** |
| Originator | `192.168.16.132` |
| Responder | `192.168.16.130` |
| Original connection records | **65,895** |
| TCP records for scan pair | **65,747** |
| Distinct destination TCP ports for scan pair | **65,535** (targeted; not necessarily open) |
| Pair states | **REJ 65,620; RSTO 15; S0 112** |
| Scan-pair time range (UTC) | `2026-05-26T06:07:27.414749Z` to `2026-05-26T06:19:45.683665Z` |
| Duration | Approximately **738.269 seconds** |
| Authorization / actor intent | **Unknown / not established** |
| Open ports / exploitation / compromise | **Not established** |

A single source targeted nearly the entire TCP destination-port range of one target over a concentrated period. This strongly supports a vertical port-scanning pattern, independent of authorization or malign intent. Zeek `REJ` indicates rejected connection attempts and by itself does not prove firewall enforcement or compromise. The source and destination are private IP addresses, which does not establish benignity.

## Context events vs. scan events

`E002` and `E031` are **UDP DNS** contextual events (`192.168.16.130` → `192.168.16.1:53`), **not** TCP port-scan flows. `E011` is a TCP scan-pair flow (`192.168.16.132:44372` → `192.168.16.130:64112`, state `REJ`). The verified timeline preserves source and destination *ports* separately; source-port numbers must never be reported as destination ports.

## AI analysis, validation and human-in-the-loop

- **Baseline analysis:** `AN-20261020-011716-3d22` — failed to explicitly identify the high-confidence scan pattern and misinterpreted aggregate `E001` as a raw connection.
- **Post-grounding analysis:** `AN-20261020-013537-8c86` — recognized aggregate `E001`, but still failed to name the scan pattern and incorrectly attributed multiple connection directions/port roles.
- **Grounded detector:** Saved independent finding `NETWORK_VERTICAL_PORT_SCAN`, high confidence **in the observed pattern**, not in malicious intent or compromise.
- **Semantic replay:** 21 v1 network review request(s) and 20 v2 review request(s), counted from the saved post-grounding report. Types: `network_direction_mismatch` (15), `network_port_role_mismatch` (4), `private_network_not_benign` (1).
- **Review scope:** CLI human reviews were reported as `Corrected` for the baseline and post-grounding analyses. This finalizer does *not* independently inspect or certify the application-specific review storage schema; it leaves both saved reviews unchanged.

**Do not interpret 20 v2 flags as 20 independent security incidents.** Repeated incorrect assertions in multiple report sections and separately referenced evidence events can produce multiple review requests.

## Verified source-derived timeline

See `NT-01-Verified-Timeline.csv` for all 30 selected original connection rows, sorted chronologically and carrying references, precise UTC timestamps, source-line IDs, UIDs and SHA-256 hashes. The aggregate scan period is described above, **not inserted as a fabricated packet, connection or user action**. The 30 rows are a **sample**, not an exhaustive incident timeline of all 65,895 original source records.

## Investigation constraints and follow-up

Determine scan authorization from change records/registered testing, assess endpoint and firewall telemetry, identify the scan tool if available, and compare against other network sources. This evidence does not establish open ports, successful compromise, exfiltration, or attacker identity. Keep security conclusions separated from observed network facts.

## Provenance and safety

Source logs, four derived evidence artifacts, `Core`, `Results`, and existing human reviews were read-only throughout this finalization. Generated documents were created exclusively, with no overwrite.
