# Feedback Lessons and Evidence Limits

| ID | Source analysis | Review gate | Generalized rule | Caveat |
|---|---|---|---|---|
| LT01_SSH_TIME | `AN-20261018-183730-901f` | Reviewed | Preserve year/timezone uncertainty in Syslog; failed logons are not successful access | May need a source-provided timestamp origin |
| LT02_AUDITD_OUTCOME | `AN-20261018-221905-552c` | Reviewed | PROCTITLE alone does not prove successful SUID/capability setting or administrative authorization | Recover SYSCALL/EXECVE/USER_AUTH to determine outcomes |
| LT03_REVERSE_SHELL | `AN-20261018-231218-e901` | Reviewed | Bash /dev/tcp is not netcat, command destination is not an observed TCP flow, do not double-count duplicates, private ≠ public IP | Private address can still be external to the local machine or VPC |

Saved human reviews are considered a gate for these *curated* rules. The package does not take arbitrary free-text review notes and teach the model to obey them. These lessons are **prompt context**, not weight updates. Semantic checks are independently evidence-based and still require human triage.
