# Test inputs

- `empty.log`, `invalid.json`, `binary.bin`, `only_comments.log`, `ndjson_with_bad_line.ndjson` - invalid/incomplete-input tests (category 9, 7).
- `SYNTHETIC_injection_attempt.log` - a log line that tries to instruct the AI (untrusted-input test).
- Main fixtures live in `Data/` (see `Data/fixtures_manifest.json`). All are **synthetic**.
