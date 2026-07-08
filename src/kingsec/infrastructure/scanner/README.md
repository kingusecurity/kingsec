# Nuclei Scanner Adapter — Module 5.1

Implements the application's `ScannerPort` by invoking the [Nuclei](https://github.com/projectdiscovery/nuclei)
CLI and parsing its JSONL output into domain `Finding` objects. Infrastructure
layer; the domain stays pure (the adapter imports domain to *build* findings, the
domain imports nothing).

## Security model (read first)

- **No `shell=True`, ever.** Commands are executed as an argument **list** with
  `shell=False`, so a target string is one opaque `argv` element — no shell can
  interpret metacharacters. This is the core defence against command injection.
- **Hard timeout** bounds every scan; a hung scanner cannot wedge the process.
- **Defense in depth with the domain gate.** The adapter is only reached via
  `StartAssessment`, which the domain permits only after `AUTHORIZED` — an
  unauthorized scan never gets here.
- **Trusted config.** `binary_path` / `templates_dir` are operator-controlled
  (supply-chain sensitive); a missing templates dir fails fast with a clear error.
- Flags force safe, deterministic runs: `-silent -nc -duc` (no banner, no colour,
  no auto-update network calls) and `-rl` (rate limit).

## Structure

| File | Role |
|---|---|
| `runner.py` | `CommandRunner` Protocol + `SubprocessCommandRunner` (the only `subprocess` caller) |
| `parser.py` | pure `parse_nuclei_jsonl(text) -> list[Finding]` + severity mapping |
| `nuclei.py` | `NucleiScannerAdapter(ScannerPort)` — builds args, runs, translates, parses |
| `errors.py` | `ScannerExecutionError` / `ScannerOutputError` (subclass shared `ScannerError`, KS-SCAN-001) |
| `provisioning.py` | `register_scanner(container, settings)` DI wiring |

## Configuration (`KINGSEC_SCANNER__*`)

| Setting | Default | Meaning |
|---|---|---|
| `binary_path` | `nuclei` | path/name of the Nuclei binary |
| `templates_dir` | `None` | templates directory (None → Nuclei default) |
| `timeout_seconds` | `300` | hard wall-clock scan timeout |
| `rate_limit` | `150` | requests/sec cap (`-rl`) |

## Usage

```python
from kingsec.infrastructure.scanner import register_scanner
register_scanner(app.container, app.settings)      # binds ScannerPort
scanner = app.resolve(ScannerPort)                  # NucleiScannerAdapter
findings = scanner.scan(target)                     # -> domain Findings
```

## Error handling

`FileNotFoundError` (bad binary), `TimeoutExpired`, and non-zero exit codes all
become `ScannerError` (KS-SCAN-001); stderr is captured into log context, never
surfaced to users. Malformed/non-JSON output lines are logged and skipped so one
bad line can't discard a whole scan; empty output is a valid "no findings" result.

## Testing

The `CommandRunner` Protocol lets unit tests inject a fake (no binary needed).
Integration tests run the **real** `SubprocessCommandRunner` against a generated
fake-nuclei script to exercise the actual process path, timeouts, and exit codes,
plus a full slice through `StartAssessment` + SQLite persistence.
