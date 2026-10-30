# Project rules

## Dual-implementation parity (MANDATORY)

This repo has two implementations of the same scanner that must stay in
lockstep:

- `filescanner.py` — Python (threads, requests)
- `go/` — Go port (goroutines, net/http, modernc.org/sqlite)

**Rule: any behavior/config/bugfix change applies to BOTH.** When you
modify one implementation, make the equivalent change in the other in the
same commit/PR, or explicitly flag why it cannot apply (e.g. platform-only
feature). Known intentional deltas are listed in README.md ("Known
differences" section) — update that list if you add one.

Checklist when changing behavior:
- config key added/renamed → update `config.ini.template`,
  `go/config.ini.template`, `load_config` (py) and `loadConfig`/`parseINI`
  consumers (go), README config table
- pipeline semantics (statuses, claim/unclaim, gating, backoff) → mirror
  in `DetectAsyncClient`/`upload_worker`/`result_poller` (py) and
  `DetectAsyncClient`/`uploadWorker`/`pollIteration` (go)
- output/DB schema → both `ScanDB` implementations share the
  `scan_state.db` schema; keep it identical so runs interoperate
- reports → JSON/CSV/HTML/PDF writers exist in both

## Per-run outputs

Every run writes artifacts to `<output_dir>/run_YYYYMMDD_HHMMSS/`
(ndjson, log, reports, quarantine, alerts). `scan_state.db` intentionally
stays at `output_dir` root — it is cross-run resume state, not a report.

## Verify

- Python: `.venv/bin/python -m pytest tests/ -q`
- Go: `cd go && gofmt -l . && go vet ./... && go build ./...`
- Binaries: `make` at repo root → `dist/`

## Secrets

`config.ini` is gitignored (contains the API token). Never commit it;
only `config.ini.template` is tracked. Secrets come from env via
`${VAR}` expansion.
