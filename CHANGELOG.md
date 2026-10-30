filescanner Change Log
=========

v1.0.0 (2026-10-30)
-------------------

Initial public release.

- **Scanning**: walks a drive or folder and submits each file to one
  ReversingLabs backend, selected via `scan.backend` — Spectra Detect,
  Spectra Analyze (A1000), File Inspection Engine, or Spectra
  Intelligence cloud.
- **Reputation pre-check**: optional Spectra Intelligence bulk-hash lookup
  classifies known files before upload (`reputation.precheck`).
- **Async pipeline**: separate upload and result-polling worker pools with
  backpressure, availability gating and exponential backoff.
- **Resume**: SQLite state (`scan_state.db`) lets an interrupted scan
  continue without resubmitting finished files.
- **Verdict actions**: optional quarantine (`copy` / `move`) and alerts via
  webhook, syslog or the Windows Event Log.
- **Reports**: JSON, CSV, HTML and PDF per run under
  `output_dir/run_YYYYMMDD_HHMMSS/`.
- **Two implementations**: Python (`filescanner.py`) and a Go port (`go/`)
  with matching features, config format and database schema; prebuilt
  binaries for Linux, macOS and Windows in `dist/`.
