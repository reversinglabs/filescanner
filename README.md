# filescanner

Scans a folder or drive (a USB stick, a local directory, a mounted
network share) with ReversingLabs services. It walks every file under
the path you give it, uploads each one to the configured backend —
Spectra Detect, Spectra Analyze (A1000), File Inspection Engine, or
Spectra Intelligence cloud — collects the verdicts, and writes
JSON/CSV/HTML/PDF reports. Malicious files can optionally be copied or
moved to a quarantine folder, and alerts sent to a webhook, syslog, or
the Windows Event Log.

Scans are resumable: progress is kept in a SQLite database, so an
interrupted scan picks up where it stopped without re-uploading files.

The tool ships as two interchangeable implementations with the same
features, the same `config.ini` format and the same `scan_state.db`
schema (a scan started by one can be resumed by the other):

| | Go binary (`go/`, prebuilt in `dist/`) | Python (`filescanner.py`) |
|---|---|---|
| Runtime | none — single static binary | Python 3.10+ and `requests` |
| Windows exe | prebuilt, or `GOOS=windows go build` anywhere | PyInstaller, on Windows only |
| Event Log alerts | yes (x/sys eventlog; build-tagged) | yes (pywin32) |

## Getting started

### 1. Get the scanner

**Go binary (easiest — nothing to install).** Prebuilt binaries are in
`dist/`:

| Platform | Binary |
|---|---|
| Linux x86-64 | `dist/filescanner-linux-amd64` |
| macOS Intel / Apple Silicon | `dist/filescanner-darwin-amd64` / `dist/filescanner-darwin-arm64` |
| Windows 64-bit / 32-bit | `dist/filescanner-windows-amd64.exe` / `dist/filescanner-windows-386.exe` |

macOS builds are unsigned: run `xattr -d com.apple.quarantine <binary>`
or right-click > Open the first time. To build your own, see
[Building](#building).

**Python.** Needs Python 3.10+:

```bash
python3 -m venv .venv
.venv/bin/pip install 'requests>=2.33.0'    # PYSEC-2026-2275
# Windows: py -m venv .venv && .venv\Scripts\pip install "requests>=2.33.0"
# add pywin32 on Windows if you use alert_eventlog
```

Either way you need network access to the backend you scan with.

### 2. Create a config file

```bash
# Go
./filescanner-linux-amd64 --init-config config.ini       # Windows: filescanner-windows-amd64.exe --init-config config.ini
# Python
.venv/bin/python filescanner.py --init-config config.ini
```

This writes the fully commented template (`config.ini.template`). There
are only two command-line flags — `--init-config PATH` (write the
template and exit) and `--config PATH` (which file to load; default
`config.ini` in the current directory). Everything else is set in
`config.ini`.

### 3. Fill in the minimum settings

Open `config.ini` and set:

1. **`[scan] drive`** — the folder to scan. The template default `E:\`
   is a Windows drive letter; on Linux/macOS use a path such as
   `/media/$USER/USBSTICK` or `/home/me/samples`. The scanner does not
   mount anything — the path must already exist (a USB stick must be
   mounted, a network share mapped).
2. **`[scan] backend`** and that backend's section:

   | `backend` | Set in `config.ini` | Credentials via env var |
   |---|---|---|
   | `detect` (default) | `detect.host`, `detect.token` | `SPECTRA_TOKEN` |
   | `a1000` | `a1000.host`, `a1000.token` | `A1000_TOKEN` |
   | `fie` | `fie.host` | none — FIE is unauthenticated |
   | `cloud` | `ticloud.host`, `ticloud.username`, `ticloud.password` | `TICLOUD_USER`, `TICLOUD_PASS` |

3. **`[detect] host` and `[detect] token` — always.** They are checked
   at startup for *every* backend, so they must be non-empty even when
   `backend` is not `detect` (any placeholder works then, e.g.
   `host = https://unused`). `[detect] proxy` and `[detect]
   no_verify_ssl` apply to whichever backend runs — set them there.

Tokens and passwords support `${VAR}` expansion — keep
`token = ${SPECTRA_TOKEN}` and export the variable instead of writing
the secret into the file.

### 4. Make the first run a safe one

The defaults are tuned for a full production scan. For a first test:

```ini
[scan]
max_files = 10                  # cap the run; 0 = scan everything
read_speed_test = off           # default "ask" may stop to prompt (see below)

[database]
cleanup_old_records = never     # default "ask" may stop to prompt (see below)

[actions]
quarantine_action = none        # default — report only, never touch files
```

- **Two settings can stop the run to ask a question.**
  `read_speed_test = ask` benchmarks the drive and prompts
  `Proceed anyway? [y/N]` if it reads slower than `min_read_mbps`
  (default 1 MB/s); with no terminal attached the answer is "no" and the
  run aborts. `cleanup_old_records = ask` prompts to delete scan records
  older than `retention_days` (default 7); with no terminal they are
  kept. Set both to a non-`ask` value for unattended or scripted runs.
- **Quarantine.** `quarantine_action = copy` copies flagged files
  (verdicts in `quarantine_on`, default `malicious`) to `quarantine_dir`;
  `move` removes them from the scanned drive. Quarantined files are the
  original, live files — not encrypted or defanged. Keep `quarantine_dir`
  **outside** the scanned folder: the walk does not skip it, so on the
  next run quarantined files are found and quarantined again. If it must
  live inside, give it a dot-name (e.g. `.Quarantine`) and set
  `skip_hidden_dirs = true`.
- **Privacy.** `backend = cloud` uploads file contents to RL's hosted
  Spectra Intelligence (see [Backends](#backends)).

### 5. Run it

```bash
# Linux / macOS
export SPECTRA_TOKEN=<api-token>        # or A1000_TOKEN / TICLOUD_USER + TICLOUD_PASS
./filescanner-linux-amd64 --config config.ini
# or: .venv/bin/python filescanner.py --config config.ini
```

```bat
:: Windows (cmd; PowerShell: $env:SPECTRA_TOKEN = "<api-token>")
set SPECTRA_TOKEN=<api-token>
filescanner-windows-amd64.exe --config config.ini
```

### 6. Find the results

Output goes to `[output] output_dir` — by default a `Spectra` folder on
your Desktop (`~/Desktop/Spectra`; on Linux/macOS `~/Desktop` is created
if it does not exist). Each run gets its own folder:

```
<output_dir>/
├── scan_state.db                       # resume state, shared by all runs
└── run_YYYYMMDD_HHMMSS/
    ├── spectra_detect_scan_results.json   # full results (also .csv, .html)
    ├── spectra_detect_scan_results.pdf    # malicious/suspicious findings
    ├── scan_results.ndjson                # one line per file, streamed
    ├── spectra_detect_scan.log            # run log
    ├── alerts.ndjson                      # when alerting is on
    └── quarantine/                        # when quarantine_dir is empty
```

Exit code: `0` — every file processed; `1` — some files failed (upload
error, timeout) or the drive/backend was unreachable; `2` — config or
authentication error. Run it again with `resume = true` (the default)
to retry failures without re-uploading finished files.

## Backends

One backend per run, picked by `scan.backend`; the walk/hash/pool/resume
machinery is identical for all four:

| `backend` | Service | Auth | Submit → verdict | Needs |
|---|---|---|---|---|
| `detect` (default) | Spectra Detect worker | `Authorization: Token` | upload → `task_url`, polled per task | `detect.host`, `detect.token` |
| `a1000` | Spectra Analyze appliance | `Authorization: Token` | `POST /api/uploads/` → sha1 receipt; bulk status by sha256, verdict from classification doc | `a1000.host`, `a1000.token` |
| `fie` | File Inspection Engine | none | synchronous verdict on submit — no pollers run | `fie.host` |
| `cloud` | Spectra Intelligence (TCA) | HTTP Basic | spex two-step upload → sha1 receipt; TCA-0101 reputation polled by sha1 | `ticloud.host`, `ticloud.username`, `ticloud.password` |

Every backend also needs `detect.host`/`detect.token` non-empty (see
[step 3](#3-fill-in-the-minimum-settings)); `ticloud.*` credentials are
additionally required for `reputation.precheck` on any backend.

Auth-bearing backends (`a1000`, `cloud`, and the reputation pre-check
client) probe once at startup — a 401/403 aborts the run with a config
error instead of surfacing as thousands of per-file failures.

**Privacy** — `backend=cloud` uploads file contents to RL's hosted
Spectra Intelligence; depending on account role, uploaded samples may be
shared with other RL customers. The reputation pre-check sends only
sha256 hashes, never file content. On-prem backends (`detect`, `a1000`,
`fie`) keep file contents on the appliance `host` points at.

## config.ini

All scan behavior is configured via `config.ini` (identical in both
implementations). Key settings:

```ini
# [detect] is required for EVERY backend: host and token must be non-empty
# even when backend != detect. proxy and no_verify_ssl apply to whichever
# backend runs.
[detect]
host = https://<detect>       # Detect worker URL
token = ${SPECTRA_TOKEN}      # ${VAR} expands from environment — never
                              # commit a literal token
proxy =                       # optional http://proxy:8080 (all backends)
no_verify_ssl = false         # set true only for self-signed test boxes
                              # (all backends)

[scan]
backend = detect              # detect | a1000 | fie | cloud — see Backends
drive = E:\                   # root to scan (USB drive, folder, etc.)
max_files = 0                 # 0 = no cap; e.g. 20000 for a test run
extensions = all              # all | preset | .exe,.dll comma list
file_types =                  # optional: pe,pdf,ole,zip,...
skip_hidden_dirs = false       # true = skip dot-directories (default: scan them)
analysis_depth = full         # full | fast  (currently no effect)

[pipeline]
upload_workers = 10           # concurrent upload threads/goroutines
result_pollers = 1            # concurrent report-poll workers
result_poll_interval = 2      # seconds between task GETs
report_wait_hours = 12        # max hours to wait for a report after each file's upload
max_in_flight = 10000         # pause uploads above this many
                              # submitted-but-uncollected tasks
progress_every = 100          # progress log line every N items
avail_probe_seconds = 20      # shared /available probe cadence

[output]
output_dir =                  # default <Desktop>\Spectra
report_formats = json,csv,html,pdf  # any subset; pdf = findings summary
log_max_mb = 50
log_backups = 5
```

Backend sections — only the selected one (plus `[ticloud]` when
`reputation.precheck` is on) is read; `${VAR}` expansion works in all:

```ini
[fie]                         # backend=fie — unauthenticated
host = http://fie.local:8000  # required
mode = hash_then_scan         # scan | hash_then_scan | hash_only
trust_ok = false              # hash modes: treat "OK" check-sample as clean
external_id = rel_path        # /scan ?external_id=: rel_path | filename | none

[a1000]                       # backend=a1000 — Authorization: Token
host = https://a1000.example.com  # required
token = ${A1000_TOKEN}            # required
analysis = cloud              # 'analysis' upload field; empty = local only
tags =                        # optional /api/uploads/ form fields:
comment =                     #   tags, comment, archive_password
archive_password =
sandbox_platform =            # sent as rl_cloud_sandbox_platform:
                              #   windows7|windows10|windows11|macos_11|ubuntu_20
report_detail = summary       # summary | full — which doc pollers fetch

[ticloud]                     # backend=cloud AND reputation.precheck — Basic auth
host = https://data.reversinglabs.com
username = ${TICLOUD_USER}    # required (with password) for both uses
password = ${TICLOUD_PASS}
domain =                      # optional <domain> in upload metadata XML
archive_password =            # optional <archive> password for uploads
upload_timeout = 300          # spex upload timeout, seconds
min_interval_ms = 100         # client pacing — spex allows 10 req/s
extended = true               # extended fields on reputation queries

[reputation]                  # optional pre-upload hash check, any backend
precheck = false              # TCA-0101 bulk lookup before upload
batch_size = 100              # API max 100 — larger values clamp to 100
skip_classified = true        # classified hashes -> done, never uploaded;
                              # false = re-enqueue to the upload path anyway
                              # (normal resume dedup still applies there)
```

See `config.ini.template` for the complete annotated set of options —
scan filters (`extensions` presets: `executables`, `documents`,
`archives`, `media`, `scripts-web`, `all`), backoff tuning, SQLite
retention/cleanup, quarantine (`copy`/`move` on verdict), and alerting
(webhook / syslog / Windows event log).

## Verdict normalization

Every backend normalizes into the same
`(classification, threat_name, threat_factor, report_json)` record;
`classification` uses the shared vocabulary `malicious | suspicious |
goodware | unknown | unavailable` regardless of source:

| `backend` | classification | `threat_name` | `threat_factor` |
|---|---|---|---|
| `detect` | worst verdict across `tc_report[]` entries (`unavailable` when absent) | `classification.result` | `classification.factor` |
| `fie` | `malicious`/`suspicious` pass through; `OK` → `goodware` (see below); else `unknown` | `threat_details.threat_name` | `threat_details.scanner_match` |
| `a1000` | `MALICIOUS`/`SUSPICIOUS`/`GOODWARE`/`UNKNOWN` → lowercased | `classification_result` | `riskscore` (0-10) |
| `cloud`, precheck | TCA-0101 `MALICIOUS`/`SUSPICIOUS` → same, `KNOWN` → `goodware` | `threat_name` | `threat_level` (malicious/suspicious) or `trust_factor` (KNOWN) |

FIE `OK` is ambiguous — a hash lookup cannot tell "known clean" from
"never seen". `mode=scan` always returns a real verdict. In
`hash_then_scan` an `OK` falls through to `/scan` unless `trust_ok=true`
(then `OK` → `goodware`); in `hash_only`, `OK` + `trust_ok=false`
records `unknown` and `report_json` keeps the raw response.

TCA-0101 `UNKNOWN` is never a verdict: the cloud poller keeps the row
pending (it times out `report_wait_hours` after its upload), and the
pre-check re-enqueues the file for upload.

## Operation notes

- **State/resume** — `scan_state.db` (SQLite, in `output_dir`) records
  each file's sha256, upload status, task URL, and verdict. Re-running
  skips hashes already done (`actions.resume = true`); a killed scan
  resumes where it left off. The Go and Python versions share the schema
  and status transitions, so they interoperate on the same DB. The
  `uploads` table gains `sha1` and `backend` columns automatically at
  open (additive migration — existing DBs keep every row); `task_url`
  doubles as the generic receipt ref (tiscale URL for detect, sha1 for
  a1000/cloud, unused for FIE).
- **Backend ownership on resume** — `submitted`/`reporting` rows whose
  `backend` differs from the current run's are reset to `pending` at
  startup (one backend can't poll another's receipts); rows stamped by
  pre-migration DBs (`backend=NULL`) count as `detect`. `done`/`cached`
  rows are terminal regardless of backend.
- **sha1 only when needed** — the hashing pass computes sha1 in the same
  streaming read only for `fie`/`cloud` (the `needs_sha1` backends);
  `detect`/`a1000` stay sha256-only.
- **FIE runs no pollers** — `backend=fie` returns its verdict on submit,
  so `result_pollers` is forced to 0; `report_wait_hours` and
  `result_poll_interval` don't apply.
- **Reputation pre-check** — with `reputation.precheck=true` a dedicated
  worker batches sha256s (up to `batch_size`) through TCA-0101 *before*
  upload. A non-UNKNOWN verdict lands directly as `done` (stamped
  `backend='ticloud'`; `skip_classified=false` still routes the file to
  the upload path — but the new `done` row makes the default
  `actions.resume=true` dedup short-circuit it there, so the enrichment
  upload only actually happens with `resume=false`). UNKNOWN, missing,
  or failed lookups re-enqueue the
  file for upload — the check fails open, never losing a file. Requires
  `ticloud.*` credentials on every backend, including `cloud` where it
  shares them.
- **Backpressure** — `max_in_flight` caps submitted-but-uncollected
  tasks; upload workers pause when it trips. Detect evicts
  post-processed task rows after `task_age_limit` minutes server-side
  (default can be as low as 30) — pollers must reach a task before its
  row expires. Sizing rule: `max_in_flight < poll_rate × task_age_limit`.
  With 4 pollers (~8/s drain) and a 12h limit, 10k in-flight is safe.
  Set the appliance limit via `tiscale-setup conf_cleanup
  task_age_limit=720` + `tiscale-setup reload`.
- **Availability gating** — a shared, backend-specific probe (detect:
  `/readyz`, falling back to `/srv/tiscale/v1/available`; fie: `/readyz`;
  a1000: `/api/uploads/`; cloud: the host root) runs at most once per `avail_probe_seconds`;
  any failure pauses all upload workers until it recovers, then backoff
  applies per upload.
- **Per-run outputs** — every run writes into
  `<output_dir>/run_YYYYMMDD_HHMMSS/` so runs never append into each
  other's files: `spectra_detect_scan_results.{json,csv,html}` (full
  results), `...pdf` (malicious/suspicious findings table),
  `scan_results.ndjson` (streaming per-record log),
  `spectra_detect_scan.log` (rotating run log), plus `quarantine/` and
  `alerts.ndjson` when used. `scan_state.db` stays at `output_dir` root —
  it is cross-run resume state, not a report.
- **Task 404s are terminal (detect)** — if the appliance drops a task
  record the row is marked `failed` immediately rather than retried to
  the deadline. a1000 `not_found` and cloud `UNKNOWN` receipts instead
  stay pending until `report_wait_hours` marks them `timeout` — same
  shape as tiscale task eviction.
- **Per-file report deadline** — `report_wait_hours` is counted from each
  file's own upload (`uploaded_at`), not from run start; pollers keep
  running until uploads are finished and no submitted rows remain. Rows
  resumed from an earlier run get `report_wait_hours` counted from this
  run's start. If no poller is left to drain, a file waiting on
  `max_in_flight` is marked `failed` (re-queued next run) instead of
  blocking forever.
- **Cached hits run verdict actions** — a resumed `done`/`cached` verdict
  matching `alert_on`/`quarantine_on` is alerted/quarantined and written
  to `scan_results.ndjson` with `"cached": true`, unless the DB shows that
  same path was already alerted/quarantined (no repeat alerts on resume).
  A duplicate at another path is acted on for that path.
  **Upgrade note:** rows written by older versions have no recorded
  actions, so the first resume after upgrading re-alerts / re-quarantines
  previously cached malicious hits once.
- **Regular files only** — the walk skips symlinks, devices and FIFOs and
  prunes symlinked dirs and NTFS junctions/reparse points; one INFO line
  `Skipped N non-regular entries (symlinks, junctions, devices, FIFOs)`
  reports the count. Hashing, uploads, the read-speed test and quarantine
  open files with `O_NOFOLLOW` + fstat (lstat first where `O_NOFOLLOW` is
  unavailable) and refuse anything that is not a regular file.
- **Summary counts come from report rows** — classification, quarantined,
  alerts and cached counts are computed from the rows in the report.

## Known differences and limitations

Go and Python are kept in lockstep; the only remaining deltas are:

- **Platform-specific** — OneDrive Desktop-folder redirection falls back to
  `%USERPROFILE%\Desktop` (Go); `alert_eventlog` is a stub off Windows.
- **Interrupts** — on the first Ctrl-C both stop walking, start no new
  file (queued and throttle-waiting files stay `pending` for resume), stop
  the pollers and write reports from the DB state. Queued files not yet
  hashed have no DB row and are simply re-walked on resume. Remaining deltas: Go
  gives in-flight work up to 2 s before writing reports (Python writes them
  immediately; an upload that completes afterwards may not be recorded and
  is then resubmitted on the next resume); Go also treats SIGTERM like Ctrl-C,
  Python dies on SIGTERM (exit 143, no reports); on a second Ctrl-C Go
  waits up to 10 s for report writing, then exits 130.
- **Windows reparse files** — Python on Windows: filter-handled reparse
  files (dedup, OneDrive placeholders while OneDrive is running — reading
  them hydrates the file) are scanned; Go skips non-dedup reparse files;
  unhandled tags are skipped by both.
- **Path strings** — Go normalises absolute paths via `filepath.Join`, so
  odd drive roots (e.g. a trailing `//`) may give slightly different
  `file_path` strings than Python.
- **Upload stall detection** — both abort an upload after N seconds without
  progress, but Go's idle timer starts at the first body read (dial/TLS and
  TiCloud request pacing are not counted) and its error text is
  `read timeout: no upload progress for Ns`.

Limitations that apply to **both** implementations:

- **No-op settings** — `analysis_depth`, `large_file_threshold` and
  `detect_file_type` have no backend API parameter yet; a non-default value
  logs `<key> is currently a no-op`. `max_enrich_bytes`, `extract_strings`
  and `extract_iocs` are parsed but unused (the extractors are not wired
  into results); they log the same warning when set to a non-default value. Head bytes are captured (max 4096) only for the
  `file_types` filter.
- **PDF report** has no quarantined/alerted column (JSON, CSV and HTML do).
- **Duplicate content at two paths in one run** — the file is uploaded once;
  verdict actions (quarantine/alert) run for one path only. Resumed
  cached hits act per path (see Operation notes).
- **FIFO swap** — files are not opened `O_NONBLOCK`, so a file swapped for
  a FIFO (or device file) after the walk could block a worker.
- **Windows reparse directories** — reparse-point directories (including
  OneDrive Files On-Demand placeholder folders) are not scanned.
- **Run-scoped reports** — a run's reports cover only rows touched since
  that run started; failures left by earlier runs and not reprocessed are
  not in the report but still count in `files_with_errors` and the exit code.

## Building

### Go (recommended — cross-compiles everywhere)

Pure-Go SQLite (`modernc.org/sqlite`, no cgo) → a static binary on any
target, built on any host. The repo-root `Makefile` wraps all five:

```bash
make            # dist/filescanner-{darwin-amd64,darwin-arm64,linux-amd64}
                #      + filescanner-windows-{amd64,386}.exe
make windows    # just the .exe
make clean

# or by hand:
cd go
go build -o filescanner .                                # native
GOOS=windows GOARCH=amd64 go build -o filescanner.exe .  # Windows .exe
GOOS=linux   GOARCH=amd64 go build -o filescanner-linux .
```

The config template is `go:embed`-ed, so `--init-config` works without
any bundled files. Windows caveat: the exe is verified to build and
parse on macOS (`file`, `--init-config` output) but has not yet been
executed on a real Windows host — smoke-test `--help` + a small
`max_files` scan before deploying.

`alert_eventlog` works on the Windows build (`golang.org/x/sys` eventlog,
auto-registers the `SpectraDetectScanner` source via EventCreate — needs
admin on first run); it's a no-op stub on other platforms. See
"Known differences" below for the remaining Go/Python deltas.

### Python (PyInstaller)

`requests` is lazily imported inside the client, so PyInstaller picks it
up automatically from the build venv. PyInstaller does **not**
cross-compile: a Windows `.exe` must be built on Windows (or in Wine).

```powershell
# Windows
py -m pip install pyinstaller
py -m PyInstaller --onefile --name filescanner --console ^
    --add-data "config.ini.template;." filescanner.py
# -> dist\filescanner.exe
```

```bash
# macOS / Linux
.venv/bin/pip install pyinstaller
.venv/bin/pyinstaller --onefile --name filescanner \
    --add-data "config.ini.template:." filescanner.py
# -> dist/filescanner
```

The `--add-data` embeds the template so `--init-config` works inside the
binary. macOS builds are unsigned — `xattr -d com.apple.quarantine` or
right-click > Open on other Macs. Linux: build on the oldest glibc you
need to support.

Wine-in-Docker (`tobix/pywine`) is an alternative for building the
Windows exe from macOS/Linux, but Wine segfaults under both Rosetta and
qemu-user on some Apple Silicon setups — if `wine64
C:/Python/python.exe -V` exits 139, use the Go build instead (it
cross-compiles for free).

### Build artifacts

`build/`, `*.spec`, and `go/filescanner{,.exe}` are throwaway —
covered by `.gitignore`. `dist/` is intentionally **tracked** so a
clone ships prebuilt binaries. Pin PyInstaller (`"pyinstaller==6.x"`) for
reproducible Python builds; Go pins via `go.mod`/`go.sum`.

## Running tests

```bash
# Python
python -m venv .venv && .venv/bin/pip install pytest requests
.venv/bin/python -m pytest tests/ -q

# Go — *_test.go unit/httptest suites incl. integration_test.go
cd go && go test ./...   # `make test` from the repo root runs vet + tests
```

### Live end-to-end tests

`tests/test_e2e_live.py` runs the real scanner CLI as a subprocess
against live RL services — walk → hash → upload/poll → verdicts in
`scan_state.db` plus report artifacts on disk. Every test is skipped
unless `FILESCANNER_E2E=1` and its backend's `FILESCANNER_E2E_*` vars
are set, so normal runs need no lab access.

#### Quick run

```bash
./tests/e2e_fie_up.sh ~/RL_<license>.lic   # start local FIE (see below)
./tests/e2e_live.sh                       # all live tests (~1 min when up)
./tests/e2e_live.sh -k "detect or a1000"  # subset
./tests/e2e_live.sh -k fie -v             # verbose single backend
```

`e2e_live.sh` sources the dotenv files listed in `FILESCANNER_ENV_FILES`
(colon-separated; default `~/.env`), maps `SPECTRA_TOKEN`,
`DUT_API_TOKEN`, `TISCALE_WORKER_*`, and `RL_*`/`TICLOUD_*` credentials
into the test vars, prebuilds the Go binary, then runs pytest.

#### What each test needs and verifies

| Test | Backend/impl | Required env vars | Verifies |
|---|---|---|---|
| `test_e2e_fie_scan_mode` | fie / py | `FIE_HOST` | `mode=scan` → real `/scan` verdicts in DB + reports |
| `test_e2e_fie_hash_then_scan_fallthrough` | fie / py | `FIE_HOST` | `check-sample` ambiguous-OK → falls through to `/scan` |
| `test_e2e_detect` | detect / py | `DETECT_HOST` (+`DETECT_TOKEN`) | upload → task poll → EICAR `malicious` |
| `test_e2e_a1000` | a1000 / py | `A1000_HOST`, `A1000_TOKEN` | upload → bulk status → verdict doc |
| `test_e2e_cloud` | cloud / py | `TICLOUD_HOST`, `TICLOUD_USER`, `TICLOUD_PASS` | spex upload → TCA-0101 reputation poll → `malicious` |
| `test_e2e_reputation_precheck` | precheck / py | `TICLOUD_*` + `FIE_HOST` | known hash classifies via reputation; unknown falls through to FIE upload |
| `test_e2e_go_fie` | fie / go | `FIE_HOST` | Go binary parity on the FIE path |
| `test_e2e_go_detect` | detect / go | `DETECT_HOST` | Go binary parity on detect |

All vars are prefixed `FILESCANNER_E2E_` (e.g.
`FILESCANNER_E2E_FIE_HOST=http://localhost:8088`);
`FILESCANNER_E2E_GO_BIN` overrides the Go binary path (default
`/tmp/filescanner-e2e`, auto-built if missing). Export the vars
directly instead of `e2e_live.sh` when your creds live elsewhere — the
module docstring lists every variable. Missing vars → the test skips,
never fails; a down service fails with the scanner's own log tail.

The detect tests need a tiscale worker reachable at
`FILESCANNER_E2E_DETECT_HOST`; workers whose `tokenauth_acl` has an
empty token for the `/api/tiscale` prefix accept any token value (the
script exports `e2e-placeholder`). A1000 needs a real API token —
a 401/403 aborts the run by design.

#### Local FIE container

`e2e_fie_up.sh` handles the whole bring-up:

```bash
docker login registry.reversinglabs.com   # cloud username/password
./tests/e2e_fie_up.sh /path/to/rl.lic     # up + waits for /readyz
./tests/e2e_fie_up.sh down                # stop + remove
```

What it does and why: pulls
`registry.reversinglabs.com/fie/file-inspection-engine` (linux/amd64 —
the image is amd64-only; on Apple Silicon it runs under emulation),
passes the license file via `RL_LICENSE`, maps container :8000 to host
:8088 (`FILESCANNER_E2E_FIE_PORT` overrides), and sets
`RL_WITHOUT_MALICIOUS_THREAT_DATA=true` to skip the ~20 GiB threat-DB
download — `/scan` still runs real Spectra Core static analysis and
`/check-sample` returns the ambiguous `OK`, which is exactly the
`hash_then_scan` fall-through path. The runtime needs real resources
(cores are OOM-killed under ~4 GiB; Colima `--cpu 8 --memory 12` is
known-good) plus `GOMAXPROCS=1` and a single regular core — amd64-under-
emulation Go binaries crash with `sync: inconsistent mutex state` under
SMP contention — those env workarounds can go away if FIE ever ships an
arm64 image.
