#!/usr/bin/env python3
# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""
End-to-end live test: run the real async pipeline against a real backend
and report how long upload + report collection takes.

Usage:
    .venv/bin/python tests/e2e_scan.py --backend BACKEND --host URL
        [--drive DIR] [--recursive] [--token TOK] [--workers N] [--pollers N]
        [--wait-minutes N] [--out DIR] [--keep-db]

Backends and their required settings (arg > FILESCANNER_E2E_* env > built-in):

    detect   --host  (env FILESCANNER_E2E_DETECT_HOST)
             --token (env FILESCANNER_E2E_DETECT_TOKEN or SPECTRA_TOKEN,
                      else first working token from the env files listed in
                      FILESCANNER_ENV_FILES — colon-separated, default
                      ~/.env and ./.env; keys tried: SPECTRA_TOKEN,
                      DUT_API_TOKEN, RL_TOKEN)
    a1000    --host  (env FILESCANNER_E2E_A1000_HOST)
             --token (env FILESCANNER_E2E_A1000_TOKEN or A1000_TOKEN)
             --analysis (optional 'analysis' form field; empty = local only)
    fie      --host  (env FILESCANNER_E2E_FIE_HOST)
             --fie-mode scan | hash_then_scan | hash_only
             (default hash_then_scan; FIE is unauthenticated)
    cloud    --host  (env FILESCANNER_E2E_TICLOUD_HOST;
                      default https://data.reversinglabs.com)
             --user     (env FILESCANNER_E2E_TICLOUD_USER or TICLOUD_USER)
             --password (env FILESCANNER_E2E_TICLOUD_PASS or TICLOUD_PASS)

Defaults:
    --backend detect
    --drive  this repo's top-level files only, copied into a
             temp corpus dir (a recursive scan of a dev tree floods the
             appliance). Pass --recursive to scan the drive as-is.

Timing is taken from wall clock plus per-row DB timestamps (uploaded_at /
report_fetched_at), so the upload window and report window are measured
independently of this script's own polling.
"""

import argparse
import logging
import os
import shutil
import sys
import tempfile
import time
import types
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import filescanner as fs

TICLOUD_DEFAULT_HOST = "https://data.reversinglabs.com"

# backend -> (env prefix for FILESCANNER_E2E_<PFX>_HOST, needs token)
_BACKENDS = {
    "detect": "DETECT",
    "a1000": "A1000",
    "fie": "FIE",
    "cloud": "TICLOUD",
}


def _env(name, default=""):
    return (os.environ.get(name) or "").strip() or default


def _load_env_tokens():
    paths = ([Path(p) for p in os.environ.get("FILESCANNER_ENV_FILES", "").split(os.pathsep) if p]
             or [Path.home() / ".env", Path(".env")])
    out = []
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            name, sep, val = line.partition("=")
            name = name.strip()
            if sep and name in ("SPECTRA_TOKEN", "DUT_API_TOKEN", "RL_TOKEN"):
                out.append((name, val.strip().strip('"').strip("'")))
    return out


def _pick_detect_token(host, explicit, log):
    if explicit:
        return explicit
    env = _env("FILESCANNER_E2E_DETECT_TOKEN") or _env("SPECTRA_TOKEN")
    if env:
        return env
    # Smoke-probe each candidate token with a 1-byte upload; first non-401/403
    # wins. This is itself a real (tiny) upload — fine for an e2e tool.
    for name, tok in _load_env_tokens():
        if not tok:
            continue
        c = fs.DetectAsyncClient(host, tok, verify_ssl=False)
        probe = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        probe.write(b"\x00")
        probe.close()
        try:
            status, _url, err = c.upload_once(probe.name, {"e2e_probe": "1"})
        finally:
            os.unlink(probe.name)
        log.info("token %s probe -> status=%s err=%s", name, status, err)
        if status == 201:
            return tok
        if status not in (401, 403):
            return tok  # reachable but odd — try anyway, upload will surface it
    log.error("no working token: set FILESCANNER_E2E_DETECT_TOKEN/"
              "SPECTRA_TOKEN or pass --token")
    sys.exit(2)


def _build_corpus(src_dir, recursive, log):
    """Return drive root to scan. Non-recursive: temp dir with copies of the
    source dir's top-level files (safe default — no .venv flood)."""
    src = Path(src_dir)
    if recursive:
        return str(src)
    corpus = Path(tempfile.mkdtemp(prefix="e2e_corpus_"))
    n = 0
    for f in sorted(src.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            shutil.copy2(f, corpus / f.name)
            n += 1
    log.info("corpus: %d top-level files from %s -> %s", n, src, corpus)
    return str(corpus)


def _timing_report(db, wall_total, t_upload_phase):
    detail = db._q(
        """SELECT rel_path, status, uploaded_at, report_fetched_at,
                  classification, threat_name, error
           FROM uploads ORDER BY uploaded_at""", fetch="all")
    up_times = [r[2] for r in detail if r[2]]
    rep_times = [r[3] for r in detail if r[3]]
    counts = db.counts()

    print("\n" + "=" * 64)
    print("E2E TIMING REPORT")
    print("=" * 64)
    print(f"total files in DB     : {sum(counts.values())}")
    print(f"status counts         : {counts}")
    print(f"upload phase (wall)   : {t_upload_phase:.1f}s"
          f"  ({len(up_times)/max(t_upload_phase,0.01):.1f} files/s)")
    if up_times:
        print(f"first->last upload    : {up_times[0]} .. {up_times[-1]}")
    if rep_times:
        print(f"first->last report    : {rep_times[0]} .. {rep_times[-1]}")
    print(f"scan wall total       : {wall_total:.1f}s")
    # Per-file server-side latency = report_fetched_at - uploaded_at (UTC,
    # sqlite 'now' timestamps — second granularity).
    lats = []
    for _r, _s, u, rp, _c, _t, _e in detail:
        if u and rp:
            try:
                du = datetime.strptime(u, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc)
                dr = datetime.strptime(rp, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc)
                lats.append((dr - du).total_seconds())
            except ValueError:
                pass
    if lats:
        lats.sort()
        print(f"server-side latency   : min {lats[0]:.0f}s  "
              f"median {lats[len(lats)//2]:.0f}s  max {lats[-1]:.0f}s")
    print("-" * 64)
    print(f"{'file':<40} {'status':<10} {'verdict':<12} threat")
    for r, s, _u, _rp, c, t, e in detail:
        print(f"{r[:40]:<40} {s:<10} {str(c or '-'):<12} {t or e or ''}")
    print("=" * 64)
    return counts


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend", choices=sorted(_BACKENDS),
                   default=_env("FILESCANNER_E2E_BACKEND", "detect"),
                   help="scan backend (env FILESCANNER_E2E_BACKEND)")
    p.add_argument("--drive",
                   default=str(Path(__file__).resolve().parent.parent))
    p.add_argument("--recursive", action="store_true",
                   help="scan the drive dir recursively as-is (WARNING: dev "
                        "trees contain .venv with thousands of files)")
    p.add_argument("--host", help="backend URL (env FILESCANNER_E2E_<BACKEND>_HOST)")
    p.add_argument("--token", help="backend token (detect/a1000)")
    p.add_argument("--user", help="cloud username (env FILESCANNER_E2E_TICLOUD_USER)")
    p.add_argument("--password", help="cloud password (env FILESCANNER_E2E_TICLOUD_PASS)")
    p.add_argument("--analysis", default="",
                   help="a1000 'analysis' form field (empty = local only)")
    p.add_argument("--fie-mode", default="hash_then_scan",
                   choices=("scan", "hash_then_scan", "hash_only"))
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--pollers", type=int, default=1)
    p.add_argument("--max-files", type=int, default=0,
                   help="cap the work list (0 = all files)")
    p.add_argument("--progress-every", type=int, default=100)
    p.add_argument("--wait-minutes", type=float, default=30)
    p.add_argument("--out", default=None)
    p.add_argument("--keep-db", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    log = logging.getLogger("e2e")
    import urllib3
    urllib3.disable_warnings()

    backend = args.backend
    if backend not in _BACKENDS:
        log.error("invalid backend %r (FILESCANNER_E2E_BACKEND): choose from %s",
                  backend, "|".join(sorted(_BACKENDS)))
        sys.exit(2)
    prefix = _BACKENDS[backend]

    host = (args.host or "").strip() or _env(f"FILESCANNER_E2E_{prefix}_HOST")
    if backend == "cloud" and not host:
        host = TICLOUD_DEFAULT_HOST
    if not host:
        log.error("--host required for backend=%s (or set "
                  "FILESCANNER_E2E_%s_HOST)", backend, prefix)
        sys.exit(2)

    if backend == "detect":
        token = _pick_detect_token(host, args.token, log)
    elif backend == "a1000":
        token = (args.token or "").strip() or \
            _env("FILESCANNER_E2E_A1000_TOKEN") or _env("A1000_TOKEN")
        if not token:
            log.error("--token required for backend=a1000 (or set "
                      "FILESCANNER_E2E_A1000_TOKEN)")
            sys.exit(2)
    else:
        token = ""

    if backend == "cloud":
        ticloud_user = (args.user or "").strip() or \
            _env("FILESCANNER_E2E_TICLOUD_USER") or _env("TICLOUD_USER")
        ticloud_pass = (args.password or "").strip() or \
            _env("FILESCANNER_E2E_TICLOUD_PASS") or _env("TICLOUD_PASS")
        if not ticloud_user or not ticloud_pass:
            log.error("--user/--password required for backend=cloud (or set "
                      "FILESCANNER_E2E_TICLOUD_USER/PASS)")
            sys.exit(2)
    else:
        ticloud_user = ticloud_pass = ""

    out_dir = Path(args.out or tempfile.mkdtemp(prefix="e2e_out_")).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    drive = _build_corpus(args.drive, args.recursive, log)

    a = types.SimpleNamespace(
        backend=backend,
        drive=drive, host=host, token=token, proxy=None,
        no_verify_ssl=True,
        db_path=str(out_dir / "e2e_state.db"),
        retention_days=7, cleanup_old_records="never",
        store_full_report=False, output_ndjson=str(out_dir / "e2e.ndjson"),
        upload_workers=args.workers, result_pollers=args.pollers,
        result_poll_interval=2, report_wait_hours=args.wait_minutes / 60.0,
        max_in_flight=10000, max_files=args.max_files,
        progress_every=args.progress_every,
        backoff_base_seconds=2, backoff_max_seconds=60,
        upload_retry_window=120, max_upload_attempts=4,
        ready_check_interval=5, ready_max_wait=60,
        avail_probe_seconds=20,
        resume=True, file_types=set(), detect_file_type=False,
        read_speed_test="off", min_read_mbps=0,
        read_test_max_bytes=0, read_test_max_seconds=0,
        extract_strings=False, extract_iocs=False, min_string_len=6,
        max_strings=0, max_iocs=0, max_enrich_bytes=1024,
        large_file_threshold=1 << 30,
        analysis_depth="full", workers=args.workers,
        quarantine_action="none", quarantine_dir=None, quarantine_on=set(),
        alert_on=set(), alert_webhook=None, alert_syslog=None,
        alert_eventlog=False,
        summary_only=False, verbose=False,
        poll_interval=2, max_retries=3, state_file=None,
        report_formats={"json", "html", "csv"}, output=None,
        output_dir=str(out_dir), extensions="", exclude_extensions="",
        preset=None, include_extensions=None, filter_all=False,
        log_max_mb=0, log_backups=0,
        fie_host=host if backend == "fie" else "",
        fie_mode=args.fie_mode, fie_trust_ok=False,
        fie_external_id="rel_path",
        a1000_host=host if backend == "a1000" else "",
        a1000_token=token if backend == "a1000" else "",
        a1000_analysis=args.analysis, a1000_tags="", a1000_comment="",
        a1000_archive_password="", a1000_sandbox_platform="",
        a1000_report_detail="summary",
        ticloud_host=host if backend == "cloud" else "",
        ticloud_username=ticloud_user, ticloud_password=ticloud_pass,
        ticloud_upload_timeout=300, ticloud_min_interval_ms=100,
        ticloud_extended=True, ticloud_domain="",
        ticloud_archive_password="",
        reputation_precheck=False, reputation_batch_size=100,
        reputation_skip_classified=True,
    )

    log.info("backend=%s host=%s", backend, host)
    t0 = time.monotonic()
    output = fs.run_scan(a, None, out_dir, log)
    wall_total = time.monotonic() - t0
    fs.write_reports(output, out_dir, fs.OUTPUT_FILENAME,
                     a.report_formats, log)

    db = fs.ScanDB(str(out_dir / "e2e_state.db"))
    # Upload-phase wall estimate: run_scan returns after pollers finish, so
    # approximate upload window by first->last uploaded_at spread + client
    # overhead; report it alongside the measured totals.
    detail = db._q("SELECT MIN(uploaded_at), MAX(uploaded_at) FROM uploads",
                   fetch="one")
    t_up = 0.0
    if detail and detail[0] and detail[1]:
        try:
            t_up = (datetime.strptime(detail[1], "%Y-%m-%d %H:%M:%S")
                    - datetime.strptime(detail[0], "%Y-%m-%d %H:%M:%S")
                    ).total_seconds()
        except ValueError:
            pass
    counts = _timing_report(db, wall_total, max(t_up, 0.01))
    db.close()
    if not args.keep_db:
        pass  # DB stays in out_dir for inspection; flag only suppresses cleanup
    print(f"artifacts: {out_dir}")
    failures = counts.get("failed", 0) + counts.get("timeout", 0)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
