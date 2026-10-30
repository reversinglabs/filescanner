# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT
"""per-row report deadline (no poller/throttle hang), cached hits
run verdict actions, summary counts derived from report rows."""
import hashlib
import json
import logging
import os
import queue
import sys
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import filescanner as fs
from test_run_scan import _scan_args


def _one(db, sql, params=()):
    row = db._conn.execute(sql, params).fetchone()
    assert row is not None
    return row


class _NeverReportsBackend:
    """Async backend whose reports never arrive."""
    name = "detect"
    needs_sha1 = False
    is_sync = False

    def __init__(self, submit_delay=0.0):
        self.submit_delay = submit_delay

    def wait_ready(self, max_wait, interval, log=None):
        return True

    def submit_with_backoff(self, fp, sha256, sha1, meta, cfg, log=None):
        time.sleep(self.submit_delay)
        return fs.SubmitOutcome(kind="receipt", ref="http://x/t/" + sha256[:8],
                                http_status=201)

    def poll_batch(self, refs, log=None):
        return {r["ref"]: "pending" for r in refs}


def _run_in_thread(fn, timeout):
    box = {}

    def _t():
        try:
            box["out"] = fn()
        except BaseException as e:  # noqa: BLE001 — surface in the test
            box["err"] = e
    t = threading.Thread(target=_t, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "hung: did not finish within %ss" % timeout
    if "err" in box:
        raise box["err"]
    return box.get("out")


# ---- C1 ---------------------------------------------------------------

def test_run_scan_terminates_when_reports_never_arrive(tmp_path, monkeypatch):
    drive = tmp_path / "drive"
    drive.mkdir()
    for i in range(4):
        (drive / f"f{i}.bin").write_bytes(b"content-%d" % i)
    out = tmp_path / "out"
    out.mkdir()
    args = _scan_args(drive, out)
    args.report_wait_hours = 1 / 3600.0         # 1 s per row
    args.max_in_flight = 2
    args.upload_workers = 1
    monkeypatch.setattr(fs, "make_backend",
                        lambda a: _NeverReportsBackend(submit_delay=0.2))
    output = _run_in_thread(
        lambda: fs.run_scan(args, None, out, MagicMock()), timeout=60)
    db = fs.ScanDB(str(out / "scan_state.db"))
    try:
        assert db.counts() == {"timeout": 4}
    finally:
        db.close()
    assert output is not None
    assert output["summary"]["files_with_errors"] == 4  # -> exit code 1


def _poll_ctx(tmp_path):
    args = types.SimpleNamespace(
        result_poll_interval=0, summary_only=True, store_full_report=False,
        quarantine_on=set(), quarantine_action="none", progress_every=100)
    return fs.ScanContext(args, None, None, None, fs.Counters(),
                          fs.KeyedLocks(), tmp_path / "q",
                          logging.getLogger("t"), 0)


def _status(db, sha):
    return _one(db, "SELECT status FROM uploads WHERE sha256=?", (sha,))[0]


def test_poller_late_submitted_row_gets_own_deadline(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("a", "fa", "fa", 1)
    db.mark_submitted("a", "http://x/t/a")
    ctx = _poll_ctx(tmp_path)
    done = threading.Event()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    p = threading.Thread(
        target=fs.result_poller,
        args=(ctx, db, _NeverReportsBackend(), 1, done, w), daemon=True)
    p.start()
    t0 = time.time()
    while _status(db, "a") != "timeout" and time.time() - t0 < 15:
        time.sleep(0.1)
    assert _status(db, "a") == "timeout"
    assert p.is_alive(), "poller exited while uploads still running"
    # A file uploaded late gets its own wait window, not the first row's.
    db.upsert_pending("b", "fb", "fb", 1)
    db.mark_submitted("b", "http://x/t/b")
    assert _status(db, "b") == "submitted"
    done.set()
    p.join(15)
    assert not p.is_alive(), "poller hung"
    w.close()
    assert _status(db, "b") == "timeout"
    assert ctx.counters.snapshot().get("errors") == 2
    db.close()


def _worker_args(**kw):
    a = dict(resume=True, file_types=set(), extract_strings=False,
             extract_iocs=False, max_enrich_bytes=0, max_in_flight=2,
             result_poll_interval=0, store_full_report=False,
             summary_only=True, quarantine_on=set(),
             quarantine_action="none", progress_every=100, alert_on=set())
    a.update(kw)
    return types.SimpleNamespace(**a)


def test_throttle_exits_when_pollers_stopped(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for s in ("x1", "x2"):                        # throttle saturated
        db.upsert_pending(s, s, s, 1)
        db.mark_submitted(s, "http://x/t/" + s)
    f = tmp_path / "new.bin"
    f.write_bytes(b"new-content")
    ctx = fs.ScanContext(_worker_args(), None, None, None, fs.Counters(),
                         fs.KeyedLocks(), tmp_path / "q",
                         logging.getLogger("t"), 0)
    ctx.pollers_stopped.set()                     # no poller will drain
    q = queue.Queue()
    q.put((str(f), "new.bin"))
    q.put(None)
    _run_in_thread(lambda: fs.upload_worker(ctx, db, _NeverReportsBackend(), q),
                   timeout=10)
    sha = hashlib.sha256(b"new-content").hexdigest()
    row = _one(db, "SELECT status,error FROM uploads WHERE sha256=?", (sha,))
    assert row[0] == "failed" and "throttle" in row[1]
    assert ctx.counters.snapshot().get("errors") == 1
    db.close()


# ---- C2 ---------------------------------------------------------------

def _cached_setup(tmp_path, content=b"evil"):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    sha = hashlib.sha256(content).hexdigest()
    db.upsert_pending(sha, "/old/place.exe", "place.exe", len(content))
    db.mark_submitted(sha, "http://x/t/1")
    db.claim_report(sha)
    db.mark_done(sha, "malicious", "Trojan.X", 9, None)
    return db, sha


def _cached_ctx(tmp_path, **kw):
    args = _worker_args(alert_on={"malicious"}, quarantine_on={"malicious"},
                        quarantine_action="copy", **kw)
    log = logging.getLogger("t")
    alerter = fs.Alerter(alert_on=args.alert_on,
                         alerts_file=tmp_path / "alerts.ndjson",
                         webhook_url=None, syslog_addr=None, eventlog=False,
                         logger=log)
    return fs.ScanContext(args, None, None, alerter, fs.Counters(),
                          fs.KeyedLocks(), tmp_path / "q", log, 0)


def _run_worker(ctx, db, items, writer):
    q = queue.Queue()
    for it in items:
        q.put(it)
    q.put(None)
    _run_in_thread(lambda: fs.upload_worker(
        ctx, db, _NeverReportsBackend(), q, writer=writer), timeout=10)


def _alerts(tmp_path):
    p = tmp_path / "alerts.ndjson"
    return p.read_text().splitlines() if p.exists() else []


def test_cached_hit_runs_actions_and_emits_record(tmp_path):
    db, sha = _cached_setup(tmp_path)
    drive = tmp_path / "drive"
    drive.mkdir()
    f = drive / "place.exe"
    f.write_bytes(b"evil")
    ctx = _cached_ctx(tmp_path)
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    _run_worker(ctx, db, [(str(f), "place.exe")], w)
    w.close()
    assert len(_alerts(tmp_path)) == 1
    recs = [json.loads(x) for x in
            (tmp_path / "r.ndjson").read_text().splitlines()]
    assert len(recs) == 1
    r = recs[0]
    assert r["cached"] is True and r["classification"] == "malicious"
    assert r["sha256"] == sha and r["absolute_path"] == str(f)
    assert r["alerted"] is True and r["quarantined_to"]
    assert r["api"]["status"] == "cached"
    v = {x["sha256"]: x for x in db.verdicts()}[sha]
    assert v["status"] == "cached" and v["alerted"] == 1
    assert v["quarantined_to"] == r["quarantined_to"]

    # Resumed scan of the same path: no alert spam, no re-quarantine.
    ctx2 = _cached_ctx(tmp_path)
    w2 = fs.ResultsWriter(str(tmp_path / "r2.ndjson"))
    _run_worker(ctx2, db, [(str(f), "place.exe")], w2)
    w2.close()
    assert len(_alerts(tmp_path)) == 1
    v2 = {x["sha256"]: x for x in db.verdicts()}[sha]
    assert v2["alerted"] == 1 and v2["quarantined_to"] == r["quarantined_to"]
    db.close()


def test_cached_duplicate_at_second_path_acts_again(tmp_path):
    db, sha = _cached_setup(tmp_path)
    drive = tmp_path / "drive"
    drive.mkdir()
    f1 = drive / "place.exe"
    f1.write_bytes(b"evil")
    (drive / "sub").mkdir()
    f2 = drive / "sub" / "copy.exe"
    f2.write_bytes(b"evil")
    ctx = _cached_ctx(tmp_path)
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    _run_worker(ctx, db, [(str(f1), "place.exe"), (str(f2), "sub/copy.exe")], w)
    w.close()
    assert len(_alerts(tmp_path)) == 2
    lines = (tmp_path / "r.ndjson").read_text().splitlines()
    assert [json.loads(x)["absolute_path"] for x in lines] == [str(f1), str(f2)]
    db.close()


class _InstantVerdictBackend(_NeverReportsBackend):
    """Receipt on submit; verdict on the first poll."""
    def poll_batch(self, refs, log=None):
        return {r["ref"]: {"classification": "malicious",
                           "threat_name": "Trojan.X", "threat_factor": 9,
                           "report_json": None} for r in refs}


def test_inflight_duplicate_paths_all_get_actions(tmp_path):
    """Two copies of the same content in one run: the hash's row tracks the
    submitter's path; the duplicate still gets quarantine + an NDJSON row
    when the verdict drains."""
    drive = tmp_path / "drive"
    drive.mkdir()
    f1 = drive / "a.exe"
    f1.write_bytes(b"evil")
    (drive / "sub").mkdir()
    f2 = drive / "sub" / "b.exe"
    f2.write_bytes(b"evil")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    ctx = _cached_ctx(tmp_path)
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    done = threading.Event()
    p = threading.Thread(
        target=fs.result_poller,
        args=(ctx, db, _InstantVerdictBackend(), 30, done, w), daemon=True)
    p.start()
    _run_worker(ctx, db, [(str(f1), "a.exe"), (str(f2), "sub/b.exe")], w)
    done.set()
    p.join(15)
    w.close()
    assert not p.is_alive(), "poller hung"
    sha = hashlib.sha256(b"evil").hexdigest()
    assert _status(db, sha) == "done"
    recs = [json.loads(x) for x in
            (tmp_path / "r.ndjson").read_text().splitlines()]
    assert {r["absolute_path"] for r in recs} == {str(f1), str(f2)}
    dup = [r for r in recs if r["absolute_path"] == str(f2)]
    assert dup and dup[0]["duplicate"] is True
    for r in recs:
        assert r["quarantined_to"] and os.path.exists(r["quarantined_to"])
    assert len(_alerts(tmp_path)) == 1          # one alert per hash
    assert ctx.counters.snapshot()["quarantined"] == 2
    db.close()


# ---- C3 ---------------------------------------------------------------

def test_summary_counts_come_from_report_rows(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for sha, cls in (("m", "malicious"), ("s", "suspicious"),
                     ("g", "goodware"), ("u", "unknown")):
        db.upsert_pending(sha, sha, sha, 1)
        db.mark_submitted(sha, "http://x/t/" + sha)
        db.claim_report(sha)
        db.mark_done(sha, cls, None, None, None)
    db.mark_actions("m", "/q/m", True)
    db.mark_cached("s")
    db.upsert_pending("f", "f", "f", 1)
    db.mark_failed("f", 500, "boom")
    counters = fs.Counters()                    # stale/empty per-run counters
    counters.inc("malicious", 7)
    counters.inc("alerts", 5)
    out = fs._build_output_from_db(_scan_args(tmp_path, tmp_path), db,
                                   counters, str(tmp_path), 5, None, tmp_path,
                                   "2000-01-01 00:00:00")
    s = out["summary"]
    assert (s["malicious"], s["suspicious"], s["goodware"], s["unknown"]) \
        == (1, 1, 1, 1)
    assert s["quarantined"] == 1 and s["alerts"] == 1
    assert s["cached_hits"] == 1
    assert s["files_processed"] == len(out["results"]) == 5
    assert s["files_with_errors"] == 1          # failed row, counter is 0
    db.close()


# ---- R1: Ctrl-C must not corrupt rows ---------------------------------

def test_results_writer_write_after_close_is_noop(tmp_path):
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    w.close()
    w.write({"a": 1})                    # must not raise
    w.close()                            # idempotent
    assert (tmp_path / "r.ndjson").read_text() == ""


def test_mark_failed_does_not_clobber_cached(tmp_path):
    db, sha = _cached_setup(tmp_path)
    db.mark_cached(sha)
    db.mark_failed(sha, None, "worker_error: boom")
    assert _status(db, sha) == "cached"
    db.close()


def test_cached_row_after_writer_close_stays_cached(tmp_path):
    """Reviewer repro: a resumed cached hit processed after run_scan closed
    the writer (Ctrl-C) must not turn into 'failed'."""
    db, sha = _cached_setup(tmp_path)
    drive = tmp_path / "drive"
    drive.mkdir()
    f = drive / "place.exe"
    f.write_bytes(b"evil")
    ctx = _cached_ctx(tmp_path)
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    w.close()
    _run_worker(ctx, db, [(str(f), "place.exe")], w)
    assert _status(db, sha) == "cached"
    db.close()


def test_worker_skips_items_after_stop(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    f = tmp_path / "new.bin"
    f.write_bytes(b"never-started")
    ctx = fs.ScanContext(_worker_args(), None, None, None, fs.Counters(),
                         fs.KeyedLocks(), tmp_path / "q",
                         logging.getLogger("t"), 0)
    ctx.stop.set()
    backend = _NeverReportsBackend()
    backend.submit_with_backoff = MagicMock()
    q = queue.Queue()
    q.put((str(f), "new.bin"))
    q.put(None)
    _run_in_thread(lambda: fs.upload_worker(ctx, db, backend, q), timeout=10)
    backend.submit_with_backoff.assert_not_called()
    assert db.counts() == {}             # never started -> not even upserted
    db.close()


def test_throttle_on_stop_leaves_row_pending(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for s in ("x1", "x2"):
        db.upsert_pending(s, s, s, 1)
        db.mark_submitted(s, "http://x/t/" + s)
    f = tmp_path / "new.bin"
    f.write_bytes(b"new-content")
    ctx = fs.ScanContext(_worker_args(), None, None, None, fs.Counters(),
                         fs.KeyedLocks(), tmp_path / "q",
                         logging.getLogger("t"), 0)
    q = queue.Queue()
    q.put((str(f), "new.bin"))
    q.put(None)
    sha = hashlib.sha256(b"new-content").hexdigest()
    t = threading.Thread(target=fs.upload_worker,
                         args=(ctx, db, _NeverReportsBackend(), q), daemon=True)
    t.start()
    t0 = time.time()
    while time.time() - t0 < 10:
        r = db._conn.execute("SELECT status FROM uploads WHERE sha256=?",
                             (sha,)).fetchone()
        if r and r[0] == "pending":
            break
        time.sleep(0.05)
    time.sleep(0.2)                      # parked in the throttle
    ctx.stop.set()                       # Ctrl-C ordering: stop first
    ctx.pollers_stopped.set()
    t.join(10)
    assert not t.is_alive(), "worker hung in throttle"
    assert _status(db, sha) == "pending"
    assert not ctx.counters.snapshot().get("errors")
    db.close()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only timing")
def test_keyboard_interrupt_run_scan_keeps_rows_intact(tmp_path, monkeypatch):
    """Ctrl-C during run_scan: no throttle-induced failures, no cached row
    flipped to failed (post-close NDJSON write), reports still built."""
    drive = tmp_path / "drive"
    drive.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (drive / "a_fresh.bin").write_bytes(b"fresh-1")       # sorts first
    cached = []
    for i in range(6):
        c = b"cached-%d" % i
        (drive / f"z_cached{i}.exe").write_bytes(c)
        cached.append(hashlib.sha256(c).hexdigest())
    fresh_sha = hashlib.sha256(b"fresh-1").hexdigest()
    seed = fs.ScanDB(str(out / "scan_state.db"))
    seed.upsert_pending("inflight", "/x", "x", 1)
    seed.mark_submitted("inflight", "http://x/t/inflight")  # throttle full
    for s in cached:
        seed.upsert_pending(s, "/old/" + s, s, 1)
        seed.mark_submitted(s, "http://x/t/" + s)
        seed.claim_report(s)
        seed.mark_done(s, "malicious", "T", 9, None)
    seed.close()

    args = _scan_args(drive, out)
    args.max_in_flight = 1
    args.upload_workers = 1
    args.report_wait_hours = 1
    args.alert_on = {"malicious"}
    monkeypatch.setattr(fs, "make_backend", lambda a: _NeverReportsBackend())

    real_join = threading.Thread.join
    fired = []

    def _join(self, timeout=None):
        if self.name == "upload-pool" and not fired:
            fired.append(1)
            probe = fs.ScanDB(str(out / "scan_state.db"))
            try:
                t0 = time.time()
                while time.time() - t0 < 20:
                    r = probe._conn.execute(
                        "SELECT status FROM uploads WHERE sha256=?",
                        (fresh_sha,)).fetchone()
                    if r and r[0] == "pending":
                        break
                    time.sleep(0.05)
            finally:
                probe.close()
            time.sleep(0.3)              # fresh file parked in throttle
            raise KeyboardInterrupt
        return real_join(self, timeout)

    monkeypatch.setattr(threading.Thread, "join", _join)
    output = _run_in_thread(
        lambda: fs.run_scan(args, None, out, MagicMock()), timeout=60)
    monkeypatch.setattr(threading.Thread, "join", real_join)
    # Daemon workers may still run after return — wait for them so a
    # post-close write can't slip past the assertions.
    t0 = time.time()
    while (any(t.name.startswith("upload-") and t.is_alive()
               for t in threading.enumerate()) and time.time() - t0 < 20):
        time.sleep(0.05)
    assert output is not None and "summary" in output
    db = fs.ScanDB(str(out / "scan_state.db"))
    try:
        rows = dict(db._conn.execute(
            "SELECT sha256,status FROM uploads").fetchall())
        errs = db._conn.execute(
            "SELECT count(*) FROM uploads WHERE error LIKE '%throttle%'"
        ).fetchone()[0]
    finally:
        db.close()
    assert errs == 0
    assert rows[fresh_sha] == "pending"
    assert all(rows[s] in ("done", "cached") for s in cached), rows


# ---- R2: resumed in-flight rows get a fresh window ---------------------

class _CountingNeverReports(_NeverReportsBackend):
    def __init__(self):
        super().__init__()
        self.polled = []

    def poll_batch(self, refs, log=None):
        self.polled.extend(r["ref"] for r in refs)
        return super().poll_batch(refs, log)


def test_expire_overdue_counts_from_run_start(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("old", "f", "f", 1)
    db.mark_submitted("old", "http://x/t/old")
    db._conn.execute("UPDATE uploads SET uploaded_at=datetime('now','-2 hours')")
    run_start = db.now()
    assert db.expire_overdue(3600, run_start) == 0      # fresh window
    assert _status(db, "old") == "submitted"
    assert db.expire_overdue(3600) == 1                 # legacy: no run start
    db.close()


def test_resumed_row_is_polled_before_expiry(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("old", "f", "f", 1)
    db.mark_submitted("old", "http://x/t/old")
    db._conn.execute("UPDATE uploads SET uploaded_at=datetime('now','-2 hours')")
    run_start = db.now()
    ctx = _poll_ctx(tmp_path)
    done = threading.Event()
    done.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    backend = _CountingNeverReports()
    t0 = time.time()
    _run_in_thread(lambda: fs.result_poller(ctx, db, backend, 2, done, w,
                                            run_started_at=run_start),
                   timeout=20)
    elapsed = time.time() - t0
    w.close()
    assert "http://x/t/old" in backend.polled
    assert _status(db, "old") == "timeout"
    assert elapsed >= 1.0, "expired before run_started_at + N"
    db.close()


def test_run_scan_resumed_row_polled_this_run(tmp_path, monkeypatch):
    drive = tmp_path / "drive"
    drive.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    seed = fs.ScanDB(str(out / "scan_state.db"))
    seed.upsert_pending("old", "/x", "x", 1)
    seed.mark_submitted("old", "http://x/t/old")
    seed._q("UPDATE uploads SET uploaded_at=datetime('now','-2 hours')")
    seed.close()
    args = _scan_args(drive, out)
    args.report_wait_hours = 1 / 3600.0
    backend = _CountingNeverReports()
    monkeypatch.setattr(fs, "make_backend", lambda a: backend)
    _run_in_thread(lambda: fs.run_scan(args, None, out, MagicMock()),
                   timeout=30)
    assert "http://x/t/old" in backend.polled
