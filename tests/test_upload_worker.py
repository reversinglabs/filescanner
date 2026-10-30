# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import hashlib
import queue
import threading
import filescanner as fs
from unittest.mock import MagicMock


def _ctx(tmp_path, **over):
    a = dict(resume=True, file_types=set(), detect_file_type=False,
             extract_strings=False, extract_iocs=False,
             max_enrich_bytes=100, large_file_threshold=1 << 30,
             backoff_base_seconds=0, backoff_max_seconds=0,
             upload_retry_window=5, max_upload_attempts=1,
             ready_check_interval=0, ready_max_wait=1, max_in_flight=0,
             result_poll_interval=0)
    a.update(over)
    ctx = MagicMock()
    ctx.args = MagicMock(**a)
    ctx.counters = fs.Counters()
    ctx.keyed_locks = fs.KeyedLocks()
    ctx.logger = MagicMock()
    return ctx


def test_upload_worker_records_success(tmp_path):
    f = tmp_path / "a.exe"; f.write_bytes(b"MZx")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("x", str(f), "a.exe", 3)  # sha placeholder, worker recomputes
    client = MagicMock()
    client.upload_with_backoff.return_value = ("https://h/t/1", 201, None, 1)
    ctx = _ctx(tmp_path)
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)                      # sentinel: pool finished feeding
    fs.upload_worker(ctx, db, client, q)
    rows = db.submitted_rows()
    assert len(rows) == 1 and rows[0]["task_url"] == "https://h/t/1"
    db.close()


def test_upload_worker_exits_on_sentinel_with_empty_queue(tmp_path):
    """Worker must return on the sentinel even if no items were ever fed."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    ctx = _ctx(tmp_path)
    q = queue.Queue()
    q.put(None)
    client = MagicMock()
    fs.upload_worker(ctx, db, client, q)                 # returns, doesn't hang
    assert client.upload_with_backoff.call_count == 0
    db.close()


def test_upload_worker_exception_marks_failed_and_survives(tmp_path):
    """An exception mid-item must not kill the worker or drop the file silently."""
    f1 = tmp_path / "a.exe"; f1.write_bytes(b"MZ-a")
    f2 = tmp_path / "b.exe"; f2.write_bytes(b"MZ-b")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    client = MagicMock()
    client.upload_with_backoff.side_effect = [
        RuntimeError("boom"),                      # item 1 blows up
        ("https://h/t/2", 201, None, 1),           # item 2 still processed
    ]
    ctx = _ctx(tmp_path)
    q = queue.Queue()
    q.put((str(f1), "a.exe"))
    q.put((str(f2), "b.exe"))
    q.put(None)
    fs.upload_worker(ctx, db, client, q)
    sha1 = hashlib.sha256(b"MZ-a").hexdigest()
    counts = db.counts()
    assert counts.get("failed") == 1               # marked, not dropped
    assert counts.get("submitted") == 1            # worker survived
    assert ctx.counters.snapshot()["errors"] == 1
    db.close()


def test_upload_worker_error_after_submit_keeps_row_submitted(tmp_path):
    """An exception between mark_submitted and the next item (e.g. progress
    bookkeeping) must not clobber the live 'submitted' row to 'failed'."""
    f = tmp_path / "a.exe"; f.write_bytes(b"MZ-live")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    client = MagicMock()
    client.upload_with_backoff.return_value = ("https://h/t/1", 201, None, 1)
    ctx = _ctx(tmp_path)
    ctx.bump_upload.side_effect = RuntimeError("progress boom")
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)
    fs.upload_worker(ctx, db, client, q)
    rows = db.submitted_rows()
    assert len(rows) == 1 and rows[0]["task_url"] == "https://h/t/1"
    assert db.counts().get("failed") is None
    assert ctx.counters.snapshot()["errors"] == 1    # error still counted
    db.close()


def test_run_upload_pool_processes_all_and_terminates(tmp_path):
    """Bounded queue + N sentinels: every item processed, workers exit."""
    files = []
    for i in range(10):
        f = tmp_path / f"f{i}.exe"
        f.write_bytes(b"MZ-%d" % i)
        files.append((str(f), f"f{i}.exe"))
    db = fs.ScanDB(str(tmp_path / "s.db"))
    client = MagicMock()
    client.upload_with_backoff.side_effect = (
        lambda fp, custom, cfg, log=None:
            (f"https://h/t/{custom['sha256'][:8]}", 201, None, 1))
    ctx = _ctx(tmp_path, upload_workers=3)
    fs.run_upload_pool(ctx, db, client, files)     # returns = no deadlock
    assert db.counts() == {"submitted": 10}
    db.close()


def test_upload_worker_resume_false_resubmits_done(tmp_path):
    """resume=False must re-upload a file that already has a verdict."""
    content = b"MZ-done"
    f = tmp_path / "a.exe"; f.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(sha, str(f), "a.exe", len(content))
    db.mark_submitted(sha, "https://h/t/old")
    db.claim_report(sha)
    db.mark_done(sha, "goodware", None, 2, None)
    client = MagicMock()
    client.upload_with_backoff.return_value = ("https://h/t/new", 201, None, 1)
    ctx = _ctx(tmp_path, resume=False)
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)
    fs.upload_worker(ctx, db, client, q)
    assert client.upload_with_backoff.call_count == 1   # re-submitted
    assert db.submitted_rows()[0]["task_url"] == "https://h/t/new"
    db.close()


def test_upload_worker_resume_true_uses_cached(tmp_path):
    """resume=True keeps the skip-a-done-verdict behaviour."""
    content = b"MZ-done"
    f = tmp_path / "a.exe"; f.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(sha, str(f), "a.exe", len(content))
    db.mark_submitted(sha, "https://h/t/old")
    db.claim_report(sha)
    db.mark_done(sha, "goodware", None, 2, None)
    client = MagicMock()
    ctx = _ctx(tmp_path, resume=True)
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)
    fs.upload_worker(ctx, db, client, q)
    assert client.upload_with_backoff.call_count == 0
    assert db.counts().get("cached") == 1
    db.close()


def test_upload_worker_resume_false_skips_inflight(tmp_path):
    """A 'submitted' row is an in-flight task — skipped even with resume off."""
    content = b"MZ-inflight"
    f = tmp_path / "a.exe"; f.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(sha, str(f), "a.exe", len(content))
    db.mark_submitted(sha, "https://h/t/flying")
    client = MagicMock()
    ctx = _ctx(tmp_path, resume=False)
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)
    fs.upload_worker(ctx, db, client, q)
    assert client.upload_with_backoff.call_count == 0
    assert db.submitted_rows()[0]["task_url"] == "https://h/t/flying"
    db.close()


def test_duplicate_content_uploaded_once_across_workers(tmp_path):
    """Two identical files on two workers race — only one POST may happen."""
    f1 = tmp_path / "a.exe"; f1.write_bytes(b"MZ-same")
    f2 = tmp_path / "b.exe"; f2.write_bytes(b"MZ-same")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    client = MagicMock()
    client.upload_with_backoff.return_value = ("https://h/t/1", 201, None, 1)
    ctx = _ctx(tmp_path, upload_workers=2, resume=False)
    fs.run_upload_pool(ctx, db, client,
                       [(str(f1), "a.exe"), (str(f2), "b.exe")])
    assert client.upload_with_backoff.call_count == 1  # keyed lock dedup
    snap = ctx.counters.snapshot()
    assert snap.get("submitted") == 1 and snap.get("cached") == 1
    db.close()


def test_upload_worker_failure_logged_at_warning(tmp_path):
    """Upload failures must be greppable by level — WARNING, not INFO."""
    f = tmp_path / "a.exe"; f.write_bytes(b"MZ-x")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    client = MagicMock()
    client.upload_with_backoff.return_value = (None, 500, "http_500: boom", 3)
    ctx = _ctx(tmp_path)
    ctx.bump_upload = fs.ScanContext.bump_upload.__get__(ctx)
    ctx.logger = MagicMock()
    ctx._done_uploads = 0
    ctx.total = 1
    ctx._progress_lock = threading.Lock()
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)
    fs.upload_worker(ctx, db, client, q)
    warned = [c for c in ctx.logger.warning.call_args_list
              if "FAILED" in str(c.args)]
    assert warned, "failure progress line must log at WARNING"
    db.close()


def test_setup_logging_uses_rotating_handler(tmp_path):
    """Log file must rotate — plain FileHandler would grow unbounded."""
    import logging.handlers
    log = tmp_path / "s.log"
    root = logging.getLogger()
    for h in list(root.handlers):            # basicConfig no-ops if handlers exist
        root.removeHandler(h)
    fs.setup_logging(False, str(log), max_mb=1, backups=2)
    assert any(isinstance(h, logging.handlers.RotatingFileHandler)
               for h in root.handlers)
    for h in list(root.handlers):
        root.removeHandler(h)


def test_pool_uploads_during_lazy_enumeration(tmp_path):
    """Uploads must start while the work iterator is still discovering files —
    not after a full enumeration completes."""
    f1 = tmp_path / "a.exe"; f1.write_bytes(b"MZ-1")
    f2 = tmp_path / "b.exe"; f2.write_bytes(b"MZ-2")
    gate = threading.Event()
    first_uploaded = threading.Event()

    def slow_iter():
        yield (str(f1), "a.exe")
        gate.wait(10)                       # still "walking" ...
        yield (str(f2), "b.exe")

    db = fs.ScanDB(str(tmp_path / "s.db"))
    client = MagicMock()
    def _up(fp, custom, cfg, log=None):
        first_uploaded.set()
        return ("https://h/t/1", 201, None, 1)
    client.upload_with_backoff.side_effect = _up
    ctx = _ctx(tmp_path, upload_workers=1)
    ctx.total = 0
    ctx.add_total = lambda n: setattr(ctx, "total", ctx.total + n)

    t = threading.Thread(target=fs.run_upload_pool,
                         args=(ctx, db, client, slow_iter()), daemon=True)
    t.start()
    assert first_uploaded.wait(5), "first file must upload while iterator blocked"
    gate.set()
    t.join(timeout=10)
    assert not t.is_alive()
    assert ctx.total == 2                    # denominator grew as items arrived
    db.close()
