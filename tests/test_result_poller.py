# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import json
import threading
import time
import filescanner as fs
from unittest.mock import MagicMock


def _ctx(tmp_path, **arg_overrides):
    args = dict(result_poll_interval=0, summary_only=False,
                quarantine_on=set(), quarantine_action="none",
                store_full_report=False)
    args.update(arg_overrides)
    ctx = MagicMock()
    ctx.args = MagicMock(**args)
    ctx.counters = fs.Counters()
    ctx.logger = MagicMock()
    ctx.alerter = None
    ctx._quarantine_lock = threading.Lock()
    ctx.quarantine_dir = tmp_path / "q"
    ctx.bump_progress = MagicMock()
    return ctx


def test_poller_marks_done(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "f", "f", 1)
    db.mark_submitted("aa", "https://h/t/1")
    client = MagicMock()
    client.task_status.return_value = {
        "processed": 1729000000,
        "tc_report": [{"classification": {"classification": 3}}]}
    ctx = _ctx(tmp_path)
    done_evt = threading.Event(); done_evt.set()   # uploads already finished
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    assert db.counts().get("done") == 1
    assert (tmp_path / "r.ndjson").read_text().count("malicious") == 1
    ctx.bump_progress.assert_called_once_with("f", "MALICIOUS")
    db.close()


def test_poller_deadline_marks_timeout(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "f", "f", 1)
    db.mark_submitted("aa", "https://h/t/1")
    # Per-row deadline: this row's upload is older than the wait budget.
    db._conn.execute("UPDATE uploads SET uploaded_at=datetime('now','-2 hours')")
    client = MagicMock()
    ctx = _ctx(tmp_path)
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    assert db.counts().get("timeout") == 1
    assert client.task_status.call_count == 0
    assert (tmp_path / "r.ndjson").read_text() == ""
    # Timed-out reports must reach the files_with_errors exit-code path.
    assert ctx.counters.snapshot().get("errors") == 1
    db.close()


def test_poller_streams_ndjson_record(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("bb", "E:\\b.exe", "b.exe", 5)
    db.mark_submitted("bb", "https://h/t/2")
    client = MagicMock()
    client.task_status.return_value = {
        "processed": 1729000001,
        "tc_report": [{"classification": {"classification": 2,
                                          "result": "Trojan.X",
                                          "factor": 7}}]}
    ctx = _ctx(tmp_path, summary_only=True)
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    lines = (tmp_path / "r.ndjson").read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["classification"] == "suspicious"
    assert rec["threat_name"] == "Trojan.X"
    assert rec["threat_factor"] == 7
    assert rec["file_path"] == "b.exe"
    assert rec["absolute_path"] == "E:\\b.exe"
    assert rec["api"]["status"] == "completed"
    assert rec["api"]["report"] is None  # summary_only
    db.close()


def test_poller_applies_quarantine_and_alert(tmp_path):
    f = tmp_path / "evil.exe"; f.write_bytes(b"MZ-evil")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("cc", str(f), "evil.exe", 7)
    db.mark_submitted("cc", "https://h/t/3")
    client = MagicMock()
    client.task_status.return_value = {
        "processed": 1729000002,
        "tc_report": [{"classification": {"classification": 3}}]}
    ctx = _ctx(tmp_path, quarantine_on={"malicious"}, quarantine_action="copy")
    alerter = MagicMock()
    alerter.maybe_alert.return_value = True
    ctx.alerter = alerter
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    rec = json.loads((tmp_path / "r.ndjson").read_text().splitlines()[0])
    assert rec["quarantined_to"] is not None
    assert (tmp_path / "q" / rec["quarantined_to"].split("/")[-1]).exists() or \
        fs.Path(rec["quarantined_to"]).exists()
    assert rec["alerted"] is True
    assert alerter.maybe_alert.call_count == 1
    snap = ctx.counters.snapshot()
    assert snap["quarantined"] == 1 and snap["alerts"] == 1
    db.close()


def test_poller_retries_after_transient_error(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("dd", "f", "f", 1)
    db.mark_submitted("dd", "https://h/t/4")
    client = MagicMock()
    client.task_status.side_effect = [
        RuntimeError("task GET 503"),
        {"processed": None},  # still running
        {"processed": 1729000003,
         "tc_report": [{"classification": {"classification": 1}}]},
    ]
    ctx = _ctx(tmp_path)
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    assert db.counts().get("done") == 1
    rec = json.loads((tmp_path / "r.ndjson").read_text().splitlines()[0])
    assert rec["classification"] == "goodware"
    db.close()


def test_poller_treats_malformed_task_body_as_transient(tmp_path):
    """task_status raising ValueError on a non-dict body must unclaim the row
    (transient server bug), not kill the row or the poller."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("hh", "f", "f", 1)
    db.mark_submitted("hh", "https://h/t/8")
    client = MagicMock()
    client.task_status.side_effect = [
        ValueError("malformed task body: list"),     # non-dict JSON body
        {"processed": 1729000007,
         "tc_report": [{"classification": {"classification": 1}}]},
    ]
    ctx = _ctx(tmp_path)
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    assert db.counts().get("done") == 1              # recovered on next pass
    assert any("malformed task body" in str(a)
               for c in ctx.logger.warning.call_args_list for a in c.args)
    db.close()


def test_poller_waits_for_uploads_done(tmp_path):
    """Still-submitted rows keep the poller alive until uploads finish."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("ee", "f", "f", 1)
    db.mark_submitted("ee", "https://h/t/5")
    client = MagicMock()
    client.task_status.return_value = {
        "processed": 1729000004,
        "tc_report": [{"classification": {"classification": 0}}]}
    ctx = _ctx(tmp_path)
    uploads_done = threading.Event()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    t = threading.Thread(
        target=fs.result_poller,
        args=(ctx, db, client, time.time() + 60, uploads_done, w),
        daemon=True)
    t.start()
    time.sleep(0.3)
    uploads_done.set()
    t.join(timeout=10)
    assert not t.is_alive()
    w.close()
    assert db.counts().get("done") == 1
    db.close()


def test_two_pollers_process_row_exactly_once(tmp_path):
    """With result_pollers>1, a row's side effects must happen exactly once."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("ff", "f", "f", 1)
    db.mark_submitted("ff", "https://h/t/6")
    client = MagicMock()
    client.task_status.return_value = {
        "processed": 1729000005,
        "tc_report": [{"classification": {"classification": 3}}]}
    ctx = _ctx(tmp_path)
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pollers = [
        threading.Thread(target=fs.result_poller,
                         args=(ctx, db, client, time.time() + 30, done_evt, w),
                         daemon=True)
        for _ in range(2)]
    for p in pollers:
        p.start()
    for p in pollers:
        p.join(timeout=10)
        assert not p.is_alive()
    w.close()
    lines = (tmp_path / "r.ndjson").read_text().splitlines()
    assert len(lines) == 1                      # exactly once, not twice
    assert db.counts().get("done") == 1
    db.close()


def test_poller_survives_unexpected_exception(tmp_path):
    """An unexpected error mid-loop must not kill the poller thread."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("gg", "f", "f", 1)
    db.mark_submitted("gg", "https://h/t/7")
    client = MagicMock()
    client.task_status.return_value = {
        "processed": 1729000006,
        "tc_report": [{"classification": {"classification": 1}}]}
    ctx = _ctx(tmp_path)
    # Blow up once at the top of the loop — outer containment must catch it.
    real_rows = db.submitted_rows
    calls = {"n": 0}
    def flaky_rows():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db hiccup")
        return real_rows()
    db.submitted_rows = flaky_rows
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    assert calls["n"] >= 2                      # loop continued after the hiccup
    assert db.counts().get("done") == 1
    db.close()


def test_poller_marks_404_task_failed(tmp_path):
    """A task GET 404 is terminal: the row must flip submitted->failed via
    the claim, not unclaim-and-retry until the report deadline."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("sha404", "f", "f", 1)
    db.mark_submitted("sha404", "https://h/t/9")
    client = MagicMock()
    client.task_status.side_effect = fs.TaskGoneError("gone")
    ctx = _ctx(tmp_path)
    done_evt = threading.Event(); done_evt.set()
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    fs.result_poller(ctx, db, client, 3600, done_evt, w)
    w.close()
    assert db.counts().get("failed") == 1
    assert db.counts().get("submitted") is None
    db.close()
