# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Tests for precheck_worker — the reputation pre-check stage that sits
between hashing and upload. Mirrors the worker/queue idioms of
tests/test_upload_worker.py and tests/test_result_poller.py: MagicMock
client/ctx, real ScanDB, real ResultsWriter.

Contract under test:
  item  = {"sha256","sha1","filepath","rel_path","size","head",
           "prehashed": True}   on precheck_q; re-enqueued verbatim to work_q
  batch = up to cfg.reputation_batch_size sha256s per reputation_bulk call;
          a partial batch flushes on the drain timeout or the None sentinel
  verdict != 'unknown' -> mark_done_direct(..., backend='ticloud') + NDJSON
          record + counters; 'unknown'/unresolvable -> work_q (fail-open)
"""
import hashlib
import json
import queue
import threading
import time
import types

import pytest

import filescanner as fs
from unittest.mock import MagicMock


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _cfg(**over):
    a = dict(reputation_batch_size=100, reputation_skip_classified=True,
             summary_only=False,
             backoff_base_seconds=0, backoff_max_seconds=0,
             upload_retry_window=5, max_upload_attempts=1,
             ready_check_interval=0, ready_max_wait=1,
             avail_probe_seconds=20)
    a.update(over)
    return MagicMock(**a)


def _ctx(tmp_path):
    ctx = MagicMock()
    ctx.counters = fs.Counters()
    ctx.logger = MagicMock()
    ctx.alerter = None
    ctx._quarantine_lock = threading.Lock()
    ctx.quarantine_dir = tmp_path / "q"
    ctx.bump_progress = MagicMock()
    return ctx


def _item(sha, rel=None):
    rel = rel or (sha[:6] + ".bin")
    return {"sha256": sha, "sha1": None, "filepath": "/abs/" + rel,
            "rel_path": rel, "size": 3, "head": b"MZ", "prehashed": True}


def _entry(sha, status, **kw):
    e = {"sha256": sha, "status": status}
    e.update(kw)
    return e


def _client(entries, invalid=None, **_kw):
    """reputation_bulk answers one 200 response with these entries; the call
    records the hash list it was asked about."""
    c = MagicMock()
    c.available_now.return_value = True
    c.wait_ready.return_value = True
    calls = []

    def answer(hashes, hash_type="sha256", timeout=30):
        calls.append((list(hashes), hash_type))
        by = {e["sha256"]: e for e in entries}
        ents = [by[h] for h in dict.fromkeys(hashes) if h in by]
        return 200, (ents, invalid or []), None
    c.reputation_bulk.side_effect = answer
    c._calls = calls
    return c


def _drain(q):
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            return out


def _run(tmp_path, items, client, cfg=None, seed_pending=True):
    """Feed items + sentinel through a synchronous precheck_worker run."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    if seed_pending:
        for it in items:
            db.upsert_pending(it["sha256"], it["filepath"], it["rel_path"],
                              it["size"])
    ctx = _ctx(tmp_path)
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    for it in items:
        pq.put(it)
    pq.put(None)                                 # feeder sentinel
    fs.precheck_worker(ctx, db, client, pq, wq, cfg or _cfg(), w)
    w.close()
    return db, ctx, _drain(wq)


def test_precheck_batches_respect_batch_size(tmp_path):
    """5 items with batch_size=2 must issue calls of [2, 2, 1] — never more
    than batch_size sha256s per reputation_bulk."""
    items = [_item(f"{i:064x}") for i in range(5)]
    client = _client([])
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(reputation_batch_size=2))
    assert [len(h) for h, _t in client._calls] == [2, 2, 1]
    assert all(t == "sha256" for _h, t in client._calls)
    assert len(enq) == 5                          # all UNKNOWN -> upload path
    assert all(it["prehashed"] for it in enq)
    db.close()


def test_precheck_classified_marks_done_with_ticloud_backend(tmp_path):
    """A MALICIOUS verdict flips pending->done straight (no submit), stamps
    backend='ticloud', writes the NDJSON record, and drops the item."""
    items = [_item(SHA_A, "evil.exe")]
    client = _client([_entry(SHA_A, "MALICIOUS",
                             threat_name="Win32.Backdoor.Poison",
                             threat_level=9, trust_factor=0)])
    db, ctx, enq = _run(tmp_path, items, client)
    row = db._q("SELECT status,classification,threat_name,threat_factor,"
                "backend,report_json FROM uploads WHERE sha256=?",
                (SHA_A,), fetch="one")
    assert row[0] == "done" and row[1] == "malicious"
    assert row[2] == "Win32.Backdoor.Poison" and row[3] == 9
    assert row[4] == "ticloud"
    assert json.loads(row[5])["status"] == "MALICIOUS"   # raw entry stored
    assert enq == []                                     # skipped upload
    assert ctx.counters.snapshot()["malicious"] == 1
    rec = json.loads((tmp_path / "r.ndjson").read_text().splitlines()[0])
    assert rec["classification"] == "malicious"
    assert rec["threat_factor"] == 9
    assert rec["backend"] == "ticloud"
    assert rec["sha256"] == SHA_A and rec["file_path"] == "evil.exe"
    assert rec["api"]["status"] == "completed"
    ctx.bump_progress.assert_called_once_with("evil.exe",
                                              "MALICIOUS (precheck)")
    db.close()


def test_precheck_known_maps_to_goodware_with_trust_factor(tmp_path):
    """KNOWN -> goodware with trust_factor — mark_done_direct gets the
    normalized verdict, not the raw fields."""
    items = [_item(SHA_A)]
    client = _client([_entry(SHA_A, "KNOWN", threat_level=9, trust_factor=2)])
    db, ctx, enq = _run(tmp_path, items, client)
    row = db._q("SELECT status,classification,threat_factor FROM uploads "
                "WHERE sha256=?", (SHA_A,), fetch="one")
    assert row == ("done", "goodware", 2)    # trust_factor, not threat_level
    db.close()


def test_precheck_unknown_reenqueues_prehashed(tmp_path):
    """UNKNOWN verdict -> item flows to work_q verbatim, prehashed=True so
    the upload path skips a second hash pass; row stays pending."""
    items = [_item(SHA_A, "mystery.bin")]
    client = _client([_entry(SHA_A, "UNKNOWN")])
    db, ctx, enq = _run(tmp_path, items, client)
    assert [it["rel_path"] for it in enq] == ["mystery.bin"]
    assert enq[0]["prehashed"] is True and enq[0]["sha256"] == SHA_A
    assert db.counts() == {"pending": 1}
    assert (tmp_path / "r.ndjson").read_text() == ""
    db.close()


def test_precheck_missing_entry_routes_to_upload(tmp_path):
    """A hash absent from the response is treated like UNKNOWN — uploaded."""
    items = [_item(SHA_A), _item(SHA_B)]
    client = _client([_entry(SHA_A, "MALICIOUS")])      # SHA_B: no entry
    db, ctx, enq = _run(tmp_path, items, client)
    assert [it["sha256"] for it in enq] == [SHA_B]
    assert db.counts() == {"done": 1, "pending": 1}
    db.close()


def test_precheck_skip_classified_false_reenqueues_everything(tmp_path):
    """skip_classified=false = enrichment-only: the reputation verdict is
    written to the NDJSON stream but the row stays 'pending' — a 'done'
    row would let the upload path's resume dedup short-circuit and the
    file would never actually upload."""
    items = [_item(SHA_A), _item(SHA_B)]
    client = _client([_entry(SHA_A, "MALICIOUS"), _entry(SHA_B, "UNKNOWN")])
    db, ctx, enq = _run(
        tmp_path, items, client,
        cfg=_cfg(reputation_skip_classified=False))
    assert sorted(it["sha256"] for it in enq) == [SHA_A, SHA_B]
    assert db.counts() == {"pending": 2}
    recs = [json.loads(l) for l in
            (tmp_path / "r.ndjson").read_text().splitlines() if l.strip()]
    assert any(r["sha256"] == SHA_A and r["backend"] == "ticloud"
               and r["classification"] == "malicious" for r in recs)
    db.close()


def _upload_args(**over):
    a = types.SimpleNamespace(
        resume=True, file_types=set(), max_in_flight=0,
        result_poll_interval=0, store_full_report=False, summary_only=True,
        quarantine_action="none", quarantine_on=set(), quarantine_dir=None,
        alert_on=set(), alert_webhook=None, alert_syslog=None,
        alert_eventlog=False, detect_file_type=False, extract_strings=False,
        extract_iocs=False, max_enrich_bytes=1024)
    for k, v in over.items():
        setattr(a, k, v)
    return a


def _upload_ctx(tmp_path, args):
    ctx = _ctx(tmp_path)
    ctx.args = args
    ctx.keyed_locks = fs.KeyedLocks()
    ctx.bump_upload = MagicMock()
    return ctx


def _verdict_backend(name="fie"):
    b = MagicMock()
    b.name = name
    b.needs_sha1 = False
    b.submit_with_backoff.return_value = fs.SubmitOutcome(
        kind="verdict", classification="malicious", threat_name="T",
        threat_factor=8, report_json={"r": 1})
    return b


def test_precheck_enrichment_reenqueued_item_uploads_under_resume(tmp_path):
    """End-to-end of the fix: a reputation-classified file re-enqueued under
    skip_classified=false must reach backend.submit even with resume=True —
    before the fix the 'done' row made the dedup mark it 'cached' and the
    backend never saw the file."""
    items = [_item(SHA_A)]
    client = _client([_entry(SHA_A, "MALICIOUS")])
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(reputation_skip_classified=False))
    assert [it["sha256"] for it in enq] == [SHA_A]
    assert db.counts() == {"pending": 1}          # enriched, not done

    backend = _verdict_backend()
    wq = queue.Queue()
    for it in enq:
        wq.put(it)
    wq.put(None)
    fs.upload_worker(_upload_ctx(tmp_path, _upload_args(resume=True)),
                     db, backend, wq, writer=MagicMock())
    backend.submit_with_backoff.assert_called_once()
    assert db.counts() == {"done": 1}
    db.close()


def test_precheck_full_queue_falls_through_to_upload(tmp_path):
    """A saturated bounded precheck_q fails open: put_nowait's Full branch
    submits inline instead of blocking under the keyed lock."""
    f = tmp_path / "e.bin"
    f.write_bytes(b"MZ-e")
    sha256 = hashlib.sha256(b"MZ-e").hexdigest()

    backend = _verdict_backend()
    db = fs.ScanDB(str(tmp_path / "s.db"))
    ctx = _upload_ctx(tmp_path, _upload_args())
    pq = queue.Queue(maxsize=1)
    pq.put(_item("f" * 64))                     # saturate the stage
    wq = queue.Queue()
    wq.put((str(f), "e.bin"))
    wq.put(None)
    fs.upload_worker(ctx, db, backend, wq, precheck_q=pq,
                     writer=MagicMock())

    backend.submit_with_backoff.assert_called_once()
    assert ctx.counters.snapshot()["precheck_bypassed"] == 1
    assert db.known_verdict(sha256)["status"] == "done"
    db.close()


def test_precheck_head_only_captured_for_consumers(tmp_path):
    """head bytes ride the precheck dict only when a consumer exists —
    no file_types filter and no extract_* means dead memory."""
    backend = _verdict_backend()
    db = fs.ScanDB(str(tmp_path / "s.db"))
    f = tmp_path / "h.exe"
    f.write_bytes(b"MZ-head")

    # no consumers -> head empty
    ctx = _upload_ctx(tmp_path, _upload_args())
    pq, wq = queue.Queue(), queue.Queue()
    wq.put((str(f), "h.exe"))
    wq.put(None)
    fs.upload_worker(ctx, db, backend, wq, precheck_q=pq,
                     writer=MagicMock())
    got = pq.get_nowait()
    assert got["head"] == b""

    # file_types filter consumes head -> captured
    ctx2 = _upload_ctx(tmp_path, _upload_args(file_types={"pe"}))
    pq2, wq2 = queue.Queue(), queue.Queue()
    wq2.put((str(f), "h.exe"))
    wq2.put(None)
    fs.upload_worker(ctx2, db, backend, wq2, precheck_q=pq2,
                     writer=MagicMock())
    got2 = pq2.get_nowait()
    assert got2["head"] == b"MZ-head"
    db.close()


def test_precheck_invalid_hashes_logged_not_lost(tmp_path):
    """invalid_hashes must be logged + counted; the affected items have no
    entry so they flow to the upload path."""
    items = [_item(SHA_A), _item("zz" * 32)]
    client = _client([_entry(SHA_A, "MALICIOUS")],
                     invalid=[{"hash_value": "zz" * 32, "reason": "invalid"}])
    db, ctx, enq = _run(tmp_path, items, client)
    warned = [c for c in ctx.logger.warning.call_args_list
              if "invalid" in str(c.args)]
    assert warned, "invalid_hashes must produce a warning"
    assert [it["sha256"] for it in enq] == ["zz" * 32]
    assert db.counts() == {"done": 1, "pending": 1}
    db.close()


def test_precheck_partial_batch_flushes_on_timeout(tmp_path):
    """Fewer than batch_size items must flush after the short drain timeout —
    the tail can't wait for a full batch forever."""
    items = [_item(f"{i:064x}") for i in range(3)]
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for it in items:
        db.upsert_pending(it["sha256"], it["filepath"], it["rel_path"], 3)
    ctx = _ctx(tmp_path)
    client = _client([_entry(it["sha256"], "UNKNOWN") for it in items])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    t = threading.Thread(target=fs.precheck_worker,
                         args=(ctx, db, client, pq, wq, _cfg(), w),
                         daemon=True)
    t.start()
    for it in items:
        pq.put(it)                                   # no sentinel yet
    deadline = time.monotonic() + 10
    while not client._calls and time.monotonic() < deadline:
        time.sleep(0.05)
    assert client._calls, "partial batch never flushed on the timeout"
    assert len(client._calls[0][0]) == 3
    pq.put(None)
    t.join(timeout=10)
    assert not t.is_alive()
    w.close()
    assert len(_drain(wq)) == 3
    db.close()


def test_precheck_sentinel_drains_pending_batch(tmp_path):
    """The sentinel must flush whatever accumulated before the worker exits —
    nothing may be stranded in the worker's batch buffer."""
    items = [_item(f"{i:064x}") for i in range(4)]
    client = _client([_entry(it["sha256"], "MALICIOUS") for it in items])
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(reputation_batch_size=100))
    assert len(client._calls) == 1 and len(client._calls[0][0]) == 4
    assert db.counts() == {"done": 4}
    assert enq == []
    db.close()


def test_precheck_bulk_failure_fails_open(tmp_path):
    """A persistently failing bulk call must re-enqueue every item — files
    are never lost, and the failure is counted separately."""
    items = [_item(SHA_A), _item(SHA_B)]
    client = MagicMock()
    client.available_now.return_value = True
    client.wait_ready.return_value = True
    client.reputation_bulk.return_value = (503, None, "http_503: down")
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(max_upload_attempts=2))
    assert client.reputation_bulk.call_count == 2    # retried, then gave up
    assert sorted(it["sha256"] for it in enq) == [SHA_A, SHA_B]
    assert db.counts() == {"pending": 2}             # nothing lost, nothing done
    assert ctx.counters.snapshot()["precheck_errors"] == 1
    db.close()


def test_precheck_retriable_error_retries_then_succeeds(tmp_path):
    """429/5xx retry the whole batch with backoff; a later success lands the
    verdicts normally."""
    items = [_item(SHA_A)]
    client = MagicMock()
    client.available_now.return_value = True
    client.wait_ready.return_value = True
    client.reputation_bulk.side_effect = [
        (503, None, "http_503: down"),
        (200, ([_entry(SHA_A, "SUSPICIOUS", threat_level=5)], []), None),
    ]
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(max_upload_attempts=3))
    assert client.reputation_bulk.call_count == 2
    assert db.counts() == {"done": 1}
    assert enq == []
    row = db._q("SELECT classification,threat_factor,backend FROM uploads "
                "WHERE sha256=?", (SHA_A,), fetch="one")
    assert row == ("suspicious", 5, "ticloud")
    db.close()


def test_precheck_auth_error_is_not_retried(tmp_path):
    """401/403 can never succeed on retry — fail open immediately."""
    items = [_item(SHA_A)]
    client = MagicMock()
    client.available_now.return_value = True
    client.wait_ready.return_value = True
    client.reputation_bulk.return_value = (401, None, "http_401: denied")
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(max_upload_attempts=5))
    assert client.reputation_bulk.call_count == 1    # no pointless retry
    assert len(enq) == 1
    db.close()


def test_precheck_duplicate_sha_each_path_gets_record(tmp_path):
    """Two files with identical content share one sha256 row and one bulk
    hash lookup, but every physical path still gets its own verdict record
    (the dup is flagged duplicate and does not alert again)."""
    items = [_item(SHA_A, "a.exe"), _item(SHA_A, "b.exe")]
    client = _client([_entry(SHA_A, "MALICIOUS")])
    db, ctx, enq = _run(tmp_path, items, client)
    # one bulk hash despite two items
    assert client._calls[0][0] == [SHA_A]
    assert db.counts() == {"done": 1}
    lines = (tmp_path / "r.ndjson").read_text().splitlines()
    assert len(lines) == 2                       # one record per path
    recs = [json.loads(l) for l in lines]
    assert {r["file_path"] for r in recs} == {"a.exe", "b.exe"}
    assert [r.get("duplicate") for r in recs].count(True) == 1
    assert ctx.counters.snapshot()["malicious"] == 2
    assert enq == []
    db.close()


def test_precheck_failed_row_is_requeued_and_gets_verdict(tmp_path):
    """A 'failed' row from a prior run is reset to pending by the upsert, so
    the synchronous precheck verdict lands (it used to be silently lost)."""
    it = _item(SHA_A, "prev-failed.exe")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(SHA_A, it["filepath"], it["rel_path"], it["size"])
    db.mark_failed(SHA_A, 500, "old failure")
    ctx = _ctx(tmp_path)
    client = _client([_entry(SHA_A, "MALICIOUS")])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    pq.put(it)
    pq.put(None)
    fs.precheck_worker(ctx, db, client, pq, wq, _cfg(), w)
    w.close()
    assert _drain(wq) == []
    assert db.counts() == {"done": 1}
    assert len((tmp_path / "r.ndjson").read_text().splitlines()) == 1
    assert ctx.counters.snapshot()["malicious"] == 1
    db.close()


def test_precheck_malformed_item_routed_to_upload(tmp_path):
    """An item without a sha256 can't be queried — fail open with
    prehashed cleared so the upload path hashes it itself."""
    bad = {"filepath": "/abs/x.bin", "rel_path": "x.bin", "size": 1,
           "head": b"", "prehashed": True}
    db = fs.ScanDB(str(tmp_path / "s.db"))
    ctx = _ctx(tmp_path)
    client = _client([])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    pq.put(bad)
    pq.put(None)
    fs.precheck_worker(ctx, db, client, pq, wq, _cfg(), w)
    w.close()
    enq = _drain(wq)
    assert len(enq) == 1 and enq[0]["prehashed"] is False
    assert ctx.counters.snapshot()["errors"] == 1
    assert client.reputation_bulk.call_count == 0
    db.close()


def test_precheck_sentinel_exits_cleanly_when_empty(tmp_path):
    """Worker must return on the sentinel even with nothing ever fed."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    ctx = _ctx(tmp_path)
    client = _client([])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    pq.put(None)
    fs.precheck_worker(ctx, db, client, pq, wq, _cfg(), w)
    w.close()
    assert client.reputation_bulk.call_count == 0
    db.close()


def test_precheck_batch_exception_never_loses_items(tmp_path):
    """A mid-batch blow-up (e.g. db down) is contained: every item
    re-enqueues to work_q rather than vanishing."""
    items = [_item(SHA_A), _item(SHA_B)]
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for it in items:
        db.upsert_pending(it["sha256"], it["filepath"], it["rel_path"], 3)
    db.mark_done_direct = MagicMock(side_effect=RuntimeError("db dead"))
    ctx = _ctx(tmp_path)
    client = _client([_entry(SHA_A, "MALICIOUS"), _entry(SHA_B, "KNOWN")])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    for it in items:
        pq.put(it)
    pq.put(None)
    fs.precheck_worker(ctx, db, client, pq, wq, _cfg(), w)   # survives
    w.close()
    assert sorted(i["sha256"] for i in _drain(wq)) == [SHA_A, SHA_B]
    assert ctx.counters.snapshot()["precheck_errors"] == 1
    db.close()


def test_precheck_respects_submitted_row(tmp_path):
    """A row already 'submitted' is a live task — the verdict can't stick
    and the item must NOT be re-enqueued (that would double-submit)."""
    it = _item(SHA_A, "live.exe")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(SHA_A, it["filepath"], it["rel_path"], it["size"])
    db.mark_submitted(SHA_A, "https://h/t/live")
    ctx = _ctx(tmp_path)
    client = _client([_entry(SHA_A, "MALICIOUS")])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    pq.put(it)
    pq.put(None)
    fs.precheck_worker(ctx, db, client, pq, wq, _cfg(), w)
    w.close()
    assert _drain(wq) == []                            # dropped, not enqueued
    assert db.counts() == {"submitted": 1}
    db.close()


@pytest.mark.parametrize("raw", ["KNOWN", "MALICIOUS", "SUSPICIOUS"])
def test_precheck_marks_available_gate_used(tmp_path, raw):
    """Every bulk call gates on the shared availability cache, and a
    saturation error stamps it unavailable."""
    items = [_item(SHA_A)]
    client = MagicMock()
    client.available_now.return_value = False
    client.wait_ready.return_value = True
    client.reputation_bulk.return_value = (
        200, ([_entry(SHA_A, raw, threat_level=4, trust_factor=4)], []), None)
    db, ctx, enq = _run(tmp_path, items, client,
                        cfg=_cfg(max_upload_attempts=1))
    client.wait_ready.assert_called()                  # gated before attempt
    assert db.counts().get("done") == 1
    db.close()


def test_precheck_verdict_cant_stick_fails_open(tmp_path):
    """mark_done_direct returns 0 (row left 'pending' under us, e.g. flipped
    to timeout) -> the verdict is lost, so the item must be re-enqueued for
    upload with no NDJSON record or verdict side effects."""
    it = _item(SHA_A, "cant-stick.exe")
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(SHA_A, it["filepath"], it["rel_path"], it["size"])

    def _lost(sha256, *a, **k):
        db._conn.execute("UPDATE uploads SET status='timeout' WHERE sha256=?",
                         (sha256,))
        return 0
    db.mark_done_direct = _lost
    ctx = _ctx(tmp_path)
    client = _client([_entry(SHA_A, "MALICIOUS")])
    w = fs.ResultsWriter(str(tmp_path / "r.ndjson"))
    pq, wq = queue.Queue(), queue.Queue()
    pq.put(it)
    pq.put(None)
    fs.precheck_worker(ctx, db, client, pq, wq, _cfg(), w)
    w.close()
    assert [e["sha256"] for e in _drain(wq)] == [SHA_A]
    assert (tmp_path / "r.ndjson").read_text() == ""
    assert not ctx.counters.snapshot().get("malicious")
    db.close()
