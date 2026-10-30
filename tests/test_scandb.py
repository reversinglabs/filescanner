# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import os, filescanner as fs


def test_scandb_lifecycle(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 100)
    db.mark_submitted("aa", "http://h/api/tiscale/v1/task/1")
    assert db.in_flight() == 1
    rows = db.submitted_rows()
    assert rows == [{"sha256": "aa", "file_path": "E:\\a.exe",
                     "rel_path": "a.exe", "task_url": "http://h/api/tiscale/v1/task/1"}]
    db.claim_report("aa")          # mark_done only completes claimed rows
    db.mark_done("aa", "malicious", "Trojan.X", 5, {"tc_report": []})
    assert db.in_flight() == 0
    assert db.counts()["done"] == 1
    db.upsert_pending("bb", "E:\\b.exe", "b.exe", 5)
    db.mark_failed("bb", 503, "unavailable")
    assert db.counts()["failed"] == 1
    db.close()


def test_old_record_cleanup(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("old", "E:\\o.exe", "o.exe", 1)
    db._conn.execute(
        "UPDATE uploads SET created_at = datetime('now', '-30 days')")
    assert db.old_records(7) == 1
    assert db.delete_old_records(7) == 1
    assert db.old_records(7) == 0
    db.close()


def test_claim_report_exactly_once(tmp_path):
    """Two pollers racing on one row: exactly one wins the claim."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    assert db.claim_report("aa") is True    # first poller wins
    assert db.claim_report("aa") is False   # second loses
    assert db.in_flight() == 1              # 'reporting' is still in flight
    assert db.submitted_rows()              # reporting row still listed (deadline)
    db.mark_done("aa", "goodware", None, 1, None)   # reporting -> done
    assert db.in_flight() == 0
    db.close()


def test_unclaim_report_recovers_row(tmp_path):
    """Released claim returns to 'submitted' and can be claimed again."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    assert db.claim_report("aa") is True
    db.unclaim_report("aa")
    assert db.claim_report("aa") is True    # retry works
    db.close()


def test_mark_report_timeout_covers_reporting(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    db.claim_report("aa")
    db.mark_report_timeout("aa")
    assert db.counts()["timeout"] == 1
    db.close()


def test_reclaim_stale_reporting(tmp_path):
    """A 'reporting' row left by a killed run must become claimable again."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    db.claim_report("aa")
    db.reclaim_stale_reporting()         # simulate process restart
    assert db.claim_report("aa") is True
    db.close()


def test_mark_done_cannot_resurrect_timeout(tmp_path):
    """A claimed row that hit the deadline while the poller was mid-fetch must
    stay 'timeout' — a late report must not flip it back to done."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    assert db.claim_report("aa") is True
    db.mark_report_timeout("aa")                      # deadline won the race
    db.mark_done("aa", "malicious", "Trojan.X", 5, None)   # late report arrives
    assert db.counts().get("timeout") == 1
    assert db.counts().get("done") is None
    db.close()


def test_mark_done_requires_claim(tmp_path):
    """mark_done only completes a 'reporting' row — a bare 'submitted' row is
    not claimable by a late/dupe completion."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    db.mark_done("aa", "malicious", None, 5, None)    # unclaimed -> no-op
    assert db.in_flight() == 1
    assert db.counts().get("done") is None
    db.close()


def test_mark_failed_never_clobbers_live_or_done_rows(tmp_path):
    """A stray mark_failed (e.g. worker exception right after submit) must not
    hide an in-flight task or erase a recorded verdict."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    db.mark_failed("aa", 500, "worker_error: boom")   # just-submitted survives
    assert db.counts()["submitted"] == 1
    db.claim_report("aa")
    db.mark_failed("aa", 500, "worker_error: boom")   # claimed row survives
    assert db.counts()["reporting"] == 1
    db.mark_done("aa", "goodware", None, 1, None)
    db.mark_failed("aa", 500, "worker_error: boom")   # verdict survives
    assert db.counts()["done"] == 1
    db.upsert_pending("bb", "E:\\b.exe", "b.exe", 1)
    db.mark_failed("bb", 503, "unavailable")          # pending -> failed works
    assert db.counts()["failed"] == 1
    db.close()


def test_mark_submitted_clears_stale_verdict(tmp_path):
    """Rescanning a failed/done file must not leave the old verdict visible
    while the new task is in flight."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/old")
    db.claim_report("aa")
    db.mark_done("aa", "malicious", "Trojan.X", 5, '{"tc_report": []}')
    db.mark_submitted("aa", "https://h/t/new")        # resubmit (resume off)
    row = db.verdicts()[0]
    assert row["status"] == "submitted"
    assert db.submitted_rows()[0]["task_url"] == "https://h/t/new"
    assert row["classification"] is None
    assert row["threat_name"] is None
    assert row["threat_factor"] is None
    assert row["report_json"] is None
    db.close()


def test_stale_error_rows_only_counts_untouched_failures(tmp_path):
    """stale_error_rows sees prior-run failures, not rows reprocessed (fresh
    updated_at) or policy-skipped this run."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("old", "E:\\old.exe", "old.exe", 1)
    db.mark_failed("old", 503, "unavailable")
    db.upsert_pending("skip", "E:\\s.bin", "s.bin", 1)
    db.mark_failed("skip", None, "skipped_filetype:png")
    db._conn.execute("UPDATE uploads SET updated_at=datetime('now','-1 day')")
    now = db._q("SELECT datetime('now')", fetch="one")[0]
    assert db.stale_error_rows(now) == 1              # 'skip' row excluded
    db.upsert_pending("new", "E:\\n.bin", "n.bin", 1)
    db.mark_failed("new", 500, "fresh fail")          # touched this run
    assert db.stale_error_rows(now) == 1              # not double-counted
    db.close()


def test_upsert_pending_preserves_path_for_inflight(tmp_path):
    """An in-flight row keeps the path of the file actually submitted — a
    same-hash path seen later (remount or a second copy) is parked and
    serviced as a duplicate, so clobbering file_path here would orphan the
    in-flight task's owner path."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 100)
    db.mark_submitted("aa", "https://h/t/1")
    db.upsert_pending("aa", "F:\\a.exe", "a.exe", 200)  # same hash, new path
    row = db.submitted_rows()[0]
    assert row["file_path"] == "E:\\a.exe"
    assert row["rel_path"] == "a.exe"
    # status untouched — the in-flight submission is still live
    assert db.in_flight() == 1
    db.close()


def test_upsert_pending_updates_path_for_final_row(tmp_path):
    """A completed/cached row tracks the latest seen path — same-path resume
    detection and rerun actions compare against it."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 100)
    db.mark_done_direct("aa", "goodware", None, None, None, "fie")
    db.upsert_pending("aa", "F:\\a.exe", "a.exe", 200)
    row = db.verdicts()[0]
    assert row["file_path"] == "F:\\a.exe"
    assert row["classification"] == "goodware"
    db.close()


_OLD_SCHEMA = """
CREATE TABLE uploads(
    sha256 TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    file_size INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    task_url TEXT,
    http_status INTEGER,
    error TEXT,
    attempts INTEGER DEFAULT 0,
    classification TEXT,
    threat_name TEXT,
    threat_factor INTEGER,
    report_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    uploaded_at TEXT,
    report_fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_status ON uploads(status);
"""


def test_migration_adds_sha1_backend_preserving_rows(tmp_path):
    """Pre-multi-backend state DBs must open cleanly, gain sha1+backend
    columns, and keep every existing row — resume state is cross-run."""
    import sqlite3
    path = str(tmp_path / "s.db")
    conn = sqlite3.connect(path)
    conn.executescript(_OLD_SCHEMA)
    conn.execute("INSERT INTO uploads(sha256,file_path,rel_path,file_size,status,"
                 "task_url) VALUES('aa','E:\\a.exe','a.exe',1,'submitted','u1')")
    conn.commit()
    conn.close()
    db = fs.ScanDB(path)                       # migrates on open
    cols = {r[1] for r in db._q("PRAGMA table_info(uploads)", fetch="all")}
    assert {"sha1", "backend"} <= cols
    rows = db._q("SELECT sha256,status,task_url,backend FROM uploads",
                 fetch="all")
    assert rows == [("aa", "submitted", "u1", None)]  # NULL reads as 'detect'
    db.close()


def test_mark_done_direct_completes_pending_row(tmp_path):
    """FIE sync verdicts and reputation pre-check write 'done' straight from
    'pending' — there is no submit/claim round-trip to wait on."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_done_direct("aa", "malicious", "Trojan.X", 5, {"r": 1}, "fie")
    v = db.verdicts()[0]
    assert v["status"] == "done"
    assert v["classification"] == "malicious"
    assert v["threat_name"] == "Trojan.X"
    assert v["threat_factor"] == 5
    assert v["report_json"] == '{"r": 1}'
    row = db._q("SELECT backend FROM uploads WHERE sha256='aa'", fetch="one")
    assert row[0] == "fie"
    db.close()


def test_mark_done_direct_requires_pending(tmp_path):
    """A submitted/reporting row is a live async task owned by a poller — a
    direct verdict must not cut across the claim machinery."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    db.mark_done_direct("aa", "malicious", "T", 5, None, "fie")
    assert db.counts()["submitted"] == 1
    assert db.counts().get("done") is None
    db.close()


def test_reset_submitted_for_backend(tmp_path):
    """Rows in-flight under a different backend can never be polled by this
    one (receipt refs are backend-specific) — reset them to pending.
    Same-backend (incl. legacy NULL='detect') and terminal rows stay."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "f", "a", 1)
    db.mark_submitted("aa", "u1")
    db._q("UPDATE uploads SET backend='a1000' WHERE sha256='aa'")
    db.upsert_pending("bb", "f", "b", 1)
    db.mark_submitted("bb", "u2")            # backend NULL -> 'detect'
    db.upsert_pending("cc", "f", "c", 1)
    db.mark_submitted("cc", "u3")
    db.claim_report("cc")                    # 'reporting' also resets
    db._q("UPDATE uploads SET backend='fie' WHERE sha256='cc'")
    db.upsert_pending("dd", "f", "d", 1)
    db.mark_submitted("dd", "u4")
    db.claim_report("dd")
    db.mark_done("dd", "malicious", None, 5, None)
    db._q("UPDATE uploads SET backend='a1000' WHERE sha256='dd'")
    db.reset_submitted_for_backend("detect")
    c = db.counts()
    assert c.get("pending") == 2             # aa + cc
    assert c.get("submitted") == 1           # bb (NULL backend = detect)
    assert c.get("done") == 1                # dd is terminal — untouched
    row = db._q("SELECT task_url FROM uploads WHERE sha256='aa'", fetch="one")
    assert row[0] is None                    # stale receipt ref cleared
    db.close()
