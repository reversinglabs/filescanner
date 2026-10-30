# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT
"""regular-file-only walk, hidden-dir config, synchronous-verdict
requeue, persisted action columns, mark_cached updated_at."""
import errno
import io
import logging
import os
import stat
import sys
import textwrap
import threading
import types
from unittest.mock import MagicMock

import pytest

import filescanner as fs


# ---- A1 ---------------------------------------------------------------

def _one(db, sql, params=()):
    row = db._conn.execute(sql, params).fetchone()
    assert row is not None
    return row


def _all(db, sql, params=()):
    return db._conn.execute(sql, params).fetchall()


def _rels(root, **kw):
    return sorted(rel for _p, rel in fs.iter_work_items(str(root), None, **kw))


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_walk_skips_symlinks(tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.bin").write_bytes(b"x")
    os.symlink(outside, root / "link.bin")
    os.symlink(tmp_path, root / "dirlink")      # dir symlink: not followed
    assert _rels(root) == ["real.bin"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on Windows")
def test_walk_skips_fifo(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "real.bin").write_bytes(b"x")
    assert _rels(tmp_path) == ["real.bin"]


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_quarantine_copy_does_not_follow_symlink(tmp_path):
    import logging
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")
    link = tmp_path / "link.bin"
    os.symlink(target, link)
    qdir = tmp_path / "q"
    dest = fs.quarantine_file(str(link), "ab" * 32, "malicious", qdir, "copy",
                              logging.getLogger("t"))
    assert dest is None                  # non-regular source is refused


# ---- A2 ---------------------------------------------------------------

def test_hidden_dirs_scanned_by_default(tmp_path):
    (tmp_path / ".hid").mkdir()
    (tmp_path / ".hid" / "a.bin").write_bytes(b"x")
    (tmp_path / "b.bin").write_bytes(b"x")
    assert _rels(tmp_path) == [os.path.join(".hid", "a.bin"), "b.bin"]


def test_skip_hidden_dirs_true_skips(tmp_path):
    (tmp_path / ".hid").mkdir()
    (tmp_path / ".hid" / "a.bin").write_bytes(b"x")
    (tmp_path / "b.bin").write_bytes(b"x")
    assert _rels(tmp_path, skip_hidden_dirs=True) == ["b.bin"]


def _cfg(tmp_path, extra):
    p = tmp_path / "config.ini"
    p.write_text(textwrap.dedent("""
        [detect]
        host = https://d.example.com
        token = t
        [scan]
        drive = E:\\
        """) + extra)
    return fs.load_config(str(p))


def test_load_config_skip_hidden_dirs(tmp_path):
    assert _cfg(tmp_path, "").skip_hidden_dirs is False
    assert _cfg(tmp_path, "skip_hidden_dirs = true\n").skip_hidden_dirs is True


# ---- B1 ---------------------------------------------------------------

def test_upsert_pending_requeues_failed_and_timeout(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for sha, st in (("f", "failed"), ("t", "timeout")):
        db.upsert_pending(sha, "/a", "a", 1)
        db._q("UPDATE uploads SET status=?, error='boom', http_status=500 "
              "WHERE sha256=?", (st, sha))
        db.upsert_pending(sha, "/a", "a", 1)
        assert db.counts().get(st, 0) == 0
        row = _one(db, "SELECT status,error,http_status FROM uploads WHERE sha256=?", (sha,))
        assert row == ("pending", None, None)
    assert db.mark_done_direct("f", "malicious", "X", 5, None, "fie") == 1
    db.close()


def test_upsert_pending_keeps_inflight_and_done_with_resume(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for sha, st in (("s", "submitted"), ("r", "reporting"), ("d", "done"),
                    ("c", "cached")):
        db.upsert_pending(sha, "/a", "a", 1)
        db._q("UPDATE uploads SET status=? WHERE sha256=?", (st, sha))
        db.upsert_pending(sha, "/a", "a", 1)
        assert _one(db, "SELECT status FROM uploads WHERE sha256=?", (sha,))[0] == st
    db.close()


def test_upsert_pending_requeue_done_when_resume_off(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for sha, st in (("d", "done"), ("c", "cached"), ("s", "submitted")):
        db.upsert_pending(sha, "/a", "a", 1)
        db._q("UPDATE uploads SET status=? WHERE sha256=?", (st, sha))
        db.upsert_pending(sha, "/a", "a", 1, requeue_done=True)
    got = {r[0]: r[1] for r in _all(db, "SELECT sha256,status FROM uploads")}
    assert got == {"d": "pending", "c": "pending", "s": "submitted"}
    db.close()


# ---- B2 ---------------------------------------------------------------

def test_action_columns_in_schema_and_verdicts(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    cols = [r[1] for r in _all(db, "PRAGMA table_info(uploads)")]
    assert cols[-3:] == ["backend", "quarantined_to", "alerted"]
    db.upsert_pending("aa", "/a", "a", 1)
    assert db.verdicts()[0]["alerted"] is None
    db.mark_actions("aa", "/q/aa_a", True)
    v = db.verdicts()[0]
    assert v["quarantined_to"] == "/q/aa_a" and v["alerted"] == 1
    db.mark_actions("aa", None, False)
    v = db.verdicts()[0]
    assert v["quarantined_to"] is None and v["alerted"] == 0
    db.close()


def test_migration_adds_action_columns_to_old_db(tmp_path):
    import sqlite3
    p = str(tmp_path / "old.db")
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE uploads(sha256 TEXT PRIMARY KEY, file_path TEXT NOT NULL,"
              " rel_path TEXT NOT NULL, file_size INTEGER, status TEXT NOT NULL "
              "DEFAULT 'pending', task_url TEXT, http_status INTEGER, error TEXT,"
              " attempts INTEGER DEFAULT 0, classification TEXT, threat_name TEXT,"
              " threat_factor INTEGER, report_json TEXT, created_at TEXT, "
              "updated_at TEXT, uploaded_at TEXT, report_fetched_at TEXT, sha1 TEXT,"
              " backend TEXT)")
    c.commit()
    c.close()
    db = fs.ScanDB(p)
    cols = [r[1] for r in _all(db, "PRAGMA table_info(uploads)")]
    assert cols[-2:] == ["quarantined_to", "alerted"]
    db.close()


def test_verdict_actions_persist(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "/a", "a", 1)
    ctx = MagicMock()
    ctx.args = types.SimpleNamespace(quarantine_on=["malicious"],
                                     quarantine_action="copy")
    ctx.alerter.maybe_alert.return_value = True
    ctx._quarantine_lock = threading.Lock()
    rec = {"classification": "malicious", "sha256": "aa",
           "absolute_path": "/a"}
    orig = fs.quarantine_file
    fs.quarantine_file = lambda *a, **k: "/q/aa_a"
    try:
        fs._verdict_actions(ctx, db, rec)
    finally:
        fs.quarantine_file = orig
    v = db.verdicts()[0]
    assert v["quarantined_to"] == "/q/aa_a" and v["alerted"] == 1
    db.close()


# ---- B3 ---------------------------------------------------------------

def test_mark_cached_bumps_updated_at(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "/a", "a", 1)
    db._q("UPDATE uploads SET updated_at='2000-01-01 00:00:00'")
    db.mark_cached("aa")
    ts = _one(db, "SELECT updated_at FROM uploads")[0]
    assert ts > "2000-01-02"
    db.close()



def test_fie_failed_row_rescanned_persists_fresh_verdict(tmp_path):
    """Synchronous (FIE) backend: a prior 'failed' row must take the new
    verdict, run verdict actions, and not be counted CACHED."""
    import hashlib
    import queue
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ-failed-before")
    sha = hashlib.sha256(b"MZ-failed-before").hexdigest()
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending(sha, str(f), "a.exe", 16)
    db.mark_failed(sha, 500, "old")
    fie = MagicMock()
    fie.scan_file.return_value = (200, {
        "classification": "malicious",
        "threat_details": {"threat_name": "T.X", "scanner_match": 5}}, None)
    backend = fs.FieBackend(fie, mode="scan", trust_ok=False,
                            external_id="rel_path")
    from test_pipeline_backends import _scan_args
    args = _scan_args(tmp_path, tmp_path)
    ctx = fs.ScanContext(args, None, None, None, fs.Counters(),
                         fs.KeyedLocks(), None, MagicMock(), 0)
    q = queue.Queue()
    q.put((str(f), "a.exe"))
    q.put(None)
    w = MagicMock()
    t = threading.Thread(target=fs.upload_worker, args=(ctx, db, backend, q),
                         kwargs={"writer": w}, daemon=True)
    t.start()
    t.join(20)
    assert not t.is_alive()
    row = _one(db, "SELECT status,classification FROM uploads")
    assert row == ("done", "malicious")
    snap = ctx.counters.snapshot()
    assert snap.get("malicious") == 1 and not snap.get("cached")
    w.write.assert_called_once()
    assert db.verdicts()[0]["alerted"] == 0     # actions evaluated + persisted
    db.close()


# ---- R3 / M8: junctions pruned, non-regular entries counted ------------

def test_walk_prunes_junction_dirs(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "junc").mkdir(parents=True)
    (root / "junc" / "inside.bin").write_bytes(b"x")
    (root / "real.bin").write_bytes(b"x")
    junc = str(root / "junc")
    monkeypatch.setattr(fs.os.path, "isjunction",
                        lambda p: os.fspath(p) == junc, raising=False)
    assert _rels(root) == ["real.bin"]


def test_walk_prunes_reparse_point_dirs(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "rp").mkdir(parents=True)
    (root / "rp" / "inside.bin").write_bytes(b"x")
    (root / "real.bin").write_bytes(b"x")
    rp = str(root / "rp")
    real_lstat = os.lstat

    class _St:
        def __init__(self, st):
            self._st = st
            self.st_mode = st.st_mode
            self.st_file_attributes = 0x400   # FILE_ATTRIBUTE_REPARSE_POINT

    def fake_lstat(p, *a, **k):
        st = real_lstat(p, *a, **k)
        return _St(st) if os.fspath(p) == rp else st

    monkeypatch.setattr(fs.os, "lstat", fake_lstat)
    monkeypatch.setattr(fs.os.path, "isjunction", lambda p: False,
                        raising=False)
    assert _rels(root) == ["real.bin"]


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_walk_skip_summary_counts_files_and_dirs(tmp_path, caplog):
    import logging
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.bin").write_bytes(b"x")
    os.symlink(tmp_path, root / "dirlink")
    os.symlink(root / "real.bin", root / "filelink.bin")
    with caplog.at_level(logging.INFO):
        assert _rels(root) == ["real.bin"]
    msgs = [r.getMessage() for r in caplog.records]
    assert ("Skipped 2 non-regular entries (symlinks, junctions, devices, "
            "FIFOs)") in msgs


# ---- M5 / M6: open_regular TOCTOU guard ---------------------------------

def test_open_regular_reads_regular_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"data")
    with fs.open_regular(str(p)) as f:
        assert f.read() == b"data"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_open_regular_refuses_symlink(tmp_path):
    target = tmp_path / "t.bin"
    target.write_bytes(b"secret")
    link = tmp_path / "l.bin"
    os.symlink(target, link)
    with pytest.raises(OSError):
        fs.open_regular(str(link))


def test_open_regular_refuses_directory(tmp_path):
    with pytest.raises(OSError):
        fs.open_regular(str(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_hash_refuses_swapped_symlink(tmp_path):
    target = tmp_path / "t.bin"
    target.write_bytes(b"secret")
    link = tmp_path / "l.bin"
    os.symlink(target, link)
    sha256, _sha1, _head, _n = fs.read_hash_capture(str(link), 0)
    assert sha256 == ""


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_read_gate_does_not_read_symlink(tmp_path):
    target = tmp_path / "t.bin"
    target.write_bytes(b"x" * 4096)
    link = tmp_path / "l.bin"
    os.symlink(target, link)
    args = types.SimpleNamespace(read_speed_test="always", min_read_mbps=0,
                                 read_test_max_bytes=1 << 20,
                                 read_test_max_seconds=5)
    log = MagicMock()
    fs.disk_read_gate(args, [(str(link), "l.bin")], log)
    msg = log.info.call_args[0]
    assert msg[1] == 0                   # zero bytes read through the link


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
@pytest.mark.parametrize("action", ["copy", "move"])
def test_quarantine_refuses_symlink_source(tmp_path, action):
    import logging
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")
    link = tmp_path / "link.bin"
    os.symlink(target, link)
    qdir = tmp_path / "q"
    dest = fs.quarantine_file(str(link), "ab" * 32, "malicious", qdir, action,
                              logging.getLogger("t"))
    assert dest is None
    assert not qdir.exists() or not list(qdir.iterdir())
    assert os.path.islink(link) and target.read_bytes() == b"secret"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_upload_body_refuses_symlink(tmp_path):
    target = tmp_path / "t.bin"
    target.write_bytes(b"secret")
    link = tmp_path / "l.bin"
    os.symlink(target, link)
    c = fs.FieClient("http://127.0.0.1:9")
    sess = MagicMock()
    c._sess = lambda: sess
    c.scan_file(str(link))
    sess.post.assert_not_called()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_walk_skip_summary_counts_filtered_out_entries(tmp_path, caplog):
    import logging
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.exe").write_bytes(b"x")
    os.symlink(root / "real.exe", root / "link.txt")   # dropped by filter
    with caplog.at_level(logging.INFO):
        got = sorted(r for _p, r in fs.iter_work_items(str(root), {".exe"}))
    assert got == ["real.exe"]
    assert ("Skipped 1 non-regular entries (symlinks, junctions, devices, "
            "FIFOs)") in [r.getMessage() for r in caplog.records]


def test_open_regular_without_nofollow_lstats_first(tmp_path, monkeypatch):
    monkeypatch.delattr(fs.os, "O_NOFOLLOW", raising=False)
    p = tmp_path / "f.bin"
    p.write_bytes(b"d")
    with fs.open_regular(str(p)) as f:
        assert f.read() == b"d"
    if sys.platform != "win32":
        os.symlink(p, tmp_path / "l.bin")
        with pytest.raises(OSError):
            fs.open_regular(str(tmp_path / "l.bin"))


# ---- Windows reparse FILES (Python: tag 0 / dedup scanned; others skipped) --

class _FakeSt:
    def __init__(self, st, tag):
        self.st_mode = st.st_mode
        self.st_file_attributes = 0x400 if tag is not None else 0
        if tag is not None:
            self.st_reparse_tag = tag


def _patch_lstat(monkeypatch, target, tag):
    real = os.lstat

    def fake(p, *a, **k):
        st = real(p, *a, **k)
        return _FakeSt(st, tag) if os.fspath(p) == target else st

    monkeypatch.setattr(fs.os, "lstat", fake)


@pytest.mark.parametrize("tag,kept", [(0, True),
                                      (0x80000013, True),
                                      (0x9000001A, False),
                                      (0xA000000C, False)])
def test_walk_reparse_file_tags(tmp_path, monkeypatch, tag, kept):
    (tmp_path / "real.bin").write_bytes(b"x")
    (tmp_path / "rp.bin").write_bytes(b"x")
    _patch_lstat(monkeypatch, str(tmp_path / "rp.bin"), tag)
    got = _rels(tmp_path)
    assert got == (["real.bin", "rp.bin"] if kept else ["real.bin"])


@pytest.mark.parametrize("tag,ok", [(0, True),
                                    (0x80000013, True),
                                    (0x9000001A, False),
                                    (0xA000000C, False)])
def test_open_regular_fallback_reparse_tags(tmp_path, monkeypatch, tag, ok):
    monkeypatch.delattr(fs.os, "O_NOFOLLOW", raising=False)
    p = tmp_path / "f.bin"
    p.write_bytes(b"d")
    _patch_lstat(monkeypatch, str(p), tag)
    if ok:
        with fs.open_regular(str(p)) as f:
            assert f.read() == b"d"
    else:
        with pytest.raises(OSError):
            fs.open_regular(str(p))


# ---- quarantine move: rename, EXDEV fallback copy+unlink ----------------

def test_quarantine_move_exdev_copies_and_unlinks(tmp_path, monkeypatch):
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"

    def boom(a, b):
        raise OSError(18, "Invalid cross-device link")

    monkeypatch.setattr(fs.os, "rename", boom)
    monkeypatch.setattr(fs.shutil, "move", lambda *a, **k: pytest.fail("shutil.move"))
    dest = fs.quarantine_file(str(src), "ab" * 32, "malicious", qdir, "move",
                              logging.getLogger("t"))
    assert dest and open(dest, "rb").read() == b"payload"
    assert not src.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_quarantine_move_exdev_refuses_symlink(tmp_path, monkeypatch):
    import errno
    import logging
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"

    def swap_then_xdev(a, b):
        # TOCTOU: source swapped for a symlink right before the fallback.
        os.unlink(a)
        os.symlink(outside, a)
        raise OSError(errno.EXDEV, "xdev")

    monkeypatch.setattr(fs.os, "rename", swap_then_xdev)
    assert fs.quarantine_file(str(src), "ab" * 32, "m", qdir, "move",
                              logging.getLogger("t")) is None
    assert outside.read_bytes() == b"secret"
    assert os.path.islink(src)
    assert not qdir.exists() or list(qdir.iterdir()) == []


# ---- partial copy cleanup -----------------------------------------------

def _failing_copyfileobj(src, dst, *a, **k):
    dst.write(b"part")
    dst.flush()
    raise OSError(28, "No space left on device")


@pytest.mark.parametrize("action", ["copy", "move"])
def test_quarantine_partial_copy_removed(tmp_path, monkeypatch, action):
    import errno
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"
    if action == "move":
        def xdev(a, b):
            raise OSError(errno.EXDEV, "xdev")
        monkeypatch.setattr(fs.os, "rename", xdev)
    monkeypatch.setattr(fs.shutil, "copyfileobj", _failing_copyfileobj)
    assert fs.quarantine_file(str(src), "ab" * 32, "m", qdir, action,
                              logging.getLogger("t")) is None
    assert src.read_bytes() == b"payload"
    assert list(qdir.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
@pytest.mark.parametrize("action", ["copy", "move"])
def test_quarantine_strips_setuid_and_exec(tmp_path, monkeypatch, action):
    import errno
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    os.chmod(src, 0o4755)
    if action == "move":
        def xdev(a, b):
            raise OSError(errno.EXDEV, "xdev")
        monkeypatch.setattr(fs.os, "rename", xdev)
    dest = fs.quarantine_file(str(src), "ab" * 32, "m", tmp_path / "q", action,
                              logging.getLogger("t"))
    assert dest
    mode = stat.S_IMODE(os.stat(dest).st_mode)
    assert not mode & 0o7000 and not mode & 0o111 and (mode & ~0o644) == 0


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="setuid semantics differ as root")
def test_quarantine_move_rename_strips_setuid(tmp_path):
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    os.chmod(src, 0o4755)
    # No monkeypatch: the same-fs os.rename fast path must not carry the
    # privileged bits into quarantine (it keeps owner perms, incl. exec).
    dest = fs.quarantine_file(str(src), "ab" * 32, "m", tmp_path / "q",
                              "move", logging.getLogger("t"))
    assert dest
    mode = stat.S_IMODE(os.stat(dest).st_mode)
    assert mode == 0o755 and not mode & 0o7000
    assert not src.exists()


class _CloseFails(io.BufferedWriter):
    def close(self):
        try:
            super().close()
        finally:
            raise OSError(errno.ENOSPC, "No space left on device")


@pytest.mark.parametrize("action", ["copy", "move"])
def test_quarantine_close_failure_removes_partial(tmp_path, monkeypatch, action):
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"
    real_fdopen = os.fdopen

    def fake_fdopen(fd, mode="r", *a, **k):
        if mode == "wb":  # _copy_verified's dest; source opens use "rb"
            return _CloseFails(real_fdopen(fd, "wb", buffering=0))
        return real_fdopen(fd, mode, *a, **k)

    if action == "move":
        def xdev(a, b):
            raise OSError(errno.EXDEV, "xdev")
        monkeypatch.setattr(fs.os, "rename", xdev)
    monkeypatch.setattr(fs.os, "fdopen", fake_fdopen)
    assert fs.quarantine_file(str(src), "ab" * 32, "m", qdir, action,
                              logging.getLogger("t")) is None
    assert list(qdir.iterdir()) == []
    assert src.read_bytes() == b"payload"


def test_copy_verified_never_touches_preexisting_dest(tmp_path):
    s = tmp_path / "s"
    s.write_bytes(b"new")
    d = tmp_path / "d"
    d.write_bytes(b"old")
    link = tmp_path / "l"
    os.symlink(tmp_path / "nowhere", link)
    for dest in (d, link):
        with pytest.raises(FileExistsError):
            fs._copy_verified(str(s), dest)
    assert d.read_bytes() == b"old" and os.path.islink(link)
    assert not (tmp_path / "nowhere").exists()


@pytest.mark.parametrize("action", ["copy", "move"])
def test_quarantine_preserves_atime_and_mtime(tmp_path, monkeypatch, action):
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    # Distinct atime/mtime: equal values would mask an atime regression.
    os.utime(src, (1_400_000_000, 1_500_000_000))
    if action == "move":
        def xdev(a, b):
            raise OSError(errno.EXDEV, "xdev")
        monkeypatch.setattr(fs.os, "rename", xdev)
    dest = fs.quarantine_file(str(src), "ab" * 32, "m", tmp_path / "q", action,
                              logging.getLogger("t"))
    assert dest and abs(os.stat(dest).st_mtime - 1_500_000_000) < 1
    assert abs(os.stat(dest).st_atime - 1_400_000_000) < 1


def test_quarantine_leftover_truncated_dest_keeps_source(tmp_path):
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"
    qdir.mkdir()
    left = qdir / ("ab" * 8 + "_s.bin")
    left.write_bytes(b"pay")
    for action in ("move", "copy"):
        assert fs.quarantine_file(str(src), "ab" * 32, "m", qdir, action,
                                  logging.getLogger("t")) is None
        assert src.read_bytes() == b"payload"
        assert left.read_bytes() == b"pay"


def test_quarantine_equal_size_dest_move_removes_source(tmp_path):
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"
    qdir.mkdir()
    (qdir / ("ab" * 8 + "_s.bin")).write_bytes(b"payload")
    assert fs.quarantine_file(str(src), "ab" * 32, "m", qdir, "move",
                              logging.getLogger("t"))
    assert not src.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_quarantine_symlink_at_dest_is_not_a_duplicate(tmp_path):
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    other = tmp_path / "other.bin"
    other.write_bytes(b"payloa2")  # same size, different content
    qdir = tmp_path / "q"
    qdir.mkdir()
    link = qdir / ("ab" * 8 + "_s.bin")
    os.symlink(other, link)
    assert fs.quarantine_file(str(src), "ab" * 32, "m", qdir, "move",
                              logging.getLogger("t")) is None
    assert src.read_bytes() == b"payload"
    assert os.path.islink(link)
    assert other.read_bytes() == b"payloa2"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
@pytest.mark.parametrize("action", ["copy", "move"])
def test_quarantine_dest_mode_respects_umask(tmp_path, monkeypatch, action):
    import errno
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    os.chmod(src, 0o644)
    if action == "move":
        def xdev(a, b):
            raise OSError(errno.EXDEV, "xdev")
        monkeypatch.setattr(fs.os, "rename", xdev)
    old = os.umask(0o077)
    try:
        dest = fs.quarantine_file(str(src), "ab" * 32, "m", tmp_path / "q",
                                  action, logging.getLogger("t"))
    finally:
        os.umask(old)
    assert dest and stat.S_IMODE(os.stat(dest).st_mode) == 0o600


# ---- Windows read-only source delete -------------------------------------

@pytest.mark.parametrize("action", ["fallback", "duplicate"])
def test_quarantine_windows_readonly_delete_retries(tmp_path, monkeypatch, action):
    import errno
    import logging
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    qdir = tmp_path / "q"
    real_unlink = os.unlink
    calls = []

    def xdev(a, b):
        raise OSError(errno.EXDEV, "xdev")

    def flaky(p, *a, **k):
        if os.fspath(p) == str(src) and not calls:
            calls.append(p)
            raise PermissionError(13, "read-only")
        return real_unlink(p, *a, **k)

    if action == "fallback":
        monkeypatch.setattr(fs.os, "rename", xdev)
    else:  # identical file already quarantined: source is just removed
        qdir.mkdir()
        (qdir / ("ab" * 8 + "_s.bin")).write_bytes(b"payload")
    monkeypatch.setattr(fs.os, "unlink", flaky)
    monkeypatch.setattr(fs.os, "name", "nt")
    fs.quarantine_file(str(src), "ab" * 32, "m", qdir, "move",
                       logging.getLogger("t"))
    assert calls and not src.exists()


# ---- updated_at untouched by resets/actions -----------------------------

def test_resets_and_actions_keep_updated_at(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    for s in ("rep", "oth", "act"):
        db.upsert_pending(s, "/" + s, s, 1)
    db.mark_submitted("rep", "t1", "detect")
    db.claim_report("rep")
    db.mark_submitted("oth", "t2", "a1000")
    db._conn.execute("UPDATE uploads SET updated_at='2000-01-01 00:00:00'")
    db.reclaim_stale_reporting()
    db.reset_submitted_for_backend("detect")
    db.mark_actions("act", "/q/act", True)
    st = {r["sha256"]: r["status"] for r in db.verdicts()}
    assert st["rep"] == "submitted" and st["oth"] == "pending"
    assert db.verdicts(since="2001-01-01 00:00:00") == []
    db.close()
