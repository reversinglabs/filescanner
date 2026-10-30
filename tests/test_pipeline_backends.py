# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""End-to-end pipeline coverage for the multi-backend dispatch (bead
filescanner-1zq): FIE synchronous verdicts through upload_worker with no
poller phase, A1000 submit/status/classification through result_poller,
Cloud two-step sha1 upload + reputation poll, the reputation pre-check
handoff (classified -> done, unknown -> upload), the cross-backend startup
reset, and Detect's unchanged legacy record shape.

Every test drives the real run_scan / upload_worker / result_poller with a
mocked *Client class — the backend adapters are exercised for real, only
the wire is faked.
"""
import hashlib
import os
import queue
import types

import pytest

import filescanner as fs
from unittest.mock import MagicMock


def _scan_args(drive, out, **over):
    """Full args namespace for run_scan incl. all backend config fields."""
    a = types.SimpleNamespace(
        drive=str(drive), host="https://h", token="tok", proxy=None,
        no_verify_ssl=True,
        db_path="scan_state.db", retention_days=7, cleanup_old_records="never",
        store_full_report=False,
        upload_workers=2, result_pollers=1, result_poll_interval=0,
        report_wait_hours=1, max_in_flight=0,
        backoff_base_seconds=0, backoff_max_seconds=0, upload_retry_window=5,
        max_upload_attempts=1, ready_check_interval=0, ready_max_wait=1,
        resume=True, file_types=set(), detect_file_type=False,
        read_speed_test="ask", min_read_mbps=0,
        read_test_max_bytes=4096, read_test_max_seconds=5,
        extract_strings=False, extract_iocs=False, min_string_len=6,
        max_strings=10, max_iocs=10, max_enrich_bytes=1024,
        large_file_threshold=1 << 30,
        analysis_depth="full", workers=2,
        quarantine_action="none", quarantine_dir=None, quarantine_on=set(),
        alert_on=set(), alert_webhook=None, alert_syslog=None,
        alert_eventlog=False,
        summary_only=False, verbose=False,
        # -- multi-backend + precheck config -------------------------------
        backend="detect",
        fie_host="", fie_mode="hash_then_scan", fie_trust_ok=False,
        fie_external_id="rel_path",
        a1000_host="", a1000_token="", a1000_analysis="", a1000_tags="",
        a1000_comment="", a1000_archive_password="",
        a1000_sandbox_platform="", a1000_report_detail="summary",
        ticloud_host="", ticloud_username="", ticloud_password="",
        ticloud_domain="", ticloud_archive_password="",
        ticloud_upload_timeout=30, ticloud_min_interval_ms=0,
        ticloud_extended=True,
        reputation_precheck=False, reputation_batch_size=100,
        reputation_skip_classified=True,
        avail_probe_seconds=0, progress_every=100,
    )
    for k, v in over.items():
        setattr(a, k, v)
    return a


def _hashes(path):
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    h256.update(path.read_bytes())
    h1.update(path.read_bytes())
    return h256.hexdigest(), h1.hexdigest()


def _drive(tmp_path, names=("a.exe",)):
    drive = tmp_path / "drive"
    drive.mkdir(exist_ok=True)
    for i, n in enumerate(names):
        f = drive / n
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"MZ-" + n.encode())
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return drive, out


def _db_row(db, sha256):
    return db._q("SELECT status, classification, threat_name, "
                 "threat_factor, task_url, backend, sha1 FROM uploads "
                 "WHERE sha256=?", (sha256,), fetch="one")


def _ndjson(out):
    """Per-result records as the workers/pollers wrote them (the report
    `results` list is DB-projected and intentionally drops backend/ref —
    the NDJSON stream is where the full record lives)."""
    import json as _json
    p = out / "scan_results.ndjson"
    if not p.exists():
        return []
    return [_json.loads(l) for l in p.read_text().splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# FIE — synchronous verdict on submit; no poller may ever spawn.
# ---------------------------------------------------------------------------

def test_fie_end_to_end_sync_done_no_poller(tmp_path, monkeypatch):
    """backend=fie: check_hash returns a verdict on submit -> the row goes
    pending -> done inside the upload worker and run_scan spawns zero
    result pollers."""
    drive, out = _drive(tmp_path)
    sha256, sha1 = _hashes(drive / "a.exe")

    fie = MagicMock()
    fie.probe.return_value = True
    fie.wait_ready.return_value = True
    fie.available_now.return_value = True
    fie.check_hash.return_value = (200, {
        "classification": "malicious",
        "threat_details": {"threat_name": "Win32.Evil",
                           "scanner_match": 37}}, None)
    monkeypatch.setattr(fs, "FieClient", lambda **kw: fie)
    poller_spy = MagicMock()
    monkeypatch.setattr(fs, "result_poller", poller_spy)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    args = _scan_args(drive, out, backend="fie",
                      fie_host="https://fie", fie_mode="hash_then_scan")
    output = fs.run_scan(args, None, out, MagicMock())

    poller_spy.assert_not_called()          # sync backend -> no poll phase
    assert fie.scan_file.call_count == 0    # check_hash verdict — no /scan
    fie.check_hash.assert_called_once_with(sha1)
    assert output["summary"]["files_completed_successfully"] == 1

    db = fs.ScanDB(str(out / "scan_state.db"))
    assert db.counts() == {"done": 1}
    status, cls, threat, factor, task_url, backend, db_sha1 = _db_row(
        db, sha256)
    assert (status, cls, threat, factor) == ("done", "malicious",
                                             "Win32.Evil", 37)
    assert backend == "fie"
    assert db_sha1 == sha1                  # needs_sha1 -> sha1 persisted
    db.close()

    rec = [r for r in _ndjson(out) if r["sha256"] == sha256][0]
    assert rec["backend"] == "fie"
    assert rec["api"]["status"] == "completed"


def test_fie_upload_worker_scan_mode_uses_rel_path_external_id(tmp_path):
    """meta['rel_path'] must reach FieBackend — external_id mode 'rel_path'
    resolves to the scan-root-relative path, not the basename."""
    drive, out = _drive(tmp_path, names=("sub/b.exe",))
    (drive / "sub").mkdir(exist_ok=True)
    (drive / "sub" / "b.exe").write_bytes(b"MZ-sub")
    f = drive / "sub" / "b.exe"

    fie = MagicMock()
    fie.available_now.return_value = True
    fie.scan_file.return_value = (200, {
        "classification": "suspicious",
        "threat_details": {"threat_name": "PUA.X", "scanner_match": 2}}, None)
    backend = fs.FieBackend(fie, mode="scan", trust_ok=False,
                            external_id="rel_path")

    db = fs.ScanDB(str(out / "scan_state.db"))
    ctx = fs.ScanContext(_scan_args(drive, out), None, None, None,
                         fs.Counters(), fs.KeyedLocks(), None, MagicMock(), 0)
    wq = queue.Queue()
    wq.put((str(f), os.path.relpath(str(f), str(drive))))
    wq.put(None)
    fs.upload_worker(ctx, db, backend, wq, writer=MagicMock())

    assert fie.scan_file.call_count == 1
    pos, kw = fie.scan_file.call_args
    external_id = kw.get("external_id") if "external_id" in kw else (
        pos[1] if len(pos) > 1 else None)
    assert external_id == os.path.join("sub", "b.exe")
    sha256, _ = _hashes(f)
    row = _db_row(db, sha256)
    assert row[0] == "done" and row[1] == "suspicious" and row[5] == "fie"
    db.close()


def test_fie_prehashed_item_skips_rehash(tmp_path):
    """A precheck-style prehashed dict must go straight to submit — the
    worker may not re-read the file (delete it after feeding to prove it)."""
    f = tmp_path / "c.exe"
    f.write_bytes(b"MZ-c")
    sha256, sha1 = _hashes(f)
    content_path = str(f)

    fie = MagicMock()
    fie.available_now.return_value = True
    fie.check_hash.return_value = (200, {
        "classification": "malicious",
        "threat_details": {"threat_name": "X", "scanner_match": 1}}, None)
    backend = fs.FieBackend(fie, mode="hash_only")

    db = fs.ScanDB(str(tmp_path / "s.db"))
    ctx = fs.ScanContext(_scan_args(tmp_path, tmp_path), None, None, None,
                         fs.Counters(), fs.KeyedLocks(), None, MagicMock(), 0)
    wq = queue.Queue()
    wq.put({"sha256": sha256, "sha1": sha1, "filepath": content_path,
            "rel_path": "c.exe", "size": 4, "head": b"MZ-c",
            "prehashed": True})
    wq.put(None)
    f.unlink()                      # re-read would crash the worker
    fs.upload_worker(ctx, db, backend, wq)

    fie.check_hash.assert_called_once_with(sha1)
    row = _db_row(db, sha256)
    assert row[0] == "done" and row[1] == "malicious" and row[6] == sha1
    db.close()


# ---------------------------------------------------------------------------
# A1000 — async: submit -> sha1 receipt -> status_bulk -> classification.
# ---------------------------------------------------------------------------

def test_a1000_end_to_end_submit_poll_done(tmp_path, monkeypatch):
    drive, out = _drive(tmp_path)
    sha256, _sha1 = _hashes(drive / "a.exe")
    receipt = "a1" * 20                                   # a1000's sha1

    a1 = MagicMock()
    a1.probe_status.return_value = 200
    a1.probe.return_value = True
    a1.wait_ready.return_value = True
    a1.available_now.return_value = True
    a1.upload.return_value = (201, receipt, None)
    a1.status_bulk.return_value = (200, {sha256: "processed"}, None)
    a1.classification.return_value = (200, {
        "classification": "MALICIOUS",
        "classification_result": "Trojan.X",
        "riskscore": 8}, None)
    monkeypatch.setattr(fs, "A1000Client", lambda **kw: a1)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    args = _scan_args(drive, out, backend="a1000",
                      a1000_host="https://a1", a1000_token="t",
                      a1000_report_detail="summary")
    output = fs.run_scan(args, None, out, MagicMock())

    assert output["summary"]["files_completed_successfully"] == 1
    a1.upload.assert_called_once()
    a1.status_bulk.assert_called_with([sha256])
    a1.classification.assert_called_with(sha256)

    db = fs.ScanDB(str(out / "scan_state.db"))
    assert db.counts() == {"done": 1}
    status, cls, threat, factor, task_url, backend, _s = _db_row(db, sha256)
    assert (status, cls) == ("done", "malicious")
    assert task_url == receipt            # a1000 receipt is its sha1
    assert backend == "a1000"
    db.close()
    rec = _ndjson(out)[0]
    assert rec["backend"] == "a1000" and rec["task_url"] == receipt


def test_a1000_auth_failure_aborts_exit2(tmp_path, monkeypatch):
    """401/403 at the startup probe must exit(2) before any file is fed —
    a bad token can never degrade into per-file upload failures."""
    drive, out = _drive(tmp_path)
    a1 = MagicMock()
    a1.probe_status.return_value = 403
    monkeypatch.setattr(fs, "A1000Client", lambda **kw: a1)
    args = _scan_args(drive, out, backend="a1000",
                      a1000_host="https://a1", a1000_token="bad")
    with pytest.raises(SystemExit) as ei:
        fs.run_scan(args, None, out, MagicMock())
    assert ei.value.code == 2
    a1.upload.assert_not_called()


# ---------------------------------------------------------------------------
# Cloud — async: spex two-step -> sha1 receipt -> TCA-0101 reputation poll.
# ---------------------------------------------------------------------------

def test_cloud_two_step_upload_poll_done(tmp_path, monkeypatch):
    drive, out = _drive(tmp_path)
    sha256, sha1 = _hashes(drive / "a.exe")

    tc = MagicMock()
    tc.probe_status.return_value = 200
    tc.probe.return_value = True
    tc.wait_ready.return_value = True
    tc.available_now.return_value = True
    tc.submit_sample.return_value = (200, True, None)
    tc.reputation_bulk.side_effect = (
        lambda hashes, hash_type="sha256", timeout=30:
            (200, ([{"status": "MALICIOUS", "sha1": hashes[0],
                     "threat_name": "Win32.Trojan", "threat_level": 9}],
                   []), None))
    monkeypatch.setattr(fs, "TiCloudClient", lambda **kw: tc)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    args = _scan_args(drive, out, backend="cloud",
                      ticloud_host="https://tc", ticloud_username="u",
                      ticloud_password="p")
    output = fs.run_scan(args, None, out, MagicMock())

    assert output["summary"]["files_completed_successfully"] == 1
    tc.submit_sample.assert_called_once()
    # Poll must be by sha1 — the receipt ref IS the sha1.
    tc.reputation_bulk.assert_called_with([sha1.lower()], hash_type="sha1")

    db = fs.ScanDB(str(out / "scan_state.db"))
    assert db.counts() == {"done": 1}
    status, cls, threat, factor, task_url, backend, db_sha1 = _db_row(
        db, sha256)
    assert (status, cls, threat, factor) == ("done", "malicious",
                                             "Win32.Trojan", 9)
    assert task_url == sha1.lower()       # cloud ref == sha1
    assert backend == "cloud"
    assert db_sha1 == sha1                # needs_sha1 persisted
    db.close()
    assert _ndjson(out)[0]["backend"] == "cloud"


# ---------------------------------------------------------------------------
# Reputation pre-check — classified short-circuits, unknown goes to upload.
# ---------------------------------------------------------------------------

def test_precheck_classified_done_unknown_uploads(tmp_path, monkeypatch):
    drive, out = _drive(tmp_path, names=("known.exe", "new.exe"))
    s256_known, _ = _hashes(drive / "known.exe")
    s256_new, _ = _hashes(drive / "new.exe")

    det = MagicMock()
    det.is_ready.return_value = True
    det.wait_ready.return_value = True
    det.available_now.return_value = True
    det.upload_with_backoff.side_effect = (
        lambda filepath, custom, cfg, log=None:
            ("https://h/task/x", 201, None, 1))
    det.task_status.return_value = {
        "processed": 1729000000,
        "tc_report": [{"classification": {"classification": 1,
                                          "result": "clean",
                                          "factor": 0}}]}
    monkeypatch.setattr(fs, "DetectAsyncClient", lambda **kw: det)

    tc = MagicMock()
    tc.probe_status.return_value = 200
    tc.wait_ready.return_value = True
    tc.available_now.return_value = True
    tc.reputation_bulk.side_effect = (
        lambda hashes, hash_type="sha256", timeout=30:
            (200, ([{"status": "MALICIOUS", "sha256": h,
                     "threat_name": "Known.Bad", "threat_level": 7}
                    for h in hashes if h == s256_known],
                   []), None))
    monkeypatch.setattr(fs, "TiCloudClient", lambda **kw: tc)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    args = _scan_args(drive, out, backend="detect",
                      reputation_precheck=True,
                      ticloud_host="https://tc", ticloud_username="u",
                      ticloud_password="p")
    output = fs.run_scan(args, None, out, MagicMock())

    # known.exe: verdict at precheck — never hits Detect upload.
    # new.exe: no reputation entry -> re-enqueued -> detect upload + poll.
    assert det.upload_with_backoff.call_count == 1
    assert output["summary"]["files_completed_successfully"] == 2

    db = fs.ScanDB(str(out / "scan_state.db"))
    assert db.counts() == {"done": 2}
    r_known = _db_row(db, s256_known)
    assert r_known[0] == "done" and r_known[1] == "malicious"
    assert r_known[2] == "Known.Bad" and r_known[5] == "ticloud"
    r_new = _db_row(db, s256_new)
    assert r_new[0] == "done" and r_new[1] == "goodware"
    assert r_new[5] in (None, "detect")   # legacy detect rows need no stamp
    db.close()


def test_precheck_bad_credentials_aborts_exit2(tmp_path, monkeypatch):
    """reputation.precheck=true with rejected ticloud creds must fail fast
    (exit 2) — never silently skip the stage."""
    drive, out = _drive(tmp_path)
    det = MagicMock()
    det.wait_ready.return_value = True
    monkeypatch.setattr(fs, "DetectAsyncClient", lambda **kw: det)
    tc = MagicMock()
    tc.probe_status.return_value = 401
    monkeypatch.setattr(fs, "TiCloudClient", lambda **kw: tc)
    args = _scan_args(drive, out, reputation_precheck=True,
                      ticloud_host="https://tc", ticloud_username="u",
                      ticloud_password="bad")
    with pytest.raises(SystemExit) as ei:
        fs.run_scan(args, None, out, MagicMock())
    assert ei.value.code == 2


# ---------------------------------------------------------------------------
# Cross-backend startup reset — in-flight rows owned by another backend go
# back to 'pending'; same-backend (incl. legacy NULL=detect) rows resume.
# ---------------------------------------------------------------------------

def test_run_scan_resets_foreign_backend_inflight_rows(tmp_path, monkeypatch):
    drive, out = _drive(tmp_path)
    db = fs.ScanDB(str(out / "scan_state.db"))
    # a1000-owned in-flight rows — a detect run can never poll these refs.
    db.upsert_pending("f1", "E:\\f1.exe", "f1.exe", 9)
    db.mark_submitted("f1", "a1" * 20, "a1000")
    db.upsert_pending("f2", "E:\\f2.exe", "f2.exe", 9)
    db.mark_submitted("f2", "b2" * 20, "fie")
    db.claim_report("f2")                 # 'reporting' resets too
    # Legacy NULL-backend submitted row reads as detect — must resume.
    db.upsert_pending("f3", "E:\\f3.exe", "f3.exe", 9)
    db.mark_submitted("f3", "https://h/task/f3")
    # A done row must never be touched.
    db.upsert_pending("f4", "E:\\f4.exe", "f4.exe", 9)
    db.mark_done_direct("f4", "malicious", "X", 9, None, "fie")
    db.close()

    det = MagicMock()
    det.is_ready.return_value = True
    det.wait_ready.return_value = True
    det.available_now.return_value = True
    det.upload_with_backoff.side_effect = (
        lambda filepath, custom, cfg, log=None:
            ("https://h/task/y", 201, None, 1))
    det.task_status.return_value = {
        "processed": 1729000000,
        "tc_report": [{"classification": {"classification": 3,
                                          "result": "T", "factor": 8}}]}
    monkeypatch.setattr(fs, "DetectAsyncClient", lambda **kw: det)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    fs.run_scan(_scan_args(drive, out), None, out, MagicMock())

    db = fs.ScanDB(str(out / "scan_state.db"))
    r1 = db._q("SELECT status, task_url FROM uploads WHERE sha256='f1'",
               fetch="one")
    r2 = db._q("SELECT status, task_url FROM uploads WHERE sha256='f2'",
               fetch="one")
    assert r1 == ("pending", None)        # foreign receipt handed back
    assert r2 == ("pending", None)        # 'reporting' resets too
    r3 = db._q("SELECT status FROM uploads WHERE sha256='f3'", fetch="one")
    assert r3 == ("done",)                # legacy detect row resumed+polled
    r4 = db._q("SELECT status, backend FROM uploads WHERE sha256='f4'",
               fetch="one")
    assert r4 == ("done", "fie")          # done rows untouched
    db.close()


# ---------------------------------------------------------------------------
# Detect regression — the legacy record shape carries no 'backend' key.
# ---------------------------------------------------------------------------

def test_detect_record_has_no_backend_key(tmp_path, monkeypatch):
    """backend=detect must stay byte-identical: no 'backend' field in the
    NDJSON/result record and task_url carries the spectra task URL."""
    drive, out = _drive(tmp_path)
    det = MagicMock()
    det.is_ready.return_value = True
    det.wait_ready.return_value = True
    det.available_now.return_value = True
    det.upload_with_backoff.side_effect = (
        lambda filepath, custom, cfg, log=None:
            ("https://h/task/z", 201, None, 1))
    det.task_status.return_value = {
        "processed": 1729000000,
        "tc_report": [{"classification": {"classification": 3,
                                          "result": "Trojan.X",
                                          "factor": 8}}]}
    monkeypatch.setattr(fs, "DetectAsyncClient", lambda **kw: det)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    fs.run_scan(_scan_args(drive, out), None, out, MagicMock())

    rec = _ndjson(out)[0]
    assert "backend" not in rec
    assert rec["task_url"] == "https://h/task/z"
    assert rec["classification"] == "malicious"

    db = fs.ScanDB(str(out / "scan_state.db"))
    row = db._q("SELECT status, backend FROM uploads", fetch="one")
    assert row == ("done", "detect")      # detect rows stamp 'detect'
    db.close()
