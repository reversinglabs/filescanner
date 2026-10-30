# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import os
import threading
import types

import pytest

import filescanner as fs
from unittest.mock import MagicMock


def _aged_db(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("x", "f", "f", 1)
    db._conn.execute("UPDATE uploads SET created_at=datetime('now','-30 days')")
    return db


def test_cleanup_prompt_always_deletes(tmp_path):
    db = _aged_db(tmp_path)
    args = MagicMock(retention_days=7, cleanup_old_records="always")
    fs.cleanup_prompt(db, args, MagicMock())
    assert db.old_records(7) == 0
    db.close()


def test_cleanup_prompt_ask_no_keeps(tmp_path, monkeypatch):
    db = _aged_db(tmp_path)
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    args = MagicMock(retention_days=7, cleanup_old_records="ask")
    fs.cleanup_prompt(db, args, MagicMock())
    assert db.old_records(7) == 1
    db.close()


def test_cleanup_prompt_ask_yes_deletes(tmp_path, monkeypatch):
    db = _aged_db(tmp_path)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    args = MagicMock(retention_days=7, cleanup_old_records="ask")
    fs.cleanup_prompt(db, args, MagicMock())
    assert db.old_records(7) == 0
    db.close()


def test_cleanup_prompt_never_keeps_without_prompt(tmp_path, monkeypatch):
    db = _aged_db(tmp_path)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))
    args = MagicMock(retention_days=7, cleanup_old_records="never")
    fs.cleanup_prompt(db, args, MagicMock())
    assert db.old_records(7) == 1
    db.close()


def test_cleanup_prompt_no_old_records_never_prompts(tmp_path, monkeypatch):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))
    args = MagicMock(retention_days=7, cleanup_old_records="ask")
    fs.cleanup_prompt(db, args, MagicMock())
    db.close()


def _scan_args(drive, out):
    """Full args namespace for run_scan (mirrors load_config/normalize_args)."""
    return types.SimpleNamespace(
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
    )


def _fake_client(monkeypatch, report=None):
    client = MagicMock()
    client.is_ready.return_value = True
    client.wait_ready.return_value = True
    client.ready_url = "https://h/readyz"
    client.upload_with_backoff.side_effect = (
        lambda filepath, custom, cfg, log=None:
            (f"https://h/task/{os.path.basename(filepath)}", 201, None, 1))
    client.task_status.return_value = report or {
        "processed": 1729000000,
        "tc_report": [{"classification": {"classification": 3,
                                          "result": "Trojan.X",
                                          "factor": 8}}]}
    monkeypatch.setattr(fs, "DetectAsyncClient", lambda **kw: client)
    return client


def test_run_scan_end_to_end(tmp_path, monkeypatch):
    drive = tmp_path / "drive"
    drive.mkdir()
    (drive / "a.exe").write_bytes(b"MZ-a")
    (drive / "b.exe").write_bytes(b"MZ-b")
    out = tmp_path / "out"
    out.mkdir()
    client = _fake_client(monkeypatch)
    # No input() may fire with cleanup_old_records=never and a fresh DB.
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))

    output = fs.run_scan(_scan_args(drive, out), None, out, MagicMock())

    summary = output["summary"]
    assert summary["files_processed"] == 2
    assert summary["files_completed_successfully"] == 2
    assert summary["uploads_submitted"] == 2
    assert summary["malicious"] == 2
    assert client.upload_with_backoff.call_count == 2
    assert {r["classification"] for r in output["results"]} == {"malicious"}
    assert all(r["api"]["status"] == "completed" for r in output["results"])
    ndjson = (out / "scan_results.ndjson").read_text().splitlines()
    assert len(ndjson) == 2
    db = fs.ScanDB(str(out / "scan_state.db"))
    assert db.counts() == {"done": 2}
    db.close()


def test_run_scan_resumes_prior_submitted_rows(tmp_path, monkeypatch):
    """Rows already 'submitted' in the DB are picked up by the poller."""
    drive = tmp_path / "drive"
    drive.mkdir()
    (drive / "a.exe").write_bytes(b"MZ-a")
    out = tmp_path / "out"
    out.mkdir()
    db = fs.ScanDB(str(out / "scan_state.db"))
    db.upsert_pending("pre", "E:\\old.exe", "old.exe", 9)
    db.mark_submitted("pre", "https://h/task/old")
    db.close()
    _fake_client(monkeypatch)

    output = fs.run_scan(_scan_args(drive, out), None, out, MagicMock())

    paths = {r["file_path"] for r in output["results"]}
    assert "old.exe" in paths
    db = fs.ScanDB(str(out / "scan_state.db"))
    assert db.counts() == {"done": 2}
    db.close()


def test_run_scan_aborts_when_detect_not_ready(tmp_path, monkeypatch):
    drive = tmp_path / "drive"
    drive.mkdir()
    (drive / "a.exe").write_bytes(b"MZ-a")
    client = _fake_client(monkeypatch)
    client.wait_ready.return_value = False
    with pytest.raises(SystemExit):
        fs.run_scan(_scan_args(drive, tmp_path), None, tmp_path, MagicMock())
    client.upload_with_backoff.assert_not_called()


def test_normalize_args_requires_host_token_drive():
    args = types.SimpleNamespace(
        file_types="", detect_file_type=False, quarantine_on="",
        alert_on="", report_formats="json", workers=1, upload_workers=1,
        result_pollers=1, cleanup_old_records="ask",
        host="", token="t", drive="E:\\")
    with pytest.raises(SystemExit):
        fs.normalize_args(args, MagicMock())


def test_normalize_args_clamps_and_validates():
    args = types.SimpleNamespace(
        file_types="", detect_file_type=False, quarantine_on="",
        alert_on="", report_formats="json", workers=0, upload_workers=0,
        result_pollers=0, cleanup_old_records="bogus",
        read_speed_test="bogus", quarantine_action="bogus", preset=None,
        host="h", token="t", drive="d")
    fs.normalize_args(args, MagicMock())
    assert args.upload_workers == 1
    assert args.result_pollers == 1
    assert args.cleanup_old_records == "ask"
    assert args.read_speed_test == "ask"          # invalid enum -> safe default
    assert args.quarantine_action == "none"       # invalid enum -> no quarantine


def test_normalize_args_rejects_bad_preset():
    args = types.SimpleNamespace(
        file_types="", detect_file_type=False, quarantine_on="",
        alert_on="", report_formats="json", workers=1, upload_workers=1,
        result_pollers=1, cleanup_old_records="ask",
        read_speed_test="ask", quarantine_action="none", preset="bogus",
        host="h", token="t", drive="d")
    with pytest.raises(SystemExit):
        fs.normalize_args(args, MagicMock())


def _now_sql(db):
    """Current time in sqlite datetime('now') format (what updated_at stores)."""
    return db._q("SELECT datetime('now')", fetch="one")[0]


def test_build_output_corrupt_report_json_is_no_report(tmp_path):
    """A corrupt report_json blob must not crash report building — the row
    simply has no stored report."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_submitted("aa", "https://h/t/1")
    db.claim_report("aa")
    db.mark_done("aa", "malicious", "Trojan.X", 5, "{not-valid-json")
    out = fs._build_output_from_db(_scan_args(tmp_path, tmp_path), db,
                                   fs.Counters(), str(tmp_path), 1, None,
                                   tmp_path, _now_sql(db))
    assert out["results"][0]["api"]["report"] is None
    assert out["results"][0]["classification"] == "malicious"
    db.close()


def test_build_output_counts_prior_run_failures(tmp_path):
    """failed/timeout rows a previous run left behind and this run never
    reprocessed must reach files_with_errors (the exit-code path)."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("old", "E:\\old.exe", "old.exe", 1)
    db.mark_failed("old", 503, "unavailable")
    db.upsert_pending("timed", "E:\\t.exe", "t.exe", 1)
    db.mark_submitted("timed", "https://h/t/old")
    db.mark_report_timeout("timed")
    db.upsert_pending("skip", "E:\\s.bin", "s.bin", 1)
    db.mark_failed("skip", None, "skipped_filetype:png")  # policy skip, not error
    db._conn.execute("UPDATE uploads SET updated_at=datetime('now','-1 day')")
    counters = fs.Counters()                          # nothing failed this run
    out = fs._build_output_from_db(_scan_args(tmp_path, tmp_path), db,
                                   counters, str(tmp_path), 0, None,
                                   tmp_path, _now_sql(db))
    assert out["summary"]["files_with_errors"] == 2  # old + timed, not 'skip'
    db.close()


def test_build_output_does_not_double_count_this_run_failures(tmp_path):
    """A row that failed during this run is already in the errors counter —
    it must not be added a second time via the DB row scan."""
    db = fs.ScanDB(str(tmp_path / "s.db"))
    db.upsert_pending("aa", "E:\\a.exe", "a.exe", 1)
    db.mark_failed("aa", 503, "upload fail")          # fresh updated_at
    counters = fs.Counters()
    counters.inc("errors")                            # worker already counted it
    out = fs._build_output_from_db(_scan_args(tmp_path, tmp_path), db,
                                   counters, str(tmp_path), 1, None,
                                   tmp_path, _now_sql(db))
    assert out["summary"]["files_with_errors"] == 1
    db.close()


def test_determine_extensions_resolves_preset_name():
    """config.ini documents 'extensions = <preset>'; it must not zero-match."""
    args = types.SimpleNamespace(exclude_extensions="",
                                 extensions="executables", preset=None)
    assert fs.determine_extensions(args) == fs.DEFAULT_EXECUTABLE_EXTENSIONS
    # A real extension list still parses normally.
    args.extensions = ".exe,.dll"
    assert fs.determine_extensions(args) == {".exe", ".dll"}
    # preset field resolves too.
    args = types.SimpleNamespace(exclude_extensions="", extensions="",
                                 preset="media")
    assert fs.determine_extensions(args) == fs.DEFAULT_MEDIA_EXTENSIONS


def test_pdf_report_valid_structure(tmp_path):
    out = {"scan_metadata": {"spectra_detect_host": "h", "usb_drive_root": "d",
                             "scanner_version": "x", "scan_started_at": "t"},
           "summary": {"files_processed": 2, "malicious": 1},
           "results": [{"file_path": "a/b.exe", "classification": "malicious",
                        "threat_name": "X.Y", "sha256": "ab" * 32,
                        "api": {"status": "completed"}},
                       {"file_path": "c.txt", "classification": "unknown",
                        "api": {"status": "completed"}}]}
    p = tmp_path / "r.pdf"
    fs.write_pdf_report(out, p, MagicMock())
    data = p.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"trailer" in data and b"%%EOF" in data and b"startxref" in data
    assert b"/BaseFont /Courier" in data
    # findings-only: the clean row must not appear, the malicious row must
    assert b"a/b.exe" in data and b"X.Y" in data
    assert b"c.txt" not in data
    # non-latin1 filename must not break the writer
    out["results"].append({"file_path": "á中文.bin", "classification": "malicious",
                           "api": {"status": "completed"}})
    fs.write_pdf_report(out, p, MagicMock())
    assert p.read_bytes().startswith(b"%PDF-1.4")
