"""CSV formula safety, persisted action columns, run-scoped reports."""
import csv
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import filescanner as fs
from test_run_scan import _scan_args


def _done(db, sha, name, cls="malicious"):
    db.upsert_pending(sha, name, name, 1)
    db.mark_submitted(sha, "http://x/t/" + sha)
    db.claim_report(sha)
    db.mark_done(sha, cls, "=EVIL", None, None)


def _build(tmp_path, db, since):
    return fs._build_output_from_db(_scan_args(tmp_path, tmp_path), db,
                                    fs.Counters(), str(tmp_path), 1, None,
                                    tmp_path, since)


def test_csv_safe_helper():
    for c in "=+-@\t\r":
        assert fs._csv_safe(c + "x") == "'" + c + "x"
    assert fs._csv_safe("ok") == "ok" and fs._csv_safe(5) == 5
    assert fs._csv_safe(None) is None and fs._csv_safe("") == ""


def test_csv_report_neutralizes_formulas_and_has_action_columns(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    _done(db, "a", "=cmd.exe")
    db.mark_actions("a", "@/q/a", True)
    _done(db, "b", "b.exe", "goodware")
    out = _build(tmp_path, db, "2000-01-01 00:00:00")
    db.close()
    recs = {r["sha256"]: r for r in out["results"]}
    assert recs["a"]["quarantined_to"] == "@/q/a" and recs["a"]["alerted"] is True
    assert recs["b"]["quarantined_to"] is None and recs["b"]["alerted"] is None
    p = tmp_path / "r.csv"
    fs.write_csv_report(out, p, logging.getLogger("t"))
    rows = {r["sha256"]: r for r in csv.DictReader(open(p, newline=""))}
    assert rows["a"]["file_path"] == "'=cmd.exe"
    assert rows["a"]["threat_name"] == "'=EVIL"
    assert rows["a"]["quarantined_to"] == "'@/q/a"
    assert rows["a"]["alerted"] == "true" and rows["b"]["alerted"] == ""
    assert rows["b"]["quarantined_to"] == ""


def test_html_shows_quarantined_path_escaped(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    _done(db, "a", "a.exe")
    db.mark_actions("a", "/q/<b>a", False)
    out = _build(tmp_path, db, "2000-01-01 00:00:00")
    db.close()
    p = tmp_path / "r.html"
    fs.write_html_report(out, p, logging.getLogger("t"))
    h = p.read_text()
    assert "/q/&lt;b&gt;a" in h and "/q/<b>a" not in h


def test_verdicts_since_and_run_scoped_report(tmp_path):
    db = fs.ScanDB(str(tmp_path / "s.db"))
    _done(db, "old", "old.exe")
    db._conn.execute("UPDATE uploads SET updated_at=datetime('now','-1 day')")
    db.upsert_pending("oldfail", "of.exe", "of.exe", 1)
    db.mark_failed("oldfail", 500, "boom")
    db._conn.execute("UPDATE uploads SET updated_at=datetime('now','-1 day') "
                     "WHERE sha256='oldfail'")
    start = db.now()
    _done(db, "new", "new.exe", "suspicious")
    assert [r["sha256"] for r in db.verdicts(since=start)] == ["new"]
    assert len(db.verdicts()) == 3
    out = _build(tmp_path, db, start)
    db.close()
    assert [r["sha256"] for r in out["results"]] == ["new"]
    s = out["summary"]
    assert s["files_processed"] == 1 and s["malicious"] == 0
    assert s["suspicious"] == 1
    # stale failure not in the report still drives the exit code
    assert s["files_with_errors"] == 1


def test_csv_booleans_lowercase(tmp_path):
    out = {"results": [
        {"sha256": "a", "cached": True, "alerted": False},
        {"sha256": "b", "cached": False, "alerted": True}]}
    p = tmp_path / "r.csv"
    fs.write_csv_report(out, p, logging.getLogger("t"))
    rows = {r["sha256"]: r for r in csv.DictReader(open(p, newline=""))}
    assert rows["a"]["cached"] == "true" and rows["a"]["alerted"] == "false"
    assert rows["b"]["cached"] == "false" and rows["b"]["alerted"] == "true"
