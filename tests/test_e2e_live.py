# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""End-to-end tests against live ReversingLabs services.

These are NOT unit tests — they run the real scanner CLI (subprocess) against
real backends and verify the full pipeline: walk -> hash -> upload/poll ->
verdicts in scan_state.db + report artifacts on disk.

Gating: every test is skipped unless its required env vars are set. The
easiest way to provide them is ./tests/e2e_live.sh which sources the known
credential files, or export the FILESCANNER_E2E_* vars directly.

Env vars:
    FILESCANNER_E2E=1                     master switch
    FILESCANNER_E2E_DETECT_HOST           e.g. https://<detect>
    FILESCANNER_E2E_DETECT_TOKEN          worker API token (empty-token ACL
                                          workers accept any value)
    FILESCANNER_E2E_A1000_HOST            e.g. https://a1000.example.com
    FILESCANNER_E2E_A1000_TOKEN           appliance API token
    FILESCANNER_E2E_FIE_HOST              e.g. http://localhost:8088
    FILESCANNER_E2E_TICLOUD_HOST          e.g. https://ticloud01.reversinglabs.com
    FILESCANNER_E2E_TICLOUD_USER          cloud username (rl/user form)
    FILESCANNER_E2E_TICLOUD_PASS          cloud password/token

Fixtures:
    - eicar.com  : EICAR test string — MALICIOUS in TiCloud, 'processed' on
                   the a1000 appliance, classified by detect workers, and a
                   conclusive non-OK verdict under FIE static analysis.
    - benign.txt : unknown to reputation DBs; exercises the fall-through to
                   the real backend scan path.

Timeouts: subprocess runs are capped per-test; backends with real upload→poll
semantics get a generous window, FIE/reputation paths are fast.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCANNER = REPO / "filescanner.py"
GO_DIR = REPO / "go"
GO_BIN = Path(os.environ.get("FILESCANNER_E2E_GO_BIN", "/tmp/filescanner-e2e"))

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-"
         "TEST-FILE!$H+H*")
EICAR_SHA1 = hashlib.sha1(EICAR.encode()).hexdigest()

DETECT_HOST = os.environ.get("FILESCANNER_E2E_DETECT_HOST", "")
DETECT_TOKEN = os.environ.get("FILESCANNER_E2E_DETECT_TOKEN", "e2e-placeholder")
A1000_HOST = os.environ.get("FILESCANNER_E2E_A1000_HOST", "")
A1000_TOKEN = os.environ.get("FILESCANNER_E2E_A1000_TOKEN", "")
FIE_HOST = os.environ.get("FILESCANNER_E2E_FIE_HOST", "")
TICLOUD_HOST = os.environ.get("FILESCANNER_E2E_TICLOUD_HOST", "")
TICLOUD_USER = os.environ.get("FILESCANNER_E2E_TICLOUD_USER", "")
TICLOUD_PASS = os.environ.get("FILESCANNER_E2E_TICLOUD_PASS", "")

ON = os.environ.get("FILESCANNER_E2E") == "1"


def _cfg(tmp_path: Path, backend: str, extra: str = "") -> Path:
    """Minimal real config.ini — non-interactive knobs set so the CLI never
    prompts (read_speed_test=off, cleanup_old_records=never)."""
    files_dir = tmp_path / "files"
    out_dir = tmp_path / "out"
    text = f"""\
[detect]
host = {DETECT_HOST or 'https://127.0.0.1'}
token = {DETECT_TOKEN}
no_verify_ssl = true

[scan]
backend = {backend}
drive = {files_dir}
extensions = all
read_speed_test = off
detect_file_type = false
analysis_depth = fast

[pipeline]
upload_workers = 2
result_pollers = 1
result_poll_interval = 2
report_wait_hours = 1
max_in_flight = 100
progress_every = 1

[backoff]
base_seconds = 1
max_seconds = 10
upload_retry_window = 120
max_upload_attempts = 3
ready_check_interval = 2
ready_max_wait = 120

[database]
path = scan_state.db
cleanup_old_records = never
store_full_report = false

[actions]
resume = false
quarantine_action = none
quarantine_on = malicious
alert_on =
alert_eventlog = false

[output]
output_dir = {out_dir}
report_formats = json,csv
summary_only = false
verbose = true
"""
    if A1000_HOST:
        text += f"""
[a1000]
host = {A1000_HOST}
token = {A1000_TOKEN}
analysis = cloud
report_detail = summary
"""
    if FIE_HOST:
        text += f"""
[fie]
host = {FIE_HOST}
mode = hash_then_scan
external_id = rel_path
"""
    if TICLOUD_HOST:
        text += f"""
[ticloud]
host = {TICLOUD_HOST}
username = {TICLOUD_USER}
password = {TICLOUD_PASS}
min_interval_ms = 100

[reputation]
precheck = false
batch_size = 50
"""
    text += extra
    cfg = tmp_path / f"config_{backend}.ini"
    cfg.write_text(text)
    return cfg


def _make_files(tmp_path: Path, names=("eicar.com", "benign.txt")) -> Path:
    d = tmp_path / "files"
    d.mkdir(parents=True, exist_ok=True)
    if "eicar.com" in names:
        (d / "eicar.com").write_text(EICAR)
    if "benign.txt" in names:
        (d / "benign.txt").write_text(
            "harmless e2e test file — plain text, no executable content\n")
    return d


def _run(cfg: Path, timeout: int, go: bool = False) -> subprocess.CompletedProcess:
    if go:
        cmd = [str(GO_BIN), "--config", str(cfg)]
    else:
        cmd = [sys.executable, str(SCANNER), "--config", str(cfg)]
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, cwd=str(cfg.parent))


def _db(tmp_path: Path) -> sqlite3.Connection:
    db = tmp_path / "out" / "scan_state.db"
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    return conn


def _rows(conn) -> list:
    return list(conn.execute(
        "SELECT sha256, sha1, status, classification, threat_name, backend, "
        "task_url, error FROM uploads"))


def _report_json(tmp_path: Path) -> dict:
    runs = sorted((tmp_path / "out").glob("run_*/spectra_detect_scan_results.json"))
    assert runs, "no report JSON produced"
    return json.loads(runs[-1].read_text())


def _fie_ready() -> bool:
    try:
        with urllib.request.urlopen(FIE_HOST + "/readyz", timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def _ticloud_reach() -> bool:
    """Cheap authenticated probe — a bulk query for a zero hash should return
    200 with an empty/UNKNOWN entry when creds and network are good."""
    import base64
    import ssl
    body = json.dumps({"rl": {"query": {"hash_type": "sha1",
                                        "hashes": ["0" * 40]}}}).encode()
    try:
        req = urllib.request.Request(
            TICLOUD_HOST + "/api/databrowser/malware_presence/bulk_query/json",
            data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + base64.b64encode(
                         f"{TICLOUD_USER}:{TICLOUD_PASS}".encode()).decode()})
        # e2e appliances may present self-signed certs; they are trusted
        # infrastructure, matching the scanner's no_verify_ssl path.
        urllib.request.urlopen(req, timeout=15,
                               context=ssl._create_unverified_context())
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# FIE — sync backend, no poller, hash_then_scan fallthrough
# --------------------------------------------------------------------------

@pytest.mark.skipif(not (ON and FIE_HOST), reason="FIE e2e not enabled")
def test_e2e_fie_scan_mode(tmp_path):
    if not _fie_ready():
        pytest.skip(f"FIE at {FIE_HOST} not ready (start container + wait for /readyz=200)")
    _make_files(tmp_path)
    cfg = _cfg(tmp_path, "fie")
    r = _run(cfg, timeout=300)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    rows = _rows(_db(tmp_path))
    assert len(rows) == 2
    for row in rows:
        assert row["status"] == "done", dict(row)
        assert row["classification"] in ("malicious", "suspicious", "goodware",
                                         "unknown")
        assert row["backend"] == "fie"
        assert row["sha1"] and len(row["sha1"]) == 40
    rep = _report_json(tmp_path)
    assert rep["summary"]["files_processed"] == 2


@pytest.mark.skipif(not (ON and FIE_HOST), reason="FIE e2e not enabled")
def test_e2e_fie_hash_then_scan_fallthrough(tmp_path):
    """check-sample on a never-seen hash returns ambiguous OK -> the pipeline
    must fall through to /scan, not trust the empty verdict."""
    if not _fie_ready():
        pytest.skip(f"FIE at {FIE_HOST} not ready")
    _make_files(tmp_path, names=("benign.txt",))
    cfg = _cfg(tmp_path, "fie")
    r = _run(cfg, timeout=300)
    assert r.returncode == 0, r.stderr[-1500:]
    rows = _rows(_db(tmp_path))
    assert len(rows) == 1 and rows[0]["status"] == "done"
    assert rows[0]["classification"]  # any verdict, but must exist


# --------------------------------------------------------------------------
# detect — existing tiscale flow, open-token worker
# --------------------------------------------------------------------------

@pytest.mark.skipif(not (ON and DETECT_HOST), reason="detect e2e not enabled")
def test_e2e_detect(tmp_path):
    _make_files(tmp_path)
    cfg = _cfg(tmp_path, "detect")
    r = _run(cfg, timeout=600)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-2000:]}"
    rows = _rows(_db(tmp_path))
    assert len(rows) == 2
    eicar = [x for x in rows
             if x["sha256"] == hashlib.sha256(EICAR.encode()).hexdigest()][0]
    assert eicar["status"] == "done"
    assert eicar["classification"] == "malicious"
    assert eicar["task_url"] and "/task/" in eicar["task_url"]
    assert (eicar["backend"] or "detect") == "detect"
    for row in rows:
        assert row["status"] == "done", dict(row)


# --------------------------------------------------------------------------
# a1000 — async hash-polled
# --------------------------------------------------------------------------

@pytest.mark.skipif(not (ON and A1000_HOST and A1000_TOKEN),
                    reason="a1000 e2e not enabled")
def test_e2e_a1000(tmp_path):
    _make_files(tmp_path)
    cfg = _cfg(tmp_path, "a1000")
    r = _run(cfg, timeout=900)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-2000:]}"
    rows = _rows(_db(tmp_path))
    assert len(rows) == 2
    eicar = [x for x in rows if x["sha1"] == EICAR_SHA1
             or x["task_url"] == EICAR_SHA1]
    for row in rows:
        assert row["status"] == "done", dict(row)
        assert row["classification"] in ("malicious", "suspicious", "goodware",
                                         "unknown")
    if eicar:
        assert eicar[0]["classification"] == "malicious"


# --------------------------------------------------------------------------
# cloud — spex two-step upload + TCA-0101 reputation poll
# --------------------------------------------------------------------------

@pytest.mark.skipif(not (ON and TICLOUD_HOST and TICLOUD_USER and TICLOUD_PASS),
                    reason="cloud e2e not enabled")
def test_e2e_cloud(tmp_path):
    """EICAR-only fixture: the hash is already MALICIOUS in TiCloud so the
    reputation poll resolves immediately (unknown files would sit 'pending'
    until the report_wait_hours deadline — not viable in a test)."""
    if not _ticloud_reach():
        pytest.skip("TiCloud unreachable or auth failed")
    _make_files(tmp_path, names=("eicar.com",))
    cfg = _cfg(tmp_path, "cloud")
    r = _run(cfg, timeout=600)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-2000:]}"
    rows = _rows(_db(tmp_path))
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "done", dict(row)
    assert row["classification"] == "malicious"
    assert row["threat_name"] and "EICAR" in row["threat_name"].upper()
    assert row["backend"] == "cloud"
    # receipt = sha1 of the uploaded file
    assert row["task_url"] == EICAR_SHA1


# --------------------------------------------------------------------------
# reputation pre-check — EICAR classified by ticloud, benign falls to backend
# --------------------------------------------------------------------------

@pytest.mark.skipif(not (ON and FIE_HOST and TICLOUD_HOST and TICLOUD_USER
                         and TICLOUD_PASS),
                    reason="precheck e2e not enabled (needs fie + ticloud)")
def test_e2e_reputation_precheck(tmp_path):
    if not _fie_ready():
        pytest.skip(f"FIE at {FIE_HOST} not ready")
    if not _ticloud_reach():
        pytest.skip("TiCloud unreachable or auth failed")
    _make_files(tmp_path)
    cfg = _cfg(tmp_path, "fie")
    # flip precheck on
    txt = cfg.read_text().replace("precheck = false", "precheck = true")
    cfg.write_text(txt)
    r = _run(cfg, timeout=600)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-3000:]}"
    rows = {x["sha256"]: x for x in _rows(_db(tmp_path))}
    assert len(rows) == 2
    eicar_sha256 = hashlib.sha256(EICAR.encode()).hexdigest()
    eicar_row = rows[eicar_sha256]
    # classified by precheck -> backend stamps ticloud, no backend scan needed
    assert eicar_row["status"] == "done"
    assert eicar_row["backend"] == "ticloud"
    assert eicar_row["classification"] == "malicious"
    benign_row = [x for s, x in rows.items() if s != eicar_sha256][0]
    assert benign_row["status"] == "done"
    # benign fell through to the real backend
    assert benign_row["backend"] in ("fie", "ticloud")


# --------------------------------------------------------------------------
# Go parity smoke — same CLI, same pipeline, real services
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def go_binary():
    if not GO_BIN.exists():
        subprocess.run(["go", "build", "-o", str(GO_BIN), "."],
                       cwd=str(GO_DIR), check=True)
    return str(GO_BIN)


@pytest.mark.skipif(not (ON and FIE_HOST), reason="go e2e not enabled")
def test_e2e_go_fie(tmp_path, go_binary):
    if not _fie_ready():
        pytest.skip(f"FIE at {FIE_HOST} not ready")
    _make_files(tmp_path)
    cfg = _cfg(tmp_path, "fie")
    r = _run(cfg, timeout=300, go=True)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    rows = _rows(_db(tmp_path))
    assert len(rows) == 2
    for row in rows:
        assert row["status"] == "done", dict(row)
        assert row["backend"] == "fie"


@pytest.mark.skipif(not (ON and DETECT_HOST), reason="go e2e not enabled")
def test_e2e_go_detect(tmp_path, go_binary):
    _make_files(tmp_path)
    cfg = _cfg(tmp_path, "detect")
    r = _run(cfg, timeout=600, go=True)
    assert r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-2000:]}"
    rows = _rows(_db(tmp_path))
    assert len(rows) == 2
    for row in rows:
        assert row["status"] == "done", dict(row)
        assert row["task_url"] and "/task/" in row["task_url"]
