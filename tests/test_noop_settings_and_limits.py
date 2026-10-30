# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT
"""No-op setting warnings, head-capture cap, detect permanent statuses."""
import logging
import queue
import textwrap
from unittest.mock import MagicMock

import pytest

import filescanner as fs
from test_detect_client import _client
from test_precheck import _upload_ctx, _upload_args, _verdict_backend


def _cfg(tmp_path, scan_body):
    p = tmp_path / "config.ini"
    p.write_text("[scan]\ndrive = X\n" + textwrap.dedent(scan_body))
    return str(p)


def test_noop_settings_warn_when_non_default(tmp_path, caplog):
    path = _cfg(tmp_path, """
        analysis_depth = fast
        large_file_threshold = 5
        detect_file_type = false
        """)
    with caplog.at_level(logging.WARNING):
        fs.load_config(path)
    msgs = [r.getMessage() for r in caplog.records]
    for key in ("analysis_depth", "large_file_threshold", "detect_file_type"):
        assert sum(m == f"{key} is currently a no-op" for m in msgs) == 1


def test_noop_settings_silent_at_defaults(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        fs.load_config(_cfg(tmp_path, "analysis_depth = full\n"))
    assert not [r for r in caplog.records if "no-op" in r.getMessage()]


def test_head_capture_capped_at_4096(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"MZ" + b"A" * 100_000)
    ctx = _upload_ctx(tmp_path, _upload_args(file_types={"pe"}))
    db = fs.ScanDB(str(tmp_path / "s.db"))
    pq, wq = queue.Queue(), queue.Queue()
    wq.put((str(f), "big.bin"))
    wq.put(None)
    fs.upload_worker(ctx, db, _verdict_backend(), wq, precheck_q=pq,
                     writer=MagicMock())
    assert len(pq.get_nowait()["head"]) == 4096
    db.close()


@pytest.mark.parametrize("status", [400, 413])
def test_detect_400_413_permanent(tmp_path, status):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c.mark_unavailable = MagicMock()
    c._session.post.return_value = MagicMock(status_code=status, text="no")
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=60, max_upload_attempts=8,
                                ready_check_interval=0, ready_max_wait=0)
    url, st, err, attempts = c.upload_with_backoff(str(f), {}, cfg)
    assert url is None and st == status and attempts == 1
    c.mark_unavailable.assert_not_called()


def test_enrich_noop_settings_warn(tmp_path, caplog):
    path = _cfg(tmp_path, """
        extract_strings = true
        extract_iocs = true
        max_enrich_bytes = 5
        """)
    with caplog.at_level(logging.WARNING):
        fs.load_config(path)
    msgs = [r.getMessage() for r in caplog.records]
    for key in ("max_enrich_bytes", "extract_strings", "extract_iocs"):
        assert sum(m == f"{key} is currently a no-op" for m in msgs) == 1


def test_template_noop_defaults_are_silent(caplog):
    import os
    tpl = os.path.join(os.path.dirname(__file__), "..", "config.ini.template")
    with caplog.at_level(logging.WARNING):
        fs.load_config(tpl)
    assert not [r for r in caplog.records if "no-op" in r.getMessage()]
