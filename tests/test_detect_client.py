# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import pytest

import filescanner as fs
from unittest.mock import MagicMock


def _client():
    c = fs.DetectAsyncClient("https://h", "tok")
    c._session = MagicMock()
    return c


def test_upload_201_returns_task_url(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "/api/tiscale/v1/task/42"}
    c._session.post.return_value = resp
    st, url, err = c.upload_once(str(f), {})
    assert st == 201
    assert url == "https://h/api/tiscale/v1/task/42"
    assert err is None


def test_upload_file_not_found(tmp_path):
    c = _client()
    st, url, err = c.upload_once(str(tmp_path / "missing.bin"), {})
    assert st is None and url is None
    assert err.startswith("file_not_found:")


def test_upload_201_cross_origin_task_url_rejected(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "https://evil.example/api/t/1"}
    c._session.post.return_value = resp
    st, url, err = c.upload_once(str(f), {})
    # 201 but task_url on a foreign origin -> no URL returned, never send token there
    assert st == 201 and url is None
    assert err == "task_url cross-origin rejected"


def test_upload_201_non_dict_body_no_crash(tmp_path):
    """A JSON array/scalar body must return an error, not AttributeError."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    resp = MagicMock(status_code=201)
    resp.json.return_value = ["not", "a", "dict"]
    c._session.post.return_value = resp
    st, url, err = c.upload_once(str(f), {})
    assert st == 201 and url is None
    assert err == "invalid upload response body"


def test_upload_201_invalid_task_url_no_crash(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": 12345}   # non-string task_url
    c._session.post.return_value = resp
    st, url, err = c.upload_once(str(f), {})
    assert st == 201 and url is None
    assert err == "invalid task_url"


def test_backoff_does_not_retry_non_retriable(tmp_path):
    """Cross-origin/invalid responses must stop after one attempt."""
    f = tmp_path / "a.bin"; f.write_bytes(b"x")
    c = _client()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "https://evil.example/api/t/1"}
    c._session.post.return_value = resp
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=60, max_upload_attempts=8,
                                ready_check_interval=0, ready_max_wait=0)
    url, status, err, attempts = c.upload_with_backoff(str(f), {}, cfg)
    assert url is None
    assert err == "task_url cross-origin rejected"
    assert attempts == 1
    assert c._session.post.call_count == 1         # 'FAILED 201' now has a reason


def test_http_calls_never_follow_redirects(tmp_path):
    """allow_redirects=False must ride on every request — a redirect would
    re-send the file body and Authorization token to a foreign origin."""
    f = tmp_path / "a.bin"; f.write_bytes(b"x")
    c = _client()
    ok = MagicMock(status_code=200)
    ok.json.return_value = {"processed": 1}
    c._session.get.return_value = ok
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "/api/tiscale/v1/task/1"}
    c._session.post.return_value = resp
    c.is_ready()
    assert c._session.get.call_args.kwargs["allow_redirects"] is False
    c.task_status("https://h/api/tiscale/v1/task/1")
    assert c._session.get.call_args.kwargs["allow_redirects"] is False
    c.upload_once(str(f), {})
    assert c._session.post.call_args.kwargs["allow_redirects"] is False


def test_task_status_non_dict_body_raises_value_error():
    """A JSON list/scalar body is a malformed response — it must raise a plain
    error the poller treats as transient, not AttributeError at task.get()."""
    c = _client()
    resp = MagicMock(status_code=200)
    resp.json.return_value = ["not", "a", "dict"]
    c._session.get.return_value = resp
    with pytest.raises(ValueError, match="malformed task body"):
        c.task_status("https://h/api/tiscale/v1/task/1")


def test_wait_ready_clamps_zero_interval(monkeypatch):
    """ready_check_interval=0 must not tight-spin — sleep is clamped to >=1s."""
    c = _client()
    c.is_ready = MagicMock(return_value=False)
    sleeps = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    log = MagicMock()
    assert c.wait_ready(0.05, 0, log=log) is False
    # mocked sleep makes the loop spin on real time — every sleep must be the
    # clamped 1s, never the raw 0 interval
    assert sleeps and all(s == 1 for s in sleeps)


def test_backoff_logs_when_ready_gate_times_out(tmp_path):
    """When the readyz gate expires the retry still proceeds — that decision
    must be visible in the log."""
    f = tmp_path / "a.bin"; f.write_bytes(b"x")
    c = _client()
    c.wait_ready = MagicMock(return_value=False)
    c._session.post.return_value = MagicMock(status_code=503, text="busy")
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=5, max_upload_attempts=2,
                                ready_check_interval=0, ready_max_wait=0)
    log = MagicMock()
    url, status, err, attempts = c.upload_with_backoff(str(f), {}, cfg, log=log)
    assert url is None and attempts == 2
    assert any("readyz gate timed out" in str(call.args[0])
               for call in log.warning.call_args_list)


def test_backoff_gates_on_ready(tmp_path):
    f = tmp_path / "a.bin"; f.write_bytes(b"x")
    c = _client()
    not_ready = MagicMock(status_code=503)
    ready = MagicMock(status_code=200)
    ok = MagicMock(status_code=201)
    ok.json.return_value = {"task_url": "https://h/api/tiscale/v1/task/7"}
    # first upload 503, readyz fails once then passes, second upload 201
    c._session.post.side_effect = [not_ready, ok]
    c._session.get.side_effect = [MagicMock(status_code=503), ready]
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=5, max_upload_attempts=3,
                                ready_check_interval=0, ready_max_wait=5)
    url, status, err, attempts = c.upload_with_backoff(str(f), {}, cfg)
    assert url == "https://h/api/tiscale/v1/task/7"
    assert attempts == 2


def test_upload_streams_multipart_body(tmp_path):
    """The request body must be a lazy generator, not a buffered bytes blob —
    and must reassemble into a valid multipart containing the file bytes."""
    payload = b"P" * (3 * 1024 * 1024 + 7)          # > 1 chunk
    f = tmp_path / "big.bin"
    f.write_bytes(payload)
    c = _client()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "/api/tiscale/v1/task/9"}
    c._session.post.return_value = resp
    st, url, err = c.upload_once(str(f), {"k": "v"})
    assert st == 201 and err is None
    kw = c._session.post.call_args.kwargs
    body_gen = kw["data"]
    assert not isinstance(body_gen, (bytes, bytearray))   # lazy, not buffered
    declared = len(body_gen)          # __len__ -> requests sets Content-Length
    boundary = kw["headers"]["Content-Type"].split("boundary=")[1]
    chunks = list(body_gen)
    assert all(len(b) <= fs.UPLOAD_CHUNK_SIZE for b in chunks)
    body = b"".join(chunks)
    assert len(body) == declared                          # Content-Length honest
    assert payload in body                                # full file on the wire
    assert b'name="custom_data"' in body and b'"k": "v"' in body
    assert b'filename="big.bin"' in body
    assert body.startswith(b"--" + boundary.encode())
    assert body.rstrip().endswith(b"--" + boundary.encode() + b"--")


def test_upload_getsize_error_is_file_not_found(tmp_path):
    c = _client()
    st, url, err = c.upload_once(str(tmp_path / "gone.bin"), {})
    assert st is None and err.startswith("file_not_found:")


def test_available_now_caches_probe(monkeypatch):
    """Within TTL the shared cache answers without hitting the endpoint."""
    c = _client()
    c._session.get.return_value = MagicMock(status_code=200)
    assert c.available_now(20) is True
    assert c.available_now(20) is True
    assert c._session.get.call_count == 1        # one probe served both calls


def test_mark_unavailable_gates_all_workers():
    """A non-2xx flips the shared cache; another worker's available_now()
    must return False WITHOUT probing again."""
    c = _client()
    c._session.get.return_value = MagicMock(status_code=200)
    assert c.available_now(20) is True
    c.mark_unavailable()                          # worker B saw a 503
    c._session.get.reset_mock()
    assert c.available_now(20) is False           # gated, no fresh probe
    assert c._session.get.call_count == 0


def test_wait_ready_propagates_recovery():
    """When the appliance recovers inside wait_ready, the shared cache must
    flip back so workers resume without waiting out a probe TTL."""
    c = _client()
    c.mark_unavailable()
    ready = MagicMock(status_code=200)
    c._session.get.side_effect = [ready]
    assert c.wait_ready(5, 1) is True
    c._session.get.reset_mock()
    assert c.available_now(60) is True            # cache says True, no probe


def test_upload_backoff_marks_unavailable_on_5xx(tmp_path):
    """A failed attempt must flip shared availability before sleeping."""
    f = tmp_path / "a.bin"; f.write_bytes(b"x")
    c = _client()
    ok = MagicMock(status_code=201)
    ok.json.return_value = {"task_url": "/api/tiscale/v1/task/5"}
    c._session.post.side_effect = [MagicMock(status_code=503, text="busy"), ok]
    c._session.get.return_value = ready = MagicMock(status_code=200)
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=30, max_upload_attempts=3,
                                ready_check_interval=1, ready_max_wait=5,
                                avail_probe_seconds=0)   # probe every attempt
    url, status, err, attempts = c.upload_with_backoff(str(f), {}, cfg)
    assert url and attempts == 2
    # after the 503, _avail_ok was False -> wait_ready polled is_ready
    assert c._session.get.called


def test_task_status_404_raises_task_gone():
    c = _client()
    c._session.get.return_value = MagicMock(status_code=404)
    with pytest.raises(fs.TaskGoneError):
        c.task_status("https://h/api/tiscale/v1/task/1")
