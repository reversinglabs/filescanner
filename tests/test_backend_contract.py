# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Contract tests for the multi-backend abstraction layer (SubmitOutcome,
ScanBackend protocol, DetectBackend adapter, make_backend factory)."""
import pytest

import filescanner as fs
from unittest.mock import MagicMock


def _backend():
    c = fs.DetectAsyncClient("https://h", "tok")
    c._session = MagicMock()
    return fs.DetectBackend(c)


def _args(**kw):
    base = dict(backend="detect", host="https://h", token="tok",
                no_verify_ssl=False, proxy="")
    base.update(kw)
    return fs.argparse.Namespace(**base)


# -- SubmitOutcome ------------------------------------------------------------

def test_submit_outcome_shape_defaults():
    o = fs.SubmitOutcome(kind="receipt", ref="https://h/task/1")
    assert o.kind == "receipt" and o.ref == "https://h/task/1"
    assert o.http_status is None and o.error is None
    assert o.classification is None and o.threat_name is None
    assert o.threat_factor is None and o.report_json is None


def test_submit_outcome_verdict_fields():
    o = fs.SubmitOutcome(kind="verdict", classification="malicious",
                         threat_name="Bad", threat_factor=7,
                         report_json='{"a":1}')
    assert o.kind == "verdict" and o.classification == "malicious"
    assert o.threat_name == "Bad" and o.threat_factor == 7
    assert o.report_json == '{"a":1}'


# -- DetectBackend satisfies the protocol --------------------------------------

def test_detect_backend_is_scan_backend():
    b = _backend()
    assert isinstance(b, fs.ScanBackend)
    assert b.name == "detect"
    assert b.needs_sha1 is False and b.is_sync is False


def test_availability_methods_delegate():
    b = _backend()
    b.client._session.get.return_value = MagicMock(status_code=200)
    assert b.probe() is True
    assert b.available_now(60) is True
    b.mark_unavailable()
    assert b.client._avail_ok is False
    b.client.wait_ready = MagicMock(return_value=True)
    assert b.wait_ready(5, 1) is True


def test_submit_once_receipt(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b = _backend()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "/api/tiscale/v1/task/42"}
    b.client._session.post.return_value = resp
    o = b.submit_once(str(f), "s256", None, {"k": "v"})
    assert o.kind == "receipt"
    assert o.ref == "https://h/api/tiscale/v1/task/42"
    assert o.http_status == 201 and o.error is None


def test_submit_once_error(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b = _backend()
    b.client._session.post.return_value = MagicMock(status_code=503,
                                                    text="busy")
    o = b.submit_once(str(f), "s256", None, {})
    assert o.kind == "error" and o.ref == ""
    assert o.http_status == 503 and o.error.startswith("http_503")


def test_submit_once_file_not_found():
    b = _backend()
    o = b.submit_once("/nonexistent/x.bin", "s256", None, {})
    assert o.kind == "error" and o.http_status is None
    assert o.error.startswith("file_not_found:")


def test_submit_with_backoff_receipt(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b = _backend()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "/api/tiscale/v1/task/7"}
    b.client._session.post.return_value = resp
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=30, max_upload_attempts=3,
                                ready_check_interval=1, ready_max_wait=5)
    o = b.submit_with_backoff(str(f), "s256", None, {}, cfg)
    assert o.kind == "receipt"
    assert o.ref == "https://h/api/tiscale/v1/task/7"


def test_submit_with_backoff_error(tmp_path):
    """Non-retriable failure surfaces as kind='error' with the reason."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b = _backend()
    resp = MagicMock(status_code=201)
    resp.json.return_value = {"task_url": "https://evil.example/api/t/1"}
    b.client._session.post.return_value = resp
    cfg = fs.argparse.Namespace(backoff_base_seconds=0, backoff_max_seconds=0,
                                upload_retry_window=60, max_upload_attempts=8,
                                ready_check_interval=0, ready_max_wait=0)
    o = b.submit_with_backoff(str(f), "s256", None, {}, cfg)
    assert o.kind == "error"
    assert o.error == "task_url cross-origin rejected"
    assert b.client._session.post.call_count == 1


# -- poll_batch -----------------------------------------------------------------

def test_poll_batch_pending_when_not_processed():
    b = _backend()
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"processed": 0}
    b.client._session.get.return_value = resp
    out = b.poll_batch([{"ref": "https://h/api/tiscale/v1/task/1"}])
    assert out == {"https://h/api/tiscale/v1/task/1": "pending"}


def test_poll_batch_gone_on_404():
    b = _backend()
    b.client._session.get.return_value = MagicMock(status_code=404)
    out = b.poll_batch([{"ref": "https://h/api/tiscale/v1/task/1"}])
    assert out == {"https://h/api/tiscale/v1/task/1": "gone"}


def test_poll_batch_transient_error_is_pending():
    b = _backend()
    b.client._session.get.return_value = MagicMock(status_code=500)
    out = b.poll_batch([{"ref": "https://h/api/tiscale/v1/task/1"}])
    assert out == {"https://h/api/tiscale/v1/task/1": "pending"}


def test_poll_batch_verdict_dict():
    b = _backend()
    task = {"processed": 1, "tc_report": [
        {"classification": {"classification": 3, "factor": 7,
                            "result": "Win32.Evil"}}]}
    resp = MagicMock(status_code=200)
    resp.json.return_value = task
    b.client._session.get.return_value = resp
    ref = "https://h/api/tiscale/v1/task/1"
    out = b.poll_batch([{"ref": ref}])
    v = out[ref]
    assert v["classification"] == "malicious"
    assert v["threat_name"] == "Win32.Evil"
    assert v["threat_factor"] == 7
    assert v["report_json"] == task


def test_poll_batch_accepts_task_url_key_and_mixed_states():
    b = _backend()
    pending = MagicMock(status_code=200)
    pending.json.return_value = {"processed": 0}
    gone = MagicMock(status_code=404)
    b.client._session.get.side_effect = [pending, gone]
    out = b.poll_batch([{"task_url": "https://h/t/1"},
                        {"ref": "https://h/t/2", "sha256": "x"},
                        {}])   # ref-less entries are skipped
    assert out == {"https://h/t/1": "pending", "https://h/t/2": "gone"}


# -- make_backend ----------------------------------------------------------------

def test_make_backend_detect():
    b = fs.make_backend(_args())
    assert isinstance(b, fs.DetectBackend)
    assert isinstance(b, fs.ScanBackend)
    assert b.client.host == "https://h"


def test_make_backend_unknown_exits():
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(_args(backend="bogus"))
    assert ei.value.code == 2


def test_make_backend_registered_backends_construct(monkeypatch):
    """a1000 and cloud factories are registered — with complete fake args
    (startup auth probes mocked out) they construct without exiting."""
    monkeypatch.setattr(fs.A1000Client, "probe_status",
                        lambda self, timeout=8: 200)
    monkeypatch.setattr(fs.TiCloudClient, "probe_status",
                        lambda self, timeout=8: 200)
    a1 = fs.make_backend(_args(
        backend="a1000", a1000_host="https://a1000.local",
        a1000_token="tok", a1000_analysis="", a1000_tags="",
        a1000_comment="", a1000_archive_password="",
        a1000_sandbox_platform="", a1000_report_detail="summary"))
    assert isinstance(a1, fs.A1000Backend) and isinstance(a1, fs.ScanBackend)
    cl = fs.make_backend(_args(
        backend="cloud", ticloud_host="https://ticloud.local",
        ticloud_username="u@x", ticloud_password="pw",
        ticloud_domain="", ticloud_archive_password="",
        ticloud_upload_timeout=300, ticloud_min_interval_ms=0,
        ticloud_extended=True))
    assert isinstance(cl, fs.CloudBackend) and isinstance(cl, fs.ScanBackend)


@pytest.mark.parametrize("name,kw", [
    ("a1000", dict(a1000_host="", a1000_token="tok")),
    ("a1000", dict(a1000_host="https://a1000.local", a1000_token="")),
    ("cloud", dict(ticloud_host="", ticloud_username="u",
                   ticloud_password="p")),
    ("cloud", dict(ticloud_host="https://ticloud.local", ticloud_username="",
                   ticloud_password="p")),
    ("cloud", dict(ticloud_host="https://ticloud.local", ticloud_username="u",
                   ticloud_password="")),
])
def test_make_backend_missing_config_exits(name, kw):
    """Each registered factory still exit(2)s on missing required config —
    before any network probe."""
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(_args(backend=name, **kw))
    assert ei.value.code == 2
