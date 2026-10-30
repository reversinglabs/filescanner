# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Tests for FieClient + FieBackend — /readyz gating, /check-sample hash
modes, synchronous /scan verdicts, external_id modes, error taxonomy.
MagicMock session injection mirrors test_detect_client.py."""
import pytest

import filescanner as fs
from unittest.mock import MagicMock


FIE_HOST = "http://fie.local:8000"


def _client():
    c = fs.FieClient(FIE_HOST)
    c._session = MagicMock()
    return c


def _backend(mode="hash_then_scan", trust_ok=False, external_id="rel_path"):
    c = _client()
    return fs.FieBackend(c, mode=mode, trust_ok=trust_ok,
                         external_id=external_id), c


def _cfg(**kw):
    base = dict(backoff_base_seconds=0, backoff_max_seconds=0,
                upload_retry_window=60, max_upload_attempts=3,
                ready_check_interval=0, ready_max_wait=0,
                avail_probe_seconds=0)
    base.update(kw)
    return fs.argparse.Namespace(**base)


def _json_resp(status, body):
    r = MagicMock(status_code=status)
    if body is not None:
        r.json.return_value = body
    return r


SCAN_MAL = {"classification": "malicious",
            "threat_details": {"threat_name": "Win32.Evil",
                               "scanner_match": 37}}
SCAN_OK = {"classification": "OK"}
HASH_SUSP = {"classification": "suspicious",
             "threat_details": {"threat_name": "Gen:Susp"}}
HASH_OK = {"classification": "OK"}


# -- contract ----------------------------------------------------------------

def test_fie_backend_is_scan_backend():
    b, _ = _backend()
    assert isinstance(b, fs.ScanBackend)
    assert b.name == "fie"
    assert b.needs_sha1 is True and b.is_sync is True


def test_poll_batch_unused_returns_empty():
    b, _ = _backend()
    assert b.poll_batch([{"ref": "x"}]) == {}


# -- probe / availability ------------------------------------------------------

def test_probe_readyz_200():
    _, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    assert c.probe() is True
    url = c._session.get.call_args.args[0]
    assert url == FIE_HOST + "/readyz"
    assert c._session.get.call_args.kwargs["allow_redirects"] is False


def test_probe_not_ready():
    _, c = _backend()
    c._session.get.return_value = MagicMock(status_code=503)
    assert c.probe() is False
    c._session.get.side_effect = Exception("conn refused")
    assert c.probe() is False


def test_available_now_caches_and_marks():
    _, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    assert c.available_now(60) is True
    c.mark_unavailable()                      # worker saw 5xx
    c._session.get.reset_mock()
    assert c.available_now(60) is False       # gated — no fresh probe
    assert c._session.get.call_count == 0


def test_backend_availability_delegates():
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    assert b.probe() is True
    assert b.available_now(60) is True
    b.mark_unavailable()
    assert c._avail_ok is False
    c.wait_ready = MagicMock(return_value=True)
    assert b.wait_ready(5, 1) is True


# -- check_hash request shape --------------------------------------------------

def test_check_hash_url_and_body():
    b, c = _backend(mode="hash_only", trust_ok=True)
    c._session.get.return_value = _json_resp(200, HASH_OK)
    o = b.submit_once("x", "s256", "abc123sha1", {})
    assert o.kind == "verdict"
    url = c._session.get.call_args.args[0]
    assert url == FIE_HOST + "/check-sample/hash/sha1/abc123sha1"
    assert c._session.get.call_args.kwargs["allow_redirects"] is False


def test_check_hash_non_200_is_error():
    b, c = _backend(mode="hash_only")
    c._session.get.return_value = MagicMock(status_code=500, text="boom")
    o = b.submit_once("x", "s256", "s1", {})
    assert o.kind == "error" and o.http_status == 500
    assert o.error.startswith("http_500")


def test_check_hash_non_dict_body_is_error():
    b, c = _backend(mode="hash_only")
    r = _json_resp(200, None)
    r.json.return_value = ["not", "dict"]
    c._session.get.return_value = r
    o = b.submit_once("x", "s256", "s1", {})
    assert o.kind == "error" and o.error == "invalid check-sample response body"


# -- /scan verdict mapping -----------------------------------------------------

def test_scan_file_raw_body_and_headers(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZ\x90payload")
    c = _client()
    sent = {}

    def capture(url, **kw):
        sent["body"] = kw["data"].read()
        return _json_resp(200, SCAN_MAL)

    c._session.post.side_effect = capture
    st, body, err = c.scan_file(str(f), "sub/dir/a.bin")
    assert st == 200 and err is None and body == SCAN_MAL
    kw = c._session.post.call_args
    assert kw.args[0] == FIE_HOST + "/scan"
    assert kw.kwargs["params"] == {"external_id": "sub/dir/a.bin"}
    assert kw.kwargs["headers"]["Content-Length"] == str(f.stat().st_size)
    assert kw.kwargs["headers"]["Content-Type"] == "application/octet-stream"
    assert kw.kwargs["allow_redirects"] is False
    assert sent["body"] == b"MZ\x90payload"      # raw bytes, not multipart


def test_scan_file_not_found(tmp_path):
    c = _client()
    st, body, err = c.scan_file(str(tmp_path / "gone.bin"), None)
    assert st is None and body is None and err.startswith("file_not_found:")


@pytest.mark.parametrize("raw,cls", [
    ("malicious", "malicious"),
    ("suspicious", "suspicious"),
    ("OK", "goodware"),
    ("weird", "unknown"),       # unrecognized classification -> unknown
    (None, "unknown"),          # missing classification -> unknown
])
def test_scan_verdict_mapping(tmp_path, raw, cls):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    body = {} if raw is None else {"classification": raw}
    c._session.post.return_value = _json_resp(200, body)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.kind == "verdict" and o.classification == cls
    assert o.http_status == 200
    assert o.report_json == body                    # raw response carried


def test_scan_verdict_threat_fields(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = _json_resp(200, SCAN_MAL)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.threat_name == "Win32.Evil"
    assert o.threat_factor == 37


def test_scan_verdict_missing_threat_details(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = _json_resp(200, {"classification": "OK"})
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.threat_name is None and o.threat_factor is None


# -- external_id modes ----------------------------------------------------------

def test_external_id_rel_path_uses_meta(tmp_path):
    f = tmp_path / "real.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan", external_id="rel_path")
    c._session.post.return_value = _json_resp(200, SCAN_OK)
    b.submit_once(str(f), "s256", "s1", {"rel_path": "usb/docs/real.bin"})
    assert c._session.post.call_args.kwargs["params"] == {
        "external_id": "usb/docs/real.bin"}


def test_external_id_rel_path_falls_back_to_basename(tmp_path):
    f = tmp_path / "real.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan", external_id="rel_path")
    c._session.post.return_value = _json_resp(200, SCAN_OK)
    b.submit_once(str(f), "s256", "s1", {})        # no meta rel_path
    assert c._session.post.call_args.kwargs["params"] == {
        "external_id": "real.bin"}


def test_external_id_filename(tmp_path):
    f = tmp_path / "real.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan", external_id="filename")
    c._session.post.return_value = _json_resp(200, SCAN_OK)
    b.submit_once(str(f), "s256", "s1", {"rel_path": "ignored/rel.bin"})
    assert c._session.post.call_args.kwargs["params"] == {
        "external_id": "real.bin"}


def test_external_id_none_omits_param(tmp_path):
    f = tmp_path / "real.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan", external_id="none")
    c._session.post.return_value = _json_resp(200, SCAN_OK)
    b.submit_once(str(f), "s256", "s1", {"rel_path": "usb/x.bin"})
    assert c._session.post.call_args.kwargs["params"] is None


# -- submit modes ---------------------------------------------------------------

def test_mode_scan_skips_check_hash(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = _json_resp(200, SCAN_MAL)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.kind == "verdict" and o.classification == "malicious"
    assert c._session.get.call_count == 0        # no /check-sample call


def test_hash_then_scan_malicious_no_upload(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_then_scan")
    c._session.get.return_value = _json_resp(200, SCAN_MAL)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.kind == "verdict" and o.classification == "malicious"
    assert o.threat_name == "Win32.Evil" and o.threat_factor == 37
    assert c._session.post.call_count == 0       # hash hit — no file upload


@pytest.mark.parametrize("cls", ["malicious", "suspicious"])
def test_hash_modes_classified_verdict(tmp_path, cls):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    for mode in ("hash_then_scan", "hash_only"):
        b, c = _backend(mode=mode)
        c._session.get.return_value = _json_resp(200, {"classification": cls})
        o = b.submit_once(str(f), "s256", "s1", {})
        assert (mode, o.kind, o.classification) == (mode, "verdict", cls)
        assert c._session.post.call_count == 0


def test_hash_then_scan_ok_falls_through_to_scan(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_then_scan", trust_ok=False)
    c._session.get.return_value = _json_resp(200, HASH_OK)
    c._session.post.return_value = _json_resp(200, SCAN_MAL)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.classification == "malicious"       # scan verdict, not hash 'OK'
    assert c._session.post.call_count == 1
    assert o.report_json == SCAN_MAL


def test_hash_then_scan_ok_trusted_is_goodware(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_then_scan", trust_ok=True)
    c._session.get.return_value = _json_resp(200, HASH_OK)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.classification == "goodware"
    assert o.report_json == HASH_OK
    assert c._session.post.call_count == 0       # trusted OK — no upload


def test_hash_then_scan_unrecognized_falls_through(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_then_scan")
    c._session.get.return_value = _json_resp(200, {"classification": "wat"})
    c._session.post.return_value = _json_resp(200, SCAN_OK)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.classification == "goodware"        # scan result wins
    assert c._session.post.call_count == 1


def test_hash_only_ok_untrusted_is_unknown(tmp_path):
    """'OK' + !trust_ok is ambiguous (unseen vs clean) — record 'unknown'
    with the raw response preserved."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_only", trust_ok=False)
    c._session.get.return_value = _json_resp(200, HASH_OK)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.kind == "verdict" and o.classification == "unknown"
    assert o.report_json == HASH_OK
    assert c._session.post.call_count == 0


def test_hash_only_ok_trusted_is_goodware(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_only", trust_ok=True)
    c._session.get.return_value = _json_resp(200, HASH_OK)
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.classification == "goodware"
    assert c._session.post.call_count == 0


def test_hash_only_unrecognized_is_unknown(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="hash_only")
    c._session.get.return_value = _json_resp(200, {"classification": "huh"})
    o = b.submit_once(str(f), "s256", "s1", {})
    assert o.classification == "unknown"


# -- error taxonomy --------------------------------------------------------------

def test_permanent_400_error(tmp_path):
    """400 (size limit/malformed) is permanent — no retry."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = MagicMock(status_code=400, text="too big")
    o = b.submit_with_backoff(str(f), "s256", "s1", {}, _cfg())
    assert o.kind == "error" and o.http_status == 400
    assert c._session.post.call_count == 1        # single attempt


def test_permanent_413_error(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = MagicMock(status_code=413, text="too big")
    o = b.submit_with_backoff(str(f), "s256", "s1", {}, _cfg())
    assert o.kind == "error" and o.http_status == 413
    assert c._session.post.call_count == 1


@pytest.mark.parametrize("status", [429, 524])
def test_retriable_statuses_retry_then_verdict(tmp_path, status):
    """429 (saturated) and 524 (FIE analysis timeout) retry — the second
    attempt's verdict must surface."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    busy = MagicMock(status_code=status, text="busy")
    ok = _json_resp(200, SCAN_MAL)
    c._session.post.side_effect = [busy, ok]
    # session.get serves /readyz probes (avail_probe_seconds=0 probes each
    # attempt + wait_ready after failure) — always ready here.
    c._session.get.return_value = MagicMock(status_code=200)
    o = b.submit_with_backoff(str(f), "s256", "s1", {}, _cfg())
    assert o.kind == "verdict" and o.classification == "malicious"
    assert c._session.post.call_count == 2


def test_5xx_marks_unavailable(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = MagicMock(status_code=503, text="down")
    c._session.get.return_value = MagicMock(status_code=503)
    o = b.submit_with_backoff(str(f), "s256", "s1", {},
                              _cfg(max_upload_attempts=2))
    assert o.kind == "error" and o.http_status == 503
    assert c._avail_ok is False                   # shared cache stamped
    assert c._session.post.call_count == 2        # retried within budget


def test_conn_error_marks_unavailable_and_retries(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    ok = _json_resp(200, SCAN_OK)
    c._session.post.side_effect = [Exception("conn reset"), ok]
    c._session.get.return_value = MagicMock(status_code=200)
    o = b.submit_with_backoff(str(f), "s256", "s1", {}, _cfg())
    assert o.kind == "verdict" and o.classification == "goodware"
    assert c._session.post.call_count == 2


def test_backoff_exhaustion_returns_last_error(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(mode="scan")
    c._session.post.return_value = MagicMock(status_code=500, text="boom")
    c._session.get.return_value = MagicMock(status_code=200)
    o = b.submit_with_backoff(str(f), "s256", "s1", {},
                              _cfg(max_upload_attempts=3))
    assert o.kind == "error" and o.http_status == 500
    assert c._session.post.call_count == 3


# -- factory --------------------------------------------------------------------

def test_make_backend_fie():
    args = fs.argparse.Namespace(
        backend="fie", fie_host="http://fie.local:8000/",
        fie_mode="hash_then_scan", fie_trust_ok=False,
        fie_external_id="rel_path", no_verify_ssl=True, proxy="http://p:3128")
    b = fs.make_backend(args)
    assert isinstance(b, fs.FieBackend)
    assert isinstance(b, fs.ScanBackend)
    assert b.client.host == "http://fie.local:8000"   # trailing slash stripped
    assert b.client._verify is False
    assert b.client._proxies == {"http": "http://p:3128",
                               "https": "http://p:3128"}


def test_make_backend_fie_requires_host():
    args = fs.argparse.Namespace(
        backend="fie", fie_host="", fie_mode="scan", fie_trust_ok=False,
        fie_external_id="none", no_verify_ssl=False, proxy="")
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(args)
    assert ei.value.code == 2


def test_fie_session_has_no_auth_header():
    """FIE is unauthenticated — the session must carry no Authorization."""
    c = fs.FieClient(FIE_HOST)
    s = c._sess()
    assert "Authorization" not in s.headers
    assert s.trust_env is False
