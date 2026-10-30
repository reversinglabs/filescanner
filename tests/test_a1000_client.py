# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Tests for A1000Client + A1000Backend — /api/uploads/ multipart submit,
bulk /api/samples/status/ polling, v3 classification + v2 list/details
verdicts, auth fail-fast, error taxonomy. MagicMock session injection
mirrors test_detect_client.py / test_fie_client.py."""
import pytest

import filescanner as fs
from unittest.mock import MagicMock


A1000_HOST = "https://a1000.local"
SHA256 = "a" * 64
SHA1 = "b" * 40


def _client():
    c = fs.A1000Client(A1000_HOST, "tok-secret")
    c._session = MagicMock()
    return c


def _backend(fields=None, report_detail="summary"):
    c = _client()
    return fs.A1000Backend(c, fields=fields,
                           report_detail=report_detail), c


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


def _a1000_args(**kw):
    base = dict(backend="a1000", a1000_host=A1000_HOST,
                a1000_token="tok-secret", a1000_analysis="cloud",
                a1000_tags="", a1000_comment="",
                a1000_archive_password="", a1000_sandbox_platform="",
                a1000_report_detail="summary",
                no_verify_ssl=False, proxy="")
    base.update(kw)
    return fs.argparse.Namespace(**base)


CLS_MAL = {"classification": "MALICIOUS",
           "classification_result": "Win32.Backdoor.Poison",
           "riskscore": 9}


# -- contract ----------------------------------------------------------------

def test_a1000_backend_is_scan_backend():
    b, _ = _backend()
    assert isinstance(b, fs.ScanBackend)
    assert b.name == "a1000"
    assert b.needs_sha1 is False and b.is_sync is False


def test_session_auth_header_and_env_isolation():
    """Authorization: Token rides on the session; env must not override
    verify/proxy (same contract as DetectAsyncClient)."""
    c = fs.A1000Client(A1000_HOST, "tok-secret",
                       verify_ssl=False, proxy="http://p:3128")
    s = c._sess()
    assert s.headers["Authorization"] == "Token tok-secret"
    assert s.trust_env is False
    assert s.verify is False
    assert s.proxies == {"http": "http://p:3128", "https": "http://p:3128"}


# -- probe / availability ------------------------------------------------------

@pytest.mark.parametrize("status", [200, 401, 403, 405])
def test_probe_any_response_under_500_is_up(status):
    _, c = _backend()
    c._session.get.return_value = MagicMock(status_code=status)
    assert c.probe() is True
    url = c._session.get.call_args.args[0]
    assert url == A1000_HOST + "/api/uploads/"
    assert c._session.get.call_args.kwargs["allow_redirects"] is False


def test_probe_5xx_and_conn_error_down():
    _, c = _backend()
    c._session.get.return_value = MagicMock(status_code=503)
    assert c.probe() is False
    c._session.get.side_effect = Exception("conn refused")
    assert c.probe() is False
    assert c.probe_status() is None


def test_available_now_caches_and_marks():
    _, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    assert c.available_now(60) is True
    c.mark_unavailable()
    c._session.get.reset_mock()
    assert c.available_now(60) is False      # gated — no fresh probe
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


# -- upload --------------------------------------------------------------------

def _multipart_body(post_call):
    kw = post_call.kwargs
    return b"".join(kw["data"]), kw


def test_upload_201_returns_sha1_ref(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZpayload")
    b, c = _backend()
    c._session.post.return_value = _json_resp(
        201, {"detail": {"sha1": SHA1}})
    o = b.submit_once(str(f), SHA256, None, {})
    assert o.kind == "receipt" and o.ref == SHA1 and o.http_status == 201
    call = c._session.post.call_args
    assert call.args[0] == A1000_HOST + "/api/uploads/"
    assert call.kwargs["allow_redirects"] is False
    assert call.kwargs["headers"]["Content-Type"].startswith(
        "multipart/form-data; boundary=")


def test_upload_multipart_field_composition(tmp_path):
    """Every configured field lands as its own form part; the file part is
    name='file' with the basename + octet-stream, and the declared
    Content-Length matches the streamed body."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZpayload")
    b, c = _backend(fields={
        "analysis": "cloud", "tags": "usb,batch1", "comment": "hi there",
        "archive_password": "infected",
        "rl_cloud_sandbox_platform": "windows10"})
    c._session.post.return_value = _json_resp(
        201, {"detail": {"sha1": SHA1}})
    o = b.submit_once(str(f), SHA256, None, {})
    assert o.kind == "receipt"
    body, kw = _multipart_body(c._session.post.call_args)
    assert len(body) == len(c._session.post.call_args.kwargs["data"])
    for field, val in [(b"filename", b"a.bin"), (b"analysis", b"cloud"),
                       (b"tags", b"usb,batch1"), (b"comment", b"hi there"),
                       (b"archive_password", b"infected"),
                       (b"rl_cloud_sandbox_platform", b"windows10")]:
        assert (b'name="' + field + b'"\r\n\r\n' + val) in body
    assert b'name="file"; filename="a.bin"' in body
    assert b"Content-Type: application/octet-stream" in body
    assert b"MZpayload" in body
    boundary = kw["headers"]["Content-Type"].split("boundary=")[1].encode()
    assert body.startswith(b"--" + boundary)
    assert body.rstrip().endswith(b"--" + boundary + b"--")


def test_upload_omits_unset_fields(tmp_path):
    """Only non-empty configured fields are sent — analysis=local config
    default still lands, empty tags/comment do not."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend(fields={"analysis": "local", "tags": "",
                            "comment": "", "archive_password": "",
                            "rl_cloud_sandbox_platform": ""})
    c._session.post.return_value = _json_resp(
        201, {"detail": {"sha1": SHA1}})
    b.submit_once(str(f), SHA256, None, {})
    body, _ = _multipart_body(c._session.post.call_args)
    assert b'name="analysis"\r\n\r\nlocal' in body
    for absent in (b'name="tags"', b'name="comment"',
                   b'name="archive_password"',
                   b'name="rl_cloud_sandbox_platform"'):
        assert absent not in body


def test_upload_non_201_is_error(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=403, text="denied")
    o = b.submit_once(str(f), SHA256, None, {})
    assert o.kind == "error" and o.http_status == 403
    assert o.error.startswith("http_403")


def test_upload_201_bad_sha1_is_error(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    for body in ({"detail": {"sha1": "not-hex"}}, {"detail": {}},
                 {"detail": "nope"}, ["not", "dict"], {}):
        c._session.post.return_value = _json_resp(201, body)
        o = b.submit_once(str(f), SHA256, None, {})
        assert o.kind == "error" and o.http_status == 201
        assert o.error in ("no sha1 in response",
                           "invalid upload response body")


def test_upload_file_not_found(tmp_path):
    b, _ = _backend()
    o = b.submit_once(str(tmp_path / "gone.bin"), SHA256, None, {})
    assert o.kind == "error" and o.http_status is None
    assert o.error.startswith("file_not_found:")


def test_token_never_in_error_strings(tmp_path):
    """A response echoing the configured token must be redacted in the error
    string — the token is never logged or surfaced."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.post.return_value = MagicMock(
        status_code=500, text="failure details: Token tok-secret echoed")
    o = b.submit_once(str(f), SHA256, None, {})
    assert o.kind == "error" and "tok-secret" not in o.error
    assert "***" in o.error


# -- status_bulk -----------------------------------------------------------------

def test_status_bulk_map_and_payload():
    c = _client()
    c._session.post.return_value = _json_resp(200, {
        "hash_type": "sha256",
        "results": [{"hash_value": SHA256, "status": "processed"}]})
    st, m, err = c.status_bulk([SHA256])
    assert err is None and st == 200 and m == {SHA256: "processed"}
    call = c._session.post.call_args
    assert call.args[0] == A1000_HOST + "/api/samples/status/"
    assert call.kwargs["json"] == {"hash_values": [SHA256]}
    assert call.kwargs["allow_redirects"] is False


def test_status_bulk_chunks_at_100():
    c = _client()

    def answer(url, **kw):
        return _json_resp(200, {"results": [
            {"hash_value": h, "status": "processed"}
            for h in kw["json"]["hash_values"]]})

    c._session.post.side_effect = answer
    hashes = [f"{i:064x}" for i in range(250)]
    st, m, err = c.status_bulk(hashes)
    assert err is None and len(m) == 250
    sizes = [len(call.kwargs["json"]["hash_values"])
             for call in c._session.post.call_args_list]
    assert sizes == [100, 100, 50]


def test_status_bulk_error_is_none_map():
    c = _client()
    c._session.post.return_value = MagicMock(status_code=500, text="down")
    st, m, err = c.status_bulk([SHA256])
    assert m is None and st == 500 and err.startswith("http_500")
    c._session.post.side_effect = Exception("conn reset")
    st, m, err = c.status_bulk([SHA256])
    assert m is None and st is None and err.startswith("request_error:")


def test_status_bulk_bad_body():
    c = _client()
    c._session.post.return_value = _json_resp(200, {"unexpected": 1})
    st, m, err = c.status_bulk([SHA256])
    assert m is None and err == "invalid status response body"


# -- classification / full_report ----------------------------------------------

def test_classification_url_and_body():
    c = _client()
    c._session.get.return_value = _json_resp(200, CLS_MAL)
    st, body, err = c.classification(SHA256)
    assert err is None and st == 200 and body == CLS_MAL
    call = c._session.get.call_args
    assert call.args[0] == (A1000_HOST + "/api/samples/v3/" + SHA256 +
                            "/classification/")
    assert call.kwargs["allow_redirects"] is False


def test_classification_non_200_is_error():
    c = _client()
    c._session.get.return_value = MagicMock(status_code=404, text="gone")
    st, body, err = c.classification(SHA256)
    assert body is None and st == 404 and err.startswith("http_404")


def test_full_report_payload_and_body():
    c = _client()
    entry = dict(CLS_MAL, sha256=SHA256)
    c._session.post.return_value = _json_resp(
        200, {"count": 1, "results": [entry]})
    st, body, err = c.full_report([SHA256])
    assert err is None and st == 200 and body["results"][0] == entry
    call = c._session.post.call_args
    assert call.args[0] == A1000_HOST + "/api/samples/v2/list/details/"
    payload = call.kwargs["json"]
    assert payload["hash_values"] == [SHA256]
    assert payload["fields"] == list(fs.A1000_DETAIL_FIELDS)
    assert call.kwargs["allow_redirects"] is False


# -- poll_batch ------------------------------------------------------------------

def _status_resp(*pairs):
    return _json_resp(200, {"results": [
        {"hash_value": h, "status": s} for h, s in pairs]})


def test_poll_batch_summary_verdict():
    b, c = _backend()
    c._session.post.return_value = _status_resp((SHA256, "processed"))
    c._session.get.return_value = _json_resp(200, CLS_MAL)
    out = b.poll_batch([{"ref": SHA1, "sha256": SHA256}])
    v = out[SHA1]
    assert v["classification"] == "malicious"
    assert v["threat_name"] == "Win32.Backdoor.Poison"
    assert v["threat_factor"] == 9
    assert v["report_json"] == CLS_MAL
    # status POST went by sha256, classification GET by sha256
    assert c._session.post.call_args.kwargs["json"] == {
        "hash_values": [SHA256]}
    assert SHA256 in c._session.get.call_args.args[0]


@pytest.mark.parametrize("raw,cls", [
    ("MALICIOUS", "malicious"), ("SUSPICIOUS", "suspicious"),
    ("GOODWARE", "goodware"), ("UNKNOWN", "unknown"),
    ("weird", "unknown"),          # unrecognized -> unknown
])
def test_poll_batch_verdict_mapping(raw, cls):
    b, c = _backend()
    c._session.post.return_value = _status_resp((SHA256, "processed"))
    c._session.get.return_value = _json_resp(
        200, {"classification": raw, "classification_result": "T",
              "riskscore": 7})
    out = b.poll_batch([{"ref": SHA1, "sha256": SHA256}])
    v = out[SHA1]
    assert v["classification"] == cls
    assert v["threat_name"] == "T" and v["threat_factor"] == 7


def test_poll_batch_full_report_detail():
    b, c = _backend(report_detail="full")
    entry = dict(CLS_MAL, sha256=SHA256,
                 sample_summary={"file_type": "PE"})
    calls = []

    def post_router(url, **kw):
        calls.append(url)
        if url.endswith("/api/samples/status/"):
            return _status_resp((SHA256, "processed"))
        return _json_resp(200, {"count": 1, "results": [entry]})

    c._session.post.side_effect = post_router
    out = b.poll_batch([{"ref": SHA1, "sha256": SHA256}])
    v = out[SHA1]
    assert v["classification"] == "malicious"
    assert v["report_json"] == entry        # the list/details entry, raw
    assert any("/api/samples/v2/list/details/" in u for u in calls)
    assert c._session.get.call_count == 0   # full mode never hits v3 GET


def test_poll_batch_not_found_and_missing_are_pending():
    b, c = _backend()
    other = "c" * 64
    c._session.post.return_value = _status_resp(
        (SHA256, "not_found"))       # `other` absent from results entirely
    out = b.poll_batch([{"ref": SHA1, "sha256": SHA256},
                        {"ref": "d" * 40, "sha256": other}])
    assert out[SHA1] == "pending"
    assert out["d" * 40] == "pending"
    assert c._session.get.call_count == 0   # no verdict fetch


def test_poll_batch_ref_is_hash_fallback():
    """Refs carry the sha256 in the row dict; when it's absent the receipt
    itself (a sha1 hex) is a valid hash for the status API."""
    b, c = _backend()
    c._session.post.return_value = _status_resp((SHA1, "processed"))
    c._session.get.return_value = _json_resp(200, CLS_MAL)
    out = b.poll_batch([{"ref": SHA1}])
    assert out[SHA1]["classification"] == "malicious"
    assert c._session.post.call_args.kwargs["json"] == {
        "hash_values": [SHA1]}


def test_poll_batch_bulk_error_all_pending():
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=503, text="down")
    out = b.poll_batch([{"ref": SHA1, "sha256": SHA256},
                        {"ref": "d" * 40, "sha256": "c" * 64}])
    assert out == {SHA1: "pending", "d" * 40: "pending"}


def test_poll_batch_verdict_fetch_failure_pending():
    """processed + a failing verdict fetch is transient -> pending."""
    b, c = _backend()
    c._session.post.return_value = _status_resp((SHA256, "processed"))
    c._session.get.return_value = MagicMock(status_code=500, text="boom")
    out = b.poll_batch([{"ref": SHA1, "sha256": SHA256}])
    assert out[SHA1] == "pending"


def test_poll_batch_skips_refless_and_unhashable():
    b, c = _backend()
    c._session.post.return_value = _status_resp((SHA256, "processed"))
    c._session.get.return_value = _json_resp(200, CLS_MAL)
    out = b.poll_batch([{}, {"ref": "not-a-hash"},
                      {"ref": SHA1, "sha256": SHA256}])
    assert out["not-a-hash"] == "pending"     # nothing pollable, keep waiting
    assert out[SHA1]["classification"] == "malicious"


# -- error taxonomy --------------------------------------------------------------

@pytest.mark.parametrize("status", [400, 413])
def test_permanent_statuses_no_retry(tmp_path, status):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=status,
                                             text="bad request")
    o = b.submit_with_backoff(str(f), SHA256, None, {}, _cfg())
    assert o.kind == "error" and o.http_status == status
    assert c._session.post.call_count == 1        # permanent — single attempt


def test_429_retriable_then_receipt_and_unavailable(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    busy = MagicMock(status_code=429, text="saturated")
    ok = _json_resp(201, {"detail": {"sha1": SHA1}})
    c._session.post.side_effect = [busy, ok]
    # session.get serves availability probes — always reachable here
    c._session.get.return_value = MagicMock(status_code=200)
    o = b.submit_with_backoff(str(f), SHA256, None, {}, _cfg())
    assert o.kind == "receipt" and o.ref == SHA1
    assert c._session.post.call_count == 2


def test_5xx_marks_unavailable(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=503, text="down")
    c._session.get.return_value = MagicMock(status_code=503)
    o = b.submit_with_backoff(str(f), SHA256, None, {},
                              _cfg(max_upload_attempts=2))
    assert o.kind == "error" and o.http_status == 503
    assert c._avail_ok is False                   # shared cache stamped
    assert c._session.post.call_count == 2


def test_conn_error_marks_unavailable_and_retries(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    ok = _json_resp(201, {"detail": {"sha1": SHA1}})
    c._session.post.side_effect = [Exception("conn reset"), ok]
    c._session.get.return_value = MagicMock(status_code=200)
    o = b.submit_with_backoff(str(f), SHA256, None, {}, _cfg())
    assert o.kind == "receipt" and o.ref == SHA1
    assert c._session.post.call_count == 2


def test_http_calls_never_follow_redirects(tmp_path):
    """allow_redirects=False on every request — a redirect would re-send the
    file body and Authorization token to a foreign origin."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.return_value = _json_resp(
        200, {"results": []})
    c.probe()
    assert c._session.get.call_args.kwargs["allow_redirects"] is False
    c.status_bulk([SHA256])
    assert c._session.post.call_args.kwargs["allow_redirects"] is False
    c.classification(SHA256)
    assert c._session.get.call_args.kwargs["allow_redirects"] is False
    c.full_report([SHA256])
    assert c._session.post.call_args.kwargs["allow_redirects"] is False
    c.upload(str(f), {})
    assert c._session.post.call_args.kwargs["allow_redirects"] is False


# -- factory ----------------------------------------------------------------------

def test_make_backend_a1000(monkeypatch):
    monkeypatch.setattr(fs.A1000Client, "probe_status",
                        lambda self, timeout=8: 200)
    args = _a1000_args(a1000_tags="usb,batch1", a1000_comment="hello",
                       a1000_archive_password="infected",
                       a1000_sandbox_platform="windows10",
                       a1000_report_detail="full",
                       no_verify_ssl=True, proxy="http://p:3128")
    b = fs.make_backend(args)
    assert isinstance(b, fs.A1000Backend) and isinstance(b, fs.ScanBackend)
    assert b.client.host == A1000_HOST
    assert b.client._token == "tok-secret"
    assert b.client._verify is False
    assert b.client._proxies == {"http": "http://p:3128",
                               "https": "http://p:3128"}
    assert b.fields == {"analysis": "cloud", "tags": "usb,batch1",
                      "comment": "hello", "archive_password": "infected",
                      "rl_cloud_sandbox_platform": "windows10"}
    assert b.report_detail == "full"


def test_make_backend_a1000_empty_fields_omitted(monkeypatch):
    monkeypatch.setattr(fs.A1000Client, "probe_status",
                        lambda self, timeout=8: 200)
    b = fs.make_backend(_a1000_args(a1000_analysis=""))
    assert b.fields == {} and b.report_detail == "summary"


def test_make_backend_a1000_requires_host_and_token():
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(_a1000_args(a1000_host=""))
    assert ei.value.code == 2
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(_a1000_args(a1000_token=""))
    assert ei.value.code == 2


@pytest.mark.parametrize("status", [401, 403])
def test_make_backend_a1000_auth_fail_fast(monkeypatch, status):
    """401/403 on the startup probe means the token is wrong — exit(2)
    instead of per-file failures."""
    monkeypatch.setattr(fs.A1000Client, "probe_status",
                        lambda self, timeout=8: status)
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(_a1000_args())
    assert ei.value.code == 2


def test_make_backend_a1000_unreachable_or_5xx_not_fatal(monkeypatch):
    """Conn errors / 5xx at the startup probe are NOT auth failures — the
    backend still constructs and wait_ready becomes the reachability gate."""
    for st in (None, 500, 503):
        monkeypatch.setattr(fs.A1000Client, "probe_status",
                            lambda self, timeout=8, s=st: s)
        b = fs.make_backend(_a1000_args())
        assert isinstance(b, fs.A1000Backend)
