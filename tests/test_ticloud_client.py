# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Tests for TiCloudClient — HTTP Basic auth, spex two-step upload (binary +
meta XML), meta-only retry path, TCA-0101 bulk/single reputation queries,
min_interval pacing, error taxonomy, credential redaction, redirects
disabled. MagicMock session injection mirrors test_a1000_client.py."""
import base64
import time

import pytest

import filescanner as fs
from unittest.mock import MagicMock


TICLOUD_HOST = "https://ticloud.local"
SHA1 = "b" * 40
SHA256 = "a" * 64
USER = "user@example.com"
PASS = "pw-secret"


def _client(**kw):
    base = dict(username=USER, password=PASS, min_interval_ms=0)
    base.update(kw)
    c = fs.TiCloudClient(TICLOUD_HOST, **base)
    c._session = MagicMock()
    return c


def _json_resp(status, body):
    r = MagicMock(status_code=status)
    if body is not None:
        r.json.return_value = body
    return r


def _bulk_resp(entries, invalid=None):
    rl = {"entries": entries}
    if invalid is not None:
        rl["invalid_hashes"] = invalid
    return _json_resp(200, {"rl": rl})


ENTRY_MAL = {"sha256": SHA256, "status": "MALICIOUS",
             "threat_name": "Win32.Backdoor.Poison", "threat_level": 9,
             "trust_factor": 0, "scanner_count": 41, "scanner_match": 38}


# -- session / auth -----------------------------------------------------------

def test_session_basic_auth_header_and_env_isolation():
    """Authorization: Basic rides on the session; env must not override
    verify/proxy (same contract as A1000Client)."""
    c = fs.TiCloudClient(TICLOUD_HOST, USER, PASS,
                         verify_ssl=False, proxy="http://p:3128")
    s = c._sess()
    want = "Basic " + base64.b64encode(
        f"{USER}:{PASS}".encode("latin-1")).decode("ascii")
    assert s.headers["Authorization"] == want
    assert s.trust_env is False
    assert s.verify is False
    assert s.proxies == {"http": "http://p:3128", "https": "http://p:3128"}


# -- probe / availability -----------------------------------------------------

@pytest.mark.parametrize("status", [200, 302, 401, 403, 404])
def test_probe_any_response_under_500_is_up(status):
    c = _client()
    c._session.get.return_value = MagicMock(status_code=status)
    assert c.probe() is True
    call = c._session.get.call_args
    assert call.args[0] == TICLOUD_HOST + "/"
    assert call.kwargs["allow_redirects"] is False


def test_probe_5xx_and_conn_error_down():
    c = _client()
    c._session.get.return_value = MagicMock(status_code=503)
    assert c.probe() is False
    c._session.get.side_effect = Exception("conn refused")
    assert c.probe() is False
    assert c.probe_status() is None


def test_available_now_caches_and_marks():
    c = _client()
    c._session.get.return_value = MagicMock(status_code=200)
    assert c.available_now(60) is True
    c.mark_unavailable()
    c._session.get.reset_mock()
    assert c.available_now(60) is False      # gated — no fresh probe
    assert c._session.get.call_count == 0


# -- upload_sample --------------------------------------------------------------

def test_upload_sample_posts_octet_stream(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZpayload")
    c = _client()
    c._session.post.return_value = MagicMock(status_code=200, text="")
    st, ok, err = c.upload_sample(SHA1, str(f))
    assert err is None and ok is True and st == 200
    call = c._session.post.call_args
    assert call.args[0] == TICLOUD_HOST + f"/api/spex/upload/{SHA1}"
    assert call.kwargs["headers"]["Content-Type"] == \
        "application/octet-stream"
    assert call.kwargs["allow_redirects"] is False
    assert call.kwargs["timeout"] == (30, 300)   # upload_timeout default
    body = b"".join(call.kwargs["data"])
    assert body == b"MZpayload"                  # streamed, not buffered
    assert len(call.kwargs["data"]) == len(b"MZpayload")


def test_upload_sample_sha1_lowercased(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.post.return_value = MagicMock(status_code=200, text="")
    c.upload_sample(SHA1.upper(), str(f))
    assert c._session.post.call_args.args[0] == \
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}"


def test_upload_sample_invalid_sha1_no_request(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    st, ok, err = c.upload_sample("not-a-sha1", str(f))
    assert (st, ok) == (None, None) and err == "invalid sha1"
    assert c._session.post.call_count == 0


def test_upload_sample_file_not_found(tmp_path):
    c = _client()
    st, ok, err = c.upload_sample(SHA1, str(tmp_path / "gone.bin"))
    assert (st, ok) == (None, None) and err.startswith("file_not_found:")


@pytest.mark.parametrize("status", [400, 401, 403, 413, 500])
def test_upload_sample_non_2xx_is_error(tmp_path, status):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.post.return_value = MagicMock(status_code=status, text="err")
    st, ok, err = c.upload_sample(SHA1, str(f))
    assert ok is None and st == status and err.startswith(f"http_{status}")


# -- upload_meta -----------------------------------------------------------------

def test_meta_xml_shape_exact():
    xml = fs.TiCloudClient._meta_xml("/tmp/dir/evil.exe", "corp.local", "")
    assert xml == (
        "<rl><properties><property><name>filename</name>"
        "<value>evil.exe</value></property><property><name>source</name>"
        "<value>filescanner</value></property></properties>"
        "<domain>corp.local</domain></rl>")


def test_meta_xml_domain_empty_and_archive():
    xml = fs.TiCloudClient._meta_xml("a.bin", "", "in&fected")
    assert "<domain></domain>" in xml
    assert ("<archive><archive_passwords><password>in&amp;fected"
            "</password></archive_passwords></archive>") in xml
    # no archive element without a password
    xml2 = fs.TiCloudClient._meta_xml("a.bin", "d", "")
    assert "<archive>" not in xml2


def test_meta_xml_escapes_values():
    xml = fs.TiCloudClient._meta_xml('a<b>&"c".bin', "<dom&>", "p<x")
    assert 'a<b>' not in xml and "<dom&>" not in xml and "p<x" not in xml
    assert "a&lt;b&gt;&amp;&quot;c&quot;.bin" in xml
    assert "&lt;dom&amp;&gt;" in xml and "p&lt;x" in xml


def test_upload_meta_posts_xml(tmp_path):
    c = _client()
    c._session.post.return_value = MagicMock(status_code=200, text="")
    st, ok, err = c.upload_meta(SHA1, "/x/evil.exe", "corp.local", "pw1")
    assert err is None and ok is True and st == 200
    call = c._session.post.call_args
    assert call.args[0] == TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta"
    assert call.kwargs["headers"]["Content-Type"] == \
        "application/octet-stream"
    assert call.kwargs["allow_redirects"] is False
    body = call.kwargs["data"].decode("utf-8")
    assert "<value>evil.exe</value>" in body
    assert "<domain>corp.local</domain>" in body
    assert "<password>pw1</password>" in body


# -- two-step submit --------------------------------------------------------------

def test_submit_sample_two_step_order(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZpayload")
    c = _client()
    c._session.post.return_value = MagicMock(status_code=200, text="")
    st, ok, err = c.submit_sample(SHA1, str(f), domain="corp.local")
    assert err is None and ok is True
    urls = [call.args[0] for call in c._session.post.call_args_list]
    assert urls == [TICLOUD_HOST + f"/api/spex/upload/{SHA1}",
                    TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta"]
    # basename of filepath used when filename not passed
    meta_body = c._session.post.call_args_list[1].kwargs["data"].decode()
    assert "<value>a.bin</value>" in meta_body


def test_submit_sample_meta_failure_is_meta_failed(tmp_path):
    """Meta failure after a good binary upload -> 'meta_failed:' prefix; a
    retry with sample_uploaded=True posts ONLY the meta step."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.post.side_effect = [
        MagicMock(status_code=200, text=""),   # binary stored
        MagicMock(status_code=500, text="meta boom")]
    st, ok, err = c.submit_sample(SHA1, str(f))
    assert ok is None and st == 500
    assert err.startswith("meta_failed: http_500")
    # meta-only retry: binary must NOT be re-posted
    c._session.post.side_effect = [MagicMock(status_code=200, text="")]
    st, ok, err = c.submit_sample(SHA1, str(f), sample_uploaded=True)
    assert err is None and ok is True
    urls = [call.args[0] for call in c._session.post.call_args_list]
    assert urls == [
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}",
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta",
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta"]


# -- pacing -----------------------------------------------------------------------

def test_spex_pacing_honored(tmp_path):
    """Two spex POSTs are separated by at least min_interval_ms via the
    shared monotonic timestamp."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client(min_interval_ms=60)
    c._session.post.return_value = MagicMock(status_code=200, text="")
    t0 = time.monotonic()
    c.upload_sample(SHA1, str(f))
    c.upload_sample(SHA1, str(f))
    assert time.monotonic() - t0 >= 0.055


def test_spex_pacing_not_applied_to_reputation():
    """Reputation calls are not spex POSTs — no pacing wait."""
    c = _client(min_interval_ms=60000)
    c._session.post.return_value = _bulk_resp([ENTRY_MAL])
    t0 = time.monotonic()
    c.reputation_bulk([SHA256])
    assert time.monotonic() - t0 < 5


# -- reputation_bulk ------------------------------------------------------------

def test_bulk_payload_url_and_parse():
    c = _client()
    invalid = [{"hash_value": "bad-hash", "reason": "invalid"}]
    c._session.post.return_value = _bulk_resp([ENTRY_MAL], invalid)
    st, res, err = c.reputation_bulk([SHA256])
    assert err is None and st == 200
    entries, inv = res
    assert entries == [ENTRY_MAL] and inv == invalid
    call = c._session.post.call_args
    assert call.args[0] == (TICLOUD_HOST +
                            "/api/databrowser/malware_presence/"
                            "bulk_query/json?extended=true")
    assert call.kwargs["json"] == {"rl": {"query": {
        "hash_type": "sha256", "hashes": [SHA256]}}}
    assert call.kwargs["allow_redirects"] is False


def test_bulk_chunks_at_100_and_merges():
    c = _client()
    seen_sizes = []

    def answer(url, **kw):
        hs = kw["json"]["rl"]["query"]["hashes"]
        seen_sizes.append(len(hs))
        return _bulk_resp(
            [{"hash_value": h, "status": "UNKNOWN"} for h in hs],
            ["bad"] if len(seen_sizes) == 2 else [])

    c._session.post.side_effect = answer
    hashes = [f"{i:064x}" for i in range(250)]
    st, res, err = c.reputation_bulk(hashes)
    assert err is None
    entries, invalid = res
    assert seen_sizes == [100, 100, 50]      # API max 100 per call
    assert len(entries) == 250 and invalid == ["bad"]


def test_bulk_extended_false_in_url():
    c = _client(extended=False)
    c._session.post.return_value = _bulk_resp([])
    c.reputation_bulk([SHA256])
    assert "extended=false" in c._session.post.call_args.args[0]


def test_bulk_hash_type_param():
    c = _client()
    c._session.post.return_value = _bulk_resp([])
    c.reputation_bulk([SHA1], hash_type="sha1")
    q = c._session.post.call_args.kwargs["json"]["rl"]["query"]
    assert q["hash_type"] == "sha1"


def test_bulk_invalid_hash_type_no_request():
    c = _client()
    st, res, err = c.reputation_bulk([SHA256], hash_type="sha512")
    assert (st, res) == (None, None) and "invalid hash_type" in err
    assert c._session.post.call_count == 0


def test_bulk_error_and_bad_body():
    c = _client()
    c._session.post.return_value = MagicMock(status_code=503, text="down")
    st, res, err = c.reputation_bulk([SHA256])
    assert res is None and st == 503 and err.startswith("http_503")
    # conn error
    c._session.post.side_effect = Exception("conn reset")
    st, res, err = c.reputation_bulk([SHA256])
    assert res is None and st is None and err.startswith("request_error:")
    # malformed bodies
    c._session.post.side_effect = None
    for bad in ({"unexpected": 1}, {"rl": {"entries": "nope"}},
                {"rl": {"invalid_hashes": "nope"}}, ["not", "dict"]):
        c._session.post.return_value = _json_resp(200, bad)
        st, res, err = c.reputation_bulk([SHA256])
        assert res is None and err == "invalid reputation response body", bad


# -- reputation_single ------------------------------------------------------------

def test_single_url_and_entry():
    c = _client()
    c._session.get.return_value = _json_resp(
        200, {"rl": {"entries": [ENTRY_MAL]}})
    st, ent, err = c.reputation_single(SHA256, "sha256")
    assert err is None and st == 200 and ent == ENTRY_MAL
    call = c._session.get.call_args
    assert call.args[0] == (TICLOUD_HOST +
                            "/api/databrowser/malware_presence/query/"
                            f"sha256/{SHA256}?extended=true")
    assert call.kwargs["allow_redirects"] is False


def test_single_entry_dict_form():
    """Servers that answer rl.entry instead of rl.entries are handled."""
    c = _client()
    c._session.get.return_value = _json_resp(
        200, {"rl": {"entry": ENTRY_MAL}})
    st, ent, err = c.reputation_single(SHA256)
    assert err is None and ent == ENTRY_MAL


def test_single_errors():
    c = _client()
    st, ent, err = c.reputation_single("zz", "sha256")
    assert ent is None and err == "invalid hash"
    st, ent, err = c.reputation_single(SHA256, "crc32")
    assert ent is None and "invalid hash_type" in err
    assert c._session.get.call_count == 0
    c._session.get.return_value = MagicMock(status_code=404, text="gone")
    st, ent, err = c.reputation_single(SHA256)
    assert ent is None and st == 404 and err.startswith("http_404")
    c._session.get.return_value = _json_resp(200, {"rl": {}})
    st, ent, err = c.reputation_single(SHA256)
    assert ent is None and err == "no entry in response"


# -- normalize_reputation_entry ---------------------------------------------------

@pytest.mark.parametrize("entry,want_cls,want_factor", [
    ({"status": "MALICIOUS", "threat_name": "T", "threat_level": 9,
      "trust_factor": 0}, "malicious", 9),
    ({"status": "SUSPICIOUS", "threat_name": "S", "threat_level": 5},
     "suspicious", 5),
    ({"status": "KNOWN", "trust_factor": 4}, "goodware", 4),
    ({"status": "UNKNOWN"}, "unknown", None),
    ({"status": "weird"}, "unknown", None),        # unrecognized -> unknown
    ({"status": "malicious", "threat_level": 3}, "malicious", 3),  # case
    ({}, "unknown", None),
])
def test_normalize_reputation_entry(entry, want_cls, want_factor):
    v = fs.normalize_reputation_entry(entry)
    assert v["classification"] == want_cls
    assert v["threat_factor"] == want_factor
    assert v["raw"] == entry


def test_normalize_reputation_entry_fields():
    v = fs.normalize_reputation_entry(ENTRY_MAL)
    assert v["classification"] == "malicious"
    assert v["threat_name"] == "Win32.Backdoor.Poison"
    assert v["threat_factor"] == 9           # threat_level, not trust_factor
    assert v["raw"] is ENTRY_MAL             # extended fields preserved
    # KNOWN uses trust_factor instead of threat_level
    v = fs.normalize_reputation_entry(
        {"status": "KNOWN", "threat_level": 9, "trust_factor": 2})
    assert v["classification"] == "goodware" and v["threat_factor"] == 2
    # non-dict and junk factors are safe
    assert fs.normalize_reputation_entry(None)["classification"] == "unknown"
    v = fs.normalize_reputation_entry(
        {"status": "MALICIOUS", "threat_level": True})
    assert v["threat_factor"] is None
    v = fs.normalize_reputation_entry(
        {"status": "KNOWN", "trust_factor": "high"})
    assert v["threat_factor"] is None


# -- error taxonomy ---------------------------------------------------------------

def test_error_taxonomy_constants():
    assert fs.TICLOUD_AUTH_STATUSES == frozenset({401, 403})
    assert fs.TICLOUD_PERMANENT_STATUSES == frozenset({413})
    assert {408, 429} <= fs.TICLOUD_RETRIABLE_STATUSES


@pytest.mark.parametrize("status", [401, 403])
def test_auth_error_status_surfaced(tmp_path, status):
    """401/403 surface their status so the factory can fail fast — the same
    code path the probe_status check uses."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.post.return_value = MagicMock(status_code=status,
                                             text="denied")
    st, ok, err = c.upload_sample(SHA1, str(f))
    assert st in fs.TICLOUD_AUTH_STATUSES and ok is None
    assert err.startswith(f"http_{status}")
    c._session.get.return_value = MagicMock(status_code=status)
    assert c.probe_status() in fs.TICLOUD_AUTH_STATUSES


# -- credentials ------------------------------------------------------------------

def test_credentials_never_in_error_strings(tmp_path):
    """A response echoing the Basic credentials must be redacted — password
    AND username — in http_* and request_error strings alike."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.post.return_value = MagicMock(
        status_code=500,
        text=f"failure details: {USER}:{PASS} echoed")
    st, ok, err = c.upload_sample(SHA1, str(f))
    assert PASS not in err and USER not in err and "***" in err
    c._session.post.side_effect = Exception(f"conn fail {PASS}")
    st, ok, err = c.upload_meta(SHA1, "a.bin")
    assert PASS not in err and err.startswith("request_error:")


def test_http_calls_never_follow_redirects(tmp_path):
    """allow_redirects=False on every request — a redirect would re-send the
    file body and the Basic credentials to a foreign origin."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    c = _client()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.return_value = MagicMock(
        status_code=200, text="",
        json=MagicMock(return_value={"rl": {"entries": []}}))
    c.probe()
    assert c._session.get.call_args.kwargs["allow_redirects"] is False
    c.upload_sample(SHA1, str(f))
    assert c._session.post.call_args.kwargs["allow_redirects"] is False
    c.upload_meta(SHA1, "a.bin")
    assert c._session.post.call_args.kwargs["allow_redirects"] is False
    c.reputation_bulk([SHA256])
    assert c._session.post.call_args.kwargs["allow_redirects"] is False
    c.reputation_single(SHA256)
    assert c._session.get.call_args.kwargs["allow_redirects"] is False
