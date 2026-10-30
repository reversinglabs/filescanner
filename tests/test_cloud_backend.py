# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""Tests for CloudBackend — ScanBackend over TiCloudClient: spex two-step
submit (binary + meta XML) yielding a sha1 receipt, meta-only retry on
'meta_failed:', TCA-0101 bulk poll verdict mapping (MALICIOUS/SUSPICIOUS/
KNOWN/UNKNOWN), error taxonomy (413 permanent, 401/403 never retried,
conn/429/5xx retriable + mark_unavailable), factory auth fail-fast and
missing-credentials errors. MagicMock session injection mirrors
test_ticloud_client.py / test_a1000_client.py."""
import pytest

import filescanner as fs
from unittest.mock import MagicMock


TICLOUD_HOST = "https://ticloud.local"
SHA1 = "b" * 40
SHA1_C = "c" * 40
SHA1_D = "d" * 40
SHA1_E = "e" * 40
SHA256 = "a" * 64
USER = "user@example.com"
PASS = "pw-secret"


def _client(**kw):
    base = dict(username=USER, password=PASS, min_interval_ms=0)
    base.update(kw)
    c = fs.TiCloudClient(TICLOUD_HOST, **base)
    c._session = MagicMock()
    return c


def _backend(domain="corp.local", archive_password="", **kw):
    c = _client(**kw)
    return fs.CloudBackend(c, domain=domain,
                           archive_password=archive_password), c


def _cfg(**kw):
    base = dict(backoff_base_seconds=0, backoff_max_seconds=0,
                upload_retry_window=60, max_upload_attempts=3,
                ready_check_interval=0, ready_max_wait=0,
                avail_probe_seconds=0)
    base.update(kw)
    return fs.argparse.Namespace(**base)


def _cloud_args(**kw):
    base = dict(backend="cloud", ticloud_host=TICLOUD_HOST,
                ticloud_username=USER, ticloud_password=PASS,
                ticloud_domain="corp.local",
                ticloud_archive_password="", ticloud_upload_timeout=300,
                ticloud_min_interval_ms=0, ticloud_extended=True,
                no_verify_ssl=False, proxy="")
    base.update(kw)
    return fs.argparse.Namespace(**base)


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


ENTRY_MAL = {"sha1": SHA1, "status": "MALICIOUS",
             "threat_name": "Win32.Backdoor.Poison", "threat_level": 9,
             "trust_factor": 0, "scanner_count": 41, "scanner_match": 38}


# -- contract -----------------------------------------------------------------

def test_cloud_backend_is_scan_backend():
    b, _ = _backend()
    assert isinstance(b, fs.ScanBackend)
    assert b.name == "cloud"
    assert b.needs_sha1 is True and b.is_sync is False


def test_availability_methods_delegate():
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    assert b.probe() is True
    assert b.available_now(60) is True
    b.mark_unavailable()
    assert b.client._avail_ok is False
    c.wait_ready = MagicMock(return_value=True)
    assert b.wait_ready(5, 1) is True


# -- submit_once ----------------------------------------------------------------

def test_submit_once_binary_then_meta_receipt_sha1(tmp_path):
    """Order enforced: POST /api/spex/upload/{sha1} then POST .../meta;
    success -> kind='receipt', ref=sha1."""
    f = tmp_path / "evil.exe"
    f.write_bytes(b"MZpayload")
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=200, text="")
    o = b.submit_once(str(f), SHA256, SHA1, {})
    assert o.kind == "receipt" and o.ref == SHA1 and o.http_status == 200
    urls = [call.args[0] for call in c._session.post.call_args_list]
    assert urls == [TICLOUD_HOST + f"/api/spex/upload/{SHA1}",
                    TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta"]
    meta_body = c._session.post.call_args_list[1].kwargs["data"].decode()
    assert "<value>evil.exe</value>" in meta_body          # basename
    assert "<domain>corp.local</domain>" in meta_body      # cfg domain


def test_submit_once_meta_carries_archive_password(tmp_path):
    f = tmp_path / "a.zip"
    f.write_bytes(b"PK")
    b, c = _backend(archive_password="infected")
    c._session.post.return_value = MagicMock(status_code=200, text="")
    b.submit_once(str(f), SHA256, SHA1, {})
    meta_body = c._session.post.call_args_list[1].kwargs["data"].decode()
    assert "<password>infected</password>" in meta_body


def test_submit_once_binary_error_no_meta(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=500, text="down")
    o = b.submit_once(str(f), SHA256, SHA1, {})
    assert o.kind == "error" and o.http_status == 500
    assert o.error.startswith("http_500")
    # only the binary POST ran — meta never attempted
    urls = [call.args[0] for call in c._session.post.call_args_list]
    assert urls == [TICLOUD_HOST + f"/api/spex/upload/{SHA1}"]


def test_submit_once_meta_failure_flagged(tmp_path):
    """Binary stored but meta fails -> 'meta_failed:' error the retry loop
    can spot (sample is already under its sha1)."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.post.side_effect = [
        MagicMock(status_code=200, text=""),
        MagicMock(status_code=503, text="boom")]
    o = b.submit_once(str(f), SHA256, SHA1, {})
    assert o.kind == "error" and o.http_status == 503
    assert o.error.startswith("meta_failed: http_503")


def test_submit_once_invalid_sha1_no_request(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    o = b.submit_once(str(f), SHA256, "not-a-sha1", {})
    assert o.kind == "error" and o.error == "invalid sha1"
    assert c._session.post.call_count == 0


# -- submit_with_backoff ------------------------------------------------------------

def test_backoff_receipt_first_try(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.return_value = MagicMock(status_code=200, text="")
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {}, _cfg())
    assert o.kind == "receipt" and o.ref == SHA1


def test_backoff_meta_failure_retries_meta_only(tmp_path):
    """meta_failed on attempt 1 -> attempt 2 posts ONLY the meta step —
    the binary is already stored under sha1."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.side_effect = [
        MagicMock(status_code=200, text=""),   # attempt 1: binary stored
        MagicMock(status_code=500, text="m"),  # attempt 1: meta fails
        MagicMock(status_code=200, text="")]   # attempt 2: meta only
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {}, _cfg())
    assert o.kind == "receipt" and o.ref == SHA1
    urls = [call.args[0] for call in c._session.post.call_args_list]
    assert urls == [
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}",
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta",
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta"]


def test_backoff_binary_failure_reuploads_binary(tmp_path):
    """A binary-upload failure is NOT meta_failed — the retry reposts the
    file body."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.side_effect = [
        MagicMock(status_code=500, text="d"),  # attempt 1: binary fails
        MagicMock(status_code=200, text=""),   # attempt 2: binary
        MagicMock(status_code=200, text="")]   # attempt 2: meta
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {}, _cfg())
    assert o.kind == "receipt"
    urls = [call.args[0] for call in c._session.post.call_args_list]
    assert urls == [
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}",
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}",
        TICLOUD_HOST + f"/api/spex/upload/{SHA1}/meta"]


def test_backoff_permanent_413_no_retry(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.return_value = MagicMock(status_code=413, text="big")
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {}, _cfg())
    assert o.kind == "error" and o.http_status == 413
    assert c._session.post.call_count == 1


@pytest.mark.parametrize("status", [401, 403])
def test_backoff_auth_error_never_retried(tmp_path, status):
    """401/403 surface immediately — bad credentials can't recover by
    retrying (the factory's startup probe is the real fail-fast)."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.return_value = MagicMock(status_code=status,
                                             text="denied")
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {}, _cfg())
    assert o.kind == "error" and o.http_status == status
    assert c._session.post.call_count == 1
    assert c._avail_ok is True          # auth errors don't gate availability


@pytest.mark.parametrize("status", [429, 500, 503])
def test_backoff_retriable_marks_unavailable(tmp_path, status):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.return_value = MagicMock(status_code=status, text="")
    # one attempt, zero retry window — the loop breaks before wait_ready
    # can re-probe and flip the cache back.
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {},
                              _cfg(upload_retry_window=0,
                                   max_upload_attempts=1))
    assert o.kind == "error"
    assert c._avail_ok is False          # 429/5xx flips the shared gate


def test_backoff_conn_error_retried(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    b, c = _backend()
    c._session.get.return_value = MagicMock(status_code=200)
    c._session.post.side_effect = [
        Exception("conn reset"),                     # attempt 1
        MagicMock(status_code=200, text=""),         # attempt 2: binary
        MagicMock(status_code=200, text="")]         # attempt 2: meta
    o = b.submit_with_backoff(str(f), SHA256, SHA1, {}, _cfg())
    assert o.kind == "receipt" and o.ref == SHA1


# -- poll_batch -----------------------------------------------------------------

def test_poll_batch_verdict_mapping_all_statuses():
    """One bulk call, four refs -> MALICIOUS/SUSPICIOUS verdicts with
    threat_level, KNOWN with trust_factor, UNKNOWN stays pending."""
    b, c = _backend()
    entries = [
        {"sha1": SHA1, "status": "MALICIOUS",
         "threat_name": "Win32.Backdoor.Poison", "threat_level": 9,
         "trust_factor": 0},
        {"sha1": SHA1_C, "status": "SUSPICIOUS", "threat_name": "Susp",
         "threat_level": 5},
        {"sha1": SHA1_D, "status": "KNOWN", "trust_factor": 4},
        {"sha1": SHA1_E, "status": "UNKNOWN"},
    ]
    c._session.post.return_value = _bulk_resp(entries)
    out = b.poll_batch([{"ref": h} for h in (SHA1, SHA1_C, SHA1_D, SHA1_E)])
    v = out[SHA1]
    assert v["classification"] == "malicious"
    assert v["threat_name"] == "Win32.Backdoor.Poison"
    assert v["threat_factor"] == 9                  # threat_level
    assert v["report_json"] == entries[0]           # raw entry
    v = out[SHA1_C]
    assert v["classification"] == "suspicious" and v["threat_factor"] == 5
    v = out[SHA1_D]
    assert v["classification"] == "goodware" and v["threat_factor"] == 4
    assert out[SHA1_E] == "pending"                 # UNKNOWN waits
    call = c._session.post.call_args
    assert call.kwargs["json"]["rl"]["query"]["hash_type"] == "sha1"
    assert sorted(call.kwargs["json"]["rl"]["query"]["hashes"]) == \
        sorted([SHA1, SHA1_C, SHA1_D, SHA1_E])


def test_poll_batch_uses_row_sha1_over_ref():
    """Refs may carry the row's sha1; it wins over a non-sha1 receipt."""
    b, c = _backend()
    c._session.post.return_value = _bulk_resp([ENTRY_MAL])
    out = b.poll_batch([{"ref": "opaque-receipt", "sha1": SHA1}])
    assert c._session.post.call_args.kwargs["json"]["rl"]["query"][
        "hashes"] == [SHA1]
    assert out["opaque-receipt"]["classification"] == "malicious"


def test_poll_batch_unhashable_ref_pending():
    b, c = _backend()
    out = b.poll_batch([{"ref": "not-a-sha1"}, {}])
    assert out == {"not-a-sha1": "pending"}     # ref-less entries skipped
    assert c._session.post.call_count == 0      # nothing pollable -> no call


def test_poll_batch_bulk_failure_all_pending():
    b, c = _backend()
    c._session.post.return_value = MagicMock(status_code=503, text="down")
    out = b.poll_batch([{"ref": SHA1}, {"ref": SHA1_C}])
    assert out == {SHA1: "pending", SHA1_C: "pending"}


def test_poll_batch_entry_absent_pending():
    """A sha1 the response doesn't echo stays pending."""
    b, c = _backend()
    c._session.post.return_value = _bulk_resp(
        [{"sha256": SHA256, "status": "MALICIOUS", "threat_level": 9}])
    out = b.poll_batch([{"ref": SHA1}])
    assert out[SHA1] == "pending"


def test_poll_batch_entry_matched_by_other_hash_fields():
    """Entries keyed only under sha256/hash_value still resolve to their
    queried sha1 ref."""
    b, c = _backend()
    c._session.post.return_value = _bulk_resp([
        {"sha256": SHA256, "sha1": SHA1, "status": "KNOWN",
         "trust_factor": 7},
        {"hash_value": SHA1_C, "status": "MALICIOUS", "threat_level": 2}])
    out = b.poll_batch([{"ref": SHA1}, {"ref": SHA1_C}])
    assert out[SHA1]["classification"] == "goodware"
    assert out[SHA1]["threat_factor"] == 7
    assert out[SHA1_C]["classification"] == "malicious"


def test_poll_batch_real_query_hash_shape():
    """Regression: the real TCA-0101 response nests the echoed hash under
    query_hash.{sha1,md5,sha256} — NOT flat fields (verified live against
    ticloud01, EICAR entry). Mock shape missed this and every ref would
    poll 'pending' forever."""
    b, c = _backend()
    real_entry = {
        "status": "MALICIOUS",
        "query_hash": {"sha1": SHA1},
        "first_seen": "2011-05-29T19:39:00",
        "last_seen": "2026-10-13T12:49:20",
        "reason": "analyst_sample_override",
        "trust_factor": 5, "threat_level": 2,
        "scanner_count": 36, "scanner_match": 34,
        "scanner_percent": 94.44,
        "threat_name": "DOS.Malware.EICAR",
        "classification": {"is_generic": False, "platform": "DOS",
                           "family_name": "EICAR", "type": "Malware"},
    }
    c._session.post.return_value = _bulk_resp([real_entry])
    out = b.poll_batch([{"ref": SHA1}])
    assert out[SHA1]["classification"] == "malicious"
    assert out[SHA1]["threat_name"] == "DOS.Malware.EICAR"
    assert out[SHA1]["threat_factor"] == 2


def test_poll_batch_invalid_hashes_dont_break_others():
    b, c = _backend()
    c._session.post.return_value = _bulk_resp(
        [ENTRY_MAL], invalid=[{"hash_value": "zz", "reason": "bad"}])
    out = b.poll_batch([{"ref": SHA1}])
    assert out[SHA1]["classification"] == "malicious"


# -- factory --------------------------------------------------------------------

def test_make_backend_cloud(monkeypatch):
    monkeypatch.setattr(fs.TiCloudClient, "probe_status",
                        lambda self, timeout=8: 200)
    b = fs.make_backend(_cloud_args(
        ticloud_archive_password="infected",
        ticloud_domain="corp.local", ticloud_min_interval_ms=250,
        ticloud_extended=False, no_verify_ssl=True,
        proxy="http://p:3128"))
    assert isinstance(b, fs.CloudBackend) and isinstance(b, fs.ScanBackend)
    assert b.name == "cloud"
    assert b.client.host == TICLOUD_HOST
    assert b.client._username == USER and b.client._password == PASS
    assert b.client._verify is False
    assert b.client._proxies == {"http": "http://p:3128",
                               "https": "http://p:3128"}
    assert b.client._upload_timeout == 300
    assert b.client._min_interval == 0.25
    assert b.client._extended is False
    assert b.domain == "corp.local" and b.archive_password == "infected"


def test_make_backend_cloud_requires_host_and_creds():
    for kw in (dict(ticloud_host=""), dict(ticloud_username=""),
               dict(ticloud_password=""), dict(ticloud_username="  ")):
        with pytest.raises(SystemExit) as ei:
            fs.make_backend(_cloud_args(**kw))
        assert ei.value.code == 2


@pytest.mark.parametrize("status", [401, 403])
def test_make_backend_cloud_auth_fail_fast(monkeypatch, status):
    """401/403 on the startup probe means the credentials are wrong —
    exit(2) instead of per-file failures."""
    monkeypatch.setattr(fs.TiCloudClient, "probe_status",
                        lambda self, timeout=8, s=status: s)
    with pytest.raises(SystemExit) as ei:
        fs.make_backend(_cloud_args())
    assert ei.value.code == 2


def test_make_backend_cloud_unreachable_or_5xx_not_fatal(monkeypatch):
    """Conn errors / 5xx at the startup probe are NOT auth failures — the
    backend still constructs and wait_ready becomes the reachability gate."""
    for st in (None, 500, 503, 404):
        monkeypatch.setattr(fs.TiCloudClient, "probe_status",
                            lambda self, timeout=8, s=st: s)
        b = fs.make_backend(_cloud_args())
        assert isinstance(b, fs.CloudBackend)
