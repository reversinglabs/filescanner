# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import textwrap, pathlib
import pytest
import filescanner as fs

def _write(tmp_path, body):
    p = tmp_path / "config.ini"
    p.write_text(textwrap.dedent(body))
    return p

def test_load_config_parses_pipeline_section(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTRA_TOKEN", "abc123")
    cfg = _write(tmp_path, """
        [detect]
        host = https://detect.example.com
        token = ${SPECTRA_TOKEN}
        [scan]
        drive = E:\\
        [pipeline]
        upload_workers = 12
        report_wait_hours = 6
        [backoff]
        base_seconds = 3
        """)
    args = fs.load_config(str(cfg))
    assert args.upload_workers == 12
    assert args.report_wait_hours == 6
    assert args.backoff_base_seconds == 3
    assert args.token == "abc123"          # env var expanded
    # defaults from unset keys/sections
    assert args.result_poll_interval == 2
    assert args.retention_days == 7
    assert args.max_upload_attempts == 8

def test_load_config_expands_missing_env_to_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("SPECTRA_TOKEN", raising=False)
    cfg = _write(tmp_path, """
        [detect]
        host = https://x
        token = ${SPECTRA_TOKEN}
        [scan]
        drive = E:\\
        """)
    args = fs.load_config(str(cfg))
    assert args.token == ""

def test_load_config_percent_token_no_interpolation(tmp_path):
    """A literal '%' in a token must not crash the ConfigParser."""
    cfg = _write(tmp_path, """
        [detect]
        host = https://x
        token = ab%cd%ef
        proxy = http://user%40corp:pw%25x@proxy:8080
        [scan]
        drive = E:\\
        """)
    args = fs.load_config(str(cfg))
    assert args.token == "ab%cd%ef"
    assert args.proxy == "http://user%40corp:pw%25x@proxy:8080"

def test_expand_env_bare_dollar_stays_literal(tmp_path, monkeypatch):
    """$VAR without braces is literal (tokens may contain '$'); ${VAR} works."""
    monkeypatch.setenv("SPECTRA_TOKEN", "abc123")
    cfg = _write(tmp_path, """
        [detect]
        host = https://x
        token = tok$SPECTRA_TOKEN-part
        [scan]
        drive = E:\\
        """)
    args = fs.load_config(str(cfg))
    assert args.token == "tok$SPECTRA_TOKEN-part"   # bare $VAR not expanded


def test_load_config_pipeline_workers_beats_legacy_alias(tmp_path):
    p = tmp_path / "c.ini"
    p.write_text("[pipeline]\nupload_workers = 25\n[output]\nworkers = 3\n")
    a = fs.load_config(str(p))
    assert a.upload_workers == 25
    assert a.workers == 25


def test_load_config_legacy_workers_alias_applies_when_pipeline_absent(tmp_path):
    p = tmp_path / "c.ini"
    p.write_text("[output]\nworkers = 7\n")
    a = fs.load_config(str(p))
    assert a.upload_workers == 7


def test_load_config_backend_sections_defaults(tmp_path):
    """Absent backend sections must yield the spec defaults so existing
    detect-only configs keep working unchanged."""
    cfg = _write(tmp_path, """
        [detect]
        host = https://x
        token = t
        [scan]
        drive = E:\\
        """)
    a = fs.load_config(str(cfg))
    assert a.backend == "detect"
    assert a.fie_host == ""
    assert a.fie_mode == "hash_then_scan"
    assert a.fie_trust_ok is False
    assert a.fie_external_id == "rel_path"
    assert a.a1000_host == ""
    assert a.a1000_token == ""
    assert a.a1000_analysis == "cloud"
    assert a.a1000_tags == ""
    assert a.a1000_comment == ""
    assert a.a1000_archive_password == ""
    assert a.a1000_sandbox_platform == ""
    assert a.a1000_report_detail == "summary"
    assert a.ticloud_host == "https://data.reversinglabs.com"
    assert a.ticloud_username == ""
    assert a.ticloud_password == ""
    assert a.ticloud_domain == ""
    assert a.ticloud_archive_password == ""
    assert a.ticloud_upload_timeout == 300
    assert a.ticloud_min_interval_ms == 100
    assert a.ticloud_extended is True
    assert a.reputation_precheck is False
    assert a.reputation_batch_size == 100
    assert a.reputation_skip_classified is True


def test_load_config_backend_sections_parsed(tmp_path, monkeypatch):
    monkeypatch.setenv("A1000_TOKEN", "tok1")
    monkeypatch.setenv("TICLOUD_USER", "u1")
    monkeypatch.setenv("TICLOUD_PASS", "p1")
    cfg = _write(tmp_path, """
        [scan]
        backend = a1000
        drive = E:\\
        [fie]
        host = http://fie.local:8000
        mode = hash_only
        trust_ok = true
        external_id = filename
        [a1000]
        host = https://a1000.example.com
        token = ${A1000_TOKEN}
        analysis = local
        tags = usb,batch1
        comment = hello
        archive_password = infected
        sandbox_platform = windows10
        report_detail = full
        [ticloud]
        host = https://ticloud.example.com
        username = ${TICLOUD_USER}
        password = ${TICLOUD_PASS}
        domain = corp.local
        archive_password = infected
        upload_timeout = 600
        min_interval_ms = 250
        extended = false
        [reputation]
        precheck = true
        batch_size = 50
        skip_classified = false
        """)
    a = fs.load_config(str(cfg))
    assert a.backend == "a1000"
    assert a.fie_host == "http://fie.local:8000"
    assert a.fie_mode == "hash_only"
    assert a.fie_trust_ok is True
    assert a.fie_external_id == "filename"
    assert a.a1000_host == "https://a1000.example.com"
    assert a.a1000_token == "tok1"          # env var expanded
    assert a.a1000_analysis == "local"
    assert a.a1000_tags == "usb,batch1"
    assert a.a1000_comment == "hello"
    assert a.a1000_archive_password == "infected"
    assert a.a1000_sandbox_platform == "windows10"
    assert a.a1000_report_detail == "full"
    assert a.ticloud_host == "https://ticloud.example.com"
    assert a.ticloud_username == "u1"
    assert a.ticloud_password == "p1"
    assert a.ticloud_domain == "corp.local"
    assert a.ticloud_archive_password == "infected"
    assert a.ticloud_upload_timeout == 600
    assert a.ticloud_min_interval_ms == 250
    assert a.ticloud_extended is False
    assert a.reputation_precheck is True
    assert a.reputation_batch_size == 50
    assert a.reputation_skip_classified is False


def test_load_config_all_backend_values_accepted(tmp_path):
    for b in ("detect", "a1000", "fie", "cloud"):
        cfg = _write(tmp_path, f"""
            [scan]
            backend = {b}
            """)
        assert fs.load_config(str(cfg)).backend == b


def test_load_config_unknown_backend_is_startup_error(tmp_path):
    """An unknown backend would run the whole pipeline against a client that
    does not exist — fail at startup, not after the first upload."""
    cfg = _write(tmp_path, """
        [scan]
        backend = bogus
        """)
    with pytest.raises(SystemExit):
        fs.load_config(str(cfg))


def test_load_config_a1000_analysis_empty_means_local(tmp_path):
    """An explicitly empty 'analysis' field means local-only analysis — it
    must not silently fall back to the 'cloud' default."""
    cfg = _write(tmp_path, """
        [a1000]
        host = https://a
        analysis =
        """)
    assert fs.load_config(str(cfg)).a1000_analysis == ""


def test_load_config_invalid_enums_fall_back(tmp_path):
    """Non-backend enum typos warn + use the default (same convention as
    cleanup_old_records/read_speed_test); only scan.backend is fatal."""
    cfg = _write(tmp_path, """
        [fie]
        mode = bogus
        external_id = bogus
        [a1000]
        report_detail = bogus
        """)
    a = fs.load_config(str(cfg))
    assert a.fie_mode == "hash_then_scan"
    assert a.fie_external_id == "rel_path"
    assert a.a1000_report_detail == "summary"


def test_load_config_reputation_batch_size_clamped(tmp_path):
    """TCA-0101 bulk accepts at most 100 hashes per call — a larger
    batch_size would make every pre-check batch fail server-side."""
    cfg = _write(tmp_path, """
        [reputation]
        batch_size = 500
        """)
    assert fs.load_config(str(cfg)).reputation_batch_size == 100
