#!/usr/bin/env python3
# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

"""
filescanner.py — async USB Spectra Detect scanner.

Indexes files on a mounted USB drive and submits each qualifying file to a
ReversingLabs Spectra Detect appliance over the async Worker HTTP API
(no SDK dependency):

    submit -> task_url -> ScanDB (sqlite) -> result poller -> NDJSON + reports

Pipeline (run_scan):
  1. readyz gate: DetectAsyncClient.is_ready() must return 200 before any
     upload starts (falls back to /srv/tiscale/v1/available on 404).
  2. Pre-scan disk-read benchmark (disk_read_gate) warns/blocks below
     scan.min_read_mbps.
  3. Upload worker pool (pipeline.upload_workers) hashes + submits files,
     bounded by pipeline.max_in_flight; per-hash dedup and resume via ScanDB.
  4. Result pollers (pipeline.result_pollers) fetch task_status until
     processed, apply verdict actions (quarantine + alerting), and stream
     records to scan_results.ndjson.
  5. Final JSON/CSV/HTML reports are built from ScanDB, so prior verdicts
     survive re-runs. Rows older than database.retention_days trigger the
     cleanup prompt (database.cleanup_old_records = ask|always|never).

Configuration is INI-driven; see config.ini.template for every section/key.

Usage:
    python filescanner.py --init-config config.ini   # write default config
    python filescanner.py --config config.ini        # run a scan

Requirements:
    pip install requests
    # optional, only if alert_eventlog is enabled on Windows:
    pip install pywin32
"""

import argparse
import configparser
import csv
import hashlib
import html
import itertools
import json
import logging
import os
from logging.handlers import RotatingFileHandler
import queue
import re
import shutil
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Set, Tuple, runtime_checkable



# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "1.0.0"
OUTPUT_FILENAME = "spectra_detect_scan_results.json"
STATE_FILENAME = ".scan_state.json"
ALERTS_FILENAME = "alerts.ndjson"
LOG_FILENAME = "spectra_detect_scan.log"

# ReversingLabs classification enum (numeric form used by some report schemas).
CLASSIFICATION_MAP = {
    0: "unknown",
    1: "goodware",
    2: "suspicious",
    3: "malicious",
}

# Normalisation for string-form classifications found in reports.
CLASSIFICATION_STRING_MAP = {
    "unknown": "unknown",
    "no_threats_found": "goodware",
    "known": "goodware",
    "goodware": "goodware",
    "suspicious": "suspicious",
    "malicious": "malicious",
}

# Default polling behaviour
# Streaming chunk size for hashing reads and upload bodies. 1 MiB is the
# sweet spot for sequential I/O: syscalls per GB stay low, per-yield HTTP
# overhead is negligible, and N workers only pin N MiB of buffers. Larger
# chunks show no measurable gain on USB 2/3 or gigabit links.
IO_CHUNK_SIZE = 1 << 20
UPLOAD_CHUNK_SIZE = IO_CHUNK_SIZE

DEFAULT_MAX_RETRIES = 60        # maximum polling attempts per file (SDK retries)
DEFAULT_WORKERS = 4
HEAD_CAPTURE_BYTES = 4096  # detect_file_type() only inspects the first 4 KiB
DEFAULT_MAX_ENRICH_BYTES = 25 * 1024 * 1024  # cap bytes read for strings/IOC extraction
DEFAULT_MIN_STRING_LEN = 6
DEFAULT_MAX_STRINGS = 200
DEFAULT_MAX_IOCS = 100          # per IOC type
DEFAULT_LARGE_FILE_THRESHOLD = 1_000_000_000  # 1 GB; SDK requires large_file=True above this

# Files/dirs to skip
SKIP_FILES = {OUTPUT_FILENAME, STATE_FILENAME, ALERTS_FILENAME, LOG_FILENAME}
SKIP_DIRS = {"System Volume Information", "$RECYCLE.BIN", "$WinREAgent"}

# Extension presets
DEFAULT_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".com", ".bat", ".cmd", ".ps1", ".scr",
    ".msi", ".msp", ".cpl", ".ocx", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".inf", ".reg", ".lnk", ".pif", ".jar", ".apk",
}
DEFAULT_DOCUMENT_EXTENSIONS = {
    ".doc", ".docx", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm", ".xltx",
    ".ppt", ".pptx", ".pdf", ".rtf", ".txt", ".csv", ".odt", ".ods", ".odp",
}
DEFAULT_ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img",
    ".cab", ".arj", ".lzh", ".uue", ".z", ".sit", ".ace", ".alz",
}
DEFAULT_MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flac", ".wav", ".ogg",
}
DEFAULT_SCRIPT_WEB_EXTENSIONS = {
    ".html", ".htm", ".xml", ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".py", ".rb", ".pl", ".pm", ".sh", ".bash", ".zsh", ".ksh",
}
ALL_DEFAULT_EXTENSIONS = (
    DEFAULT_EXECUTABLE_EXTENSIONS
    | DEFAULT_DOCUMENT_EXTENSIONS
    | DEFAULT_ARCHIVE_EXTENSIONS
    | DEFAULT_MEDIA_EXTENSIONS
    | DEFAULT_SCRIPT_WEB_EXTENSIONS
)

# Valid detected file-type categories (for --file-types filtering / reporting).
FILE_TYPE_CATEGORIES = {
    "pe", "elf", "macho", "java-class", "pdf", "ole", "zip", "rar", "7z",
    "gzip", "bzip2", "xz", "cab", "jpeg", "png", "gif", "bmp", "tiff",
    "script", "text", "data", "empty", "unreadable",
}

# File extensions that look like a domain's TLD — used to drop false-positive
# "domains" like "invoice.exe" or "kernel32.dll" during IOC extraction.
# NOTE: deliberately excludes real, common TLDs such as "com" and "co" so that
# genuine domains (evil.example.com) are not discarded. This heuristic can still
# drop a legitimate domain on a rare collision TLD (e.g. .sh, .zip); the full
# strings list is retained separately, so nothing is truly lost.
_FILE_EXT_LIKE_TLDS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "scr", "msi", "js",
    "vbs", "jar", "py", "sh", "gz", "png", "jpg", "gif",
    "txt", "dat", "bin", "log", "tmp", "doc", "pdf", "html", "htm", "xml",
}

# ---- IOC regexes (bounded to avoid pathological backtracking) --------------
_RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\)\]}]{1,2048}", re.IGNORECASE)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_RE_IPV6 = re.compile(
    r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE
)
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"
)
# Domains are extracted by tokenizing first (linear) then validating each token
# with a bounded, fully-anchored pattern. Never run the label-repeat pattern with
# finditer over free text — that backtracks catastrophically on 'a.a.a...' input.
_RE_DOMAIN_SPLIT = re.compile(r"[^A-Za-z0-9.\-]+")
_RE_DOMAIN_TOKEN = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,10}[A-Za-z]{2,24}"
)
MAX_IOC_TEXT_CHARS = 1_000_000   # cap text fed to IOC regexes (memory/time guard)
MAX_STRING_CHARS = 4096          # cap length of any single extracted string
_RE_ASCII_STR = None   # compiled per-call because min length is configurable
_RE_UTF16_STR = None

# Printable-byte set for the text/data heuristic in detect_file_type(). A
# frozenset gives O(1) membership; the old bytes `in` scan was O(n) per byte.
_TEXT_BYTES = frozenset(range(0x20, 0x7F)) | frozenset(b"\t\n\r\f\b")

# Keys we harvest, wherever they appear, from the Spectra Detect report itself.
_REPORT_STRING_KEYS = {"interesting_strings", "strings"}
_REPORT_INDICATOR_KEYS = {"indicators"}
_REPORT_NETWORK_KEYS = {
    "uri", "uris", "url", "urls", "domain", "domains", "host", "hosts",
    "ipv4", "ipv6", "ip", "ips", "requested_url",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool, log_file: Optional[str],
                  max_mb: int = 50, backups: int = 5) -> logging.Logger:
    """Configure console (and optional rotating file) logging."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(RotatingFileHandler(
            log_file, maxBytes=max(1, max_mb) * 1024 * 1024,
            backupCount=max(0, backups), encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )
    return logging.getLogger("usb_scanner")


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


_REPARSE_TAG_DEDUP = 0x80000013   # Windows dedup: transparently readable


def _st_is_regular(st) -> bool:
    """True for a regular file. On Windows a reparse-point file is regular
    only if its reported tag is 0 or dedup; CPython's os.lstat traverses
    filter-handled reparse points (dedup, OneDrive placeholders while
    OneDrive runs) and reports tag 0, so those are treated as regular (and
    reading a placeholder hydrates it). Unhandled tags (symlinks, ...) are
    not regular. Windows-only attrs are getattr-guarded so other platforms
    behave unchanged."""
    if not stat.S_ISREG(st.st_mode):
        return False
    if (getattr(st, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        return getattr(st, "st_reparse_tag", 0) in (0, _REPARSE_TAG_DEDUP)
    return True


def open_regular(path: str):
    """Open `path` for binary reading only if it is a regular file and not a
    symlink. O_NOFOLLOW makes the open itself refuse a symlink swapped in
    after the walk's lstat (TOCTOU); fstat on the opened fd rejects
    FIFOs/devices/dirs. Without O_NOFOLLOW (Windows) an lstat first
    refuses symlinks and reparse points whose reported tag is neither 0 nor
    dedup (see _st_is_regular). Raises OSError otherwise."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        st = os.lstat(path)
        if not _st_is_regular(st):
            raise OSError(f"not a regular file: {path}")
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_hash_capture(
    filepath: str,
    capture_bytes: int,
    want_sha1: bool = False,
    chunk_size: int = IO_CHUNK_SIZE,
) -> Tuple[str, Optional[str], bytes, int]:
    """
    Single streaming pass over a file: SHA-256 the whole thing while retaining
    the first `capture_bytes` for enrichment. Returns
    (sha256_hex, sha1_hex_or_None, captured_head, bytes_read).

    sha1 is computed in the same pass only when `want_sha1` is set — FIE and
    cloud backends address samples by sha1, detect/a1000 stay sha256-only.

    This replaces the old hash-pass + separate enrichment-read pattern, which
    read every file twice from the (slow, USB-attached) source.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1() if want_sha1 else None
    captured = bytearray()
    total = 0
    try:
        with open_regular(filepath) as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
                if sha1 is not None:
                    sha1.update(chunk)
                total += len(chunk)
                if len(captured) < capture_bytes:
                    captured += chunk[: capture_bytes - len(captured)]
    except (PermissionError, OSError) as e:
        logging.warning("Could not read %s for hashing: %s", filepath, e)
        return "", None, bytes(captured), total
    return (sha256.hexdigest(),
            sha1.hexdigest() if sha1 is not None else None,
            bytes(captured), total)


def human_readable_size(size_bytes: int) -> str:
    """Convert bytes to a human-readable string."""
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def sanitize_drive_path(drive_arg: str) -> str:
    """Normalise 'E:', 'E:\\' or 'E:\\\\' to 'E:\\'. Leaves full paths intact."""
    drive_arg = drive_arg.strip()
    if len(drive_arg) == 2 and drive_arg[1] == ":":
        drive_arg += os.sep
    return drive_arg


def parse_extension_list(extension_str: str) -> Set[str]:
    """Parse a comma-separated extension list into a normalized set of '.ext'."""
    extensions = set()
    for ext in extension_str.split(","):
        ext = ext.strip().lower()
        if not ext:
            continue
        extensions.add(ext if ext.startswith(".") else "." + ext)
    return extensions


def parse_csv_option(value: Optional[str]) -> Set[str]:
    """Parse a comma-separated CLI value into a lowercase set."""
    if not value:
        return set()
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def should_include_file(filename: str, include_extensions: Optional[Set[str]]) -> bool:
    """True if the file matches the extension filter (None/empty => accept all)."""
    if not include_extensions:
        return True
    _, ext = os.path.splitext(filename.lower())
    return ext in include_extensions


# ---------------------------------------------------------------------------
# Classification / report summarisation
# ---------------------------------------------------------------------------

def _normalize_classification(value) -> str:
    """Map a raw classification value (int or string) to a canonical label."""
    if isinstance(value, bool):  # guard: bool is a subclass of int
        return "unavailable"
    if isinstance(value, int):
        return CLASSIFICATION_MAP.get(value, "unavailable")
    if isinstance(value, str):
        return CLASSIFICATION_STRING_MAP.get(value.strip().lower(), value.strip().lower())
    return "unavailable"


def summarize_report(report_json: dict) -> Tuple[str, Optional[str], Optional[int]]:
    """
    Best-effort extraction of (classification, threat_name, factor) from a
    Spectra Detect task report. The full report is preserved separately, so this
    is only a convenience summary and tolerant of schema differences.

    Real Worker taskinfo responses carry the verdict at:
        tc_report[i].classification.classification   (int 0-3: unknown/goodware/
                                                        suspicious/malicious)
        tc_report[i].classification.factor            (severity/rca_factor)
        tc_report[i].classification.scan_results[].name  (threat/detection name)
    tc_report is a LIST: index 0 is the top-level submitted file, and any
    remaining entries are extracted children (archives, installers, etc).
    See: https://docs.reversinglabs.com/SpectraDetect/report-schema/
    """
    classification = "unavailable"
    threat_name: Optional[str] = None
    factor: Optional[int] = None

    if not isinstance(report_json, dict):
        return classification, threat_name, factor

    tc_report = report_json.get("tc_report")
    if not isinstance(tc_report, list):
        return classification, threat_name, factor

    # Take the WORST (most severe) verdict across all entries (top-level file +
    # any extracted children). A container/archive can have one classification
    # per extracted object; picking the first decisive one could report a
    # malicious file as goodware.
    severity_rank = {"malicious": 4, "suspicious": 3, "goodware": 2,
                     "unknown": 1, "unavailable": 0}
    best_rank = -1
    for entry in tc_report:
        if not isinstance(entry, dict):
            continue
        cls_obj = entry.get("classification")
        if not isinstance(cls_obj, dict):
            continue

        cls_val = cls_obj.get("classification")
        entry_factor = cls_obj.get("factor")
        if not isinstance(entry_factor, int):
            entry_factor = None

        # The malware/threat name lives on classification.result (per RL's
        # report-schema docs). scan_results[].name is the INTERNAL SCANNER
        # name (e.g. "TitaniumCore Format", "TitaniumCore Certificate Lists"),
        # not a threat name - do not conflate the two, that was wrong in an
        # earlier version of this fix.
        entry_threat = cls_obj.get("result") or None

        label = _normalize_classification(cls_val)
        rank = severity_rank.get(label, 0)  # unmapped strings rank as low
        if rank > best_rank:
            best_rank = rank
            classification = label
            if entry_threat:
                threat_name = entry_threat
            if entry_factor is not None:
                factor = entry_factor
        # Retain a threat name / factor even if the worst entry lacked one.
        if threat_name is None and entry_threat:
            threat_name = entry_threat
        if factor is None and entry_factor is not None:
            factor = entry_factor

    return classification, threat_name, factor


def extract_report_indicators(report_json: dict, max_items: int = 200) -> dict:
    """
    Harvest interesting strings / indicators / network artifacts that the Spectra
    Detect report itself provides, wherever they appear in the nested structure.
    Bounded recursion so a huge report can't blow up memory or time.
    """
    found = {"interesting_strings": [], "indicators": [], "network": []}

    def _add(bucket: str, value):
        lst = found[bucket]
        if len(lst) >= max_items:
            return
        if isinstance(value, (str, int, float)):
            s = str(value).strip()
            if s and s not in lst:
                lst.append(s)
        elif isinstance(value, dict):
            # Common indicator shapes: {"description": ...} / {"value": ...}
            for k in ("description", "value", "name", "reason"):
                if k in value:
                    _add(bucket, value[k])
                    return
            lst.append(value)  # keep the raw dict if nothing obvious
        elif isinstance(value, list):
            for item in value[:max_items]:
                _add(bucket, item)

    def _walk(node, depth: int):
        if depth > 12:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                lk = key.lower()
                if lk in _REPORT_STRING_KEYS:
                    _add("interesting_strings", val)
                elif lk in _REPORT_INDICATOR_KEYS:
                    _add("indicators", val)
                elif lk in _REPORT_NETWORK_KEYS:
                    _add("network", val)
                _walk(val, depth + 1)
        elif isinstance(node, list):
            for item in node:
                _walk(item, depth + 1)

    if isinstance(report_json, dict):
        _walk(report_json, 0)

    # Drop empty buckets for a tidy report.
    return {k: v for k, v in found.items() if v}


# ---------------------------------------------------------------------------
# File reading, type detection, strings & IOC extraction
# ---------------------------------------------------------------------------


def detect_file_type(head: bytes) -> str:
    """Classify a file by its leading bytes (magic numbers). Best-effort."""
    if not head:
        return "empty"
    b = head

    # Executables / object formats
    if b[:2] == b"MZ":
        return "pe"
    if b[:4] == b"\x7fELF":
        return "elf"
    if b[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if b[:4] == b"\xca\xfe\xba\xbe":
        return "java-class"

    # Documents / containers
    if b[:4] == b"%PDF":
        return "pdf"
    if b[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"          # legacy Office / MSI
    if b[:4] == b"PK\x03\x04":
        return "zip"          # also OOXML / JAR / APK (all ZIP containers)
    if b[:4] == b"Rar!"[:4] or b[:7] == b"Rar!\x1a\x07\x00":
        return "rar"
    if b[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if b[:2] == b"\x1f\x8b":
        return "gzip"
    if b[:3] == b"BZh":
        return "bzip2"
    if b[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if b[:4] in (b"MSCF", b"ISc("):
        return "cab"

    # Images
    if b[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b[:2] == b"BM":
        return "bmp"
    if b[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"

    # Scripts (shebang)
    if b[:2] == b"#!":
        return "script"

    # Text vs binary heuristic
    sample = b[:4096]
    if not sample:
        return "data"
    text_chars = bytes(range(0x20, 0x7f)) + b"\t\n\r\f\b"
    nonprintable = sum(1 for c in sample if c not in text_chars)
    if nonprintable / max(1, len(sample)) < 0.10:
        return "text"
    return "data"



def _defang(indicator: str) -> str:
    """Return a defanged copy of a URL/domain/IP so reports are click-safe."""
    out = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace("ftp://", "fxp://")
    # Defang the last few dots without mangling every dot in a long URL path.
    return out.replace(".", "[.]")


def extract_iocs(text: str, max_per_type: int) -> dict:
    """Extract network indicators from decoded text. Bounded and de-duplicated."""
    if not text:
        return {}

    def _collect(regex, transform=lambda x: x, predicate=lambda x: True):
        out: List[str] = []
        seen = set()
        for m in regex.finditer(text):
            val = transform(m.group())
            if not val or val in seen or not predicate(val):
                continue
            seen.add(val)
            out.append(val)
            if len(out) >= max_per_type:
                break
        return out

    urls = _collect(_RE_URL)
    ipv4 = _collect(_RE_IPV4)
    ipv6 = _collect(_RE_IPV6)
    emails = _collect(_RE_EMAIL)

    # Domains: drop values whose TLD is really a file extension, and drop bare
    # IPs already covered by ipv4.
    def _domain_ok(d: str) -> bool:
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXT_LIKE_TLDS:
            return False
        if _RE_IPV4.fullmatch(d):
            return False
        return True

    # Tokenize on non-domain characters (linear), then validate each token with a
    # bounded, anchored fullmatch. Oversized tokens are skipped without matching,
    # so adversarial 'a.a.a...' input can't trigger catastrophic backtracking.
    domains: List[str] = []
    seen_domains: Set[str] = set()
    for token in _RE_DOMAIN_SPLIT.split(text):
        if len(domains) >= max_per_type:
            break
        if len(token) > 255 or "." not in token:
            continue
        if not _RE_DOMAIN_TOKEN.fullmatch(token):
            continue
        d = token.lower()
        if d in seen_domains or not _domain_ok(d):
            continue
        seen_domains.add(d)
        domains.append(d)

    iocs = {}
    if urls:
        iocs["urls"] = urls
        iocs["urls_defanged"] = [_defang(u) for u in urls]
    if domains:
        iocs["domains"] = domains
    if ipv4:
        iocs["ipv4"] = ipv4
    if ipv6:
        iocs["ipv6"] = ipv6
    if emails:
        iocs["emails"] = emails
    return iocs


# ---------------------------------------------------------------------------
# Thread-safe helpers: counters, keyed locks, scan state
# ---------------------------------------------------------------------------

class Counters:
    """Thread-safe integer counters."""

    def __init__(self):
        self._lock = threading.Lock()
        self._c: Dict[str, int] = {}

    def inc(self, key: str, by: int = 1) -> None:
        with self._lock:
            self._c[key] = self._c.get(key, 0) + by

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._c)


class KeyedLocks:
    """Hands out one lock per key so identical hashes are processed once."""

    def __init__(self):
        self._master = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}

    def get(self, key: str) -> threading.Lock:
        with self._master:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def _remove_source(path: str) -> None:
    """Delete the scanned source. On Windows a read-only file raises
    PermissionError: clear the read-only bit and retry once."""
    try:
        os.unlink(path)
    except PermissionError:
        if os.name != "nt":
            raise
        os.chmod(path, stat.S_IWRITE)
        os.unlink(path)


def _copy_verified(filepath: str, dest) -> None:
    """Copy `filepath` to a new `dest` (exclusive create) through a verified
    regular fd. Metadata comes from that fd, never from the path: mtime is
    kept, mode is masked to 0o666 and the umask (no setuid/setgid/sticky/exec).
    A failed copy, including a failed final flush/close, removes the partial
    dest (which this call created)."""
    with open_regular(filepath) as src:
        st = os.fstat(src.fileno())
        # Exclusive create carries the final mode — the kernel applies the
        # umask: same result as Go's OpenFile(perm), no post-chmod needed.
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     stat.S_IMODE(st.st_mode) & 0o666)
        # FileExistsError: dest is not ours, untouched
        try:
            dst = os.fdopen(fd, "wb")
            with dst:  # the final flush/close error is caught below too
                shutil.copyfileobj(src, dst)
        except BaseException:
            try:
                os.close(fd)  # a failed fdopen may not have taken the fd
            except OSError:
                pass
            try:
                os.unlink(dest)
            except OSError:
                pass
            raise
    try:
        os.utime(dest, ns=(st.st_atime_ns, st.st_mtime_ns))
    except OSError:
        pass  # metadata is best-effort; the content is quarantined


def _dest_matches_source(filepath: str, dest) -> bool:
    """True if `dest` is a regular file with the same size as the source
    (size taken from a verified regular fd). Guards against treating a
    truncated leftover as an already-quarantined duplicate."""
    try:
        with open_regular(filepath) as src:
            size = os.fstat(src.fileno()).st_size
        dst = os.lstat(dest)
    except OSError:
        return False
    return _st_is_regular(dst) and dst.st_size == size


def quarantine_file(
    filepath: str,
    sha256: str,
    classification: str,
    quarantine_dir: Path,
    action: str,
    logger: logging.Logger,
) -> Optional[str]:
    """
    Copy or move a flagged file into the quarantine directory. The destination
    name is prefixed with the hash to avoid collisions and is confined to the
    quarantine directory (no path traversal from the source name).
    Returns the destination path, or None on failure / no-op.
    """
    if action == "none":
        return None
    # Never quarantine through a symlink/FIFO/device swapped in after the
    # walk: lstat and refuse anything that is not a regular file.
    try:
        regular = _st_is_regular(os.lstat(filepath))
    except OSError:
        regular = False
    if not regular:
        logger.error("Refusing to quarantine non-regular file %s", filepath)
        return None
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error("Could not create quarantine dir %s: %s", quarantine_dir, e)
        return None

    safe_base = os.path.basename(filepath).replace("\x00", "")
    safe_base = re.sub(r"[^A-Za-z0-9._\- ]", "_", safe_base)[:150] or "file"
    prefix = (sha256[:16] if sha256 else "nohash")
    # Never resolve `dest` itself: a symlink planted at the dest name must be
    # seen by lstat below, not followed into another file.
    qdir_resolved = quarantine_dir.resolve()
    dest = qdir_resolved / f"{prefix}_{safe_base}"

    # Confinement check: dest must stay inside quarantine_dir.
    try:
        inside = os.path.commonpath([str(dest), str(qdir_resolved)]) == str(qdir_resolved)
    except ValueError:
        inside = False  # e.g. different drives on Windows
    if not inside:
        logger.error("Refusing to quarantine outside %s (computed %s)", qdir_resolved, dest)
        return None

    if dest.exists():
        if not _dest_matches_source(filepath, dest):
            logger.error("Quarantine destination %s exists but does not match "
                         "source; leaving both", dest)
            return None
        if action == "move":
            # An identical file is already quarantined; still get this duplicate
            # off the untrusted drive instead of leaving it behind.
            try:
                _remove_source(filepath)
                logger.warning("Duplicate already quarantined; removed source %s", filepath)
            except OSError as e:
                logger.error("Could not remove duplicate source %s: %s", filepath, e)
        else:
            logger.debug("Quarantine target already exists, skipping copy: %s", dest)
        return str(dest)

    try:
        if action == "move":
            # Re-verify via O_NOFOLLOW + fstat right before the move; the
            # fstat mode is reused to de-privilege the dest after a rename.
            with open_regular(filepath) as src:
                st_mode = os.fstat(src.fileno()).st_mode
            try:
                os.rename(filepath, str(dest))
            except OSError:
                # e.g. EXDEV: copy through the verified fd, then drop the
                # source. Never shutil.move on the scanned path.
                _copy_verified(filepath, dest)
                _remove_source(filepath)
            else:
                # rename preserves the full mode, incl. setuid/setgid/
                # sticky — strip the privileged bits (the copy path's
                # 0o666 mask never lets them through).
                os.chmod(dest, stat.S_IMODE(st_mode) & ~0o7000)
        else:  # copy — read the source only through a verified regular fd
            _copy_verified(filepath, dest)
        logger.warning("Quarantined (%s) %s -> %s [%s]",
                       action, filepath, dest, classification)
        return str(dest)
    except (OSError, shutil.Error) as e:
        logger.error("Quarantine %s failed for %s: %s", action, filepath, e)
        return None


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Alert webhooks must never be redirected — a 3xx would re-POST the
    alert payload to a foreign host. Returning None here turns the 3xx into
    an HTTPError, which _to_webhook logs as a failure like any other."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Alerter:
    """Fan-out detection alerts to any configured channels. Never raises."""

    _SYSLOG_SEVERITY = {"malicious": 2, "suspicious": 4}  # crit / warning

    def __init__(
        self,
        alert_on: Set[str],
        alerts_file: Optional[Path],
        webhook_url: Optional[str],
        syslog_addr: Optional[Tuple[str, int]],
        eventlog: bool,
        logger: logging.Logger,
    ):
        self.alert_on = alert_on
        self.alerts_file = alerts_file
        self.webhook_url = webhook_url
        self.syslog_addr = syslog_addr
        self.eventlog = eventlog
        self.logger = logger
        self._lock = threading.Lock()
        self._eventlog_ok = True
        if eventlog:
            import importlib.util
            if (importlib.util.find_spec("win32evtlogutil") is None
                    or importlib.util.find_spec("win32evtlog") is None):
                self._eventlog_ok = False
                logger.warning("--alert-eventlog requested but pywin32 is unavailable; "
                               "Event Log alerts disabled.")

    def maybe_alert(self, record: dict) -> bool:
        classification = record.get("classification")
        if classification not in self.alert_on:
            return False
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner_version": SCRIPT_VERSION,
            "classification": classification,
            "threat_name": record.get("threat_name"),
            "file_path": record.get("file_path"),
            "absolute_path": record.get("absolute_path"),
            "sha256": record.get("sha256"),
            "file_type": record.get("file_type"),
            "quarantined_to": record.get("quarantined_to"),
        }
        self._to_file(payload)
        self._to_webhook(payload)
        self._to_syslog(payload)
        self._to_eventlog(payload)
        return True

    def _to_file(self, payload: dict) -> None:
        if not self.alerts_file:
            return
        try:
            with self._lock:
                with open(self.alerts_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as e:
            self.logger.error("Could not write alert to %s: %s", self.alerts_file, e)

    def _to_webhook(self, payload: dict) -> None:
        if not self.webhook_url:
            return
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url, data=data,
                headers={"Content-Type": "application/json"}, method="POST")
            # build_opener with a HTTPRedirectHandler subclass instance
            # replaces the default redirect handler — a 3xx surfaces as an
            # HTTPError instead of being silently followed.
            opener = urllib.request.build_opener(_NoRedirect())
            opener.open(req, timeout=10).close()
        except Exception as e:  # noqa: BLE001
            self.logger.error("Webhook alert failed: %s", e)

    def _to_syslog(self, payload: dict) -> None:
        if not self.syslog_addr:
            return
        try:
            severity = self._SYSLOG_SEVERITY.get(payload["classification"], 5)
            pri = 13 * 8 + severity  # facility 13 (log audit)
            msg = (f"<{pri}>SpectraDetectScanner: {payload['classification'].upper()} "
                   f"{payload.get('threat_name') or ''} sha256={payload.get('sha256')} "
                   f"path={payload.get('file_path')}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(msg.encode("utf-8", "replace")[:1024], self.syslog_addr)
            finally:
                sock.close()
        except Exception as e:  # noqa: BLE001
            self.logger.error("Syslog alert failed: %s", e)

    def _to_eventlog(self, payload: dict) -> None:
        if not self.eventlog or not self._eventlog_ok:
            return
        try:
            import win32evtlogutil
            import win32evtlog
            etype = (win32evtlog.EVENTLOG_ERROR_TYPE
                     if payload["classification"] == "malicious"
                     else win32evtlog.EVENTLOG_WARNING_TYPE)
            win32evtlogutil.ReportEvent(
                "SpectraDetectScanner", 1, eventType=etype,
                strings=[json.dumps(payload, ensure_ascii=False)])
        except Exception as e:  # noqa: BLE001
            self.logger.error("Event Log alert failed: %s", e)


# ---------------------------------------------------------------------------
# Async Spectra Detect client (submit -> task_url, poll task_url)
# ---------------------------------------------------------------------------

# Upload outcomes that can never succeed on retry — return immediately
# instead of burning the whole retry window re-POSTing the same file.
DETECT_PERMANENT_STATUSES = frozenset({400, 413})

NON_RETRIABLE_UPLOAD_ERRORS = (
    "invalid task_url",
    "task_url cross-origin rejected",
    "invalid upload response body",
)


class TaskGoneError(RuntimeError):
    """Task GET returned 404: the server discarded the task record."""


class DetectAsyncClient:
    """Async Spectra Detect Worker client: submit -> task_url, poll task_url."""

    def __init__(self, host, token, verify_ssl=True, proxy=None, ready_path="/readyz"):
        import requests
        self.host = host.rstrip("/")
        self.ready_url = self.host + ready_path
        self._local = threading.local()
        self._session = None  # test seam: an injected session wins over thread-local
        self._verify = verify_ssl
        self._proxies = {"http": proxy, "https": proxy} if proxy else None
        self._token = token
        self._requests = requests
        # Shared availability cache: workers probe `is_ready` at most every
        # `avail_probe_seconds`, and any non-2xx flips it off so every worker
        # gates instead of hammering a saturated Worker.
        self._avail_ok = True
        self._avail_at = 0.0
        self._avail_lock = threading.Lock()

    def _sess(self):
        s = self._session
        if s is not None:
            return s
        s = getattr(self._local, "s", None)
        if s is None:
            s = self._requests.Session()
            s.headers.update({"Authorization": f"Token {self._token}"})
            # Explicit config only: REQUESTS_CA_BUNDLE / *_PROXY env vars must
            # not override verify_ssl/proxy (a CA bundle env would force TLS
            # verification back on for a self-signed appliance).
            s.trust_env = False
            s.verify = self._verify
            s.proxies = self._proxies
            self._local.s = s
        return s

    def _err_text(self, r):
        """Response body for error strings — the token is redacted even if
        the appliance echoes request headers back."""
        t = r.text[:200]
        if self._token:
            t = t.replace(self._token, "***")
        return t

    # -- ready gate ----------------------------------------------------------
    def is_ready(self, timeout=8):
        try:
            r = self._sess().get(self.ready_url, timeout=timeout,
                                 allow_redirects=False)
            if r.status_code == 404:
                # Older receivers expose the availability endpoint under /srv.
                r = self._sess().get(
                    self.host + "/srv/tiscale/v1/available", timeout=timeout,
                    allow_redirects=False)
            return r.status_code == 200
        except Exception:
            return False

    def wait_ready(self, max_wait, interval, log=None):
        import time as _t
        interval = max(1, interval)  # an unclamped 0s interval tight-spins
        deadline = _t.monotonic() + max_wait
        while _t.monotonic() < deadline:
            if self.is_ready():
                with self._avail_lock:   # propagate recovery to all workers
                    self._avail_ok = True
                    self._avail_at = _t.monotonic()
                return True
            if log:
                log.warning("Detect not ready (%s); rechecking in %ss",
                            self.ready_url, interval)
            _t.sleep(interval)
        return False

    def available_now(self, ttl):
        """Cached availability check — one shared probe at most every `ttl`
        seconds across all workers. Fresh-False gates every worker without
        probing (that IS the backoff signal); stale cache re-probes."""
        import time as _t
        with self._avail_lock:
            if _t.monotonic() - self._avail_at < ttl:
                return self._avail_ok
        ok = self.is_ready()
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = ok
        return ok

    def mark_unavailable(self):
        """A worker saw a non-2xx/error — stamp a FRESH unavailable state so
        every other worker gates for avail_probe_seconds without probing.
        Recovery arrives via wait_ready's probe loop updating the cache."""
        import time as _t
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = False

    # -- submit ---------------------------------------------------------------
    def same_origin(self, task_url):
        from urllib.parse import urljoin, urlsplit
        if not isinstance(task_url, str) or "\\" in task_url or any(ord(c) < 0x21 for c in task_url):
            return None
        resolved = urljoin(self.host + "/", task_url)
        try:
            base, cand = urlsplit(self.host), urlsplit(resolved)
            if cand.username or cand.password or "@" in cand.netloc:
                return None
            default = {"http": 80, "https": 443}
            same = (cand.scheme.lower() == base.scheme.lower()
                    and (cand.hostname or "") == (base.hostname or "") != ""
                    and (cand.port or default.get(cand.scheme.lower()))
                        == (base.port or default.get(base.scheme.lower())))
        except ValueError:
            return None
        return resolved if same else None

    def upload_once(self, filepath, custom_data):
        """Stream the file as a multipart body: requests' `files=` kwarg
        buffers the WHOLE body in RAM, so a large file x N workers means GBs.
        A generator + explicit Content-Length streams chunk-by-chunk instead.
        Chunk size 1 MiB matches the hash-read pass — big enough to keep
        per-yield overhead negligible, small enough that 10 workers peak
        at ~10 MiB of send buffers."""
        import uuid
        try:
            file_size = os.path.getsize(filepath)
        except OSError as e:
            return None, None, f"file_not_found: {e}"
        # Header-injection guard: basename could carry quotes/CR/LF.
        fname = (os.path.basename(filepath)
                 .replace('"', "_").replace("\r", "").replace("\n", ""))
        boundary = "----rlscan" + uuid.uuid4().hex  # random: file bytes can't collide
        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="custom_data"\r\n'
            f"\r\n{json.dumps(custom_data)}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8")
        tail = f"\r\n--{boundary}--\r\n".encode("ascii")

        def _stream():
            yield head
            with open_regular(filepath) as f:
                while True:
                    b = f.read(UPLOAD_CHUNK_SIZE)
                    if not b:
                        break
                    yield b
            yield tail

        class _SizedStream:
            """requests must see a length or it marks the body chunked; a
            manually-set Content-Length + chunked TE together gets a 400."""
            def __init__(self, gen, n):
                self._gen, self._n = gen, n
            def __len__(self):
                return self._n
            def __iter__(self):
                return self._gen

        try:
            r = self._sess().post(
                f"{self.host}/api/tiscale/v1/upload",
                data=_SizedStream(_stream(), len(head) + file_size + len(tail)),
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                timeout=(30, 300),
                # The API never legitimately redirects; a 307/308 would
                # re-POST the file body (and Authorization) cross-origin.
                allow_redirects=False)
        except FileNotFoundError as e:
            return None, None, f"file_not_found: {e}"
        except Exception as e:
            return None, None, f"request_error: {e}"
        if r.status_code in (200, 201):
            try:
                body = r.json()
            except ValueError:
                return r.status_code, None, "no task_url in response"
            if not isinstance(body, dict):
                return r.status_code, None, "invalid upload response body"
            task_url = body.get("task_url")
            if not task_url:
                return r.status_code, None, "no task_url in response"
            resolved = self.same_origin(task_url)
            if resolved is None:
                # A foreign (or malformed) task_url must never be followed —
                # retrying an identical POST can't change the verdict.
                return r.status_code, None, (
                    "task_url cross-origin rejected"
                    if isinstance(task_url, str) else "invalid task_url")
            return r.status_code, resolved, None
        return r.status_code, None, \
            f"http_{r.status_code}: {self._err_text(r)}"

    def upload_with_backoff(self, filepath, custom_data, cfg, log=None):
        """Retry non-2xx/errors with exp backoff; gate each retry on readyz."""
        import time as _t
        deadline = _t.monotonic() + cfg.upload_retry_window
        delay = max(0.001, cfg.backoff_base_seconds)
        attempts = 0
        last_status, last_err = None, None
        while attempts < cfg.max_upload_attempts:
            # Gate every attempt on the shared availability cache (~one probe
            # per avail_probe_seconds across all workers). A False gates here
            # AND parks us in wait_ready which keeps polling `available`.
            if not self.available_now(getattr(cfg, "avail_probe_seconds", 20)):
                if log:
                    log.warning("Detect not available — pausing upload of %s",
                                os.path.basename(filepath))
                self.wait_ready(cfg.ready_max_wait, cfg.ready_check_interval,
                                log=log)
            attempts += 1
            last_status, task_url, last_err = self.upload_once(filepath, custom_data)
            if task_url:
                return task_url, last_status, None, attempts
            if last_err in NON_RETRIABLE_UPLOAD_ERRORS \
                    or last_status in DETECT_PERMANENT_STATUSES:
                break  # deterministic failure — retries can't help
            self.mark_unavailable()  # non-2xx/error: other workers gate now
            if _t.monotonic() >= deadline:
                break
            # gate: don't hammer a sick Worker — wait until ready before retrying
            if not self.wait_ready(cfg.ready_max_wait, cfg.ready_check_interval,
                                   log=log) and log:
                log.warning("readyz gate timed out after %ss; retrying anyway",
                            cfg.ready_max_wait)
            wait = min(delay, max(0.0, deadline - _t.monotonic()))
            if log:
                log.warning("upload attempt %d failed (%s); retry in %.0fs",
                            attempts, last_err, wait)
            _t.sleep(wait)
            delay = min(delay * 2, cfg.backoff_max_seconds)
        return None, last_status, last_err, attempts

    # -- poll ------------------------------------------------------------------
    def task_status(self, task_url, timeout=30):
        r = self._sess().get(task_url, timeout=timeout, allow_redirects=False)
        if r.status_code == 404:
            # The appliance dropped/purged the task record — no report will
            # ever arrive; polling until the deadline just burns cycles.
            raise TaskGoneError(task_url)
        if r.status_code != 200:
            raise RuntimeError(f"task GET {r.status_code}")
        body = r.json()
        if not isinstance(body, dict):
            # A non-dict body is a malformed server response. Raise a plain
            # error here so the poller sees a transient failure (unclaim and
            # retry) instead of an AttributeError at task.get().
            raise ValueError(f"malformed task body: {type(body).__name__}")
        return body


# FIE (File Inspection Engine) — synchronous verdict service: sha1 lookup via
# /check-sample and full-file analysis via POST /scan. Internal service, no
# auth. Per-file permanence: 400 (size limit / malformed request) and 413 are
# never retriable; everything else retries bounded by max_upload_attempts —
# 524 is FIE's own analysis timeout and must NOT be treated as permanent.
FIE_PERMANENT_STATUSES = frozenset({400, 413})


class FieClient:
    """File Inspection Engine client: GET /check-sample hash lookups and a
    synchronous POST /scan verdict. Unauthenticated — no Authorization
    header. Session/availability-cache shape mirrors DetectAsyncClient."""

    def __init__(self, host, verify_ssl=True, proxy=None):
        import requests
        self.host = host.rstrip("/")
        self._local = threading.local()
        self._session = None  # test seam: an injected session wins
        self._verify = verify_ssl
        self._proxies = {"http": proxy, "https": proxy} if proxy else None
        self._requests = requests
        # Shared availability cache: same semantics as DetectAsyncClient —
        # workers probe /readyz at most every avail_probe_seconds and any
        # saturated/5xx response flips it off so every worker gates.
        self._avail_ok = True
        self._avail_at = 0.0
        self._avail_lock = threading.Lock()

    def _sess(self):
        s = self._session
        if s is not None:
            return s
        s = getattr(self._local, "s", None)
        if s is None:
            s = self._requests.Session()
            # Explicit config only: REQUESTS_CA_BUNDLE / *_PROXY env vars must
            # not override verify_ssl/proxy. FIE sends no credentials, but a
            # redirect could still re-POST the sample body cross-origin —
            # every request below pins allow_redirects=False.
            s.trust_env = False
            s.verify = self._verify
            s.proxies = self._proxies
            self._local.s = s
        return s

    # -- ready gate (same shared-cache shape as DetectAsyncClient) ----------
    def probe(self, timeout=8):
        try:
            r = self._sess().get(f"{self.host}/readyz", timeout=timeout,
                                 allow_redirects=False)
            return r.status_code == 200
        except Exception:
            return False

    def wait_ready(self, max_wait, interval, log=None):
        import time as _t
        interval = max(1, interval)  # an unclamped 0s interval tight-spins
        deadline = _t.monotonic() + max_wait
        while _t.monotonic() < deadline:
            if self.probe():
                with self._avail_lock:   # propagate recovery to all workers
                    self._avail_ok = True
                    self._avail_at = _t.monotonic()
                return True
            if log:
                log.warning("FIE not ready (%s/readyz); rechecking in %ss",
                            self.host, interval)
            _t.sleep(interval)
        return False

    def available_now(self, ttl):
        """Cached availability check — at most one /readyz probe per ttl
        across all workers; a fresh-False gates without probing."""
        import time as _t
        with self._avail_lock:
            if _t.monotonic() - self._avail_at < ttl:
                return self._avail_ok
        ok = self.probe()
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = ok
        return ok

    def mark_unavailable(self):
        """A worker saw saturation/5xx/a conn error — stamp a FRESH False so
        every other worker gates for avail_probe_seconds without probing."""
        import time as _t
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = False

    # -- requests --------------------------------------------------------------
    def check_hash(self, sha1, timeout=30):
        """GET /check-sample/hash/sha1/{sha1} -> (status, body|None, err).
        body is the parsed JSON dict; only a 200 yields one."""
        try:
            r = self._sess().get(
                f"{self.host}/check-sample/hash/sha1/{sha1}",
                timeout=timeout, allow_redirects=False)
        except Exception as e:
            return None, None, f"request_error: {e}"
        if r.status_code != 200:
            return r.status_code, None, \
                f"http_{r.status_code}: {r.text[:200]}"
        try:
            body = r.json()
        except ValueError:
            return r.status_code, None, "invalid check-sample response body"
        if not isinstance(body, dict):
            return r.status_code, None, "invalid check-sample response body"
        return r.status_code, body, None

    def scan_file(self, filepath, external_id=None, timeout=(30, 600)):
        """POST /scan with the raw file body -> (status, body|None, err).

        Synchronous verdict: FIE holds the request for the whole analysis
        window and answers 524 on its own timeout, so the default read
        timeout is generous. `external_id` is sent verbatim as a query param
        (FieBackend resolves the configured mode to a value or None)."""
        try:
            file_size = os.path.getsize(filepath)
        except OSError as e:
            return None, None, f"file_not_found: {e}"
        params = {"external_id": external_id} if external_id else None
        try:
            with open_regular(filepath) as f:
                r = self._sess().post(
                    f"{self.host}/scan",
                    params=params, data=f,
                    headers={
                        "Content-Type": "application/octet-stream",
                        # Explicit Content-Length — the body must not go out
                        # chunked (mirrors the tiscale upload contract).
                        "Content-Length": str(file_size),
                    },
                    timeout=timeout, allow_redirects=False)
        except FileNotFoundError as e:
            return None, None, f"file_not_found: {e}"
        except Exception as e:
            return None, None, f"request_error: {e}"
        if r.status_code != 200:
            return r.status_code, None, \
                f"http_{r.status_code}: {r.text[:200]}"
        try:
            body = r.json()
        except ValueError:
            return r.status_code, None, "invalid scan response body"
        if not isinstance(body, dict):
            return r.status_code, None, "invalid scan response body"
        return r.status_code, body, None


# A1000 (Spectra Analyze) — async file analysis appliance: POST /api/uploads/
# returns detail.sha1; status is polled in bulk (sha256) and the verdict comes
# from /api/samples/v3/{h}/classification/ (summary) or
# /api/samples/v2/list/details/ (full). Authenticated via `Authorization:
# Token`. Per-file permanence: 400 (malformed request) and 413 (file too
# large) never retry; 429/5xx/conn/timeout are retriable and flip the shared
# availability gate.
A1000_PERMANENT_STATUSES = frozenset({400, 413})
A1000_STATUS_CHUNK = 100          # /api/samples/status/ caps hash_values at 100
A1000_DETAIL_FIELDS = ("sha256", "classification_result", "classification",
                       "riskscore", "av_scanners_summary", "sample_summary",
                       "tags")
_A1000_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_A1000_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def _is_a1000_hash(v):
    """SHA1/SHA256/SHA512/MD5 hex — what the status/classification endpoints
    accept."""
    return isinstance(v, str) and bool(_A1000_HASH_RE.match(v))


class A1000Client:
    """Spectra Analyze (A1000) client: multipart upload, bulk status poll,
    classification/full-report fetch. Session/availability-cache shape mirrors
    DetectAsyncClient — same `Authorization: Token` header contract, and every
    request pins allow_redirects=False so the token can never leak to a
    redirect target."""

    def __init__(self, host, token, verify_ssl=True, proxy=None):
        import requests
        self.host = host.rstrip("/")
        self._local = threading.local()
        self._session = None  # test seam: an injected session wins
        self._verify = verify_ssl
        self._proxies = {"http": proxy, "https": proxy} if proxy else None
        self._token = token
        self._requests = requests
        # Shared availability cache: same semantics as DetectAsyncClient —
        # workers probe at most every avail_probe_seconds and any 5xx/conn
        # error flips it off so every worker gates.
        self._avail_ok = True
        self._avail_at = 0.0
        self._avail_lock = threading.Lock()

    def _sess(self):
        s = self._session
        if s is not None:
            return s
        s = getattr(self._local, "s", None)
        if s is None:
            s = self._requests.Session()
            s.headers.update({"Authorization": f"Token {self._token}"})
            # Explicit config only: REQUESTS_CA_BUNDLE / *_PROXY env vars must
            # not override verify_ssl/proxy.
            s.trust_env = False
            s.verify = self._verify
            s.proxies = self._proxies
            self._local.s = s
        return s

    def _err_text(self, r):
        """Response body for error strings — token can never appear in it even
        if the appliance echoes request headers back."""
        t = r.text[:200]
        if self._token:
            t = t.replace(self._token, "***")
        return t

    # -- ready gate (same shared-cache shape as DetectAsyncClient) ----------
    def probe_status(self, timeout=8):
        """GET {host}/api/uploads/ -> status code, or None on request error.
        Any HTTP answer < 500 means the appliance is up — 401/403/405 still
        mean reachable (make_backend reads the code for the auth check)."""
        try:
            r = self._sess().get(f"{self.host}/api/uploads/",
                                 timeout=timeout, allow_redirects=False)
            return r.status_code
        except Exception:
            return None

    def probe(self, timeout=8):
        s = self.probe_status(timeout)
        # isinstance guard: a non-int (conn error -> None) is down; anything
        # answered < 500 is up.
        return isinstance(s, int) and s < 500

    def wait_ready(self, max_wait, interval, log=None):
        import time as _t
        interval = max(1, interval)  # an unclamped 0s interval tight-spins
        deadline = _t.monotonic() + max_wait
        while _t.monotonic() < deadline:
            if self.probe():
                with self._avail_lock:   # propagate recovery to all workers
                    self._avail_ok = True
                    self._avail_at = _t.monotonic()
                return True
            if log:
                log.warning("A1000 not ready (%s/api/uploads/); "
                            "rechecking in %ss", self.host, interval)
            _t.sleep(interval)
        return False

    def available_now(self, ttl):
        """Cached availability check — at most one probe per ttl across all
        workers; a fresh-False gates without probing."""
        import time as _t
        with self._avail_lock:
            if _t.monotonic() - self._avail_at < ttl:
                return self._avail_ok
        ok = self.probe()
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = ok
        return ok

    def mark_unavailable(self):
        """A worker saw saturation/5xx/a conn error — stamp a FRESH False so
        every other worker gates for avail_probe_seconds without probing."""
        import time as _t
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = False

    # -- requests --------------------------------------------------------------
    def upload(self, filepath, fields=None, timeout=(30, 300)):
        """POST /api/uploads/ multipart -> (status, sha1|None, err).

        Carries one form field per configured option (`filename` is always the
        basename) plus the `file` part. Streams the body chunk-by-chunk like
        DetectAsyncClient.upload_once — requests' `files=` kwarg would buffer
        the whole file in RAM."""
        import uuid
        try:
            file_size = os.path.getsize(filepath)
        except OSError as e:
            return None, None, f"file_not_found: {e}"

        def _clean(v):  # header-injection guard for part names/values
            return str(v).replace('"', "_").replace("\r", "").replace("\n", "")

        fname = _clean(os.path.basename(filepath))
        boundary = "----rlscan" + uuid.uuid4().hex
        parts = [f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="filename"\r\n'
                 f"\r\n{fname}\r\n"]
        for k, v in (fields or {}).items():
            if v is None or str(v) == "":
                continue
            parts.append(f"--{boundary}\r\n"
                         f'Content-Disposition: form-data; name="{_clean(k)}"'
                         f"\r\n\r\n{_clean(v)}\r\n")
        parts.append(f"--{boundary}\r\n"
                     f'Content-Disposition: form-data; name="file"; '
                     f'filename="{fname}"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n")
        head = "".join(parts).encode("utf-8")
        tail = f"\r\n--{boundary}--\r\n".encode("ascii")

        def _stream():
            yield head
            with open_regular(filepath) as f:
                while True:
                    b = f.read(UPLOAD_CHUNK_SIZE)
                    if not b:
                        break
                    yield b
            yield tail

        class _SizedStream:
            """requests must see a length or it marks the body chunked."""
            def __init__(self, gen, n):
                self._gen, self._n = gen, n
            def __len__(self):
                return self._n
            def __iter__(self):
                return self._gen

        try:
            r = self._sess().post(
                f"{self.host}/api/uploads/",
                data=_SizedStream(_stream(),
                                  len(head) + file_size + len(tail)),
                headers={
                    "Content-Type":
                        f"multipart/form-data; boundary={boundary}",
                },
                timeout=timeout,
                # A 307/308 would re-POST the file body and the Authorization
                # token cross-origin — never follow.
                allow_redirects=False)
        except FileNotFoundError as e:
            return None, None, f"file_not_found: {e}"
        except Exception as e:
            return None, None, f"request_error: {e}"
        if r.status_code != 201:
            return r.status_code, None, \
                f"http_{r.status_code}: {self._err_text(r)}"
        try:
            body = r.json()
        except ValueError:
            return r.status_code, None, "invalid upload response body"
        if not isinstance(body, dict):
            return r.status_code, None, "invalid upload response body"
        detail = body.get("detail")
        sha1 = detail.get("sha1") if isinstance(detail, dict) else None
        if not (isinstance(sha1, str) and _A1000_SHA1_RE.match(sha1)):
            return r.status_code, None, "no sha1 in response"
        return r.status_code, sha1, None

    def status_bulk(self, hashes, timeout=30):
        """POST /api/samples/status/ -> (status, {hash_value: status}|None,
        err). hash_values is chunked at A1000_STATUS_CHUNK (API max 100);
        one failing chunk fails the whole call."""
        merged = {}
        last_status = None
        for i in range(0, len(hashes), A1000_STATUS_CHUNK):
            chunk = [str(h) for h in hashes[i:i + A1000_STATUS_CHUNK]]
            try:
                r = self._sess().post(
                    f"{self.host}/api/samples/status/",
                    json={"hash_values": chunk},
                    timeout=timeout, allow_redirects=False)
            except Exception as e:
                return None, None, f"request_error: {e}"
            last_status = r.status_code
            if r.status_code != 200:
                return r.status_code, None, \
                    f"http_{r.status_code}: {self._err_text(r)}"
            try:
                body = r.json()
            except ValueError:
                return r.status_code, None, "invalid status response body"
            results = body.get("results") if isinstance(body, dict) else None
            if not isinstance(results, list):
                return r.status_code, None, "invalid status response body"
            for ent in results:
                if not isinstance(ent, dict):
                    continue
                hv, st = ent.get("hash_value"), ent.get("status")
                if isinstance(hv, str) and isinstance(st, str):
                    merged[hv.lower()] = st
        return last_status, merged, None

    def classification(self, hash_value, timeout=30):
        """GET /api/samples/v3/{h}/classification/ -> (status, body|None,
        err). Only a 200 yields the classification doc."""
        try:
            r = self._sess().get(
                f"{self.host}/api/samples/v3/{hash_value}/classification/",
                timeout=timeout, allow_redirects=False)
        except Exception as e:
            return None, None, f"request_error: {e}"
        if r.status_code != 200:
            return r.status_code, None, \
                f"http_{r.status_code}: {self._err_text(r)}"
        try:
            body = r.json()
        except ValueError:
            return r.status_code, None, "invalid classification response body"
        if not isinstance(body, dict):
            return r.status_code, None, "invalid classification response body"
        return r.status_code, body, None

    def full_report(self, hashes, timeout=(30, 120)):
        """POST /api/samples/v2/list/details/ -> (status, body|None, err).
        body carries a `results` list with one entry per hash. The read
        timeout is generous — the API itself documents highly variable
        response speeds."""
        try:
            r = self._sess().post(
                f"{self.host}/api/samples/v2/list/details/",
                json={"hash_values": [str(h) for h in hashes],
                      "fields": list(A1000_DETAIL_FIELDS)},
                timeout=timeout, allow_redirects=False)
        except Exception as e:
            return None, None, f"request_error: {e}"
        if r.status_code != 200:
            return r.status_code, None, \
                f"http_{r.status_code}: {self._err_text(r)}"
        try:
            body = r.json()
        except ValueError:
            return r.status_code, None, "invalid report response body"
        if not isinstance(body, dict):
            return r.status_code, None, "invalid report response body"
        return r.status_code, body, None


# TiCloud (Spectra Intelligence / TitaniumCloud) — Basic-auth cloud service:
# two-step spex file upload (binary, then metadata XML — required before the
# sample is processed) plus TCA-0101 reputation queries (bulk + single)
# shared by CloudBackend and the reputation pre-check. HTTP Basic credentials
# ride on the session and are redacted from every error string; no request
# ever follows a redirect — a 307/308 would re-POST the sample body and the
# Basic credentials cross-origin.
# Error taxonomy: 401/403 are auth failures (status surfaced for factory
# fail-fast), 413 is permanent per file, 408/429/5xx/conn/timeout retriable.
TICLOUD_AUTH_STATUSES = frozenset({401, 403})
TICLOUD_PERMANENT_STATUSES = frozenset({413})
TICLOUD_RETRIABLE_STATUSES = frozenset({408, 429})  # + 5xx / conn / timeout
TICLOUD_REPUTATION_CHUNK = 100      # bulk_query caps hashes at 100
TICLOUD_HASH_TYPES = frozenset({"md5", "sha1", "sha256"})
_TICLOUD_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def _is_ticloud_sha1(v):
    """True for a 40-hex sha1 (case-insensitive) — the spex/TCA-0101 key."""
    return isinstance(v, str) and bool(_TICLOUD_SHA1_RE.match(v.lower()))


def normalize_reputation_entry(entry):
    """TCA-0101 extended entry -> normalized verdict dict shared by the
    CloudBackend poll and the reputation pre-check.

    status: MALICIOUS->malicious, SUSPICIOUS->suspicious, KNOWN->goodware,
    UNKNOWN->unknown (anything unrecognized also -> unknown). threat_factor
    is threat_level for malicious/suspicious, trust_factor for KNOWN.
    `raw` keeps the full entry (extended fields incl. scanner_*)."""
    if not isinstance(entry, dict):
        entry = {}
    raw = entry.get("status")
    cls = {"MALICIOUS": "malicious", "SUSPICIOUS": "suspicious",
           "KNOWN": "goodware", "UNKNOWN": "unknown"}.get(
               str(raw).upper() if isinstance(raw, str) else "", "unknown")
    threat_name = entry.get("threat_name")
    factor = (entry.get("threat_level")
              if cls in ("malicious", "suspicious")
              else entry.get("trust_factor") if cls == "goodware" else None)
    if isinstance(factor, bool) or not isinstance(factor, (int, float)):
        factor = None
    return {
        "classification": cls,
        "threat_name": threat_name if threat_name else None,
        "threat_factor": int(factor) if factor is not None else None,
        "raw": entry,
    }


def _ticloud_entry_hashes(entry):
    """Every hash an extended TCA-0101 entry echoes, lower-cased. Real
    responses nest them under query_hash/sample_hash
    ({"sha1": "..."}); flat sha1/md5/sha256/hash_value keys also occur
    (and are what test mocks use)."""
    out = []
    if not isinstance(entry, dict):
        return out
    for key in ("sha1", "md5", "sha256", "hash_value"):
        v = entry.get(key)
        if isinstance(v, str) and v:
            out.append(v.lower())
    for key in ("query_hash", "sample_hash"):
        sub = entry.get(key)
        if isinstance(sub, dict):
            for v in sub.values():
                if isinstance(v, str) and v:
                    out.append(v.lower())
    return out


class TiCloudClient:
    """Spectra Intelligence (TitaniumCloud) client: spex two-step upload
    (POST /api/spex/upload/{sha1} octet-stream, then POST .../meta XML) and
    TCA-0101 reputation queries (bulk + single). Session/availability-cache
    shape mirrors A1000Client — the Basic auth header lives on the session,
    credentials are redacted from every error string, and every request pins
    allow_redirects=False so credentials can never leak to a redirect
    target. spex POSTs are paced at min_interval_ms (the API allows
    10 req/s) via one shared monotonic timestamp."""

    def __init__(self, host, username, password, verify_ssl=True, proxy=None,
                 upload_timeout=300, min_interval_ms=100, extended=True):
        import base64
        import requests
        self.host = host.rstrip("/")
        self._local = threading.local()
        self._session = None  # test seam: an injected session wins
        self._verify = verify_ssl
        self._proxies = {"http": proxy, "https": proxy} if proxy else None
        self._username = username
        self._password = password
        self._upload_timeout = upload_timeout
        self._min_interval = max(0, min_interval_ms) / 1000.0
        self._extended = extended
        self._requests = requests
        # RFC 7617: requests' _basic_auth_str encodes latin-1 first with a
        # utf-8 fallback — mirror it for the explicit session header.
        try:
            creds = f"{username}:{password}".encode("latin-1")
        except UnicodeEncodeError:
            creds = f"{username}:{password}".encode("utf-8")
        self._auth_header = "Basic " + base64.b64encode(creds).decode("ascii")
        # spex pacing: one shared monotonic timestamp for the whole client —
        # every worker's spex POST waits for the same slot.
        self._spex_lock = threading.Lock()
        self._spex_last = 0.0
        # Shared availability cache: same semantics as A1000Client — workers
        # probe {host}/ at most every avail_probe_seconds and any 5xx/conn
        # error flips it off so every worker gates.
        self._avail_ok = True
        self._avail_at = 0.0
        self._avail_lock = threading.Lock()

    def _sess(self):
        s = self._session
        if s is not None:
            return s
        s = getattr(self._local, "s", None)
        if s is None:
            s = self._requests.Session()
            s.headers.update({"Authorization": self._auth_header})
            # Explicit config only: REQUESTS_CA_BUNDLE / *_PROXY env vars must
            # not override verify_ssl/proxy.
            s.trust_env = False
            s.verify = self._verify
            s.proxies = self._proxies
            self._local.s = s
        return s

    def _redact(self, text):
        """Strip credentials from any string destined for an error/log —
        password first, then username."""
        t = text
        for sec in (self._password, self._username):
            if sec:
                t = t.replace(sec, "***")
        return t

    def _err_text(self, r):
        """Response body for error strings — Basic credentials can never
        appear in it even if the server echoes request headers back."""
        return self._redact(r.text[:200])

    def _request_error(self, e):
        return f"request_error: {self._redact(str(e))}"

    def _pace_spex(self):
        """Client-side pacing for spex POSTs: at most one call per
        min_interval_ms across all workers (shared monotonic timestamp)."""
        import time as _t
        if self._min_interval <= 0:
            return
        with self._spex_lock:
            wait = self._min_interval - (_t.monotonic() - self._spex_last)
            if wait > 0:
                _t.sleep(wait)
            self._spex_last = _t.monotonic()

    # -- ready gate (same shared-cache shape as A1000Client) -----------------
    def probe_status(self, timeout=8):
        """GET {host}/ -> status code, or None on request error. Any HTTP
        answer < 500 means the service is up — 401/403 still mean reachable
        (the factory reads the code for the auth fail-fast check)."""
        try:
            r = self._sess().get(f"{self.host}/", timeout=timeout,
                                 allow_redirects=False)
            return r.status_code
        except Exception:
            return None

    def probe(self, timeout=8):
        s = self.probe_status(timeout)
        # isinstance guard: a non-int (conn error -> None) is down; anything
        # answered < 500 is up.
        return isinstance(s, int) and s < 500

    def wait_ready(self, max_wait, interval, log=None):
        import time as _t
        interval = max(1, interval)  # an unclamped 0s interval tight-spins
        deadline = _t.monotonic() + max_wait
        while _t.monotonic() < deadline:
            if self.probe():
                with self._avail_lock:   # propagate recovery to all workers
                    self._avail_ok = True
                    self._avail_at = _t.monotonic()
                return True
            if log:
                log.warning("TiCloud not ready (%s/); rechecking in %ss",
                            self.host, interval)
            _t.sleep(interval)
        return False

    def available_now(self, ttl):
        """Cached availability check — at most one probe per ttl across all
        workers; a fresh-False gates without probing."""
        import time as _t
        with self._avail_lock:
            if _t.monotonic() - self._avail_at < ttl:
                return self._avail_ok
        ok = self.probe()
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = ok
        return ok

    def mark_unavailable(self):
        """A worker saw saturation/5xx/a conn error — stamp a FRESH False so
        every other worker gates for avail_probe_seconds without probing."""
        import time as _t
        with self._avail_lock:
            self._avail_at = _t.monotonic()
            self._avail_ok = False

    # -- spex upload (TCA-0202/0203) ------------------------------------------
    def upload_sample(self, sha1, filepath, timeout=None):
        """POST {host}/api/spex/upload/{sha1} — raw octet-stream body streamed
        chunk-by-chunk like DetectAsyncClient.upload_once (never buffered in
        RAM). Any 2xx means the sample is stored under its sha1.
        -> (status, True|None, err). sha1 is a lowercase path param."""
        sha1 = str(sha1).lower()
        if not _TICLOUD_SHA1_RE.match(sha1):
            return None, None, "invalid sha1"
        try:
            file_size = os.path.getsize(filepath)
        except OSError as e:
            return None, None, f"file_not_found: {e}"

        def _stream():
            with open_regular(filepath) as f:
                while True:
                    b = f.read(UPLOAD_CHUNK_SIZE)
                    if not b:
                        break
                    yield b

        class _SizedStream:
            """requests must see a length or it marks the body chunked."""
            def __init__(self, gen, n):
                self._gen, self._n = gen, n
            def __len__(self):
                return self._n
            def __iter__(self):
                return self._gen

        self._pace_spex()
        try:
            r = self._sess().post(
                f"{self.host}/api/spex/upload/{sha1}",
                data=_SizedStream(_stream(), file_size),
                headers={"Content-Type": "application/octet-stream"},
                timeout=(timeout if timeout is not None
                         else (30, self._upload_timeout)),
                # A 307/308 would re-POST the file body and the Basic
                # credentials cross-origin — never follow.
                allow_redirects=False)
        except FileNotFoundError as e:
            return None, None, f"file_not_found: {e}"
        except Exception as e:
            return None, None, self._request_error(e)
        if not 200 <= r.status_code < 300:
            return r.status_code, None, \
                f"http_{r.status_code}: {self._err_text(r)}"
        return r.status_code, True, None

    @staticmethod
    def _meta_xml(filename, domain, archive_password):
        """Upload metadata XML per the spex contract — required or the sample
        is never processed. <domain> is always present (empty when
        unconfigured); the <archive> element appears only when
        archive_password is set. Every interpolated value is XML-escaped."""
        body = (
            "<rl><properties><property><name>filename</name><value>"
            f"{html.escape(os.path.basename(str(filename or '')))}"
            "</value></property><property><name>source</name>"
            "<value>filescanner</value></property></properties>"
            f"<domain>{html.escape(str(domain or ''))}</domain>")
        if archive_password:
            body += ("<archive><archive_passwords><password>"
                     f"{html.escape(str(archive_password))}"
                     "</password></archive_passwords></archive>")
        return body + "</rl>"

    def upload_meta(self, sha1, filename, domain="", archive_password="",
                    timeout=None):
        """POST {host}/api/spex/upload/{sha1}/meta — the metadata XML the spex
        pipeline requires before it processes the binary (Content-Type
        application/octet-stream per the API contract). Safe to retry alone
        once the binary is stored. -> (status, True|None, err)."""
        sha1 = str(sha1).lower()
        if not _TICLOUD_SHA1_RE.match(sha1):
            return None, None, "invalid sha1"
        self._pace_spex()
        try:
            r = self._sess().post(
                f"{self.host}/api/spex/upload/{sha1}/meta",
                data=self._meta_xml(filename, domain,
                                    archive_password).encode("utf-8"),
                headers={"Content-Type": "application/octet-stream"},
                timeout=(timeout if timeout is not None
                         else (30, self._upload_timeout)),
                allow_redirects=False)
        except Exception as e:
            return None, None, self._request_error(e)
        if not 200 <= r.status_code < 300:
            return r.status_code, None, \
                f"http_{r.status_code}: {self._err_text(r)}"
        return r.status_code, True, None

    def submit_sample(self, sha1, filepath, filename=None, domain="",
                      archive_password="", sample_uploaded=False):
        """Two-step spex submit, order enforced: binary POST first, metadata
        POST second. -> (status, True|None, err).

        If the meta POST fails after a successful binary upload the sample is
        already stored under its sha1 — err is prefixed "meta_failed:" and a
        retry must post ONLY the meta step (sample_uploaded=True) instead of
        re-uploading the binary."""
        if not sample_uploaded:
            status, _ok, err = self.upload_sample(sha1, filepath)
            if err:
                return status, None, err
        status, _ok, err = self.upload_meta(
            sha1,
            filename if filename else os.path.basename(filepath),
            domain, archive_password)
        if err:
            return status, None, f"meta_failed: {err}"
        return status, True, None

    # -- reputation (TCA-0101) -------------------------------------------------
    def _extended_q(self):
        return "true" if self._extended else "false"

    def reputation_bulk(self, hashes, hash_type="sha256", timeout=30):
        """POST {host}/api/databrowser/malware_presence/bulk_query/json
        ?extended={cfg} -> (status, (entries, invalid_hashes)|None, err).

        hashes is chunked at TICLOUD_REPUTATION_CHUNK (API max 100) — one
        failing chunk fails the whole call. entries carry the raw extended
        fields (status, threat_name, threat_level, trust_factor, scanner_*);
        invalid_hashes are returned verbatim for the caller to log+count."""
        hash_type = str(hash_type).lower()
        if hash_type not in TICLOUD_HASH_TYPES:
            return None, None, f"invalid hash_type {hash_type!r}"
        entries, invalid = [], []
        last_status = None
        for i in range(0, len(hashes), TICLOUD_REPUTATION_CHUNK):
            chunk = [str(h) for h in hashes[i:i + TICLOUD_REPUTATION_CHUNK]]
            try:
                r = self._sess().post(
                    f"{self.host}/api/databrowser/malware_presence/"
                    f"bulk_query/json?extended={self._extended_q()}",
                    json={"rl": {"query": {"hash_type": hash_type,
                                           "hashes": chunk}}},
                    timeout=timeout, allow_redirects=False)
            except Exception as e:
                return None, None, self._request_error(e)
            last_status = r.status_code
            if r.status_code != 200:
                return r.status_code, None, \
                    f"http_{r.status_code}: {self._err_text(r)}"
            try:
                body = r.json()
            except ValueError:
                return r.status_code, None, \
                    "invalid reputation response body"
            rl = body.get("rl") if isinstance(body, dict) else None
            if not isinstance(rl, dict):
                return r.status_code, None, \
                    "invalid reputation response body"
            ents = rl.get("entries")
            inv = rl.get("invalid_hashes")
            if ents is None:
                ents = []
            if inv is None:
                inv = []
            if not isinstance(ents, list) or not isinstance(inv, list):
                return r.status_code, None, \
                    "invalid reputation response body"
            entries.extend(ents)
            invalid.extend(inv)
        return last_status, (entries, invalid), None

    def reputation_single(self, hash_value, hash_type="sha256", timeout=30):
        """GET {host}/api/databrowser/malware_presence/query/{hash_type}/{h}
        ?extended={cfg} -> (status, entry|None, err). entry is the single
        rl.entry dict (or rl.entries[0]) — same raw shape as bulk entries."""
        hash_type = str(hash_type).lower()
        hash_value = str(hash_value).lower()
        if hash_type not in TICLOUD_HASH_TYPES:
            return None, None, f"invalid hash_type {hash_type!r}"
        if not _A1000_HASH_RE.match(hash_value):
            return None, None, "invalid hash"
        try:
            r = self._sess().get(
                f"{self.host}/api/databrowser/malware_presence/query/"
                f"{hash_type}/{hash_value}?extended={self._extended_q()}",
                timeout=timeout, allow_redirects=False)
        except Exception as e:
            return None, None, self._request_error(e)
        if r.status_code != 200:
            return r.status_code, None, \
                f"http_{r.status_code}: {self._err_text(r)}"
        try:
            body = r.json()
        except ValueError:
            return r.status_code, None, "invalid reputation response body"
        rl = body.get("rl") if isinstance(body, dict) else None
        if not isinstance(rl, dict):
            return r.status_code, None, "invalid reputation response body"
        ent = rl.get("entry")
        if isinstance(ent, dict):
            return r.status_code, ent, None
        ents = rl.get("entries")
        if isinstance(ents, list) and ents and isinstance(ents[0], dict):
            return r.status_code, ents[0], None
        return r.status_code, None, "no entry in response"


# ---------------------------------------------------------------------------
# Backend contract — SubmitOutcome + ScanBackend + adapters + factory
# ---------------------------------------------------------------------------

@dataclass
class SubmitOutcome:
    """Result of one submit attempt.

    kind:
      'receipt' — accepted for async processing; `ref` is the backend-specific
                  receipt (detect: task_url) stored in ScanDB.task_url.
      'verdict' — a synchronous verdict was returned on submit (FIE); the
                  verdict fields are populated.
      'error'   — submission failed; http_status/error say why.
    """
    kind: str
    ref: str = ""
    http_status: Optional[int] = None
    error: Optional[str] = None
    classification: Optional[str] = None
    threat_name: Optional[str] = None
    threat_factor: Optional[int] = None
    report_json: Optional[str] = None


@runtime_checkable
class ScanBackend(Protocol):
    """Contract every scan backend implements; the pipeline only sees this.

    submit_* take (filepath, sha256, sha1, meta): hashes arrive pre-computed
    (sha1 is only non-None for needs_sha1 backends); `meta` is backend-defined
    submit metadata (detect: tiscale custom_data).

    poll_batch(refs) maps each receipt ref -> 'pending' | 'gone' | verdict
    dict {classification, threat_name, threat_factor, report_json}; each entry
    in `refs` is a dict carrying at least "ref" (backends that poll by hash
    may also read "sha256"). 'gone' is terminal (receipt purged server-side);
    transient poll errors map to 'pending' so the caller unclaims and retries.
    """
    name: str
    needs_sha1: bool
    is_sync: bool               # verdict on submit (FIE) — poll_batch unused

    def probe(self, timeout=8) -> bool: ...
    def wait_ready(self, max_wait, interval, log=None) -> bool: ...
    def available_now(self, ttl) -> bool: ...
    def mark_unavailable(self) -> None: ...
    def submit_once(self, filepath, sha256, sha1, meta) -> SubmitOutcome: ...
    def submit_with_backoff(self, filepath, sha256, sha1, meta, cfg,
                            log=None) -> SubmitOutcome: ...
    def poll_batch(self, refs, log=None) -> dict: ...


class DetectBackend:
    """ScanBackend adapter over DetectAsyncClient — client internals untouched;
    upload_once/upload_with_backoff/task_status keep their exact semantics."""

    name = "detect"
    needs_sha1 = False
    is_sync = False

    def __init__(self, client: DetectAsyncClient):
        self.client = client

    # -- availability: pure delegates ----------------------------------------
    def probe(self, timeout=8):
        return self.client.is_ready(timeout)

    def wait_ready(self, max_wait, interval, log=None):
        return self.client.wait_ready(max_wait, interval, log=log)

    def available_now(self, ttl):
        return self.client.available_now(ttl)

    def mark_unavailable(self):
        self.client.mark_unavailable()

    # -- submit ----------------------------------------------------------------
    def submit_once(self, filepath, sha256, sha1, meta):
        status, task_url, err = self.client.upload_once(filepath, meta)
        if task_url:
            return SubmitOutcome(kind="receipt", ref=task_url,
                                 http_status=status)
        return SubmitOutcome(kind="error", http_status=status, error=err)

    def submit_with_backoff(self, filepath, sha256, sha1, meta, cfg, log=None):
        task_url, status, err, _attempts = self.client.upload_with_backoff(
            filepath, meta, cfg, log=log)
        if task_url:
            return SubmitOutcome(kind="receipt", ref=task_url,
                                 http_status=status)
        return SubmitOutcome(kind="error", http_status=status, error=err)

    # -- poll ------------------------------------------------------------------
    def poll_batch(self, refs, log=None):
        """Detect polls each task_url serially (no bulk endpoint)."""
        out = {}
        for item in refs:
            ref = item.get("ref") or item.get("task_url")
            if not ref:
                continue
            try:
                task = self.client.task_status(ref)
            except TaskGoneError:
                out[ref] = "gone"      # terminal: server purged the task
                continue
            except Exception:          # noqa: BLE001 — transient; retry later
                out[ref] = "pending"
                continue
            if task.get("processed") in (None, 0):
                out[ref] = "pending"
                continue
            cls, threat, factor = summarize_report(task)
            out[ref] = {
                "classification": cls,
                "threat_name": threat,
                "threat_factor": factor,
                # raw task dict — caller decides store_full_report/dumps
                "report_json": task,
            }
        return out


class FieBackend:
    """ScanBackend over FieClient — FIE answers the verdict synchronously on
    submit, so is_sync=True and poll_batch is never called. needs_sha1:
    /check-sample addresses samples by sha1.

    meta contract: dict may carry "rel_path" — the scan-root-relative path
    the pipeline stamps per file; used for external_id mode 'rel_path'.
    """

    name = "fie"
    needs_sha1 = True
    is_sync = True

    def __init__(self, client: FieClient, mode="hash_then_scan",
                 trust_ok=False, external_id="rel_path"):
        self.client = client
        self.mode = mode
        self.trust_ok = trust_ok
        self.external_id = external_id

    # -- availability: pure delegates ----------------------------------------
    def probe(self, timeout=8):
        return self.client.probe(timeout)

    def wait_ready(self, max_wait, interval, log=None):
        return self.client.wait_ready(max_wait, interval, log=log)

    def available_now(self, ttl):
        return self.client.available_now(ttl)

    def mark_unavailable(self):
        self.client.mark_unavailable()

    # -- verdict normalization -------------------------------------------------
    @staticmethod
    def _verdict(body, status):
        """FIE response dict -> SubmitOutcome verdict. classification:
        malicious/suspicious pass through, 'OK' -> goodware, anything else ->
        unknown. threat fields come from threat_details; report_json carries
        the raw response dict (caller decides store_full_report/dumps — same
        shape as DetectBackend.poll_batch verdict maps)."""
        raw = str(body.get("classification") or "")
        cls = {"malicious": "malicious", "suspicious": "suspicious",
               "OK": "goodware"}.get(raw, "unknown")
        td = body.get("threat_details")
        if not isinstance(td, dict):
            td = {}
        factor = td.get("scanner_match")
        if isinstance(factor, bool) or not isinstance(factor, (int, float)):
            factor = None
        threat_name = td.get("threat_name")
        return SubmitOutcome(
            kind="verdict", http_status=status, classification=cls,
            threat_name=threat_name if threat_name else None,
            threat_factor=int(factor) if factor is not None else None,
            report_json=body)

    def _external_id(self, filepath, meta):
        """Resolve the configured external_id mode to the ?external_id=
        value: rel_path -> meta["rel_path"]; filename -> basename; none ->
        param omitted."""
        if self.external_id == "none":
            return None
        if self.external_id == "filename":
            return os.path.basename(filepath)
        rel = (meta or {}).get("rel_path")
        return rel if rel else os.path.basename(filepath)

    def _scan_submit(self, filepath, meta):
        status, body, err = self.client.scan_file(
            filepath, self._external_id(filepath, meta))
        if body is None:
            return SubmitOutcome(kind="error", http_status=status, error=err)
        return self._verdict(body, status)

    # -- submit ----------------------------------------------------------------
    def submit_once(self, filepath, sha256, sha1, meta):
        """One submit attempt per [fie] mode:
          scan           — POST /scan straight to a verdict.
          hash_then_scan — /check-sample first; malicious/suspicious is a
                           verdict, 'OK' under trust_ok is a clean verdict,
                           otherwise fall through to /scan (also for any
                           unrecognized hash classification).
          hash_only      — /check-sample only; 'OK' + !trust_ok records
                           'unknown' (FIE can't tell unseen from clean),
                           report_json keeps the raw response."""
        if self.mode == "scan":
            return self._scan_submit(filepath, meta)
        status, body, err = self.client.check_hash(sha1)
        if body is None:
            return SubmitOutcome(kind="error", http_status=status, error=err)
        raw = str(body.get("classification") or "")
        if raw in ("malicious", "suspicious"):
            return self._verdict(body, status)
        if self.mode == "hash_only":
            out = self._verdict(body, status)
            if raw == "OK" and not self.trust_ok:
                out.classification = "unknown"   # ambiguous: unseen vs clean
            return out
        if raw == "OK" and self.trust_ok:
            return self._verdict(body, status)
        return self._scan_submit(filepath, meta)

    def submit_with_backoff(self, filepath, sha256, sha1, meta, cfg, log=None):
        """Same retry shape as DetectBackend: every attempt gates on the
        shared availability cache, retriable failures (conn errors, timeouts,
        408/429/5xx/524 — anything not in FIE_PERMANENT_STATUSES) back off
        exponentially inside upload_retry_window, bounded by
        max_upload_attempts. 400/413 return immediately."""
        import time as _t
        deadline = _t.monotonic() + cfg.upload_retry_window
        delay = max(0.001, cfg.backoff_base_seconds)
        attempts = 0
        last = SubmitOutcome(kind="error", error="no attempt made")
        while attempts < cfg.max_upload_attempts:
            if not self.client.available_now(
                    getattr(cfg, "avail_probe_seconds", 20)):
                if log:
                    log.warning("FIE not available — pausing scan of %s",
                                os.path.basename(filepath))
                self.client.wait_ready(cfg.ready_max_wait,
                                       cfg.ready_check_interval, log=log)
            attempts += 1
            last = self.submit_once(filepath, sha256, sha1, meta)
            if last.kind != "error":
                return last
            if last.http_status in FIE_PERMANENT_STATUSES:
                return last
            # conn error / saturation / server-side failure — gate all
            # workers on the shared cache instead of racing a sick service.
            if last.http_status is None or last.http_status == 429 \
                    or last.http_status >= 500:
                self.client.mark_unavailable()
            if _t.monotonic() >= deadline:
                break
            # gate: don't hammer a sick FIE — wait until ready before retrying
            if not self.client.wait_ready(cfg.ready_max_wait,
                                          cfg.ready_check_interval,
                                          log=log) and log:
                log.warning("readyz gate timed out after %ss; retrying anyway",
                            cfg.ready_max_wait)
            wait = min(delay, max(0.0, deadline - _t.monotonic()))
            if log:
                log.warning("FIE submit attempt %d failed (%s); retry in %.0fs",
                            attempts, last.error, wait)
            _t.sleep(wait)
            delay = min(delay * 2, cfg.backoff_max_seconds)
        return last

    # -- poll ------------------------------------------------------------------
    def poll_batch(self, refs, log=None):
        """Unused — FIE is synchronous (is_sync=True) so verdicts land in
        submit_once and rows go pending -> done directly. Defined only for
        ScanBackend conformance."""
        return {}


class A1000Backend:
    """ScanBackend over A1000Client — async: submit returns a receipt (the
    sha1 A1000 assigns at upload), poll_batch resolves statuses by sha256.
    needs_sha1: A1000 status/classification APIs accept sha256, so the
    pipeline's hash pass stays sha256-only.

    meta contract: unused — no per-file submit metadata today."""

    name = "a1000"
    needs_sha1 = False
    is_sync = False

    def __init__(self, client: A1000Client, fields=None,
                 report_detail="summary"):
        self.client = client
        # Optional /api/uploads/ form fields — only non-empty configured
        # values (filename is always added by the client itself).
        self.fields = dict(fields or {})
        self.report_detail = report_detail

    # -- availability: pure delegates ----------------------------------------
    def probe(self, timeout=8):
        return self.client.probe(timeout)

    def wait_ready(self, max_wait, interval, log=None):
        return self.client.wait_ready(max_wait, interval, log=log)

    def available_now(self, ttl):
        return self.client.available_now(ttl)

    def mark_unavailable(self):
        self.client.mark_unavailable()

    # -- verdict normalization -------------------------------------------------
    @staticmethod
    def _verdict(body):
        """A1000 doc -> poll verdict dict (same shape as
        DetectBackend.poll_batch entries). classification is normalized to
        the shared vocabulary; threat_name=classification_result; factor=
        riskscore (0-10 int). report_json carries the raw doc — the caller
        decides store_full_report/dumps."""
        raw = body.get("classification")
        cls = {"MALICIOUS": "malicious", "SUSPICIOUS": "suspicious",
               "GOODWARE": "goodware", "UNKNOWN": "unknown"}.get(
                   str(raw).upper() if isinstance(raw, str) else "",
                   "unknown")
        threat_name = body.get("classification_result")
        factor = body.get("riskscore")
        if isinstance(factor, bool) or not isinstance(factor, (int, float)):
            factor = None
        return {
            "classification": cls,
            "threat_name": threat_name if threat_name else None,
            "threat_factor": int(factor) if factor is not None else None,
            "report_json": body,
        }

    @staticmethod
    def _detail_entry(body, hash_value):
        """list/details response -> the entry dict for this hash (sha256 match
        first, then any dict entry — a single-hash request)."""
        results = body.get("results") if isinstance(body, dict) else None
        if not isinstance(results, list):
            return None
        first = None
        for ent in results:
            if not isinstance(ent, dict):
                continue
            if first is None:
                first = ent
            hv = ent.get("sha256")
            if isinstance(hv, str) and hv.lower() == hash_value.lower():
                return ent
        return first

    def _poll_verdict(self, hash_value):
        """'processed' -> fetch the verdict doc per report_detail. Returns the
        verdict dict, or None on any transient fetch failure (caller maps it
        to 'pending' and retries next sweep)."""
        if self.report_detail == "full":
            _st, body, _err = self.client.full_report([hash_value])
            entry = self._detail_entry(body, hash_value) if body else None
            return self._verdict(entry) if entry else None
        _st, body, _err = self.client.classification(hash_value)
        return self._verdict(body) if body else None

    # -- submit ----------------------------------------------------------------
    def submit_once(self, filepath, sha256, sha1, meta):
        status, ref, err = self.client.upload(filepath, self.fields)
        if ref:
            return SubmitOutcome(kind="receipt", ref=ref,
                                 http_status=status)
        return SubmitOutcome(kind="error", http_status=status, error=err)

    def submit_with_backoff(self, filepath, sha256, sha1, meta, cfg, log=None):
        """Same retry shape as FieBackend: every attempt gates on the shared
        availability cache, retriable failures (conn errors, timeouts,
        408/429/5xx — anything not in A1000_PERMANENT_STATUSES) back off
        exponentially inside upload_retry_window, bounded by
        max_upload_attempts. 400/413 return immediately."""
        import time as _t
        deadline = _t.monotonic() + cfg.upload_retry_window
        delay = max(0.001, cfg.backoff_base_seconds)
        attempts = 0
        last = SubmitOutcome(kind="error", error="no attempt made")
        while attempts < cfg.max_upload_attempts:
            if not self.client.available_now(
                    getattr(cfg, "avail_probe_seconds", 20)):
                if log:
                    log.warning("A1000 not available — pausing upload of %s",
                                os.path.basename(filepath))
                self.client.wait_ready(cfg.ready_max_wait,
                                       cfg.ready_check_interval, log=log)
            attempts += 1
            last = self.submit_once(filepath, sha256, sha1, meta)
            if last.kind != "error":
                return last
            if last.http_status in A1000_PERMANENT_STATUSES:
                return last
            # conn error / saturation / server-side failure — gate all
            # workers on the shared cache instead of racing a sick appliance.
            if last.http_status is None or last.http_status == 429 \
                    or last.http_status >= 500:
                self.client.mark_unavailable()
            if _t.monotonic() >= deadline:
                break
            if not self.client.wait_ready(cfg.ready_max_wait,
                                          cfg.ready_check_interval,
                                          log=log) and log:
                log.warning("readyz gate timed out after %ss; retrying anyway",
                            cfg.ready_max_wait)
            wait = min(delay, max(0.0, deadline - _t.monotonic()))
            if log:
                log.warning(
                    "A1000 submit attempt %d failed (%s); retry in %.0fs",
                    attempts, last.error, wait)
            _t.sleep(wait)
            delay = min(delay * 2, cfg.backoff_max_seconds)
        return last

    # -- poll ------------------------------------------------------------------
    def poll_batch(self, refs, log=None):
        """Bulk-poll by sha256 (refs carry the row's sha256; the receipt ref —
        a sha1 — is itself a valid hash fallback). 'processed' -> fetch and
        normalize the verdict; 'not_found', missing, or any transient fetch
        error -> 'pending' (rows time out via report_wait_hours, like
        evicted tiscale tasks)."""
        out = {}
        pairs = []                     # (ref, hash) pollable entries
        for item in refs:
            ref = item.get("ref") or item.get("task_url")
            if not ref:
                continue
            h = item.get("sha256")
            if not _is_a1000_hash(h):
                h = ref if _is_a1000_hash(ref) else None
            if h is None:
                out[ref] = "pending"   # nothing to poll with — keep waiting
                continue
            pairs.append((ref, h))
        if not pairs:
            return out
        _st, statuses, _err = self.client.status_bulk(
            [h for _ref, h in pairs])
        if statuses is None:           # bulk call failed — all transient
            for ref, _h in pairs:
                out[ref] = "pending"
            return out
        for ref, h in pairs:
            st = statuses.get(h.lower())
            if not (isinstance(st, str) and st.lower() == "processed"):
                out[ref] = "pending"   # not_found / missing / still working
                continue
            verdict = self._poll_verdict(h)
            out[ref] = verdict if verdict else "pending"
        return out


class CloudBackend:
    """ScanBackend over TiCloudClient — async: submit runs the spex
    two-step upload (binary, then the metadata XML the pipeline requires
    before it processes the sample) and returns the sha1 as the receipt;
    poll_batch resolves TCA-0101 reputation by sha1. needs_sha1: spex
    addresses samples by sha1, so the pipeline's hash pass must produce
    one per file.

    meta contract: unused — no per-file submit metadata today (domain and
    archive_password come from [ticloud] config)."""

    name = "cloud"
    needs_sha1 = True
    is_sync = False

    def __init__(self, client: TiCloudClient, domain="",
                 archive_password=""):
        self.client = client
        self.domain = domain
        self.archive_password = archive_password

    # -- availability: pure delegates ----------------------------------------
    def probe(self, timeout=8):
        return self.client.probe(timeout)

    def wait_ready(self, max_wait, interval, log=None):
        return self.client.wait_ready(max_wait, interval, log=log)

    def available_now(self, ttl):
        return self.client.available_now(ttl)

    def mark_unavailable(self):
        self.client.mark_unavailable()

    # -- submit ----------------------------------------------------------------
    def _submit_once(self, filepath, sha1, sample_uploaded):
        status, _ok, err = self.client.submit_sample(
            sha1, filepath, domain=self.domain,
            archive_password=self.archive_password,
            sample_uploaded=sample_uploaded)
        if err is None:
            return SubmitOutcome(kind="receipt", ref=str(sha1).lower(),
                                 http_status=status)
        return SubmitOutcome(kind="error", http_status=status, error=err)

    def submit_once(self, filepath, sha256, sha1, meta):
        return self._submit_once(filepath, sha1, sample_uploaded=False)

    def submit_with_backoff(self, filepath, sha256, sha1, meta, cfg,
                            log=None):
        """Same retry shape as A1000Backend: every attempt gates on the
        shared availability cache, retriable failures (conn errors,
        timeouts, 408/429/5xx) back off exponentially inside
        upload_retry_window bounded by max_upload_attempts. 413 returns
        immediately; 401/403 are never retried (the factory's startup
        probe already failed fast on bad credentials).

        spex-specific: a 'meta_failed:' error means the binary is already
        stored under its sha1 — the next attempt posts ONLY the meta step
        (sample_uploaded=True), never re-uploading the file."""
        import time as _t
        deadline = _t.monotonic() + cfg.upload_retry_window
        delay = max(0.001, cfg.backoff_base_seconds)
        attempts = 0
        sample_uploaded = False
        last = SubmitOutcome(kind="error", error="no attempt made")
        while attempts < cfg.max_upload_attempts:
            if not self.client.available_now(
                    getattr(cfg, "avail_probe_seconds", 20)):
                if log:
                    log.warning("TiCloud not available — pausing upload "
                                "of %s", os.path.basename(filepath))
                self.client.wait_ready(cfg.ready_max_wait,
                                       cfg.ready_check_interval, log=log)
            attempts += 1
            last = self._submit_once(filepath, sha1, sample_uploaded)
            if last.kind != "error":
                return last
            if last.error and last.error.startswith("meta_failed:"):
                # binary already stored under sha1 — retry posts meta only
                sample_uploaded = True
            if last.http_status in TICLOUD_PERMANENT_STATUSES \
                    or last.http_status in TICLOUD_AUTH_STATUSES:
                return last
            # conn error / saturation / server-side failure — gate all
            # workers on the shared cache instead of racing a sick service.
            if last.http_status is None or last.http_status == 429 \
                    or last.http_status >= 500:
                self.client.mark_unavailable()
            if _t.monotonic() >= deadline:
                break
            if not self.client.wait_ready(cfg.ready_max_wait,
                                          cfg.ready_check_interval,
                                          log=log) and log:
                log.warning("readyz gate timed out after %ss; retrying "
                            "anyway", cfg.ready_max_wait)
            wait = min(delay, max(0.0, deadline - _t.monotonic()))
            if log:
                log.warning(
                    "TiCloud submit attempt %d failed (%s); retry in %.0fs",
                    attempts, last.error, wait)
            _t.sleep(wait)
            delay = min(delay * 2, cfg.backoff_max_seconds)
        return last

    # -- poll ------------------------------------------------------------------
    def poll_batch(self, refs, log=None):
        """Bulk-poll by sha1 (the receipt ref IS the sha1; rows may also
        carry it under 'sha1'). TCA-0101 status != UNKNOWN -> normalized
        verdict dict {classification, threat_name, threat_factor,
        report_json=raw entry}; UNKNOWN / missing / bulk failure ->
        'pending' (rows time out via report_wait_hours)."""
        out = {}
        pairs = []                     # (ref, sha1) pollable entries
        for item in refs:
            ref = item.get("ref") or item.get("task_url")
            if not ref:
                continue
            h = item.get("sha1")
            if not _is_ticloud_sha1(h):
                h = ref if _is_ticloud_sha1(ref) else None
            if h is None:
                out[ref] = "pending"   # nothing to poll with — keep waiting
                continue
            pairs.append((ref, h.lower()))
        if not pairs:
            return out
        _st, res, _err = self.client.reputation_bulk(
            [h for _ref, h in pairs], hash_type="sha1")
        if res is None:                # bulk call failed — all transient
            for ref, _h in pairs:
                out[ref] = "pending"
            return out
        entries, invalid = res
        if invalid and log:
            log.warning("ticloud reputation poll: %d invalid hash(es)",
                        len(invalid))
        # Extended entries echo the sample's hashes under sha1/md5/sha256
        # or nested under query_hash/sample_hash (the real API shape;
        # mocks may use hash_value) — index every hash field back to its
        # entry so each queried sha1 resolves to its record.
        by_hash = {}
        for ent in entries:
            for h in _ticloud_entry_hashes(ent):
                by_hash.setdefault(h, ent)
        for ref, h in pairs:
            ent = by_hash.get(h)
            if ent is None:
                out[ref] = "pending"
                continue
            v = normalize_reputation_entry(ent)
            if v["classification"] == "unknown":
                out[ref] = "pending"
                continue
            out[ref] = {
                "classification": v["classification"],
                "threat_name": v["threat_name"],
                "threat_factor": v["threat_factor"],
                "report_json": v["raw"],
            }
        return out


def _make_detect_backend(args):
    return DetectBackend(DetectAsyncClient(
        host=args.host,
        token=args.token,
        verify_ssl=not args.no_verify_ssl,
        proxy=args.proxy or None,
    ))


def _make_fie_backend(args):
    host = (getattr(args, "fie_host", "") or "").strip()
    if not host:
        logging.error("fie.host is required when scan.backend='fie'")
        sys.exit(2)
    return FieBackend(
        FieClient(host=host,
                  verify_ssl=not args.no_verify_ssl,
                  proxy=args.proxy or None),
        mode=args.fie_mode,
        trust_ok=args.fie_trust_ok,
        external_id=args.fie_external_id)


def _make_a1000_backend(args):
    host = (getattr(args, "a1000_host", "") or "").strip()
    if not host:
        logging.error("a1000.host is required when scan.backend='a1000'")
        sys.exit(2)
    token = (getattr(args, "a1000_token", "") or "").strip()
    if not token:
        logging.error("a1000.token is required when scan.backend='a1000'")
        sys.exit(2)
    client = A1000Client(host=host, token=token,
                         verify_ssl=not args.no_verify_ssl,
                         proxy=args.proxy or None)
    # One auth check at startup: 401/403 means the token is wrong and every
    # request would fail — fail fast instead of per-file errors. Unreachable
    # or 5xx is NOT fatal here: run_scan's wait_ready is the reachability
    # gate (same shape as detect/fie).
    status = client.probe_status()
    if status in (401, 403):
        logging.error("a1000 rejected the configured token (HTTP %d) — "
                      "check a1000.token", status)
        sys.exit(2)
    fields = {}
    for attr, name in (("a1000_analysis", "analysis"),
                       ("a1000_tags", "tags"),
                       ("a1000_comment", "comment"),
                       ("a1000_archive_password", "archive_password"),
                       ("a1000_sandbox_platform", "rl_cloud_sandbox_platform")):
        v = (getattr(args, attr, "") or "").strip()
        if v:
            fields[name] = v
    return A1000Backend(client, fields=fields,
                        report_detail=args.a1000_report_detail)


def _make_cloud_backend(args):
    host = (getattr(args, "ticloud_host", "") or "").strip()
    if not host:
        logging.error("ticloud.host is required when scan.backend='cloud'")
        sys.exit(2)
    username = (getattr(args, "ticloud_username", "") or "").strip()
    password = (getattr(args, "ticloud_password", "") or "").strip()
    if not username or not password:
        logging.error("ticloud.username and ticloud.password are required "
                      "when scan.backend='cloud'")
        sys.exit(2)
    client = TiCloudClient(
        host=host, username=username, password=password,
        verify_ssl=not args.no_verify_ssl,
        proxy=args.proxy or None,
        upload_timeout=getattr(args, "ticloud_upload_timeout", 300),
        min_interval_ms=getattr(args, "ticloud_min_interval_ms", 100),
        extended=getattr(args, "ticloud_extended", True))
    # One auth check at startup (same shape as a1000): 401/403 means the
    # credentials are wrong and every request would fail — fail fast
    # instead of per-file errors. Unreachable or 5xx is NOT fatal here:
    # run_scan's wait_ready is the reachability gate.
    status = client.probe_status()
    if status in TICLOUD_AUTH_STATUSES:
        logging.error("ticloud rejected the configured credentials "
                      "(HTTP %d) — check ticloud.username/"
                      "ticloud.password", status)
        sys.exit(2)
    return CloudBackend(
        client,
        domain=(getattr(args, "ticloud_domain", "") or "").strip(),
        archive_password=(getattr(args, "ticloud_archive_password", "")
                          or "").strip())


# Backend registry: name -> factory(args) -> ScanBackend. The a1000/cloud
# backend beads register their factories here; factories for auth-bearing
# backends must probe once and fail fast on 401/403 (detect needs no auth
# probe — wait_ready in run_scan is its reachability gate; fie is likewise
# unauthenticated and gated by wait_ready).
_BACKEND_FACTORIES = {
    "detect": _make_detect_backend,
    "fie": _make_fie_backend,
    "a1000": _make_a1000_backend,
    "cloud": _make_cloud_backend,
}

_VALID_BACKENDS = ("detect", "a1000", "fie", "cloud")


def make_backend(args):
    """Construct the ScanBackend selected by args.backend; exit(2) on an
    unknown value or a backend whose adapter is not registered yet."""
    name = (getattr(args, "backend", None) or "detect").lower()
    if name not in _VALID_BACKENDS:
        logging.error("scan.backend=%r invalid; valid: detect|a1000|fie|cloud",
                      name)
        sys.exit(2)
    factory = _BACKEND_FACTORIES.get(name)
    if factory is None:
        logging.error("backend %r is not yet supported in this build", name)
        sys.exit(2)
    return factory(args)


def _make_precheck_client(args):
    """TiCloudClient for the reputation pre-check stage — a separate client
    from the scan backend (precheck works with every backend, including
    cloud where it shares the same credentials). Same fail-fast shape as
    the backend factories: missing creds or a 401/403 probe abort the run
    with a logged error instead of silently degrading every precheck."""
    host = (getattr(args, "ticloud_host", "") or "").strip()
    username = (getattr(args, "ticloud_username", "") or "").strip()
    password = (getattr(args, "ticloud_password", "") or "").strip()
    if not host or not username or not password:
        logging.error("reputation.precheck=true requires ticloud.host, "
                      "ticloud.username and ticloud.password")
        sys.exit(2)
    client = TiCloudClient(
        host=host, username=username, password=password,
        verify_ssl=not args.no_verify_ssl,
        proxy=args.proxy or None,
        upload_timeout=getattr(args, "ticloud_upload_timeout", 300),
        min_interval_ms=getattr(args, "ticloud_min_interval_ms", 100),
        extended=getattr(args, "ticloud_extended", True))
    status = client.probe_status()
    if status in TICLOUD_AUTH_STATUSES:
        logging.error("ticloud rejected the configured credentials "
                      "(HTTP %d) — check ticloud.username/ticloud.password "
                      "or disable reputation.precheck", status)
        sys.exit(2)
    return client


# ---------------------------------------------------------------------------
# Directory Traversal
# ---------------------------------------------------------------------------

def _is_link_dir(path: str) -> bool:
    """True for a directory entry that is a symlink, NTFS junction or other
    reparse point — never descended into (it can point outside the drive)."""
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)   # py3.12+
    if isjunction is not None and isjunction(path):
        return True
    try:
        attrs = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def walk_usb_drive(drive_root: str, include_extensions: Optional[Set[str]],
                   skip_hidden_dirs: bool = False,
                   skipped: Optional[List[int]] = None):
    """Yield (dirpath, filenames) for readable dirs, skipping system dirs
    (and dot-directories when skip_hidden_dirs is set). Symlinked dirs,
    junctions and reparse points are pruned; `skipped[0]`, when given, is
    incremented per pruned entry."""
    for dirpath, dirnames, filenames in os.walk(drive_root, topdown=True):
        kept = []
        for d in dirnames:
            if d in SKIP_DIRS or (skip_hidden_dirs and d.startswith(".")):
                continue
            if _is_link_dir(os.path.join(dirpath, d)):
                if skipped is not None:
                    skipped[0] += 1
                logging.debug("Skipping non-regular dir: %s",
                              os.path.join(dirpath, d))
                continue
            kept.append(d)
        dirnames[:] = kept
        usable_files = []
        for fn in filenames:
            if fn in SKIP_FILES:
                continue
            if should_include_file(fn, include_extensions):
                usable_files.append(fn)
            elif skipped is not None:
                # Non-regular entries count toward the skip summary even
                # when the extension filter drops them (Go parity).
                try:
                    if not _st_is_regular(
                            os.lstat(os.path.join(dirpath, fn))):
                        skipped[0] += 1
                except OSError:
                    skipped[0] += 1
        if usable_files:
            yield dirpath, usable_files


def iter_work_items(drive_root: str, include_extensions: Optional[Set[str]],
                    skip_hidden_dirs: bool = False):
    """Yield (absolute_path, relative_path) lazily as the walk discovers them —
    uploads start on the first files found instead of waiting for a full
    tree enumeration. Only regular files are yielded: symlinks (which could
    point outside the drive), FIFOs, sockets and devices are skipped."""
    skipped = [0]       # files + pruned dirs (walk_usb_drive bumps dirs)
    for dirpath, filenames in walk_usb_drive(drive_root, include_extensions,
                                             skip_hidden_dirs, skipped):
        for filename in sorted(filenames):
            filepath = os.path.join(dirpath, filename)
            try:
                regular = _st_is_regular(os.lstat(filepath))
            except OSError:
                regular = False
            if not regular:
                skipped[0] += 1
                logging.debug("Skipping non-regular file: %s", filepath)
                continue
            yield filepath, os.path.relpath(filepath, drive_root)
    if skipped[0]:
        logging.info("Skipped %d non-regular entries (symlinks, junctions, "
                     "devices, FIFOs)", skipped[0])


def build_work_list(drive_root: str, include_extensions: Optional[Set[str]]) -> List[Tuple[str, str]]:
    """Return a list of (absolute_path, relative_path) for all matching files."""
    return list(iter_work_items(drive_root, include_extensions))


def disk_read_gate(args, work, logger: logging.Logger) -> None:
    """
    Time-boxed sequential read of files on the drive. Below min_read_mbps the
    USB/drive becomes the bottleneck, so warn and gate before any upload starts.
    Modes: 'ask' (warn + prompt), 'always' (warn + abort), 'off' (skip).
    """
    if args.read_speed_test == "off" or not work:
        return
    budget_bytes = args.read_test_max_bytes
    deadline = time.monotonic() + args.read_test_max_seconds
    start = time.monotonic()
    read = 0
    for filepath, _rel in work:
        if read >= budget_bytes or time.monotonic() >= deadline:
            break
        try:
            with open_regular(filepath) as f:
                while read < budget_bytes and time.monotonic() < deadline:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    read += len(chunk)
        except OSError:
            continue
    elapsed = max(0.001, time.monotonic() - start)
    mbps = read / elapsed / 1_000_000
    logger.info("Disk read test: %.1f MB in %.1fs = %.2f MB/s",
                read / 1_000_000, elapsed, mbps)
    if mbps >= args.min_read_mbps:
        return
    msg = (f"Disk read speed {mbps:.2f} MB/s is below "
           f"{args.min_read_mbps} MB/s - the drive will bottleneck scanning")
    if args.read_speed_test == "always":
        logger.error("%s (read_speed_test=always - aborting)", msg)
        sys.exit(1)
    logger.warning(msg)
    try:
        ans = input("Proceed anyway? [y/N] ")
    except EOFError:
        ans = ""
    if ans.strip().lower() not in ("y", "yes"):
        logger.error("Aborted: disk read test %.2f MB/s below threshold.", mbps)
        sys.exit(1)
    logger.warning("Continuing despite slow disk read speed.")


# ---------------------------------------------------------------------------
# Per-file processing (runs in worker threads)
# ---------------------------------------------------------------------------

class ScanContext:
    """Shared, thread-safe configuration/state passed to every worker."""

    def __init__(self, args, sdk_client, state, alerter, counters,
                 keyed_locks, quarantine_dir, logger, total):
        self.args = args
        self.sdk = sdk_client
        self.state = state
        self.alerter = alerter
        self.counters = counters
        self.keyed_locks = keyed_locks
        self.quarantine_dir = quarantine_dir
        self.logger = logger
        self.total = total
        self._progress_lock = threading.Lock()
        # Uploads and reports are counted separately — sharing one counter
        # makes "[report n/total]" overshoot total.
        self._done_uploads = 0
        self._done_reports = 0
        # Serializes filesystem quarantine so check-then-act is atomic.
        self._quarantine_lock = threading.Lock()
        # Set when no result poller is (or will be) draining in-flight rows
        # (none started, all exited, or interrupted) — the max_in_flight
        # throttle must then give up instead of spinning forever.
        self.pollers_stopped = threading.Event()
        # Set on the first Ctrl-C (before reports are written): the feeder
        # stops enqueuing, workers start no new item, pollers exit.
        self.stop = threading.Event()
        # sha256 -> [(abs_path, rel_path)] for in-run duplicates: files
        # whose content already owns an in-flight/completed row. Verdict
        # actions drain this so every path is quarantined, not just the
        # row's single file_path.
        self._dup_paths = {}
        self._dup_paths_lock = threading.Lock()

    def note_dup_path(self, sha256: str, abs_path: str, rel_path: str) -> None:
        with self._dup_paths_lock:
            self._dup_paths.setdefault(sha256, []).append((abs_path, rel_path))

    def take_dup_paths(self, sha256: str):
        """Pop every queued duplicate path for a hash (drain is one-shot)."""
        with self._dup_paths_lock:
            return self._dup_paths.pop(sha256, [])

    def add_total(self, n: int) -> None:
        """Enumeration is lazy — total grows as files are discovered; the
        progress denominator converges on the real count."""
        with self._progress_lock:
            self.total += n

    def bump_progress(self, relative_path: str, note: str, ok: bool = True) -> None:
        v = getattr(self.args, "progress_every", 100)
        every = v if isinstance(v, int) and v > 0 else 100
        with self._progress_lock:
            self._done_reports += 1
            done, total = self._done_reports, self.total
        line = "[report %d/%d] %s %s"
        if ok:
            # Per-file lines flood stdout on big scans — DEBUG unless verbose.
            self.logger.debug(line, done, total, note, relative_path)
            if done % every == 0:
                self.logger.info("progress reports: %d/%d collected", done, total)
        else:
            self.logger.warning(line, done, total, note, relative_path)

    def bump_upload(self, relative_path: str, note: str, ok: bool = True) -> None:
        v = getattr(self.args, "progress_every", 100)
        every = v if isinstance(v, int) and v > 0 else 100
        with self._progress_lock:
            self._done_uploads += 1
            done, total = self._done_uploads, self.total
        line = "[upload %d/%d] %s %s"
        if ok:
            self.logger.debug(line, done, total, note, relative_path)
            if done % every == 0:
                c = self.counters.snapshot()
                self.logger.info(
                    "progress uploads: %d/%d done "
                    "(submitted=%d cached=%d failed=%d skipped=%d)",
                    done, total, c.get("submitted", 0), c.get("cached", 0),
                    c.get("errors", 0), c.get("skipped_filetype", 0))
        else:
            self.logger.warning(line, done, total, note, relative_path)


def _as_backend(client):
    """Coerce a pipeline `client` argument into a ScanBackend.

    run_scan/upload tests may still hand in a raw DetectAsyncClient (or a
    mock of one): anything without a registered backend `.name` is wrapped
    in the detect adapter so legacy call sites keep byte-identical
    behavior. A real ScanBackend's `name` is one of _VALID_BACKENDS —
    a bare client/mock's `.name` never matches."""
    if getattr(client, "name", None) in _VALID_BACKENDS:
        return client
    return DetectBackend(client)


def _ctx_event(ctx, name):
    """ctx.<name> if it is a real threading.Event (tests may pass mocks)."""
    ev = getattr(ctx, name, None)
    return ev if isinstance(ev, threading.Event) else None


def upload_worker(ctx, db, client, work_q, precheck_q=None, writer=None):
    """Drain work_q: hash+head in one pass, dedup, submit, record in DB.

    `client` is a ScanBackend (a raw DetectAsyncClient is wrapped — see
    _as_backend). work_q items are either (filepath, rel_path) tuples from
    the feeder or prehashed dicts re-enqueued by the precheck stage
    ({"sha256","sha1","filepath","rel_path","size","head","prehashed":True})
    which skip the hashing pass. With precheck_q enabled, hashed items are
    queued for the reputation pre-check instead of being submitted.

    Termination is sentinel-driven: the feeder appends one None per worker
    after the last item, so a worker exits only when the feed is truly done
    (a bounded queue can sit empty for >0.5s while the feeder blocks on a
    full queue — a timeout exit here would strand items or deadlock). A
    failure on one item is logged/counted, never kills the worker.
    """
    backend = _as_backend(client)
    args = ctx.args
    stop = _ctx_event(ctx, "stop")
    while True:
        item = work_q.get()
        sha256 = filepath = rel_path = None
        try:
            if item is None:            # sentinel: feeder finished — exit
                return
            if stop is not None and stop.is_set():
                # Interrupted: drain without starting the item — its row
                # (if any) stays as-is and is picked up on resume.
                continue
            # Feed tuples are (filepath, rel_path); the precheck stage hands
            # back dicts carrying the precomputed hashes + head bytes.
            item_sha1 = None
            prior = None    # persisted (file_path, actions) before upsert
            if isinstance(item, dict):
                filepath = item.get("filepath")
                rel_path = item.get("rel_path")
                if item.get("prehashed") and item.get("sha256"):
                    sha256 = item["sha256"]
                    item_sha1 = item.get("sha1")
                    head = item.get("head") or b""
                    file_size = item.get("size") or 0
                    prior = db.action_state(sha256)
                    db.upsert_pending(sha256, filepath, rel_path,
                                      file_size, item_sha1,
                                      requeue_done=not args.resume)
                else:
                    sha256 = None       # malformed dict — hash it below
            else:
                filepath, rel_path = item
            if sha256 is None:
                try:
                    file_size = os.path.getsize(filepath)
                except OSError:
                    file_size = 0

                # One streaming pass: sha256 (+sha1 for needs_sha1 backends)
                # of whole file + head bytes. Head is only consumed by the
                # file_types filter, which reads head[:4096] — cap there;
                # without the filter capturing head would be dead memory.
                capture = min(file_size, HEAD_CAPTURE_BYTES) if args.file_types else 0
                sha256, item_sha1, head, _total = read_hash_capture(
                    filepath, capture, want_sha1=backend.needs_sha1)
                if not sha256:
                    db.upsert_pending(f"nohash:{rel_path}", filepath, rel_path, file_size)
                    db.mark_failed(f"nohash:{rel_path}", None, "read_error")
                    ctx.counters.inc("errors")
                    ctx.bump_upload(rel_path, "READ-ERROR", ok=False)
                    continue

                # Read the persisted path/actions BEFORE the upsert overwrites
                # file_path: a cached hit re-runs actions only for a new path.
                prior = db.action_state(sha256)
                db.upsert_pending(sha256, filepath, rel_path, file_size,
                                  item_sha1, requeue_done=not args.resume)

            # Dedup-check + submit is check-then-act: identical files landing
            # on two workers must not both POST (the second mark_submitted
            # would clobber the first's task_url). Serialize per sha256.
            with ctx.keyed_locks.get(sha256):
                # A 'submitted'/'reporting' row means an in-flight task
                # exists — always skip, even with resume off.
                # done/cached skip needs resume.
                known = db.known_verdict(sha256)
                if known and known["status"] in ("submitted", "reporting"):
                    ctx.counters.inc("cached")
                    ctx.bump_upload(rel_path, "ALREADY-SUBMITTED")
                    # The row is owned by another path but the verdict's
                    # actions apply to every copy of this content.
                    _park_dup_path(ctx, db, backend.name, sha256, filepath,
                                   rel_path, writer)
                    continue
                if args.resume and known and known["status"] in ("done", "cached"):
                    db.mark_cached(sha256)
                    ctx.counters.inc("cached")
                    # A cached verdict still gets alert/quarantine for this
                    # file — unless the persisted actions show this same
                    # path was already handled (no alert spam on resume).
                    same = (prior is not None
                            and prior["file_path"] == filepath)
                    prev_q = prior["quarantined_to"] if same else None
                    prev_a = bool(same and prior["alerted"] == 1)
                    record = {
                        "file_path": rel_path,
                        "absolute_path": filepath,
                        "file_type": None,
                        "sha256": sha256,
                        "classification": known["classification"] or "unknown",
                        "threat_name": known["threat_name"],
                        "threat_factor": known["threat_factor"],
                        "task_url": None,
                        "quarantined_to": prev_q,
                        "alerted": prev_a,
                        "cached": True,
                        "api": {"status": "cached", "error": None,
                                "report": None},
                    }
                    if backend.name != "detect":
                        record["backend"] = backend.name
                    _verdict_actions(ctx, db, record,
                                     skip_quarantine=bool(prev_q),
                                     skip_alert=prev_a, writer=writer)
                    if writer is not None:
                        writer.write(record)
                    ctx.bump_upload(rel_path, "CACHED")
                    continue

                # Optional detected-type filter (head already captured above).
                if args.file_types:
                    ftype = detect_file_type(head[:4096])
                    if ftype not in args.file_types:
                        db.mark_failed(sha256, None, f"skipped_filetype:{ftype}")
                        ctx.counters.inc("skipped_filetype")
                        ctx.bump_upload(rel_path, "SKIP (file-type)")
                        continue

                if precheck_q is not None and not isinstance(item, dict):
                    # Reputation pre-check stage: hand the freshly-hashed
                    # item off — put_nowait never blocks -> no deadlock
                    # under the keyed lock even though the queue is
                    # bounded. A saturated stage fails open the same way
                    # a bulk error does: fall through to the inline
                    # submit below (every local is already populated).
                    # Verdicts land there; unknowns come back as
                    # prehashed dicts. Dict items are exactly that
                    # precheck output — re-diverting them would bounce
                    # the file between the two queues forever, so only
                    # raw feed tuples take this branch.
                    try:
                        precheck_q.put_nowait(
                            {"sha256": sha256, "sha1": item_sha1,
                             "filepath": filepath, "rel_path": rel_path,
                             "size": file_size, "head": head,
                             "prehashed": True})
                        continue
                    except queue.Full:
                        ctx.counters.inc("precheck_bypassed")

                # Don't overwhelm Detect: throttle when too many in flight.
                # Pollers time rows out per-row, so in_flight always drains
                # while they run; if they are gone it never will — fail the
                # item (re-queued on the next run) instead of spinning. On
                # Ctrl-C (ctx.stop) the row is left pending, not failed.
                stopped = _ctx_event(ctx, "pollers_stopped")
                throttle_aborted = False
                while args.max_in_flight and db.in_flight() >= args.max_in_flight:
                    if stopped is not None and stopped.is_set():
                        throttle_aborted = True
                        break
                    if stopped is not None:
                        stopped.wait(max(1, args.result_poll_interval))
                    else:
                        time.sleep(max(1, args.result_poll_interval))
                if throttle_aborted and stop is not None and stop.is_set():
                    continue            # interrupted: leave the row pending
                if throttle_aborted:
                    db.mark_failed(sha256, None, "max_in_flight throttle: "
                                   "result pollers stopped")
                    ctx.counters.inc("errors")
                    ctx.bump_upload(rel_path, "FAILED (throttle)", ok=False)
                    continue

                meta = {"original_relative_path": rel_path,
                        "original_absolute_path": filepath, "sha256": sha256,
                        "rel_path": rel_path}
                outcome = backend.submit_with_backoff(
                    filepath, sha256, item_sha1, meta, args, log=ctx.logger)
                if outcome.kind == "receipt":
                    db.mark_submitted(sha256, outcome.ref, backend.name,
                                      file_path=filepath, rel_path=rel_path)
                    ctx.counters.inc("submitted")
                    ctx.bump_upload(rel_path,
                                    f"SUBMITTED [{backend.name}]")
                elif outcome.kind == "verdict":
                    # Synchronous verdict (FIE): pending -> done directly,
                    # then the same side effects the result poller applies.
                    rj = outcome.report_json
                    stored = (json.dumps(rj)
                              if args.store_full_report and rj is not None
                              else None)
                    cls = outcome.classification or "unknown"
                    flipped = db.mark_done_direct(
                        sha256, cls, outcome.threat_name,
                        outcome.threat_factor, stored, backend.name)
                    if flipped:
                        record = {
                            "file_path": rel_path,
                            "absolute_path": filepath,
                            "file_type": None,
                            "sha256": sha256,
                            "classification": cls,
                            "threat_name": outcome.threat_name,
                            "threat_factor": outcome.threat_factor,
                            "task_url": None,
                            "quarantined_to": None,
                            "alerted": False,
                            "api": {"status": "completed", "error": None,
                                    "report": None if args.summary_only
                                    else outcome.report_json},
                        }
                        if backend.name != "detect":
                            record["backend"] = backend.name
                        _verdict_actions(ctx, db, record, writer=writer)
                        if writer is not None:
                            writer.write(record)
                        ctx.bump_upload(rel_path,
                                        cls.upper() + " (sync)", ok=True)
                    else:
                        # Row was not 'pending' — another path owns it now
                        # (dup content / resumed run). Queue this path so
                        # its verdict's actions still reach every copy.
                        ctx.counters.inc("cached")
                        ctx.bump_upload(rel_path, "CACHED")
                        _park_dup_path(ctx, db, backend.name, sha256,
                                       filepath, rel_path, writer)
                else:
                    db.mark_failed(sha256, outcome.http_status,
                                   outcome.error)
                    ctx.counters.inc("errors")
                    ctx.bump_upload(rel_path,
                                    f"FAILED {outcome.http_status or ''}",
                                    ok=False)
        except Exception as e:  # noqa: BLE001 — a bad file must not kill a worker
            ctx.counters.inc("errors")
            ctx.logger.error("Upload worker error on %s: %s", rel_path or item, e)
            try:
                # Record a 'failed' row so the file is never silently dropped.
                key = sha256 or (f"nohash:{rel_path}" if rel_path else None)
                if key:
                    if sha256 is None:
                        db.upsert_pending(key, filepath or "", rel_path or "", 0)
                    db.mark_failed(key, None, f"worker_error: {e}")
            except Exception:  # noqa: BLE001 — DB itself failing; count stands
                pass
        finally:
            work_q.task_done()


def run_upload_pool(ctx, db, client, work_items, writer=None,
                    precheck_client=None):
    """Feed `work_items` (list or lazy iterator) through the bounded queue.
    With a lazy iterator, uploads start while the directory walk is still
    discovering files; the queue maxsize back-pressures the walk. Returns the
    number of items fed.

    With `precheck_client` set, one precheck_worker runs alongside the
    upload workers: hashed items detour through precheck_q for a TCA-0101
    verdict and unknowns come back as prehashed dicts. Shutdown is ordered —
    the feed drains (work_q.join), the precheck stage gets its sentinel and
    fully flushes (precheck_q.join), then worker sentinels go on work_q:
    FIFO guarantees every re-enqueued dict is processed before a worker can
    see its sentinel, so no file is stranded and no worker exits early."""
    backend = _as_backend(client)
    work_q = queue.Queue(maxsize=max(4, 4 * ctx.args.upload_workers))
    precheck_q = None
    pre_threads = []
    if precheck_client is not None:
        # Bounded like work_q; producers use put_nowait and fail open to
        # inline submit on Full, so a stalled TiCloud can't grow memory.
        precheck_q = queue.Queue(maxsize=max(4, 4 * ctx.args.upload_workers))
        t = threading.Thread(
            target=precheck_worker,
            args=(ctx, db, precheck_client, precheck_q, work_q, ctx.args,
                  writer),
            name="precheck-0", daemon=True)
        t.start()
        pre_threads.append(t)
    threads = [
        threading.Thread(target=upload_worker,
                         args=(ctx, db, backend, work_q, precheck_q, writer),
                         name=f"upload-{i}", daemon=True)
        for i in range(ctx.args.upload_workers)]
    for t in threads:
        t.start()
    fed = 0
    stop = _ctx_event(ctx, "stop")
    for item in work_items:         # bounded queue -> lazy feeding, low memory
        if stop is not None and stop.is_set():
            break                   # Ctrl-C: enqueue nothing more
        work_q.put(item)
        fed += 1
        ctx.add_total(1)
    if precheck_q is not None:
        work_q.join()               # every raw item hashed -> precheck fed
        for _ in pre_threads:       # one sentinel per precheck worker
            precheck_q.put(None)
        precheck_q.join()           # all batches flushed; unknowns re-queued
        for t in pre_threads:
            t.join()
    for _ in threads:               # one sentinel per worker; FIFO guarantees
        work_q.put(None)            # they arrive after every real item
    for t in threads:
        t.join()
    return fed


# ---------------------------------------------------------------------------
# Reputation pre-check (TCA-0101 bulk) — stage between hashing and upload
# ---------------------------------------------------------------------------
#
# Queue contract. The hashing stage produces precheck_q items of the shape:
#
#     {"sha256": str, "sha1": str | None, "filepath": str, "rel_path": str,
#      "size": int, "head": bytes, "prehashed": True}
#
# and has already called db.upsert_pending for each item. The SAME dict shape
# is re-enqueued verbatim onto work_q whenever a file still needs the upload
# path — `prehashed=True` tells upload_worker to skip a second
# read_hash_capture (the integration bead owns that branch). Termination
# mirrors upload_worker exactly: the feeder appends one None sentinel after
# the last item, so exit is sentinel-driven (a bounded queue can sit empty
# for a while — a timeout must never terminate the worker).

# Partial-batch drain deadline: caps how long a short tail (fewer items than
# batch_size) waits for company before flushing. 2s keeps the drain prompt
# without busy-polling the queue.
PRECHECK_FLUSH_SECONDS = 2.0


def _reputation_bulk_with_backoff(ctx, client, hashes, cfg):
    """TCA-0101 bulk query with the shared availability gate + exponential
    backoff — same retry shape as ScanBackend.submit_with_backoff: every
    attempt gates on available_now (at most one probe per avail_probe_seconds
    across workers); conn errors/timeouts/429/5xx stamp the shared cache
    unavailable so other callers gate instead of racing a sick service;
    retries are bounded by max_upload_attempts inside upload_retry_window.
    Non-retriable outcomes (auth 401/403, other 4xx, malformed body) return
    immediately — retrying them cannot help.

    Returns the reputation_bulk triple: (status, (entries, invalid)|None,
    err|None)."""
    deadline = time.monotonic() + cfg.upload_retry_window
    delay = max(0.001, cfg.backoff_base_seconds)
    attempts = 0
    last = (None, None, "no attempt made")
    while attempts < cfg.max_upload_attempts:
        if not client.available_now(getattr(cfg, "avail_probe_seconds", 20)):
            ctx.logger.warning("TiCloud not available — pausing reputation "
                               "pre-check")
            client.wait_ready(cfg.ready_max_wait, cfg.ready_check_interval,
                              log=ctx.logger)
        attempts += 1
        last = client.reputation_bulk(hashes, hash_type="sha256")
        status, res, err = last
        if err is None:
            return last
        # conn error / saturation / server-side failure — gate all callers
        # on the shared cache instead of racing a sick service.
        if status is None or status == 429 or status >= 500:
            client.mark_unavailable()
        retriable = (status is None or status in TICLOUD_RETRIABLE_STATUSES
                     or status >= 500)
        if not retriable or time.monotonic() >= deadline:
            break
        if not client.wait_ready(cfg.ready_max_wait, cfg.ready_check_interval,
                                 log=ctx.logger):
            ctx.logger.warning("readyz gate timed out after %ss; retrying "
                               "anyway", cfg.ready_max_wait)
        wait = min(delay, max(0.0, deadline - time.monotonic()))
        ctx.logger.warning("TiCloud reputation precheck attempt %d failed "
                           "(%s); retry in %.0fs", attempts, err, wait)
        time.sleep(wait)
        delay = min(delay * 2, cfg.backoff_max_seconds)
    return last


def _precheck_apply_batch(ctx, db, client, items, work_q, cfg, writer):
    """Resolve one batch of sha256s via TCA-0101 and route each item.

    Per item:
      * classification != 'unknown' and the verdict lands (pending -> done)
        -> mark_done_direct(backend='ticloud') + NDJSON record + counters/
        quarantine/alert via _verdict_actions — the same side effects the
        result poller applies. skip_classified drops the item (never
        uploaded); skip_classified=False re-enqueues it anyway (enrichment
        mode).
      * 'unknown', missing entry, or a verdict that can't stick (the row is
        no longer 'pending' — e.g. failed/timeout) -> re-enqueued to work_q:
        fail-open, the upload path must never lose a file. Rows already
        in-flight ('submitted'/'reporting') are dropped instead — the live
        task owns the row.
      * Bulk-call failure -> every item re-enqueued to work_q (fail-open).
    """
    skip_classified = getattr(cfg, "reputation_skip_classified", True)
    # Dedup preserves order; identical content shares one sha256 row.
    hashes = list(dict.fromkeys(it["sha256"] for it in items))
    _status, res, err = _reputation_bulk_with_backoff(ctx, client, hashes, cfg)
    if res is None:
        # Persistent bulk failure — fail open to the upload path. Counted
        # separately from per-file errors: no file failed.
        ctx.counters.inc("precheck_errors")
        ctx.logger.warning("reputation precheck failed (%s); %d item(s) "
                           "re-enqueued for upload", err, len(items))
        for it in items:
            work_q.put(it)
        return
    entries, invalid = res
    if invalid:
        ctx.counters.inc("precheck_invalid_hashes", len(invalid))
        ctx.logger.warning("ticloud reputation precheck: %d invalid "
                           "hash(es)", len(invalid))
    # Extended entries echo the sample's hashes under sha1/md5/sha256 or
    # nested under query_hash/sample_hash — same indexing as
    # CloudBackend.poll_batch via _ticloud_entry_hashes.
    by_hash = {}
    for ent in entries:
        for h in _ticloud_entry_hashes(ent):
            by_hash.setdefault(h, ent)
    for it in items:
        sha256 = it["sha256"]
        ent = by_hash.get(str(sha256).lower())
        classified = False
        if ent is not None:
            v = normalize_reputation_entry(ent)
            if v["classification"] != "unknown":
                classified = True
                # Hashing already upsert_pending'ed; repeating keeps the
                # worker safe if that contract drifts — the upsert only
                # requeues failed/timeout (and done/cached with resume off),
                # never in-flight 'submitted'/'reporting' rows.
                # sha1 rides along so needs_sha1 backends keep their hash.
                db.upsert_pending(sha256, it.get("filepath", ""),
                                  it.get("rel_path", ""), it.get("size", 0),
                                  it.get("sha1"),
                                  requeue_done=not ctx.args.resume)
                # Same record shape result_poller writes, plus the
                # backend marker.
                record = {
                    "file_path": it.get("rel_path", ""),
                    "absolute_path": it.get("filepath", ""),
                    "file_type": None,
                    "sha256": sha256,
                    "classification": v["classification"],
                    "threat_name": v["threat_name"],
                    "threat_factor": v["threat_factor"],
                    "task_url": None,
                    "quarantined_to": None,
                    "alerted": False,
                    "backend": "ticloud",
                    "api": {"status": "completed", "error": None,
                            "report": None if getattr(
                                cfg, "summary_only", False) else ent},
                }
                flipped = (skip_classified and db.mark_done_direct(
                    sha256, v["classification"], v["threat_name"],
                    v["threat_factor"], json.dumps(v["raw"]), "ticloud"))
                if flipped:
                    _verdict_actions(ctx, db, record, writer=writer)
                    writer.write(record)
                    ctx.bump_progress(
                        it.get("rel_path", ""),
                        v["classification"].upper() + " (precheck)")
                elif not skip_classified:
                    # Enrichment only: the row stays 'pending' so the
                    # upload path's resume dedup can't short-circuit —
                    # the backend verdict owns the final row. No
                    # quarantine or alerts yet: those are final-verdict
                    # actions (a quarantine move would break the pending
                    # upload, and alerting now would double-alert).
                    writer.write(record)
                    ctx.bump_progress(
                        it.get("rel_path", ""),
                        v["classification"].upper() + " (precheck)")
                else:
                    # The row was not 'pending': a verdict may already stand
                    # (dup content, resumed run) or the row may be unwritable
                    # ('failed'/'timeout' — never lose the file).
                    kv = db.known_verdict(sha256)
                    if kv is not None and kv["status"] in (
                            "submitted", "reporting"):
                        # live task owns the row — drop; its verdict's
                        # drain still reaches this path.
                        _park_dup_path(ctx, db, "ticloud", sha256,
                                       it.get("filepath", ""),
                                       it.get("rel_path", ""), writer)
                        continue
                    if kv is None or kv["status"] not in ("done", "cached"):
                        classified = False      # verdict lost -> fail open
                    else:
                        # Verdict already final: run per-path actions for
                        # this copy now — no drain is coming for it.
                        _apply_dup_path(
                            ctx, sha256, kv["classification"],
                            kv["threat_name"], kv["threat_factor"],
                            "ticloud", it.get("filepath", ""),
                            it.get("rel_path", ""), writer)
        if not classified or not skip_classified:
            work_q.put(it)


def precheck_worker(ctx, db, ticloud_client, precheck_q, work_q, cfg, writer):
    """Drain precheck_q in sha256 batches; verdict items via TCA-0101.

    cfg is the args namespace (reputation_batch_size,
    reputation_skip_classified, summary_only, backoff_* knobs); None falls
    back to ctx.args so the worker can run off ScanContext alone.

    Drain: collect up to batch_size items; each get() waits at most
    PRECHECK_FLUSH_SECONDS, so a partial batch flushes instead of stalling
    the tail of a feed. The None sentinel ends the worker exactly like
    upload_worker — the accumulated batch is flushed first so queued files
    are never stranded. A failure mid-batch is contained (log + count) and
    fails open: every affected item is re-enqueued to work_q.
    """
    if cfg is None:
        cfg = ctx.args
    batch_size = getattr(cfg, "reputation_batch_size", 100) or 100
    # reputation_bulk also chunks at TICLOUD_REPUTATION_CHUNK (API max 100);
    # clamping here keeps one worker batch == one API call.
    batch_size = max(1, min(100, batch_size))
    batch = []

    def _flush():
        nonlocal batch
        items, batch = batch, []
        if not items:
            return
        try:
            _precheck_apply_batch(ctx, db, ticloud_client, items, work_q,
                                  cfg, writer)
        except Exception as e:  # noqa: BLE001 — never lose files
            ctx.counters.inc("precheck_errors")
            ctx.logger.error("precheck batch failed; re-enqueueing %d "
                             "item(s): %s", len(items), e)
            for it in items:
                work_q.put(it)
        finally:
            for _ in items:
                precheck_q.task_done()

    while True:
        try:
            item = precheck_q.get(timeout=PRECHECK_FLUSH_SECONDS)
        except queue.Empty:
            _flush()
            continue
        if item is None:                # sentinel: feed finished — drain, exit
            try:
                _flush()
            finally:
                precheck_q.task_done()
            return
        if not isinstance(item, dict) or not item.get("sha256"):
            # Malformed item — nothing to query without a sha256; hand it to
            # the upload path with prehashed cleared so it is hashed there.
            ctx.counters.inc("errors")
            ctx.logger.warning("precheck got malformed item (no sha256): "
                               "%r — routed to upload path", item)
            try:
                if isinstance(item, dict):
                    item["prehashed"] = False
                work_q.put(item)
            finally:
                precheck_q.task_done()
            continue
        batch.append(item)
        if len(batch) >= batch_size:
            _flush()


class ResultsWriter:
    """Append-only NDJSON sink for per-file records (crash-safe streaming)."""
    def __init__(self, path):
        self._f = open(path, "a", encoding="utf-8")
        self._lock = threading.Lock()
        self._closed = False

    def write(self, record: dict) -> None:
        # No-op after close: daemon workers may still finish an item after
        # run_scan closed the writer on Ctrl-C (Go parity).
        with self._lock:
            if self._closed:
                return
            self._f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._f.flush()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._f.close()


def _apply_dup_path(ctx, sha256, cls, threat, factor, backend_name,
                    abs_path, rel_path, writer):
    """Verdict side effects + NDJSON row for ONE duplicate path of a hash
    whose verdict already landed. Quarantine runs per path (each physical
    copy); the alert stays per-hash — the primary record's alert fired
    already. The row keeps its single file_path/action columns."""
    cls = cls or "unknown"
    record = {
        "file_path": rel_path,
        "absolute_path": abs_path,
        "file_type": None,
        "sha256": sha256,
        "classification": cls,
        "threat_name": threat,
        "threat_factor": factor,
        "task_url": None,
        "quarantined_to": None,
        "alerted": False,
        "duplicate": True,
        "cached": True,
        "api": {"status": "cached", "error": None, "report": None},
    }
    if backend_name and backend_name != "detect":
        record["backend"] = backend_name
    args = ctx.args
    ctx.counters.inc(cls if cls in ("malicious", "suspicious", "goodware",
                                    "unknown") else "other")
    if cls in args.quarantine_on and args.quarantine_action != "none":
        with ctx._quarantine_lock:
            dest = quarantine_file(abs_path, sha256, cls, ctx.quarantine_dir,
                                   args.quarantine_action, ctx.logger)
        record["quarantined_to"] = dest
        if dest:
            ctx.counters.inc("quarantined")
    if writer is not None:
        writer.write(record)
    ctx.bump_upload(rel_path, cls.upper() + " (dup)")


def _park_dup_path(ctx, db, backend_name, sha256, abs_path, rel_path, writer):
    """This file's content shares a hash-keyed row owned by another path:
    queue it for the verdict's per-path drain — or service every queued
    path right now if the verdict already landed between our dedup check
    and here (no drain is coming for late arrivals)."""
    ctx.note_dup_path(sha256, abs_path, rel_path)
    kv = db.known_verdict(sha256)
    if kv is None or kv["status"] not in ("done", "cached"):
        return
    dups = ctx.take_dup_paths(sha256)
    if not isinstance(dups, list):
        return
    for abs_p, rel_p in dups:
        _apply_dup_path(ctx, sha256, kv["classification"], kv["threat_name"],
                        kv["threat_factor"], backend_name, abs_p, rel_p,
                        writer)


def _verdict_actions(ctx, db, record, skip_quarantine=False, skip_alert=False,
                     writer=None):
    """Quarantine + alert side effects for a completed verdict. skip_* keep
    an action already persisted for this same path (cached hits); the
    record's quarantined_to/alerted then carry the persisted values."""
    args = ctx.args
    cls = record["classification"]
    ctx.counters.inc(cls if cls in ("malicious", "suspicious", "goodware", "unknown")
                     else "other")
    if (not skip_quarantine and cls in args.quarantine_on
            and args.quarantine_action != "none"):
        with ctx._quarantine_lock:  # make check-then-act atomic across pollers
            dest = quarantine_file(record["absolute_path"], record["sha256"], cls,
                                   ctx.quarantine_dir, args.quarantine_action,
                                   ctx.logger)
        record["quarantined_to"] = dest
        if dest:
            ctx.counters.inc("quarantined")
    if not skip_alert and ctx.alerter and ctx.alerter.maybe_alert(record):
        record["alerted"] = True
        ctx.counters.inc("alerts")
    db.mark_actions(record["sha256"], record.get("quarantined_to"),
                    record.get("alerted", False))
    # Every in-run duplicate path queued behind this verdict gets the same
    # per-path treatment; the hash's alert stays single.
    take = getattr(ctx, "take_dup_paths", None)
    dups = take(record["sha256"]) if callable(take) else None
    if isinstance(dups, list):
        for abs_p, rel_p in dups:
            if abs_p == record["absolute_path"]:
                continue                # the row's own path — actioned above
            _apply_dup_path(ctx, record["sha256"], record["classification"],
                            record.get("threat_name"),
                            record.get("threat_factor"),
                            record.get("backend") or "detect",
                            abs_p, rel_p, writer)


def result_poller(ctx, db, client, report_wait_seconds, uploads_done_event,
                  writer, run_started_at=None):
    """Poll every submitted task_url until processed; per-row deadline ->
    mark timeout.

    report_wait_seconds is a PER-ROW budget: each sweep first flips every
    submitted/reporting row with uploaded_at older than it to 'timeout'
    (db.expire_overdue). The poller exits only when the upload phase is
    finished (uploads_done_event) AND no submitted/reporting rows remain —
    a file uploaded late still gets its full wait window. Rows resumed from
    an earlier run get the budget counted from run_started_at (this run's
    start, DB clock) instead of their old uploaded_at.

    `client` is a ScanBackend — its poll_batch resolves a batch of claimed
    receipts each sweep ('gone' -> fail_claimed, 'pending' -> unclaim, a
    verdict dict -> mark_done + record + verdict_actions). A raw
    DetectAsyncClient (legacy callers/tests) keeps the original per-row
    task_status loop verbatim — byte-identical detect behavior.

    Exactly-once per row: db.claim_report atomically flips submitted->reporting
    so multiple pollers can never apply side effects (NDJSON/alert/quarantine)
    twice. The outer try/except keeps the poller alive through unexpected
    errors — if the only poller dies, submitted rows are never collected and
    the in_flight throttle deadlocks the upload pool.
    """
    args = ctx.args
    backend = client if getattr(client, "name", None) in _VALID_BACKENDS \
        else None
    seen_stuck = 0
    stop = _ctx_event(ctx, "stop")
    while True:
        if stop is not None and stop.is_set():
            return                  # Ctrl-C: reports come from DB state
        try:
            # Per-row deadline: one atomic sweep; the rowcount is exactly the
            # rows this call flipped, so concurrent pollers never
            # double-count. Timed-out tasks are errors (files_with_errors
            # exit-code path).
            n_timeout = db.expire_overdue(report_wait_seconds, run_started_at)
            if n_timeout:
                ctx.counters.inc("errors", n_timeout)
                ctx.logger.warning("Report wait exceeded; %d row(s) timed out",
                                   n_timeout)
            rows = db.submitted_rows()
            if backend is not None:
                # ---- ScanBackend path: claim a batch, one poll_batch call ----
                # Atomic claim: only one poller wins each submitted->reporting
                # flip, so each report's side effects happen exactly once.
                claimed = [row for row in rows
                           if db.claim_report(row["sha256"])]
                if claimed:
                    # Each ref dict carries at least 'ref' plus the row fields
                    # backends may poll by (sha256 for a1000, sha1 via ref for
                    # cloud, task_url for detect).
                    refs = [dict(row, ref=row["task_url"]) for row in claimed]
                    try:
                        results = backend.poll_batch(refs, log=ctx.logger) or {}
                    except Exception as e:  # noqa: BLE001 — transient sweep
                        ctx.logger.warning("report poll_batch failed: %s", e)
                        results = {}
                    for row in claimed:
                        res = results.get(row["task_url"])
                        if res is None or res == "pending":
                            db.unclaim_report(row["sha256"])
                            continue
                        if res == "gone":
                            # Receipt purged server-side — terminal, not
                            # retriable (detect task-eviction parity).
                            db.fail_claimed(row["sha256"],
                                            "task record lost (404)")
                            ctx.counters.inc("errors", 1)
                            ctx.logger.warning(
                                "task record gone (404), marked failed: %s",
                                row["rel_path"])
                            continue
                        if not isinstance(res, dict):   # unexpected -> retry
                            db.unclaim_report(row["sha256"])
                            continue
                        cls = res.get("classification") or "unknown"
                        threat = res.get("threat_name")
                        factor = res.get("threat_factor")
                        report = res.get("report_json")
                        if db.mark_done(
                                row["sha256"], cls, threat, factor,
                                json.dumps(report)
                                if args.store_full_report and report is not None
                                else None) == 0:
                            # Deadline/claim race: the row left 'reporting'
                            # (e.g. flipped to 'timeout') between claim and
                            # now — a "completed" record + quarantine/alert
                            # would be wrong for it.
                            continue
                        record = {
                            "file_path": row["rel_path"],
                            "absolute_path": row["file_path"],
                            "file_type": None,
                            "sha256": row["sha256"],
                            "classification": cls, "threat_name": threat,
                            "threat_factor": factor,
                            "task_url": row["task_url"],
                            "quarantined_to": None,
                            "alerted": False,
                            "api": {"status": "completed", "error": None,
                                    "report": None if args.summary_only
                                    else report},
                        }
                        if backend.name != "detect":
                            record["backend"] = backend.name
                        if isinstance(report, dict):
                            ind = extract_report_indicators(report)
                            if ind:
                                record["spectra_report_indicators"] = ind
                        _verdict_actions(ctx, db, record, writer=writer)
                        writer.write(record)
                        ctx.bump_progress(row["rel_path"], cls.upper())
            else:
                # ---- Legacy path: per-row task_status (raw detect client) ----
                for row in rows:
                    # Atomic claim: only one poller wins the
                    # submitted->reporting flip, so each report's side
                    # effects happen exactly once.
                    if not db.claim_report(row["sha256"]):
                        continue
                    try:
                        task = client.task_status(row["task_url"])
                        if task.get("processed") in (None, 0):
                            db.unclaim_report(row["sha256"])
                            continue  # still running on the Worker
                        cls, threat, factor = summarize_report(task)
                        if db.mark_done(
                                row["sha256"], cls, threat, factor,
                                json.dumps(task)
                                if args.store_full_report else None) == 0:
                            # Deadline/claim race: the row left 'reporting'
                            # (e.g. flipped to 'timeout') between claim and
                            # now — a "completed" record + quarantine/alert
                            # would be wrong for it.
                            continue
                        record = {
                            "file_path": row["rel_path"],
                            "absolute_path": row["file_path"],
                            "file_type": None,
                            "sha256": row["sha256"],
                            "classification": cls, "threat_name": threat,
                            "threat_factor": factor,
                            "task_url": row["task_url"],
                            "quarantined_to": None,
                            "alerted": False,
                            "api": {"status": "completed", "error": None,
                                    "report": None if args.summary_only else task},
                        }
                        ind = extract_report_indicators(task)
                        if ind:
                            record["spectra_report_indicators"] = ind
                        _verdict_actions(ctx, db, record, writer=writer)
                        writer.write(record)
                        ctx.bump_progress(row["rel_path"], cls.upper())
                    except TaskGoneError:
                        # Task record purged server-side — terminal, not
                        # retriable.
                        db.fail_claimed(row["sha256"], "task record lost (404)")
                        ctx.counters.inc("errors", 1)
                        ctx.logger.warning("task record gone (404), marked failed: %s",
                                           row["rel_path"])
                    except Exception as e:  # noqa: BLE001 — release claim, retry later
                        ctx.logger.warning("report processing failed %s: %s",
                                           row["task_url"], e)
                        try:
                            db.unclaim_report(row["sha256"])
                        except Exception:  # noqa: BLE001 — DB down; outer loop copes
                            pass
                        continue
            # heartbeat: first pass fires immediately, then every ~60s
            if time.time() - seen_stuck > 60:
                seen_stuck = time.time()
                c = db.counts()
                ctx.logger.info("progress: uploads %s | reports pending=%d",
                                c, db.in_flight())
            if uploads_done_event.is_set() and not db.submitted_rows():
                return
            time.sleep(max(1, args.result_poll_interval))
        except Exception as e:  # noqa: BLE001 — the poller must not die
            ctx.logger.error("result poller error (continuing): %s", e)
            time.sleep(max(1, args.result_poll_interval))


class ScanDB:
    """SQLite-backed pipeline state: one row per submitted file, status-tracked."""
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS uploads(
        sha256 TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        rel_path TEXT NOT NULL,
        file_size INTEGER,
        status TEXT NOT NULL DEFAULT 'pending',
        -- pending|submitted|reporting|failed|done|timeout|cached
        task_url TEXT,
        http_status INTEGER,
        error TEXT,
        attempts INTEGER DEFAULT 0,
        classification TEXT,
        threat_name TEXT,
        threat_factor INTEGER,
        report_json TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        uploaded_at TEXT,
        report_fetched_at TEXT,
        sha1 TEXT,
        backend TEXT,
        quarantined_to TEXT,
        alerted INTEGER
    );
    CREATE INDEX IF NOT EXISTS ix_status ON uploads(status);
    """

    def __init__(self, path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self._conn.executescript(self._SCHEMA)
            self._migrate()

    def _migrate(self):
        """Additive columns for multi-backend support. Fresh DBs already get
        them from _SCHEMA, so the duplicate-column error is expected and
        ignored; pre-existing DBs gain them here without losing rows."""
        for col in ("sha1 TEXT", "backend TEXT", "quarantined_to TEXT",
                    "alerted INTEGER"):
            try:
                self._conn.execute(f"ALTER TABLE uploads ADD COLUMN {col}")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

    def _q(self, sql, params=(), fetch=None):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            if fetch == "one":
                return cur.fetchone()
            if fetch == "all":
                return cur.fetchall()
            return cur.rowcount

    def upsert_pending(self, sha256, file_path, rel_path, size, sha1=None,
                       requeue_done=False):
        # DO UPDATE (not DO NOTHING): on a re-run the same file may live at a
        # different path, and a stale file_path would make quarantine act on
        # the wrong location. sha1 is additive (needs_sha1 backends); the
        # COALESCE keeps an existing sha1 when a caller has none to give.
        # (Re)queueing a file also resets a 'failed'/'timeout' row (and
        # 'done'/'cached' when requeue_done — resume off) to 'pending', so a
        # fresh synchronous verdict (mark_done_direct, guarded on 'pending')
        # can land. In-flight 'submitted'/'reporting' rows are never reset.
        # file_path/rel_path/file_size always track the latest seen path
        # EXCEPT on in-flight rows: pointing a 'submitted'/'reporting' row
        # at a duplicate's path would make the verdict's actions hit the
        # wrong file — mark_submitted stamps the submitter's path instead.
        # ('done'/'cached' rows DO update: the next run's cached-hit dedup
        # compares prior file_path against the scanned path.)
        reset = ("(uploads.status IN ('failed','timeout') OR "
                 "(? AND uploads.status IN ('done','cached')))")
        self._q(f"""INSERT INTO uploads(sha256,file_path,rel_path,file_size,
                                     status,sha1)
                   VALUES(?,?,?,?,'pending',?)
                   ON CONFLICT(sha256) DO UPDATE SET
                       file_path=CASE WHEN uploads.status IN
                                      ('submitted','reporting')
                                      THEN uploads.file_path
                                      ELSE excluded.file_path END,
                       rel_path=CASE WHEN uploads.status IN
                                     ('submitted','reporting')
                                     THEN uploads.rel_path
                                     ELSE excluded.rel_path END,
                       file_size=CASE WHEN uploads.status IN
                                      ('submitted','reporting')
                                      THEN uploads.file_size
                                      ELSE excluded.file_size END,
                       sha1=COALESCE(excluded.sha1, uploads.sha1),
                       error=CASE WHEN {reset} THEN NULL
                                  ELSE uploads.error END,
                       http_status=CASE WHEN {reset} THEN NULL
                                        ELSE uploads.http_status END,
                       status=CASE WHEN {reset} THEN 'pending'
                                   ELSE uploads.status END""",
                (sha256 or "", file_path, rel_path, size, sha1,
                 int(bool(requeue_done)), int(bool(requeue_done)),
                 int(bool(requeue_done))))

    def known_verdict(self, sha256):
        row = self._q(
            "SELECT classification,threat_name,threat_factor,status FROM uploads "
            "WHERE sha256=? AND status IN ('done','submitted','reporting','cached')",
            (sha256,), fetch="one")
        if not row:
            return None
        return {"classification": row[0], "threat_name": row[1],
                "threat_factor": row[2], "status": row[3]}

    def mark_submitted(self, sha256, task_url, backend=None,
                       file_path=None, rel_path=None):
        # A resubmit of a failed/done row starts a fresh task — clear the old
        # verdict and error fields so a stale outcome can't shadow the new one.
        # backend stamps which backend owns the receipt ref (COALESCE: None
        # leaves an existing stamp untouched — legacy callers stay neutral).
        # file_path/rel_path stamp the SUBMITTER's path: an upsert for a
        # duplicate at another path must never repoint an in-flight row.
        self._q("""UPDATE uploads SET status='submitted', task_url=?,
                   classification=NULL, threat_name=NULL, threat_factor=NULL,
                   report_json=NULL, error=NULL, http_status=NULL,
                   backend=COALESCE(?, backend),
                   file_path=COALESCE(?, file_path),
                   rel_path=COALESCE(?, rel_path),
                   uploaded_at=datetime('now'), updated_at=datetime('now'),
                   attempts=attempts+1 WHERE sha256=?""",
                (task_url, backend, file_path, rel_path, sha256))

    def mark_failed(self, sha256, http_status, error):
        # Never clobber an in-flight ('submitted'/'reporting') or completed
        # ('done'/'cached') row — e.g. a worker exception right after
        # mark_submitted would otherwise hide a live task from the poller.
        self._q("""UPDATE uploads SET status='failed', http_status=?, error=?,
                   updated_at=datetime('now') WHERE sha256=?
                   AND status NOT IN ('submitted','reporting','done','cached')""",
                (http_status, (error or "")[:500], sha256))

    def fail_claimed(self, sha256, error):
        """Terminal failure on a claimed ('reporting') row, e.g. task 404."""
        self._q("""UPDATE uploads SET status='failed', error=?,
                   updated_at=datetime('now')
                   WHERE sha256=? AND status='reporting'""",
                ((error or "")[:500], sha256))

    def claim_report(self, sha256):
        """Atomically flip submitted->reporting. True iff this caller won the
        claim, so >1 poller can never process the same row twice."""
        return self._q("""UPDATE uploads SET status='reporting',
                          updated_at=datetime('now')
                          WHERE sha256=? AND status='submitted'""",
                       (sha256,)) == 1

    def unclaim_report(self, sha256):
        """Release a claim (reporting->submitted) so any poller can retry."""
        self._q("""UPDATE uploads SET status='submitted',
                   updated_at=datetime('now')
                   WHERE sha256=? AND status='reporting'""", (sha256,))

    def reclaim_stale_reporting(self):
        """A 'reporting' row at startup can only come from a killed run — its
        claim can never be released, so hand it back to 'submitted'."""
        # No updated_at bump: a row enters a run's report only once this
        # run actually processes it.
        self._q("UPDATE uploads SET status='submitted' "
                "WHERE status='reporting'")

    def submitted_rows(self):
        # 'reporting' rows are claimed but not yet done — they still count
        # toward the wait deadline, and a poller that crashed mid-row must not
        # let a task escape the timeout.
        return [{"sha256": r[0], "file_path": r[1], "rel_path": r[2], "task_url": r[3]}
                for r in self._q(
                    "SELECT sha256,file_path,rel_path,task_url FROM uploads "
                    "WHERE status IN ('submitted','reporting')", fetch="all")]

    def mark_done(self, sha256, classification, threat_name, threat_factor, report_json):
        # Only a claimed ('reporting') row may complete: if the deadline flipped
        # it to 'timeout' while the poller was mid-fetch, an unconditional
        # UPDATE would resurrect the timed-out row. Returns the UPDATE rowcount
        # (like mark_done_direct) so the caller can skip the record + verdict
        # side effects when the flip didn't land — 0 means the row left
        # 'reporting' between claim and now.
        return self._q("""UPDATE uploads SET status='done', classification=?,
                   threat_name=?, threat_factor=?, report_json=?,
                   report_fetched_at=datetime('now'),
                   updated_at=datetime('now')
                   WHERE sha256=? AND status='reporting'""",
                (classification, threat_name, threat_factor,
                 report_json if report_json is None or isinstance(report_json, str)
                 else json.dumps(report_json), sha256))

    def mark_done_direct(self, sha256, classification, threat_name,
                         threat_factor, report_json, backend):
        """Synchronous verdict with no submit/poll round-trip (FIE /scan,
        reputation pre-check): flips a 'pending' row straight to 'done' and
        stamps which backend produced the verdict. Returns the UPDATE
        rowcount — 1 iff this call actually flipped a 'pending' row — so a
        caller can tell its verdict landed (vs the row being absent or in
        another state) without a second query."""
        return self._q("""UPDATE uploads SET status='done', classification=?,
                   threat_name=?, threat_factor=?, report_json=?, backend=?,
                   report_fetched_at=datetime('now'),
                   updated_at=datetime('now')
                   WHERE sha256=? AND status='pending'""",
                (classification, threat_name, threat_factor,
                 report_json if report_json is None or isinstance(report_json, str)
                 else json.dumps(report_json), backend, sha256))

    def reset_submitted_for_backend(self, current_backend):
        """Startup resume: 'submitted'/'reporting' rows owned by a different
        backend can never be polled by this one (receipt refs are
        backend-specific), so hand them back to 'pending'. Legacy rows have
        backend=NULL, which reads as 'detect'. task_url is cleared — it is the
        other backend's stale receipt ref."""
        # No updated_at bump (run-scoped reports — see reclaim_stale_reporting).
        self._q("""UPDATE uploads SET status='pending', task_url=NULL
                   WHERE status IN ('submitted','reporting')
                   AND COALESCE(backend,'detect') != ?""", (current_backend,))

    def mark_cached(self, sha256):
        self._q("""UPDATE uploads SET status='cached',
                   updated_at=datetime('now') WHERE sha256=?""", (sha256,))

    def action_state(self, sha256):
        """Persisted file_path + verdict-action columns, or None."""
        r = self._q("SELECT file_path,quarantined_to,alerted FROM uploads "
                    "WHERE sha256=?", (sha256,), fetch="one")
        if not r:
            return None
        return {"file_path": r[0], "quarantined_to": r[1], "alerted": r[2]}

    def mark_actions(self, sha256, quarantined_to, alerted):
        """Persist verdict-action outcomes (alerted: 0/1, NULL = never
        evaluated)."""
        self._q("""UPDATE uploads SET quarantined_to=?, alerted=?
                   WHERE sha256=?""",
                (quarantined_to, 1 if alerted else 0, sha256))

    def mark_report_timeout(self, sha256):
        """Flip a live row to 'timeout'. Returns 1 iff this call did it —
        lets concurrent pollers count each timed-out task exactly once."""
        return self._q("""UPDATE uploads SET status='timeout',
                          updated_at=datetime('now')
                          WHERE sha256=? AND status IN ('submitted','reporting')""",
                       (sha256,))

    def expire_overdue(self, wait_seconds, run_started_at=None):
        """Per-row report deadline: flip every submitted/reporting row whose
        upload is older than wait_seconds to 'timeout'. The clock starts at
        max(upload, run_started_at), so rows resumed from an earlier run get
        a full window this run. Returns the rowcount (rows this call
        flipped)."""
        # COALESCE keeps MAX() non-NULL when run_started_at is not given.
        return self._q("""UPDATE uploads SET status='timeout',
                          error='report wait exceeded',
                          updated_at=datetime('now')
                          WHERE status IN ('submitted','reporting')
                          AND MAX(COALESCE(uploaded_at, created_at),
                                  COALESCE(?, uploaded_at, created_at))
                              < datetime('now', ?)""",
                       (run_started_at,
                        f"-{float(wait_seconds):.3f} seconds"))

    def stale_error_rows(self, before):
        """failed/timeout rows untouched since `before` — failures from a
        previous run this run never reprocessed. Rows reprocessed this run all
        get a fresh updated_at; skipped_filetype rows are policy skips, not
        errors, and are excluded."""
        r = self._q("SELECT COUNT(*) FROM uploads "
                    "WHERE status IN ('failed','timeout') AND updated_at < ? "
                    "AND (error IS NULL OR error NOT LIKE 'skipped_filetype:%')",
                    (before,), fetch="one")
        return r[0] if r else 0

    def counts(self):
        return {r[0]: r[1] for r in self._q(
            "SELECT status, COUNT(*) FROM uploads GROUP BY status", fetch="all")}

    def in_flight(self):
        r = self._q("SELECT COUNT(*) FROM uploads "
                    "WHERE status IN ('submitted','reporting')", fetch="one")
        return r[0] if r else 0

    def failed_rows(self):
        return [{"rel_path": r[0], "status": r[1], "error": r[2]}
                for r in self._q(
                    "SELECT rel_path, status, error FROM uploads "
                    "WHERE status IN ('failed','timeout') "
                    "ORDER BY rel_path", fetch="all")]

    def old_records(self, days):
        r = self._q("SELECT COUNT(*) FROM uploads WHERE created_at < "
                    "datetime('now', ?)", (f"-{int(days)} days",), fetch="one")
        return r[0] if r else 0

    def delete_old_records(self, days):
        return self._q("DELETE FROM uploads WHERE created_at < "
                       "datetime('now', ?)", (f"-{int(days)} days",))

    def now(self):
        """SQLite-compatible UTC timestamp, same clock/format as updated_at."""
        return self._q("SELECT datetime('now')", fetch="one")[0]

    def verdicts(self, since=None):
        """All rows, or only rows touched at/after `since` (a datetime('now')
        string) when given."""
        cols = ("sha256,file_path,rel_path,file_size,status,classification,"
                "threat_name,threat_factor,report_json,error,http_status,attempts,"
                "quarantined_to,alerted")
        out = []
        sql = f"SELECT {cols} FROM uploads"
        params = ()
        if since is not None:
            sql += " WHERE updated_at >= ?"
            params = (since,)
        for r in self._q(sql, params, fetch="all"):
            out.append(dict(zip(cols.split(","), r)))
        return out

    def close(self):
        with self._lock:
            self._conn.close()


# ---------------------------------------------------------------------------
# Main Scan Logic
# ---------------------------------------------------------------------------

def cleanup_prompt(db: "ScanDB", args, logger: logging.Logger) -> None:
    """
    Startup retention check. When rows older than args.retention_days exist:
    cleanup_old_records=ask -> prompt y/N; always -> delete; never -> keep.
    """
    old = db.old_records(args.retention_days)
    if old == 0:
        return
    mode = args.cleanup_old_records
    if mode == "never":
        logger.info("%d record(s) older than %d days kept (cleanup=never)",
                    old, args.retention_days)
        return
    do_delete = mode == "always"
    if mode == "ask":
        try:
            ans = input(f"{old} scan record(s) older than {args.retention_days} "
                        f"days found. Delete them? [y/N] ")
            do_delete = ans.strip().lower() in ("y", "yes")
        except EOFError:
            do_delete = False
    if do_delete:
        n = db.delete_old_records(args.retention_days)
        logger.info("Deleted %d old scan record(s)", n)


def run_scan(args, include_extensions, output_dir: Path, logger: logging.Logger,
             run_dir: Optional[Path] = None) -> dict:
    """
    Async pipeline: walk the drive, submit each matching file via the bounded
    upload pool, collect verdicts via the result poller(s), report from SQLite.

    output_dir anchors persistent state (scan_state.db — shared across runs so
    resume works); run_dir is the per-run folder for artifacts (ndjson, log,
    reports, quarantine, alerts). Defaults to output_dir for back-compat.
    """
    if run_dir is None:
        run_dir = output_dir
    drive_root = sanitize_drive_path(args.drive)
    logger.info("USB drive root: %s", drive_root)

    if include_extensions:
        logger.info("Extension filter: %d extensions (%s)",
                    len(include_extensions), ", ".join(sorted(include_extensions)))
    else:
        logger.info("No extension filter - ALL file types will be scanned")

    if not os.path.isdir(drive_root):
        logger.error("Drive %s is not accessible. Is the USB mounted?", drive_root)
        sys.exit(1)

    # Backend construction probes auth-bearing services once and sys.exit(2)s
    # with a logged error on bad credentials — an invalid token must abort the
    # run here, not surface as thousands of per-file upload failures.
    backend = make_backend(args)
    # Single-shot readyz can flap on a busy appliance; tolerate a ~30s blip.
    if not backend.wait_ready(30, 5, log=logger):
        logger.error("Backend %r is not ready. Aborting.", backend.name)
        sys.exit(1)

    # Lazy enumeration: the walk feeds the bounded work queue while still
    # discovering files — uploads start immediately instead of waiting for a
    # full tree index (hundreds of thousands of files = minutes of dead time).
    logger.info("Scanning drive (uploads start as files are discovered)...")
    work_iter = iter_work_items(drive_root, include_extensions,
                                getattr(args, "skip_hidden_dirs", False))

    # Disk gate needs real files before any upload — sample the first items,
    # then chain them back so nothing is lost.
    sample = list(itertools.islice(work_iter, 256))
    disk_read_gate(args, sample, logger)
    work_iter = itertools.chain(sample, work_iter)
    if getattr(args, "max_files", 0) > 0:
        work_iter = itertools.islice(work_iter, args.max_files)
        logger.info("File cap: max_files=%d", args.max_files)

    db_path = (Path(args.db_path) if os.path.isabs(args.db_path)
               else output_dir / args.db_path)
    db = ScanDB(str(db_path))
    db.reclaim_stale_reporting()  # claims from a killed run are unclaimable
    # In-flight rows owned by a different backend can never be polled by this
    # one — hand them back to 'pending' before any work begins.
    db.reset_submitted_for_backend(backend.name)
    cleanup_prompt(db, args, logger)

    # Run boundary (DB clock, same format as updated_at): reports cover only
    # rows touched at/after it; failures left by earlier runs and not
    # reprocessed are still counted in files_with_errors (exit code).
    run_started_at = db.now()

    # Shared, thread-safe scaffolding. ScanDB replaces ScanState; per-hash dedup
    # is via db.known_verdict, so ctx.state is None.
    counters = Counters()
    quarantine_dir = Path(args.quarantine_dir) if args.quarantine_dir else (run_dir / "quarantine")

    alerter = None
    if args.alert_on:
        syslog_addr = None
        if args.alert_syslog:
            host, _, port = args.alert_syslog.partition(":")
            try:
                port_num = int(port) if port else 514
            except ValueError:
                logger.warning("Invalid alert_syslog port %r; using 514.", port)
                port_num = 514
            syslog_addr = (host, port_num)
        alerter = Alerter(
            alert_on=args.alert_on,
            alerts_file=run_dir / ALERTS_FILENAME,
            webhook_url=args.alert_webhook,
            syslog_addr=syslog_addr,
            eventlog=args.alert_eventlog,
            logger=logger,
        )

    ctx = ScanContext(args, backend, None, alerter, counters, KeyedLocks(),
                      quarantine_dir, logger, 0)  # total grows while enumerating

    # Synchronous backends (FIE) return verdicts on submit — no poll phase.
    n_pollers = 0 if backend.is_sync else max(1, args.result_pollers)

    # Reputation pre-check is a separate TiCloud client (works with every
    # backend) — built only when enabled, and it fails fast on bad creds so
    # a typo'd password aborts the run instead of silently skipping.
    precheck_client = None
    if getattr(args, "reputation_precheck", False):
        precheck_client = _make_precheck_client(args)

    logger.info("Submitting with %d upload worker(s), %d result poller(s) "
                "[backend=%s]%s...", args.upload_workers, n_pollers,
                backend.name,
                " +reputation-precheck" if precheck_client else "")

    writer = ResultsWriter(str(run_dir / "scan_results.ndjson"))
    report_wait_seconds = args.report_wait_hours * 3600  # per row
    uploads_done = threading.Event()

    fed_box = [0]

    def _pool_supervisor():
        try:
            fed_box[0] = run_upload_pool(
                ctx, db, backend, work_iter, writer=writer,
                precheck_client=precheck_client)
            logger.info("Enumeration complete: %d files fed to upload workers.",
                        fed_box[0])
        finally:
            uploads_done.set()   # always release pollers, even on pool failure

    up = threading.Thread(target=_pool_supervisor, name="upload-pool", daemon=True)
    pollers = [
        threading.Thread(target=result_poller,
                         args=(ctx, db, backend, report_wait_seconds,
                               uploads_done, writer, run_started_at),
                         name=f"poller-{i}", daemon=True)
        for i in range(n_pollers)]
    if not pollers:
        ctx.pollers_stopped.set()    # nothing will ever drain in_flight

    def _poller_watch():
        for p in pollers:
            p.join()
        ctx.pollers_stopped.set()    # all pollers gone -> release throttle

    up.start()
    for p in pollers:
        p.start()
    if pollers:
        threading.Thread(target=_poller_watch, name="poller-watch",
                         daemon=True).start()
    try:
        up.join()
        for p in pollers:
            p.join()
    except KeyboardInterrupt:
        # Workers/pollers are daemons; still report whatever the DB collected.
        # stop BEFORE pollers_stopped: a worker parked in the throttle must
        # see stop when it wakes, or it would mark its row failed.
        ctx.stop.set()
        ctx.pollers_stopped.set()
        logger.warning("Interrupted - writing reports from collected state.")
    finally:
        writer.close()

    total_files = fed_box[0]

    # 'submitted' rows from a previous run are resumed by the poller even when
    # this run's work list is empty; only bail when there is truly nothing.
    if total_files == 0 and db.in_flight() == 0 and not db.counts():
        logger.warning("No files matched the specified extensions.")
        metadata = _build_metadata(args, drive_root, total_files, include_extensions)
        db.close()
        return {"scan_metadata": metadata, "summary": {}, "results": []}

    # Per-run outcome: makes successes vs failures greppable without parsing
    # the whole progress stream.
    sc = db.counts()
    logger.info("OUTCOME uploads: submitted=%d cached=%d failed=%d | "
                "reports: done=%d timeout=%d",
                sc.get("submitted", 0), sc.get("cached", 0),
                sc.get("failed", 0), sc.get("done", 0), sc.get("timeout", 0))
    for r in db.failed_rows():
        logger.warning("  FAIL %-50s %s: %s", r["rel_path"], r["status"],
                       (r["error"] or "")[:120])

    # Final reports are built from the DB so a re-run keeps prior verdicts.
    try:
        return _build_output_from_db(args, db, counters, drive_root, total_files,
                                     include_extensions, output_dir,
                                     run_started_at)
    finally:
        db.close()


def _build_output_from_db(args, db, counters, drive_root, total_files,
                          include_extensions, output_dir, run_started_at) -> dict:
    """Map db.verdicts() rows to the record shape write_*_report expects."""
    metadata = _build_metadata(args, drive_root, total_files, include_extensions)
    c = counters.snapshot()
    results = []
    rows = db.verdicts(since=run_started_at)
    for r in rows:
        try:
            report = (json.loads(r["report_json"])
                      if r["report_json"] and not args.summary_only else None)
        except (ValueError, TypeError):
            report = None  # corrupt stored report JSON -> treat as no report
        results.append({
            "file_path": r["rel_path"],
            "absolute_path": r["file_path"],
            "file_name": os.path.basename(r["file_path"]),
            "file_extension": os.path.splitext(r["file_path"])[1].lower(),
            "file_size_bytes": r["file_size"],
            "file_type": None,  # head bytes not persisted (see upload_worker)
            "sha256": r["sha256"],
            "classification": r["classification"] or "unavailable",
            "threat_name": r["threat_name"],
            "threat_factor": r["threat_factor"],
            "cached": r["status"] == "cached",
            "quarantined_to": r["quarantined_to"] or None,
            "alerted": (None if r["alerted"] is None else bool(r["alerted"])),
            "api": {"status": {"done": "completed"}.get(r["status"], r["status"]),
                    "error": r["error"],
                    "report": report},
        })
    # Summary cards are derived from the rows actually in the report (not the
    # per-run counters) so header and table always agree. Classification
    # counts cover rows with a verdict (done/cached); 'other' = such a row
    # with an unmapped label.
    verdict_rows = [x for x in results
                    if x["api"]["status"] in ("completed", "cached")]

    def _n_cls(label):
        return sum(1 for x in verdict_rows if x["classification"] == label)
    _known = ("malicious", "suspicious", "goodware", "unknown")
    return {
        "scan_metadata": metadata,
        "summary": {
            "total_files_matched_filter": total_files,
            "files_processed": len(results),
            "files_completed_successfully": sum(
                1 for x in results
                if x["api"]["status"] in ("completed", "cached")
            ),
            # failed/timeout rows in this run's report, plus failures from
            # earlier runs this run never reprocessed (not in the report, but
            # still errors); skipped_filetype rows are policy skips, not
            # errors. Drives the exit code.
            "files_with_errors": sum(
                1 for r in rows if r["status"] in ("failed", "timeout")
                and not (r["error"] or "").startswith("skipped_filetype:"))
                + db.stale_error_rows(run_started_at),
            "cached_hits": sum(1 for x in results if x["cached"]),
            "skipped_by_filetype": c.get("skipped_filetype", 0),
            "quarantined": sum(1 for r in rows if r["quarantined_to"]),
            "alerts": sum(1 for r in rows if r["alerted"] == 1),
            "malicious": _n_cls("malicious"),
            "suspicious": _n_cls("suspicious"),
            "goodware": _n_cls("goodware"),
            "unknown": _n_cls("unknown"),
            # Verdict rows carrying an unmapped label.
            "other": sum(1 for x in verdict_rows
                         if x["classification"] not in _known),
            "uploads_submitted": c.get("submitted", 0),
        },
        "results": results,
    }


def _build_metadata(args, drive_root, total_files, include_extensions) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "scan_started_at": now,
        "scanner_version": SCRIPT_VERSION,
        "usb_drive_root": drive_root,
        "spectra_detect_host": args.host,
        "total_files_identified": total_files,
        "workers": args.workers,
        "extension_filter_enabled": include_extensions is not None,
        "extension_filter_values": sorted(include_extensions) if include_extensions else [],
        "file_type_filter": sorted(args.file_types) if args.file_types else [],
        "analysis_depth": args.analysis_depth,
        "enrichment": {
            "detect_file_type": args.detect_file_type,
            "extract_strings": args.extract_strings,
            "extract_iocs": args.extract_iocs,
            "max_enrich_bytes": args.max_enrich_bytes,
        },
        "resume_enabled": args.resume,
        "quarantine_action": args.quarantine_action,
        "quarantine_on": sorted(args.quarantine_on),
        "alert_on": sorted(args.alert_on) if args.alert_on else [],
        "upload_workers": args.upload_workers,
        "result_poll_interval": args.result_poll_interval,
        "report_wait_hours": args.report_wait_hours,
        "max_in_flight": args.max_in_flight,
        "ssl_verification": not args.no_verify_ssl,
        "timestamp": now,
    }


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def write_json_report(output: dict, path: Path, logger: logging.Logger) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    logger.info("Wrote JSON report: %s", path)


def _csv_safe(v):
    """Neutralize spreadsheet formula injection: prefix a leading
    = + - @ TAB CR with a single quote."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def write_csv_report(output: dict, path: Path, logger: logging.Logger) -> None:
    cols = ["file_path", "file_name", "file_extension", "file_type",
            "file_size_bytes", "sha256", "classification", "threat_name",
            "threat_factor", "cached", "quarantined_to", "alerted",
            "api_status", "api_error", "num_iocs", "num_strings"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([_csv_safe(c) for c in cols])
        for r in output.get("results", []):
            iocs = r.get("iocs") or {}
            num_iocs = sum(len(v) for k, v in iocs.items()
                           if isinstance(v, list) and k != "urls_defanged")
            alerted = r.get("alerted")
            writer.writerow([_csv_safe(v) for v in [
                r.get("file_path"), r.get("file_name"), r.get("file_extension"),
                r.get("file_type"), r.get("file_size_bytes"), r.get("sha256"),
                r.get("classification"), r.get("threat_name"), r.get("threat_factor"),
                "" if r.get("cached") is None
                else str(bool(r.get("cached"))).lower(),
                r.get("quarantined_to"),
                "" if alerted is None else str(bool(alerted)).lower(),
                r.get("api", {}).get("status"), r.get("api", {}).get("error"),
                num_iocs, r.get("strings_total"),
            ]])
    logger.info("Wrote CSV report: %s", path)


_HTML_COLORS = {
    "malicious": "#c0392b", "suspicious": "#d68910",
    "goodware": "#1e8449", "unknown": "#7f8c8d", "unavailable": "#95a5a6",
}


def write_html_report(output: dict, path: Path, logger: logging.Logger) -> None:
    """Styled after the RL release-notes template: logo + generator byline,
    Roboto, RL red #f6143f accents on dark #373547 headers."""
    meta = output.get("scan_metadata", {})
    summary = output.get("summary", {})
    rows = []
    for r in output.get("results", []):
        cls = r.get("classification", "unavailable")
        color = _HTML_COLORS.get(cls, "#95a5a6")
        iocs = r.get("iocs") or {}
        num_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        rows.append(
            "<tr>"
            f"<td class='mono'>{html.escape(str(r.get('file_path','')))}</td>"
            f"<td>{html.escape(str(r.get('file_type') or ''))}</td>"
            f"<td><span class='chip' style='background:{color}'>{html.escape(cls)}</span></td>"
            f"<td>{html.escape(str(r.get('threat_name') or ''))}</td>"
            f"<td class='mono'>{html.escape(str(r.get('sha256') or '')[:16])}</td>"
            f"<td>{num_iocs}</td>"
            f"<td>{html.escape(str(r.get('api',{}).get('status') or ''))}</td>"
            f"<td class='mono'>{html.escape(str(r.get('quarantined_to') or ''))}</td>"
            "</tr>"
        )
    summary_cards = "".join(
        f"<div class='card'><div class='num'>{summary.get(k,0)}</div>"
        f"<div class='lbl'>{k.replace('_',' ')}</div></div>"
        for k in ("files_processed", "malicious", "suspicious", "goodware",
                  "unknown", "quarantined", "alerts", "files_with_errors")
    )
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Spectra Detect Scan Report</title>
<style>
 body {{ font-family: Roboto, "Segoe UI", Arial, sans-serif; margin: 32px; color:#373547; }}
 .topbar {{ display:flex; justify-content:space-between; align-items:flex-start;
           border-bottom:3px solid #f6143f; padding-bottom:14px; margin-bottom:18px; }}
 .brand {{ color:#f6143f; font-size:26px; font-weight:700; letter-spacing:-0.5px; }}
 .byline {{ color:#999999; font-size:11px; text-align:right; line-height:1.4; }}
 h1 {{ font-size: 20px; color:#373547; margin: 8px 0 4px; }}
 .meta {{ color:#666; font-size: 13px; margin-bottom: 18px; }}
 .cards {{ display:flex; flex-wrap:wrap; gap:12px; margin-bottom:22px; }}
 .card {{ background:#efefef; border-radius:4px; padding:12px 16px; min-width:110px;
         border-top:3px solid #f6143f; }}
 .card .num {{ font-size:24px; font-weight:700; color:#373547; }}
 .card .lbl {{ font-size:11px; color:#666; text-transform:capitalize; }}
 table {{ border-collapse: collapse; width:100%; font-size:13px; }}
 th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #efefef; }}
 th {{ background:#373547; color:#fff; position:sticky; top:0; }}
 .mono {{ font-family: Consolas, monospace; font-size:12px; }}
 .chip {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:12px; }}
 .foot {{ margin-top:22px; padding-top:10px; border-top:1px solid #efefef;
         color:#999999; font-size:11px; }}
</style></head><body>
<div class="topbar">
 <div class="brand">ReversingLabs</div>
 <div class="byline">Generated by filescanner<br>
 Open source &middot; MIT License</div>
</div>
<h1>Spectra Detect Scan Report</h1>
<div class="meta">
 Host: {html.escape(str(meta.get('spectra_detect_host','')))} &middot;
 Drive: {html.escape(str(meta.get('usb_drive_root','')))} &middot;
 Scanner v{html.escape(str(meta.get('scanner_version','')))} &middot;
 Started: {html.escape(str(meta.get('scan_started_at','')))}
</div>
<div class="cards">{summary_cards}</div>
<table>
<thead><tr><th>File</th><th>Type</th><th>Classification</th><th>Threat</th>
<th>SHA-256</th><th>IOCs</th><th>Status</th><th>Quarantined</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<div class="foot">Generated by filescanner (MIT License)</div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    logger.info("Wrote HTML report: %s", path)


_PDF_COLORS = {  # RGB 0-1, mirrors _HTML_COLORS
    "malicious": (0.75, 0.22, 0.17), "suspicious": (0.84, 0.54, 0.06),
    "goodware": (0.12, 0.52, 0.29), "unknown": (0.50, 0.55, 0.55),
    "unavailable": (0.58, 0.65, 0.65),
}


_PDF_FINDINGS = ("malicious", "suspicious")


def _pdf_threat_desc(r) -> str:
    """Best-effort threat description from the stored tc_report scan results:
    'Engine: verdict' pairs, falling back to the factor when the report body
    wasn't retained (summary_only / store_full_report=false)."""
    rep = (r.get("api") or {}).get("report") or {}
    parts = []
    for entry in rep.get("tc_report", []):
        if not isinstance(entry, dict):
            continue
        cls = entry.get("classification") or {}
        for s in cls.get("scan_results") or []:
            if not isinstance(s, dict):
                continue
            eng, res = s.get("name"), s.get("result")
            if eng and res:
                parts.append(f"{eng}: {res}")
    if parts:
        return "; ".join(dict.fromkeys(parts))
    f = r.get("threat_factor")
    return f"threat factor {f}" if f is not None else "-"


def write_pdf_report(output: dict, path: Path, logger: logging.Logger) -> None:
    """Dependency-free PDF/1.4 findings report styled after the RL release
    notes template: red ReversingLabs wordmark + generator byline +
    RL-red rule, summary, table of ONLY malicious/suspicious files.
    Landscape Letter."""
    def esc(s):  # WinAnsi(cp1252)-safe literal-string escape
        return str(s).encode("cp1252", "replace").decode("latin-1") \
            .replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    meta = output.get("scan_metadata", {})
    summary = output.get("summary", {})
    res = output.get("results", [])

    findings = [r for r in res
                if (r.get("classification") or "") in _PDF_FINDINGS]
    order = {c: i for i, c in enumerate(_PDF_FINDINGS)}
    findings.sort(key=lambda r: (order.get(r["classification"], 9),
                                 str(r.get("file_path") or "")))

    col_hdr = (f"{'FILE PATH':<64} {'FILE NAME':<26} {'THREAT':<26} "
               f"DESCRIPTION")
    title_block = [
        ("H2", "Spectra Detect Scan Report", (0.216, 0.208, 0.278)),
        ("P", f"Host: {meta.get('spectra_detect_host','')}   "
              f"Drive: {meta.get('usb_drive_root','')}   "
              f"Scanner v{meta.get('scanner_version','')}   "
              f"Started: {meta.get('scan_started_at','')}", (0.35, 0.35, 0.35)),
        ("P", "   ".join(f"{k.replace('_',' ')}: {summary.get(k, 0)}" for k in
             ("files_processed", "malicious", "suspicious", "goodware",
              "unknown", "quarantined", "alerts", "files_with_errors")),
         (0, 0, 0)),
        ("P", "Findings shown: malicious + suspicious only — full results are "
              "in the JSON/CSV report.", (0.35, 0.35, 0.35)),
    ]

    def row_line(r):
        fp = str(r.get("file_path") or "")
        name = str(r.get("file_name") or "") or fp.rsplit("/", 1)[-1]
        cls = r.get("classification") or "unavailable"
        return (f"{fp[-64:]:<64} {name[:26]:<26} "
                f"{str(r.get('threat_name') or cls)[:26]:<26} "
                f"{_pdf_threat_desc(r)[:60]}",
                _PDF_COLORS.get(cls, (0.5, 0.5, 0.5)))

    LINE_H, TOP, BOT = 11, 555, 40  # landscape Letter: 792x612
    per_page = (TOP - BOT) // LINE_H
    # simple pagination: page 1 carries title block, all pages carry col header
    body = [row_line(r) for r in findings] or \
        [("(no malicious or suspicious findings)", (0.2, 0.5, 0.2))]
    pages, i = [], 0
    while True:
        cap = per_page - (10 if not pages else 0)  # logo+title on p1
        chunk = body[i:i + cap]
        pages.append(chunk)
        i += cap
        if i >= len(body):
            break

    def page_stream(pageno, chunk):
        ops = []
        y_start = TOP
        if pageno == 0:
            # RL template header: red wordmark left, byline right-aligned,
            # red rule below. Courier 7pt → exact 4.2pt/char for right-align.
            ops.append(f"BT /F2 16 Tf 0.965 0.078 0.247 rg 40 {TOP + 26} Td "
                       f"(ReversingLabs) Tj ET")
            for dy, txt in ((10, "Generated by filescanner"),
                            (0, "Open source - MIT License")):
                x = 752 - len(txt) * 4.2
                ops.append(f"BT /F1 7 Tf 0.6 0.6 0.6 rg {x:.1f} "
                           f"{TOP + 26 + dy} Td ({esc(txt)}) Tj ET")
            ops.append("0.965 0.078 0.247 RG 1.5 w 40 %.1f m 752 %.1f l S"
                       % (TOP + 18, TOP + 18))
            y_start = TOP + 6
            for kind, text, rgb in title_block:
                size = 14 if kind == "H2" else 8
                font = "F2" if kind == "H2" else "F1"
                ops.append(f"BT /{font} {size} Tf {rgb[0]} {rgb[1]} {rgb[2]} rg "
                           f"40 {y_start} Td ({esc(text)}) Tj ET")
                y_start -= 18 if kind == "H2" else 12
            y_start -= 6
        else:
            # slim header on continuation pages: red rule only
            ops.append("0.965 0.078 0.247 RG 1 w 40 %.1f m 752 %.1f l S"
                       % (TOP + 14, TOP + 14))
            y_start = TOP
        ops.append("0.216 0.208 0.278 rg 40 %.1f 712 12 re f"
                   % (y_start - 3))          # dark header bar (template #373547)
        ops.append(f"BT /F2 7 Tf 1 1 1 rg 42 {y_start} Td "
                   f"({esc(col_hdr)}) Tj ET")
        y_start -= 13
        for text, rgb in chunk:
            ops.append(f"BT /F1 7 Tf {rgb[0]} {rgb[1]} {rgb[2]} rg "
                       f"40 {y_start} Td ({esc(text)}) Tj ET")
            y_start -= LINE_H
        footer = (f"Generated by filescanner (MIT License)   |   "
                  f"Page {pageno + 1} of {len(pages)}   |   "
                  f"generated {meta.get('scan_started_at','')}")
        ops.append(f"BT /F1 7 Tf 0.5 0.5 0.5 rg 40 25 Td ({esc(footer)}) Tj ET")
        return "\n".join(ops).encode("latin-1", "replace")

    objs = []  # 1 catalog, 2 pages, 3 Courier, 4 Helv-Bold,
    kids = []  # then per-page: page, content
    next_id = 5
    for _ in pages:
        kids.append(next_id)
        next_id += 2
    objs.append("<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] "
                f"/Count {len(kids)} >>")
    objs.append("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    objs.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    for pageno, chunk in enumerate(pages):
        content = page_stream(pageno, chunk)
        page_id, cont_id = 5 + 2 * pageno, 6 + 2 * pageno
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 792 612] "
                    f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                    f"/Contents {cont_id} 0 R >>")
        objs.append(f"<< /Length {len(content)} >>\nstream\n"
                    + content.decode("latin-1") + "\nendstream")

    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body_text in enumerate(objs, start=1):
        offsets.append(len(buf))
        buf += f"{i} 0 obj\n{body_text}\nendobj\n".encode("latin-1")
    xref = len(buf)
    buf += (f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n"
            + "".join(f"{o:010d} 00000 n \n" for o in offsets)
            + f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
              f"startxref\n{xref}\n%%EOF\n").encode("latin-1")
    with open(path, "wb") as f:
        f.write(bytes(buf))
    logger.info("Wrote PDF report: %s (%d findings, %d page%s)", path,
                len(findings), len(pages), "" if len(pages) == 1 else "s")


def write_reports(output: dict, output_dir: Path, base_name: str,
                  formats: Set[str], logger: logging.Logger) -> None:
    stem = Path(base_name).stem
    writers = {
        "json": (write_json_report, output_dir / base_name),
        "csv": (write_csv_report, output_dir / f"{stem}.csv"),
        "html": (write_html_report, output_dir / f"{stem}.html"),
        "pdf": (write_pdf_report, output_dir / f"{stem}.pdf"),
    }
    wrote_any = False
    for fmt in formats:
        writer, path = writers[fmt]
        try:
            writer(output, path, logger)
            wrote_any = True
        except (PermissionError, OSError) as e:
            logger.error("Failed to write %s report: %s", fmt, e)
    if not wrote_any:
        # Last-ditch effort so a scan's results are never silently lost.
        for fallback in (Path(os.getcwd()) / base_name,
                         Path(tempfile.gettempdir()) / base_name):
            try:
                logger.warning("Falling back to %s", fallback)
                write_json_report(output, fallback, logger)
                return
            except (PermissionError, OSError) as e:
                logger.error("Fallback report write to %s failed: %s", fallback, e)
        logger.error("Could not write scan results to any location.")


# ---------------------------------------------------------------------------
# Output location
# ---------------------------------------------------------------------------

def _default_desktop_dir() -> Path:
    """
    Locate the user's Desktop, honoring OneDrive/known-folder redirection on
    Windows 11 (where Path.home()/Desktop is often NOT the real desktop).
    """
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "Desktop")
            resolved = Path(os.path.expandvars(val))
            if resolved.exists():
                return resolved
        except Exception:  # noqa: BLE001 - fall back to the naive path
            pass
    return Path.home() / "Desktop"


def resolve_output_dir(args, logger: logging.Logger) -> Path:
    """Resolve the output directory (default <Desktop>\\Spectra); create it."""
    out_dir = Path(args.output_dir).expanduser() if args.output_dir else (_default_desktop_dir() / "Spectra")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error("Could not create output directory %s: %s", out_dir, e)
        logger.warning("Falling back to current working directory: %s", os.getcwd())
        out_dir = Path(os.getcwd())
    return out_dir


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_PIPELINE_DEFAULTS = {
    "upload_workers": 10, "result_pollers": 1, "result_poll_interval": 2,
    "report_wait_hours": 12, "max_in_flight": 10000,
    "backoff_base_seconds": 2, "backoff_max_seconds": 60,
    "upload_retry_window": 600, "max_upload_attempts": 8,
    "ready_check_interval": 5, "ready_max_wait": 300,
    "db_path": "scan_state.db", "retention_days": 7,
    "cleanup_old_records": "ask", "store_full_report": False,
}

_ENV_VAR_RE = re.compile(r"\$\{([^}]*)\}")

def _expand_env(value: str) -> str:
    if not value:
        return value
    # ${VAR} expands to env value; missing vars expand to "". A bare $VAR is
    # left literal — tokens/passwords may legitimately contain '$'.
    return _ENV_VAR_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)

def load_config(path: str) -> argparse.Namespace:
    """Load scanner configuration from an INI file into an args-shaped Namespace."""
    # interpolation=None: default BasicInterpolation would crash on a literal
    # '%' in tokens/proxy URLs.
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"),
                                   interpolation=None)
    with open(path, encoding="utf-8") as f:
        cp.read_file(f)

    def g(sec, key, default=None):
        if cp.has_option(sec, key):
            return _expand_env(cp.get(sec, key).strip())
        return default

    def gi(sec, key, default):
        v = g(sec, key)
        try:
            return int(v) if v not in (None, "") else default
        except ValueError:
            logging.warning("Invalid int for %s.%s=%r; using %s", sec, key, v, default)
            return default

    def gb(sec, key, default):
        v = g(sec, key)
        if v in (None, ""):
            return default
        return str(v).lower() in ("1", "true", "yes", "on")

    a = argparse.Namespace()
    # [detect]
    a.host = g("detect", "host", "") or ""
    a.token = g("detect", "token", "") or ""
    a.proxy = g("detect", "proxy", "") or None
    a.no_verify_ssl = gb("detect", "no_verify_ssl", False)
    # [scan]
    a.drive = g("scan", "drive", "") or ""
    a.extensions = g("scan", "extensions", "") or ""
    a.exclude_extensions = g("scan", "exclude_extensions", "") or ""
    a.preset = g("scan", "preset", "") or None
    a.file_types = g("scan", "file_types", "") or ""
    a.skip_hidden_dirs = gb("scan", "skip_hidden_dirs", False)
    a.analysis_depth = g("scan", "analysis_depth", "full") or "full"
    a.detect_file_type = gb("scan", "detect_file_type", True)
    a.extract_strings = gb("scan", "extract_strings", False)
    a.extract_iocs = gb("scan", "extract_iocs", False)
    a.min_string_len = gi("scan", "min_string_len", DEFAULT_MIN_STRING_LEN)
    a.max_strings = gi("scan", "max_strings", DEFAULT_MAX_STRINGS)
    a.max_iocs = gi("scan", "max_iocs", DEFAULT_MAX_IOCS)
    a.max_enrich_bytes = gi("scan", "max_enrich_bytes", DEFAULT_MAX_ENRICH_BYTES)
    a.large_file_threshold = gi("scan", "large_file_threshold", DEFAULT_LARGE_FILE_THRESHOLD)
    # No backend API parameter exists for these yet (and the string/IOC
    # extractors are not wired into results); say so instead of silently
    # ignoring a non-default value.
    if a.analysis_depth != "full":
        logging.warning("analysis_depth is currently a no-op")
    if a.large_file_threshold != DEFAULT_LARGE_FILE_THRESHOLD:
        logging.warning("large_file_threshold is currently a no-op")
    if not a.detect_file_type:
        logging.warning("detect_file_type is currently a no-op")
    if a.max_enrich_bytes != DEFAULT_MAX_ENRICH_BYTES:
        logging.warning("max_enrich_bytes is currently a no-op")
    if a.extract_strings:
        logging.warning("extract_strings is currently a no-op")
    if a.extract_iocs:
        logging.warning("extract_iocs is currently a no-op")
    a.read_speed_test = (g("scan", "read_speed_test", "ask") or "ask").lower()
    a.min_read_mbps = gi("scan", "min_read_mbps", 1)
    a.read_test_max_bytes = gi("scan", "read_test_max_bytes", 64 << 20)
    a.read_test_max_seconds = gi("scan", "read_test_max_seconds", 10)
    a.backend = (g("scan", "backend", "detect") or "detect").lower()
    if a.backend not in ("detect", "a1000", "fie", "cloud"):
        logging.error("scan.backend=%r invalid; valid: detect|a1000|fie|cloud",
                      a.backend)
        sys.exit(2)
    # [pipeline]
    a.upload_workers = gi("pipeline", "upload_workers", _PIPELINE_DEFAULTS["upload_workers"])
    a.result_pollers = gi("pipeline", "result_pollers", _PIPELINE_DEFAULTS["result_pollers"])
    a.result_poll_interval = gi("pipeline", "result_poll_interval", 2)
    a.report_wait_hours = gi("pipeline", "report_wait_hours", 12)
    a.max_in_flight = gi("pipeline", "max_in_flight", 10000)
    a.progress_every = gi("pipeline", "progress_every", 100)
    a.avail_probe_seconds = gi("pipeline", "avail_probe_seconds", 20)
    a.max_files = gi("scan", "max_files", 0)
    # legacy alias: [output] workers -> upload_workers, only when [pipeline]
    # does not set upload_workers (explicit pipeline config always wins)
    if not cp.has_option("pipeline", "upload_workers"):
        legacy_workers = gi("output", "workers", None)
        if legacy_workers:
            a.upload_workers = legacy_workers
    a.workers = a.upload_workers  # keep old attr alive for _build_metadata
    # legacy SDK polling attrs (until async pipeline replaces them)
    a.poll_interval = a.result_poll_interval
    a.max_retries = DEFAULT_MAX_RETRIES
    # [backoff]
    a.backoff_base_seconds = gi("backoff", "base_seconds", 2)
    a.backoff_max_seconds = gi("backoff", "max_seconds", 60)
    a.upload_retry_window = gi("backoff", "upload_retry_window", 600)
    a.max_upload_attempts = gi("backoff", "max_upload_attempts", 8)
    a.ready_check_interval = gi("backoff", "ready_check_interval", 5)
    a.ready_max_wait = gi("backoff", "ready_max_wait", 300)
    # [database]
    a.db_path = g("database", "path", "scan_state.db") or "scan_state.db"
    a.retention_days = gi("database", "retention_days", 7)
    a.cleanup_old_records = (g("database", "cleanup_old_records", "ask") or "ask").lower()
    a.store_full_report = gb("database", "store_full_report", False)
    # [actions]
    a.resume = gb("actions", "resume", True)
    a.quarantine_action = g("actions", "quarantine_action", "none") or "none"
    a.quarantine_dir = g("actions", "quarantine_dir", "") or None
    a.quarantine_on = g("actions", "quarantine_on", "malicious") or "malicious"
    a.alert_on = g("actions", "alert_on", "malicious,suspicious") or ""
    a.alert_webhook = g("actions", "alert_webhook", "") or None
    a.alert_syslog = g("actions", "alert_syslog", "") or None
    a.alert_eventlog = gb("actions", "alert_eventlog", False)
    # [output]
    a.output_dir = g("output", "output_dir", "") or None
    a.output = g("output", "output", OUTPUT_FILENAME) or OUTPUT_FILENAME
    a.report_formats = g("output", "report_formats", "json,csv,html,pdf") or "json"
    a.summary_only = gb("output", "summary_only", False)
    a.verbose = gb("output", "verbose", False)
    a.log_max_mb = gi("output", "log_max_mb", 50)
    a.log_backups = gi("output", "log_backups", 5)
    # [fie]
    a.fie_host = g("fie", "host", "") or ""
    a.fie_mode = (g("fie", "mode", "hash_then_scan") or "hash_then_scan").lower()
    if a.fie_mode not in ("scan", "hash_then_scan", "hash_only"):
        logging.warning("fie.mode=%r invalid; using 'hash_then_scan'", a.fie_mode)
        a.fie_mode = "hash_then_scan"
    a.fie_trust_ok = gb("fie", "trust_ok", False)
    a.fie_external_id = (g("fie", "external_id", "rel_path") or "rel_path").lower()
    if a.fie_external_id not in ("rel_path", "filename", "none"):
        logging.warning("fie.external_id=%r invalid; using 'rel_path'",
                        a.fie_external_id)
        a.fie_external_id = "rel_path"
    # [a1000]
    a.a1000_host = g("a1000", "host", "") or ""
    a.a1000_token = g("a1000", "token", "") or ""
    a.a1000_analysis = g("a1000", "analysis", "cloud")
    a.a1000_tags = g("a1000", "tags", "") or ""
    a.a1000_comment = g("a1000", "comment", "") or ""
    a.a1000_archive_password = g("a1000", "archive_password", "") or ""
    a.a1000_sandbox_platform = g("a1000", "sandbox_platform", "") or ""
    a.a1000_report_detail = (g("a1000", "report_detail", "summary")
                             or "summary").lower()
    if a.a1000_report_detail not in ("summary", "full"):
        logging.warning("a1000.report_detail=%r invalid; using 'summary'",
                        a.a1000_report_detail)
        a.a1000_report_detail = "summary"
    # [ticloud]
    a.ticloud_host = (g("ticloud", "host", "https://data.reversinglabs.com")
                      or "https://data.reversinglabs.com")
    a.ticloud_username = g("ticloud", "username", "") or ""
    a.ticloud_password = g("ticloud", "password", "") or ""
    a.ticloud_domain = g("ticloud", "domain", "") or ""
    a.ticloud_archive_password = g("ticloud", "archive_password", "") or ""
    a.ticloud_upload_timeout = gi("ticloud", "upload_timeout", 300)
    a.ticloud_min_interval_ms = gi("ticloud", "min_interval_ms", 100)
    a.ticloud_extended = gb("ticloud", "extended", True)
    # [reputation]
    a.reputation_precheck = gb("reputation", "precheck", False)
    a.reputation_batch_size = gi("reputation", "batch_size", 100)
    if a.reputation_batch_size > 100:
        logging.warning("reputation.batch_size=%d exceeds API max 100; clamping",
                        a.reputation_batch_size)
        a.reputation_batch_size = 100
    a.reputation_skip_classified = gb("reputation", "skip_classified", True)
    # [scan] extensions: "all" means no filter (None)
    if (a.extensions or "").lower() == "all":
        a.extensions = ""
    return a


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Async USB Spectra Detect scanner (config.ini driven).")
    p.add_argument("--config", default="config.ini", help="Path to config.ini")
    p.add_argument("--init-config", metavar="PATH",
                   help="Write a default config.ini to PATH and exit")
    ns = p.parse_args()
    if ns.init_config:
        src = Path(__file__).with_name("config.ini.template")
        shutil.copyfile(src, ns.init_config)
        print(f"Wrote {ns.init_config}")
        sys.exit(0)
    return load_config(ns.config)


EXTENSION_PRESETS = {
    "executables": DEFAULT_EXECUTABLE_EXTENSIONS,
    "documents": DEFAULT_DOCUMENT_EXTENSIONS,
    "archives": DEFAULT_ARCHIVE_EXTENSIONS,
    "media": DEFAULT_MEDIA_EXTENSIONS,
    "scripts-web": DEFAULT_SCRIPT_WEB_EXTENSIONS,
    "all": ALL_DEFAULT_EXTENSIONS,
}


def determine_extensions(args) -> Optional[Set[str]]:
    """Resolve which extension set to use based on CLI arguments (None => all)."""
    if args.exclude_extensions:
        return ALL_DEFAULT_EXTENSIONS.difference(parse_extension_list(args.exclude_extensions))
    if args.extensions:
        exts = parse_extension_list(args.extensions)
        # config.ini documents 'extensions = <preset name>'; '.executables' as
        # a literal extension would silently match nothing.
        if len(exts) == 1:
            only = next(iter(exts)).lstrip(".")
            if only in EXTENSION_PRESETS:
                return set(EXTENSION_PRESETS[only])
        return exts
    if args.preset:
        return set(EXTENSION_PRESETS[args.preset])  # validated in normalize_args
    return None


def normalize_args(args, logger: logging.Logger) -> None:
    """Post-process raw CLI args into the typed collections the scan expects."""
    args.file_types = parse_csv_option(args.file_types)
    invalid = args.file_types - FILE_TYPE_CATEGORIES
    if invalid:
        logger.warning("Ignoring unknown --file-types: %s", ", ".join(sorted(invalid)))
        args.file_types &= FILE_TYPE_CATEGORIES

    # Filtering by detected type is impossible without detection; force it on.
    if args.file_types and not args.detect_file_type:
        logger.info("--file-types requires file-type detection; enabling it.")
        args.detect_file_type = True

    args.quarantine_on = parse_csv_option(args.quarantine_on)
    args.alert_on = parse_csv_option(args.alert_on)

    fmts = parse_csv_option(args.report_formats) or {"json"}
    valid_fmts = {"json", "csv", "html", "pdf"}
    bad = fmts - valid_fmts
    if bad:
        logger.warning("Ignoring unknown --report-formats: %s", ", ".join(sorted(bad)))
    args.report_formats = (fmts & valid_fmts) or {"json"}

    if args.workers < 1:
        args.workers = 1
    if args.upload_workers < 1:
        args.upload_workers = 1
    if args.result_pollers < 1:
        args.result_pollers = 1

    if args.cleanup_old_records not in ("ask", "always", "never"):
        logger.warning("cleanup_old_records=%r invalid; using 'ask'",
                       args.cleanup_old_records)
        args.cleanup_old_records = "ask"

    args.read_speed_test = str(getattr(args, "read_speed_test", "ask")).lower()
    if args.read_speed_test not in ("ask", "always", "off"):
        logger.warning("read_speed_test=%r invalid; using 'ask'",
                       args.read_speed_test)
        args.read_speed_test = "ask"

    args.quarantine_action = str(getattr(args, "quarantine_action", "none")).lower()
    if args.quarantine_action not in ("none", "copy", "move"):
        logger.warning("quarantine_action=%r invalid; using 'none'",
                       args.quarantine_action)
        args.quarantine_action = "none"

    if getattr(args, "preset", None) and args.preset not in EXTENSION_PRESETS:
        logger.error("preset=%r invalid; valid presets: %s",
                     args.preset, ", ".join(sorted(EXTENSION_PRESETS)))
        sys.exit(2)

    if not args.host or not args.token or not args.drive:
        logger.error("config.ini missing required detect.host/detect.token/scan.drive")
        sys.exit(2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    provisional = setup_logging(args.verbose, None)
    output_dir = resolve_output_dir(args, provisional)
    # Per-run artifact folder: keeps each scan's log/reports/ndjson separate
    # instead of appending into the same files run over run. scan_state.db
    # deliberately stays at output_dir so resume works across runs.
    run_dir = output_dir / ("run_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    run_dir.mkdir(parents=True, exist_ok=True)
    output_filename = args.output or OUTPUT_FILENAME
    log_path = run_dir / LOG_FILENAME

    # Reconfigure logging to also write into the Spectra folder.
    for h in list(logging.getLogger().handlers):
        logging.getLogger().removeHandler(h)
    logger = setup_logging(args.verbose, str(log_path),
                           getattr(args, "log_max_mb", 50),
                           getattr(args, "log_backups", 5))

    normalize_args(args, logger)
    include_extensions = determine_extensions(args)

    if args.no_verify_ssl:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # noqa: BLE001
            pass

    logger.info("=" * 72)
    logger.info("USB Spectra Detect Scanner v%s (Official SDK)", SCRIPT_VERSION)
    logger.info("=" * 72)
    logger.info("Configuration:")
    logger.info("  Drive:                %s", args.drive)
    logger.info("  Spectra Detect Host:  %s", args.host)
    logger.info("  Workers:              %s", args.workers)
    logger.info("  Analysis Depth:       %s", args.analysis_depth)
    logger.info("  Resume:               %s", "on" if args.resume else "off")
    logger.info("  Detect File Type:     %s", "on" if args.detect_file_type else "off")
    logger.info("  Extract Strings:      %s", "on" if args.extract_strings else "off")
    logger.info("  Extract IOCs:         %s", "on" if args.extract_iocs else "off")
    logger.info("  File-type Filter:     %s", ", ".join(sorted(args.file_types)) or "none")
    logger.info("  Quarantine:           %s (on: %s)", args.quarantine_action,
                ", ".join(sorted(args.quarantine_on)) or "none")
    logger.info("  Alert On:             %s", ", ".join(sorted(args.alert_on)) or "none")
    logger.info("  Report Formats:       %s", ", ".join(sorted(args.report_formats)))
    logger.info("  SSL Verification:     %s", "Disabled" if args.no_verify_ssl else "Enabled")
    logger.info("  Output Directory:     %s", output_dir)
    logger.info("  Run Directory:        %s", run_dir)
    logger.info("  Extension Filter:     %s",
                f"{len(include_extensions)} types" if include_extensions else "NONE (all files)")
    logger.info("-" * 72)

    output = run_scan(args, include_extensions, output_dir, logger,
                      run_dir=run_dir)

    write_reports(output, run_dir, output_filename, args.report_formats, logger)

    summary = output.get("summary", {})
    logger.info("-" * 72)
    logger.info("SCAN COMPLETE")
    logger.info("  Total files matched:     %s", summary.get("total_files_matched_filter", 0))
    logger.info("  Files processed:         %s", summary.get("files_processed", 0))
    logger.info("  Completed/cached:        %s", summary.get("files_completed_successfully", 0))
    logger.info("  Uploads submitted:       %s", summary.get("uploads_submitted", 0))
    logger.info("  Cached hits:             %s", summary.get("cached_hits", 0))
    logger.info("  Skipped (file-type):     %s", summary.get("skipped_by_filetype", 0))
    logger.info("  Malicious:               %s", summary.get("malicious", 0))
    logger.info("  Suspicious:              %s", summary.get("suspicious", 0))
    logger.info("  Quarantined:             %s", summary.get("quarantined", 0))
    logger.info("  Alerts raised:           %s", summary.get("alerts", 0))
    logger.info("  Errors:                  %s", summary.get("files_with_errors", 0))
    logger.info("=" * 72)

    sys.exit(1 if summary.get("files_with_errors", 0) > 0 else 0)


if __name__ == "__main__":
    main()
