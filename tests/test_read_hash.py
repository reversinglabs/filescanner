# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import hashlib
import filescanner as fs


def test_sha1_computed_only_when_requested(tmp_path):
    """FIE/cloud backends address samples by sha1, detect/a1000 do not — the
    extra hasher is opt-in so the default path stays sha256-only."""
    data = b"hello world" * 1000
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    sha256, sha1, head, total = fs.read_hash_capture(str(p), 4)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert sha1 is None
    assert head == data[:4]
    assert total == len(data)

    sha256, sha1, head, total = fs.read_hash_capture(str(p), 4, want_sha1=True)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert sha1 == hashlib.sha1(data).hexdigest()


def test_sha1_single_streaming_pass(tmp_path, monkeypatch):
    """Both digests must come from ONE read of the file — a second pass would
    double I/O cost on slow USB-attached sources."""
    data = b"x" * (3 * 1024 * 1024 + 7)      # spans multiple read chunks
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    real_open = fs.open_regular
    opens = []

    def spy(*a, **k):
        opens.append(a[0])
        return real_open(*a, **k)

    monkeypatch.setattr(fs, "open_regular", spy)
    sha256, sha1, _, _ = fs.read_hash_capture(str(p), 0, want_sha1=True)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert sha1 == hashlib.sha1(data).hexdigest()
    assert opens == [str(p)]                  # exactly one open
