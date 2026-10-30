# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

import pytest
import filescanner as fs
from unittest.mock import MagicMock


def _args(mode="ask", min_mbps=99999, max_bytes=4096, max_secs=5):
    return MagicMock(read_speed_test=mode, min_read_mbps=min_mbps,
                     read_test_max_bytes=max_bytes,
                     read_test_max_seconds=max_secs)


def test_disk_gate_blocks_on_user_no(tmp_path, monkeypatch):
    f = tmp_path / "f.bin"; f.write_bytes(b"x" * 4096)
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    with pytest.raises(SystemExit):
        fs.disk_read_gate(_args(), [(str(f), "f.bin")], MagicMock())


def test_disk_gate_proceeds_on_user_yes(tmp_path, monkeypatch):
    f = tmp_path / "f.bin"; f.write_bytes(b"x" * 4096)
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    fs.disk_read_gate(_args(), [(str(f), "f.bin")], MagicMock())  # no exit


def test_disk_gate_eof_input_aborts(tmp_path, monkeypatch):
    f = tmp_path / "f.bin"; f.write_bytes(b"x" * 4096)
    def _eof(*a):
        raise EOFError
    monkeypatch.setattr("builtins.input", _eof)
    with pytest.raises(SystemExit):
        fs.disk_read_gate(_args(), [(str(f), "f.bin")], MagicMock())


def test_disk_gate_always_aborts_without_prompt(tmp_path, monkeypatch):
    f = tmp_path / "f.bin"; f.write_bytes(b"x" * 4096)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))
    with pytest.raises(SystemExit):
        fs.disk_read_gate(_args(mode="always"), [(str(f), "f.bin")],
                          MagicMock())


def test_disk_gate_off_skips(tmp_path, monkeypatch):
    f = tmp_path / "f.bin"; f.write_bytes(b"x" * 4096)
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))
    fs.disk_read_gate(_args(mode="off"), [(str(f), "f.bin")], MagicMock())


def test_disk_gate_passes_when_fast(tmp_path):
    f = tmp_path / "f.bin"; f.write_bytes(b"x" * 4096)
    fs.disk_read_gate(_args(min_mbps=0), [(str(f), "f.bin")], MagicMock())


def test_disk_gate_empty_work_skips(monkeypatch):
    monkeypatch.setattr("builtins.input",
                        lambda *a: pytest.fail("must not prompt"))
    fs.disk_read_gate(_args(), [], MagicMock())
