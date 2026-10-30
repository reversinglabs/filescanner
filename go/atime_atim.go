// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build aix || android || hurd || illumos || linux || solaris

package main

import (
	"os"
	"syscall"
	"time"
)

// accessTime returns the atime from st (taken by fstat on the verified
// source fd), matching Python's st_atime_ns in _copy_verified. Falls back
// to mtime when the stat payload is missing — the pre-parity behaviour.
func accessTime(_ *os.File, st os.FileInfo) time.Time {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(s.Atim.Sec), int64(s.Atim.Nsec))
	}
	return st.ModTime()
}
