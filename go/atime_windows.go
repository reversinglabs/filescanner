// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// accessTime returns the source atime via GetFileTime on the verified fd —
// Windows FileInfo.Sys() is nil, so the handle is the only source. The
// caller must invoke it before the copy reads the file (a read bumps
// atime). Falls back to mtime on error — the pre-parity behaviour.
func accessTime(f *os.File, st os.FileInfo) time.Time {
	var at windows.Filetime
	if err := windows.GetFileTime(windows.Handle(f.Fd()),
		nil, &at, nil); err == nil {
		return time.Unix(0, at.Nanoseconds())
	}
	return st.ModTime()
}
