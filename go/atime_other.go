// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build !(aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris || windows)

package main

import (
	"os"
	"time"
)

// accessTime: no portable atime on this platform — fall back to mtime,
// the pre-parity behaviour.
func accessTime(_ *os.File, st os.FileInfo) time.Time {
	return st.ModTime()
}
