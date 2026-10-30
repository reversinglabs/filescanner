// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build unix

package main

import (
	"os"
	"syscall"
)

// openNoFollow opens path read-only without following a final symlink
// (O_NOFOLLOW: a symlink fails with ELOOP).
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
