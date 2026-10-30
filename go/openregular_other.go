// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build !unix

package main

import "os"

// openNoFollow: no O_NOFOLLOW here (Windows) — reject a symlink/reparse
// point by Lstat first; openRegular's fstat check still refuses anything
// that is not a regular file once opened.
func openNoFollow(path string) (*os.File, error) {
	if li, err := os.Lstat(path); err != nil {
		return nil, err
	} else if li.Mode()&os.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path,
			Err: errNotRegular}
	}
	return os.Open(path)
}
