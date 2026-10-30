// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// M5: scanned files are opened only if they are regular files and not
// symlinks (TOCTOU: a file swapped for a symlink after the walk must not be
// hashed, uploaded or quarantined through the link).
func TestOpenRegularRefusesSymlinkAndDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t.bin")
	if err := os.WriteFile(target, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	f, err := openRegular(target)
	if err != nil {
		t.Fatalf("regular file refused: %v", err)
	}
	f.Close()
	if f, err := openRegular(link); err == nil {
		f.Close()
		t.Fatal("symlink opened")
	}
	if f, err := openRegular(dir); err == nil {
		f.Close()
		t.Fatal("directory opened")
	}
	// Every scanned-file consumer goes through it.
	if sha, _, _, _ := readHashCapture(link, 16, false); sha != "" {
		t.Fatalf("symlink hashed: %s", sha)
	}
	if err := copyFile(link, filepath.Join(dir, "copy.bin")); err == nil {
		t.Fatal("quarantine copy followed a symlink")
	}
}
