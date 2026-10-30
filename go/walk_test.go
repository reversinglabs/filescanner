// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func walkAll(t *testing.T, root string, skipHidden bool) []string {
	t.Helper()
	ch := make(chan workItem, 64)
	go iterWorkItems(root, nil, skipHidden, ch)
	var got []string
	timeout := time.After(10 * time.Second)
	for {
		select {
		case it, ok := <-ch:
			if !ok {
				sort.Strings(got)
				return got
			}
			got = append(got, it.RelPath)
		case <-timeout:
			t.Fatal("walk timed out")
		}
	}
}

func TestWalkSkipsSymlinksAndFifos(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	outside := filepath.Join(t.TempDir(), "secret.bin")
	os.MkdirAll(root, 0o755)
	os.WriteFile(outside, []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "a.bin"), []byte("a"), 0o644)
	if err := os.Symlink(outside, filepath.Join(root, "link.bin")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if runtime.GOOS != "windows" {
		if err := mkfifo(filepath.Join(root, "pipe")); err != nil {
			t.Fatal(err)
		}
	}
	got := walkAll(t, root, false)
	if len(got) != 1 || got[0] != "a.bin" {
		t.Fatalf("got %v, want [a.bin]", got)
	}
}

func TestWalkHiddenDirsConfigurable(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".hid"), 0o755)
	os.WriteFile(filepath.Join(root, ".hid", "h.bin"), []byte("h"), 0o644)
	os.WriteFile(filepath.Join(root, "v.bin"), []byte("v"), 0o644)
	if got := walkAll(t, root, false); len(got) != 2 {
		t.Fatalf("scan hidden: got %v", got)
	}
	if got := walkAll(t, root, true); len(got) != 1 || got[0] != "v.bin" {
		t.Fatalf("skip hidden: got %v", got)
	}
}

func TestQuarantineRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t.bin")
	os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(dir, "l.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	lg := newLogger(false, "", 0, 0)
	if got := quarantineFile(link, "abcdef0123456789ab", "malicious",
		filepath.Join(dir, "q"), "copy", lg); got != "" {
		t.Fatalf("symlink quarantined to %q", got)
	}
}

// M3: a symlinked drive root is walked through its resolved target, but the
// emitted absolute paths keep the ORIGINAL root prefix (Python parity).
func TestWalkSymlinkedRootKeepsOriginalPrefix(t *testing.T) {
	real := t.TempDir()
	os.WriteFile(filepath.Join(real, "a.bin"), []byte("a"), 0o644)
	link := filepath.Join(t.TempDir(), "drive")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	ch := make(chan workItem, 8)
	go iterWorkItems(link, nil, false, ch)
	var got []workItem
	timeout := time.After(10 * time.Second)
	for done := false; !done; {
		select {
		case it, ok := <-ch:
			if !ok {
				done = true
				break
			}
			got = append(got, it)
		case <-timeout:
			t.Fatal("walk timed out")
		}
	}
	want := filepath.Join(link, "a.bin")
	if len(got) != 1 || got[0].AbsPath != want || got[0].RelPath != "a.bin" {
		t.Fatalf("got %+v, want AbsPath=%s RelPath=a.bin", got, want)
	}
}

// Exclusions (skipFiles / skipDirs) are applied before counting an entry as
// non-regular, matching Python's order.
func TestWalkSkipCountExcludesSkippedNames(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "real.bin"), []byte("x"), 0o644)
	if err := os.Symlink(filepath.Join(root, "real.bin"), filepath.Join(root, StateFilename)); err != nil {
		t.Skip("symlinks unavailable")
	}
	os.Symlink(root, filepath.Join(root, "dirlink"))
	var buf bytes.Buffer
	lg := newLogger(false, "", 0, 0)
	lg.out = &buf
	out := make(chan workItem, 16)
	iterWorkItems(root, nil, false, out, lg)
	// only "dirlink" is counted; the excluded state file is not.
	if !strings.Contains(buf.String(), "Skipped 1 non-regular entries") {
		t.Fatalf("log=%q", buf.String())
	}
}
